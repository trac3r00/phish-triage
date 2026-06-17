"""Stage 2 enrichment — VirusTotal v3 + AbuseIPDB lookups + verdict scoring.

The :func:`enrich_eml` entry point takes a parsed email (see :mod:`.parser`)
and returns a :class:`EnrichmentResult` with:

* per-URL / per-hash VirusTotal verdicts
* per-IP AbuseIPDB confidence
* a 0-100 weighted score with verdict ``benign | suspicious | malicious``
* a list of textual rationale strings explaining how we got to the score

Network calls go through :class:`HTTPSession`, a thin wrapper around
``requests.Session`` that:

* respects a per-source rate limit (default 4 req/min, the VT free tier)
* caches responses under ``.cache/`` keyed by ``(source, IOC)``
* skips a source entirely if its API key is missing (with a note in the report)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover - requests is a hard dep at runtime
    requests = None  # type: ignore[assignment]

from .parser import ParsedEmail


VT_API = "https://www.virustotal.com/api/v3"
ABUSE_API = "https://api.abuseipdb.com/api/v2"


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------


@dataclass
class VTVerdict:
    """One VirusTotal v3 attributes payload, condensed."""

    ioc: str
    kind: str  # "url" | "domain" | "file"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    error: str | None = None


@dataclass
class AbuseVerdict:
    """One AbuseIPDB check response, condensed."""

    ip: str
    abuse_confidence: int = 0
    total_reports: int = 0
    country_code: str | None = None
    domain: str | None = None
    error: str | None = None


@dataclass
class EnrichmentResult:
    """Top-level enrichment payload."""

    vt_url_results: list[VTVerdict] = field(default_factory=list)
    vt_file_results: list[VTVerdict] = field(default_factory=list)
    abuseipdb_results: list[AbuseVerdict] = field(default_factory=list)
    score: int = 0
    verdict: str = "benign"
    rationale: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rate limiter + cache + HTTP wrapper
# ---------------------------------------------------------------------------


class RateLimiter:
    """Simple sliding-window rate limiter (requests-per-minute)."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = max(1, per_minute)
        self._stamps: list[float] = []

    def wait(self) -> None:
        now = time.monotonic()
        window_start = now - 60.0
        self._stamps = [t for t in self._stamps if t > window_start]
        if len(self._stamps) >= self.per_minute:
            sleep_for = 60.0 - (now - self._stamps[0]) + 0.05
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._stamps.append(time.monotonic())


def _cache_key(source: str, ioc: str) -> str:
    digest = hashlib.sha1(f"{source}:{ioc}".encode("utf-8")).hexdigest()
    return f"{source}_{digest}.json"


class HTTPSession:
    """``requests.Session`` + cache + rate limit, with graceful degradation."""

    def __init__(
        self,
        cache_dir: Path | None,
        vt_key: str | None,
        abuse_key: str | None,
        vt_per_minute: int = 4,
        abuse_per_minute: int = 30,
    ) -> None:
        if requests is None:  # pragma: no cover
            raise RuntimeError("`requests` is required for Stage 2 enrichment")
        self.cache_dir = cache_dir
        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.vt_key = vt_key
        self.abuse_key = abuse_key
        self.vt_rl = RateLimiter(vt_per_minute)
        self.abuse_rl = RateLimiter(abuse_per_minute)

    # -- cache ----------------------------------------------------------------

    def _cache_get(self, source: str, ioc: str) -> dict[str, Any] | None:
        if self.cache_dir is None:
            return None
        path = self.cache_dir / _cache_key(source, ioc)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _cache_put(self, source: str, ioc: str, payload: dict[str, Any]) -> None:
        if self.cache_dir is None:
            return
        path = self.cache_dir / _cache_key(source, ioc)
        try:
            path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass

    # -- VirusTotal -----------------------------------------------------------

    def vt_url(self, url: str) -> VTVerdict:
        return self._vt_lookup("url", url)

    def vt_file(self, sha256: str) -> VTVerdict:
        return self._vt_lookup("file", sha256)

    def _vt_lookup(self, kind: str, ioc: str) -> VTVerdict:
        if not self.vt_key:
            return VTVerdict(ioc=ioc, kind=kind, error="missing VT_API_KEY")
        cached = self._cache_get(f"vt_{kind}", ioc)
        if cached is not None:
            return self._vt_summarise(ioc, kind, cached)

        if kind == "url":
            ident = _vt_url_id(ioc)
            endpoint = f"{VT_API}/urls/{ident}"
        elif kind == "file":
            endpoint = f"{VT_API}/files/{ioc}"
        else:
            return VTVerdict(ioc=ioc, kind=kind, error=f"unknown kind {kind}")

        self.vt_rl.wait()
        try:
            r = self.session.get(
                endpoint,
                headers={"x-apikey": self.vt_key, "Accept": "application/json"},
                timeout=15,
            )
        except requests.RequestException as exc:  # type: ignore[union-attr]
            return VTVerdict(ioc=ioc, kind=kind, error=f"request failed: {exc}")
        if r.status_code == 404:
            payload = {"data": {"attributes": {"last_analysis_stats": {}}}}
            self._cache_put(f"vt_{kind}", ioc, payload)
            return self._vt_summarise(ioc, kind, payload)
        if r.status_code != 200:
            return VTVerdict(ioc=ioc, kind=kind, error=f"HTTP {r.status_code}")
        payload = r.json()
        self._cache_put(f"vt_{kind}", ioc, payload)
        return self._vt_summarise(ioc, kind, payload)

    @staticmethod
    def _vt_summarise(ioc: str, kind: str, payload: dict[str, Any]) -> VTVerdict:
        attrs = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return VTVerdict(
            ioc=ioc,
            kind=kind,
            malicious=int(stats.get("malicious") or 0),
            suspicious=int(stats.get("suspicious") or 0),
            harmless=int(stats.get("harmless") or 0),
            undetected=int(stats.get("undetected") or 0),
            reputation=attrs.get("reputation"),
        )

    # -- AbuseIPDB ------------------------------------------------------------

    def abuse_check(self, ip: str) -> AbuseVerdict:
        if not self.abuse_key:
            return AbuseVerdict(ip=ip, error="missing ABUSEIPDB_API_KEY")
        cached = self._cache_get("abuse", ip)
        if cached is not None:
            return self._abuse_summarise(ip, cached)
        self.abuse_rl.wait()
        try:
            r = self.session.get(
                f"{ABUSE_API}/check",
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=15,
            )
        except requests.RequestException as exc:  # type: ignore[union-attr]
            return AbuseVerdict(ip=ip, error=f"request failed: {exc}")
        if r.status_code != 200:
            return AbuseVerdict(ip=ip, error=f"HTTP {r.status_code}")
        payload = r.json()
        self._cache_put("abuse", ip, payload)
        return self._abuse_summarise(ip, payload)

    @staticmethod
    def _abuse_summarise(ip: str, payload: dict[str, Any]) -> AbuseVerdict:
        data = payload.get("data") or {}
        return AbuseVerdict(
            ip=ip,
            abuse_confidence=int(data.get("abuseConfidenceScore") or 0),
            total_reports=int(data.get("totalReports") or 0),
            country_code=data.get("countryCode"),
            domain=data.get("domain"),
        )


def _vt_url_id(url: str) -> str:
    """VT v3 URL identifier = URL-safe base64 of the URL, no padding."""

    import base64

    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# IOC selection
# ---------------------------------------------------------------------------


_PUBLIC_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _hostname_from_url(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host or None


def _select_public_ips(parsed: ParsedEmail) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for hop in parsed.received_chain:
        ip = hop.from_ip
        if not ip or hop.private_ip or not _PUBLIC_IP_RE.match(ip):
            continue
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


SIGNAL_WEIGHTS: dict[str, int] = {
    "spf_fail": 15,
    "dkim_fail": 10,
    "dmarc_fail": 15,
    "from_reply_to_mismatch": 15,
    "display_name_spoof": 20,
    "received_private_to_public": 10,
    "url_shortener": 10,
    "suspicious_tld": 10,
    "has_attachment": 5,
}


def _verdict_for(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    return "benign"


def _score(
    parsed: ParsedEmail,
    vt_urls: Iterable[VTVerdict],
    vt_files: Iterable[VTVerdict],
    abuses: Iterable[AbuseVerdict],
) -> tuple[int, str, list[str]]:
    score = 0
    rationale: list[str] = []
    for sig in parsed.signals:
        weight = SIGNAL_WEIGHTS.get(sig, 0)
        if weight:
            score += weight
            rationale.append(f"signal `{sig}` (+{weight})")

    for v in vt_urls:
        if v.error:
            continue
        if v.malicious >= 1:
            inc = min(30, 10 * v.malicious)
            score += inc
            rationale.append(
                f"VirusTotal flagged URL `{v.ioc}` as malicious "
                f"({v.malicious} engines) (+{inc})"
            )
        elif v.suspicious >= 2:
            score += 10
            rationale.append(
                f"VirusTotal flagged URL `{v.ioc}` as suspicious "
                f"({v.suspicious} engines) (+10)"
            )

    for v in vt_files:
        if v.error:
            continue
        if v.malicious >= 1:
            inc = min(40, 15 * v.malicious)
            score += inc
            rationale.append(
                f"VirusTotal flagged attachment `{v.ioc[:12]}…` as malicious "
                f"({v.malicious} engines) (+{inc})"
            )

    for a in abuses:
        if a.error:
            continue
        if a.abuse_confidence >= 75:
            score += 20
            rationale.append(
                f"AbuseIPDB confidence {a.abuse_confidence} for IP {a.ip} (+20)"
            )
        elif a.abuse_confidence >= 25:
            score += 10
            rationale.append(
                f"AbuseIPDB confidence {a.abuse_confidence} for IP {a.ip} (+10)"
            )

    score = max(0, min(100, score))
    return score, _verdict_for(score), rationale


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def enrich_eml(
    parsed: ParsedEmail,
    *,
    cache_dir: Path | None = Path(".cache"),
    vt_key: str | None = None,
    abuse_key: str | None = None,
) -> EnrichmentResult:
    """Enrich a parsed email with external threat-intel sources."""

    vt_key = vt_key if vt_key is not None else os.environ.get("VT_API_KEY")
    abuse_key = abuse_key if abuse_key is not None else os.environ.get("ABUSEIPDB_API_KEY")

    notes: list[str] = []
    if not vt_key:
        notes.append("VirusTotal lookups skipped: VT_API_KEY not set.")
    if not abuse_key:
        notes.append("AbuseIPDB lookups skipped: ABUSEIPDB_API_KEY not set.")

    session = HTTPSession(cache_dir=cache_dir, vt_key=vt_key, abuse_key=abuse_key)

    vt_url_results: list[VTVerdict] = []
    if vt_key:
        for url in parsed.urls:
            vt_url_results.append(session.vt_url(url))

    vt_file_results: list[VTVerdict] = []
    if vt_key:
        for att in parsed.attachments:
            vt_file_results.append(session.vt_file(att.sha256))

    abuse_results: list[AbuseVerdict] = []
    if abuse_key:
        for ip in _select_public_ips(parsed):
            abuse_results.append(session.abuse_check(ip))

    score, verdict, rationale = _score(
        parsed, vt_url_results, vt_file_results, abuse_results
    )

    return EnrichmentResult(
        vt_url_results=vt_url_results,
        vt_file_results=vt_file_results,
        abuseipdb_results=abuse_results,
        score=score,
        verdict=verdict,
        rationale=rationale,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def render_report(parsed: ParsedEmail, result: EnrichmentResult) -> str:
    """Analyst-facing markdown report combining Stage 1 + Stage 2."""

    lines: list[str] = []
    lines.append(f"# Phishing triage report — {parsed.subject or '(no subject)'}")
    lines.append("")
    lines.append(f"**Source:** `{parsed.source}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Verdict:** `{result.verdict.upper()}`")
    lines.append(f"- **Score:** {result.score} / 100")
    lines.append(f"- **From:** {parsed.from_header or 'n/a'}")
    lines.append(f"- **Reply-To:** {parsed.reply_to_header or 'n/a'}")
    lines.append(f"- **Subject:** {parsed.subject or 'n/a'}")
    lines.append("")
    lines.append("## IOC table")
    lines.append("")
    lines.append("| Type | Value | Notes |")
    lines.append("|------|-------|-------|")
    for url, defanged in zip(parsed.urls, parsed.urls_defanged):
        host = _hostname_from_url(url) or "?"
        lines.append(f"| url | `{defanged}` | host `{host}` |")
    for att in parsed.attachments:
        lines.append(
            f"| file | `{att.filename}` | sha256 `{att.sha256}` "
            f"({att.size} bytes) |"
        )
    for ip in _select_public_ips(parsed):
        lines.append(f"| ip | `{ip}` | from Received chain |")
    if not (parsed.urls or parsed.attachments or _select_public_ips(parsed)):
        lines.append("| _none_ | | |")
    lines.append("")
    lines.append("## Enrichment evidence")
    lines.append("")
    if result.vt_url_results:
        lines.append("### VirusTotal — URLs")
        lines.append("")
        lines.append("| IOC | mal | susp | harm | err |")
        lines.append("|-----|-----|------|------|-----|")
        for v in result.vt_url_results:
            lines.append(
                f"| `{v.ioc}` | {v.malicious} | {v.suspicious} | "
                f"{v.harmless} | {v.error or '-'} |"
            )
        lines.append("")
    if result.vt_file_results:
        lines.append("### VirusTotal — attachments")
        lines.append("")
        lines.append("| SHA256 | mal | susp | err |")
        lines.append("|--------|-----|------|-----|")
        for v in result.vt_file_results:
            lines.append(
                f"| `{v.ioc}` | {v.malicious} | {v.suspicious} | "
                f"{v.error or '-'} |"
            )
        lines.append("")
    if result.abuseipdb_results:
        lines.append("### AbuseIPDB — Received-chain IPs")
        lines.append("")
        lines.append("| IP | Confidence | Reports | Country | Domain | Err |")
        lines.append("|----|------------|---------|---------|--------|-----|")
        for a in result.abuseipdb_results:
            lines.append(
                f"| `{a.ip}` | {a.abuse_confidence} | {a.total_reports} | "
                f"{a.country_code or '-'} | {a.domain or '-'} | "
                f"{a.error or '-'} |"
            )
        lines.append("")
    lines.append("## Rationale")
    lines.append("")
    if result.rationale:
        for r in result.rationale:
            lines.append(f"- {r}")
    else:
        lines.append("- No suspicious signals were observed.")
    lines.append("")
    if result.notes:
        lines.append("## Notes")
        lines.append("")
        for n in result.notes:
            lines.append(f"- {n}")
        lines.append("")
    return "\n".join(lines)


__all__ = [
    "AbuseVerdict",
    "EnrichmentResult",
    "HTTPSession",
    "RateLimiter",
    "SIGNAL_WEIGHTS",
    "VTVerdict",
    "enrich_eml",
    "render_report",
]


def _payload_to_dict(result: EnrichmentResult) -> dict[str, Any]:  # pragma: no cover
    return asdict(result)
