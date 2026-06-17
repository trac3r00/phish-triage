"""Stage 1 parser — pure stdlib phishing email triage.

Parses a single .eml file and extracts the signals an analyst cares about:

* Authentication-Results: SPF / DKIM / DMARC outcome
* From vs Reply-To address & display-name mismatches
* Received chain with private→public anomaly detection
* All URLs found in text/html body parts (decoded + defanged)
* Attachments with MD5 / SHA1 / SHA256 hashes

The module exposes :func:`parse_eml` which returns a JSON-serialisable
:class:`ParsedEmail` dataclass.  The CLI in :mod:`phish_triage.cli` wraps it.

Only the Python standard library is allowed in this module.
"""

from __future__ import annotations

import email
import email.message
import email.policy
import email.utils
import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.header import decode_header, make_header
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Dataclasses (output schema)
# ---------------------------------------------------------------------------


@dataclass
class AuthResults:
    """Parsed Authentication-Results header."""

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    raw: list[str] = field(default_factory=list)


@dataclass
class AddressMismatch:
    """From vs Reply-To and display-name vs addr-spec checks."""

    from_addr: str | None = None
    from_display_name: str | None = None
    reply_to_addr: str | None = None
    reply_to_display_name: str | None = None
    from_vs_reply_to_mismatch: bool = False
    display_name_addr_mismatch: bool = False


@dataclass
class ReceivedHop:
    """One hop in the Received chain (top = furthest from sender)."""

    index: int
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    timestamp: str | None = None
    private_ip: bool = False
    raw: str = ""


@dataclass
class Attachment:
    """Decoded attachment metadata + cryptographic hashes."""

    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str


@dataclass
class ParsedEmail:
    """Top-level parser output."""

    source: str
    subject: str | None
    message_id: str | None
    date: str | None
    from_header: str | None
    to_header: str | None
    reply_to_header: str | None
    auth_results: AuthResults
    address_mismatch: AddressMismatch
    received_chain: list[ReceivedHop]
    received_anomaly_private_to_public: bool
    urls: list[str]
    urls_defanged: list[str]
    attachments: list[Attachment]
    signals: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------


def _decode(value: str | None) -> str | None:
    """Best-effort RFC 2047 decoder.  Returns ``None`` for missing headers."""

    if value is None:
        return None
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # pragma: no cover - defensive
        return value


def _split_address(value: str | None) -> tuple[str | None, str | None]:
    """Return ``(display_name, addr_spec)`` for an RFC 5322 address header."""

    if not value:
        return None, None
    name, addr = email.utils.parseaddr(value)
    name = _decode(name) or None
    addr = addr or None
    if name == "":
        name = None
    return name, addr


# Authentication-Results — capture mechanism=result tokens.
_AUTH_RE = re.compile(
    r"(?P<mech>spf|dkim|dmarc)\s*=\s*(?P<result>pass|fail|none|neutral|softfail|temperror|permerror|policy|bestguesspass)",
    re.IGNORECASE,
)


def parse_auth_results(message: email.message.Message) -> AuthResults:
    """Parse one or more ``Authentication-Results`` headers."""

    headers = message.get_all("Authentication-Results") or []
    out = AuthResults(raw=list(headers))
    for raw in headers:
        for match in _AUTH_RE.finditer(raw):
            mech = match.group("mech").lower()
            result = match.group("result").lower()
            # Don't overwrite a stronger signal with "none".
            current = getattr(out, mech)
            if current == "none" or current == "":
                setattr(out, mech, result)
    return out


def parse_address_mismatch(message: email.message.Message) -> AddressMismatch:
    """Detect From vs Reply-To mismatches and display-name spoofing."""

    from_name, from_addr = _split_address(message.get("From"))
    rt_name, rt_addr = _split_address(message.get("Reply-To"))

    from_vs_rt = bool(
        from_addr and rt_addr and from_addr.lower() != rt_addr.lower()
    )

    # display-name vs addr-spec: e.g. "PayPal Support <ceo@evil.tld>"
    name_addr_mismatch = False
    if from_name and from_addr:
        # If the display name itself contains an email address that doesn't
        # match the real addr-spec, that's the classic exec-impersonation tell.
        embedded = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", from_name)
        if embedded and embedded.group(0).lower() != from_addr.lower():
            name_addr_mismatch = True
        else:
            # Brand-keyword in display name with unrelated addr-spec domain.
            brands = ("paypal", "microsoft", "apple", "google", "amazon",
                      "irs", "bank", "chase", "wells fargo", "dhl", "fedex")
            lower_name = from_name.lower()
            addr_domain = from_addr.split("@", 1)[-1].lower()
            for brand in brands:
                if brand in lower_name and brand not in addr_domain:
                    name_addr_mismatch = True
                    break

    return AddressMismatch(
        from_addr=from_addr,
        from_display_name=from_name,
        reply_to_addr=rt_addr,
        reply_to_display_name=rt_name,
        from_vs_reply_to_mismatch=from_vs_rt,
        display_name_addr_mismatch=name_addr_mismatch,
    )


# ---------------------------------------------------------------------------
# Received chain
# ---------------------------------------------------------------------------


_RECEIVED_FROM_RE = re.compile(
    r"from\s+(?P<host>[A-Za-z0-9._-]+)?\s*"
    r"(?:\(\s*(?:(?P<host2>[A-Za-z0-9._-]+)?\s*)?\[?(?P<ip>[0-9a-fA-F:.]+)?\]?\s*\))?",
    re.IGNORECASE,
)
_RECEIVED_BY_RE = re.compile(r"by\s+(?P<by>[A-Za-z0-9._-]+)", re.IGNORECASE)


_RFC1918_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def _is_private(ip: str | None) -> bool:
    """True for RFC 1918 / loopback / link-local — i.e. *internal* hops.

    Note: we intentionally do NOT use :pyattr:`ipaddress.IPv4Address.is_private`
    here, because the stdlib lumps RFC 5737 documentation ranges
    (192.0.2/24, 198.51.100/24, 203.0.113/24) into ``is_private``.  Those
    ranges are what test fixtures use to represent *public* internet hosts,
    so treating them as private would mask real anomalies.
    """

    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local:
        return True
    return any(addr in net for net in _RFC1918_NETS)


def parse_received_chain(message: email.message.Message) -> list[ReceivedHop]:
    """Return Received hops ordered from origin (earliest) to recipient.

    The ``Received`` headers in an RFC 5322 message are written newest-first
    (last hop at the top).  We reverse so index 0 is the earliest hop — the
    origin — which is how analysts read the chain mentally.
    """

    headers = message.get_all("Received") or []
    hops: list[ReceivedHop] = []
    for raw in reversed(headers):
        # Collapse folded whitespace.
        flat = re.sub(r"\s+", " ", raw).strip()
        from_host: str | None = None
        from_ip: str | None = None
        m = _RECEIVED_FROM_RE.search(flat)
        if m:
            from_host = m.group("host") or m.group("host2")
            from_ip = m.group("ip")
        by_host = None
        m2 = _RECEIVED_BY_RE.search(flat)
        if m2:
            by_host = m2.group("by")

        # Timestamp is whatever follows the last semicolon.
        ts: str | None = None
        if ";" in flat:
            ts_raw = flat.rsplit(";", 1)[-1].strip()
            try:
                dt = email.utils.parsedate_to_datetime(ts_raw)
                if dt is not None:
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    ts = dt.astimezone(timezone.utc).isoformat()
            except (TypeError, ValueError):
                ts = ts_raw

        hops.append(
            ReceivedHop(
                index=len(hops),
                from_host=from_host,
                from_ip=from_ip,
                by_host=by_host,
                timestamp=ts,
                private_ip=_is_private(from_ip),
                raw=flat,
            )
        )
    return hops


def detect_private_to_public_anomaly(hops: Iterable[ReceivedHop]) -> bool:
    """True if a private-IP hop is followed by a public-IP hop (spoof tell)."""

    seen_private = False
    for hop in hops:
        if hop.private_ip:
            seen_private = True
        elif seen_private and hop.from_ip:
            return True
    return False


# ---------------------------------------------------------------------------
# Body extraction (URLs)
# ---------------------------------------------------------------------------


_URL_RE = re.compile(
    r"\bhttps?://[^\s<>\"'\)]+",
    re.IGNORECASE,
)


def _decode_part(part: email.message.Message) -> str:
    """Decode a single MIME part to text, handling QP / base64."""

    payload = part.get_payload(decode=True)
    if not isinstance(payload, (bytes, bytearray)):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return bytes(payload).decode(charset, errors="replace")
    except LookupError:
        return bytes(payload).decode("utf-8", errors="replace")


def extract_urls(message: email.message.Message) -> list[str]:
    """Collect URLs from every text/* body part."""

    urls: list[str] = []
    seen: set[str] = set()
    for part in message.walk():
        ctype = part.get_content_type()
        if not ctype.startswith("text/"):
            continue
        if part.get_content_disposition() == "attachment":
            continue
        text = _decode_part(part)
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(".,);]")
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def defang(url: str) -> str:
    """Render a URL unclickable: ``http`` → ``hxxp``, ``.`` → ``[.]``."""

    return (
        url.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------


def extract_attachments(message: email.message.Message) -> list[Attachment]:
    """Return one :class:`Attachment` per non-inline binary part."""

    out: list[Attachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition != "attachment" and not filename:
            continue
        raw_payload = part.get_payload(decode=True)
        payload: bytes = bytes(raw_payload) if isinstance(raw_payload, (bytes, bytearray)) else b""
        out.append(
            Attachment(
                filename=_decode(filename) or "(unnamed)",
                content_type=part.get_content_type(),
                size=len(payload),
                md5=hashlib.md5(payload).hexdigest(),
                sha1=hashlib.sha1(payload).hexdigest(),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------


def _derive_signals(
    auth: AuthResults,
    mismatch: AddressMismatch,
    received_anomaly: bool,
    urls: list[str],
    attachments: list[Attachment],
) -> list[str]:
    """Plain-language signals — fed into the Stage 2 scorer."""

    signals: list[str] = []
    if auth.spf == "fail":
        signals.append("spf_fail")
    if auth.dkim == "fail":
        signals.append("dkim_fail")
    if auth.dmarc == "fail":
        signals.append("dmarc_fail")
    if mismatch.from_vs_reply_to_mismatch:
        signals.append("from_reply_to_mismatch")
    if mismatch.display_name_addr_mismatch:
        signals.append("display_name_spoof")
    if received_anomaly:
        signals.append("received_private_to_public")
    # URL shorteners / suspicious TLDs
    shorteners = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd")
    sus_tlds = (".zip", ".mov", ".top", ".xyz", ".click", ".country", ".support")
    for url in urls:
        lower = url.lower()
        if any(s in lower for s in shorteners):
            signals.append("url_shortener")
            break
    for url in urls:
        lower = url.lower().split("?", 1)[0]
        if any(lower.endswith(t) or t + "/" in lower for t in sus_tlds):
            signals.append("suspicious_tld")
            break
    if attachments:
        signals.append("has_attachment")
    return signals


def parse_eml(path: str | Path) -> ParsedEmail:
    """Parse a single ``.eml`` file from disk."""

    p = Path(path)
    with p.open("rb") as fh:
        message = email.message_from_binary_file(fh, policy=email.policy.default)

    auth = parse_auth_results(message)
    mismatch = parse_address_mismatch(message)
    hops = parse_received_chain(message)
    received_anomaly = detect_private_to_public_anomaly(hops)
    urls = extract_urls(message)
    attachments = extract_attachments(message)
    signals = _derive_signals(auth, mismatch, received_anomaly, urls, attachments)

    return ParsedEmail(
        source=str(p),
        subject=_decode(message.get("Subject")),
        message_id=message.get("Message-ID"),
        date=message.get("Date"),
        from_header=_decode(message.get("From")),
        to_header=_decode(message.get("To")),
        reply_to_header=_decode(message.get("Reply-To")),
        auth_results=auth,
        address_mismatch=mismatch,
        received_chain=hops,
        received_anomaly_private_to_public=received_anomaly,
        urls=urls,
        urls_defanged=[defang(u) for u in urls],
        attachments=attachments,
        signals=signals,
    )


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def render_markdown(parsed: ParsedEmail) -> str:
    """Render a human-readable analyst summary for the parsed email."""

    lines: list[str] = []
    lines.append(f"# Triage — {parsed.subject or '(no subject)'}")
    lines.append("")
    lines.append(f"- **Source file:** `{parsed.source}`")
    lines.append(f"- **Message-ID:** `{parsed.message_id or 'n/a'}`")
    lines.append(f"- **Date:** {parsed.date or 'n/a'}")
    lines.append(f"- **From:** {parsed.from_header or 'n/a'}")
    lines.append(f"- **Reply-To:** {parsed.reply_to_header or 'n/a'}")
    lines.append(f"- **To:** {parsed.to_header or 'n/a'}")
    lines.append("")
    lines.append("## Authentication")
    lines.append("")
    lines.append("| Mechanism | Result |")
    lines.append("|-----------|--------|")
    lines.append(f"| SPF       | {parsed.auth_results.spf} |")
    lines.append(f"| DKIM      | {parsed.auth_results.dkim} |")
    lines.append(f"| DMARC     | {parsed.auth_results.dmarc} |")
    lines.append("")
    lines.append("## Address checks")
    lines.append("")
    am = parsed.address_mismatch
    lines.append(f"- From vs Reply-To mismatch: **{am.from_vs_reply_to_mismatch}**")
    lines.append(f"- Display-name spoofing: **{am.display_name_addr_mismatch}**")
    lines.append("")
    lines.append("## Received chain (origin → recipient)")
    lines.append("")
    if parsed.received_chain:
        lines.append("| # | From host | From IP | By | Timestamp | Private? |")
        lines.append("|---|-----------|---------|----|-----------|----------|")
        for hop in parsed.received_chain:
            lines.append(
                f"| {hop.index} | {hop.from_host or '-'} | "
                f"{hop.from_ip or '-'} | {hop.by_host or '-'} | "
                f"{hop.timestamp or '-'} | {hop.private_ip} |"
            )
    else:
        lines.append("_no Received headers_")
    lines.append("")
    lines.append(
        f"Private→public anomaly: **{parsed.received_anomaly_private_to_public}**"
    )
    lines.append("")
    lines.append("## URLs (defanged)")
    lines.append("")
    if parsed.urls_defanged:
        for u in parsed.urls_defanged:
            lines.append(f"- `{u}`")
    else:
        lines.append("_none_")
    lines.append("")
    lines.append("## Attachments")
    lines.append("")
    if parsed.attachments:
        lines.append("| Filename | Content-Type | Size | SHA256 |")
        lines.append("|----------|--------------|------|--------|")
        for a in parsed.attachments:
            lines.append(
                f"| {a.filename} | {a.content_type} | {a.size} | `{a.sha256}` |"
            )
    else:
        lines.append("_none_")
    lines.append("")
    lines.append("## Signals")
    lines.append("")
    if parsed.signals:
        for s in parsed.signals:
            lines.append(f"- `{s}`")
    else:
        lines.append("_no suspicious signals_")
    lines.append("")
    lines.append(
        f"_Generated {datetime.now(timezone.utc).isoformat()} by phish-triage._"
    )
    return "\n".join(lines)
