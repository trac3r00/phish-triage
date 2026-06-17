"""Tests for :mod:`phish_triage.enrich` — HTTP fully mocked, no live API."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from phish_triage.enrich import (
    AbuseVerdict,
    EnrichmentResult,
    HTTPSession,
    RateLimiter,
    SIGNAL_WEIGHTS,
    VTVerdict,
    _select_public_ips,
    _verdict_for,
    enrich_eml,
    render_report,
)
from phish_triage.parser import parse_eml

from tests.make_fixtures import _write_benign, _write_phish

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _ensure_fixtures() -> None:
    FIX.mkdir(parents=True, exist_ok=True)
    _write_benign()
    _write_phish()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vt_url_response(malicious: int = 0, suspicious: int = 0) -> dict[str, Any]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": 60,
                    "undetected": 10,
                },
                "reputation": -malicious,
            }
        }
    }


def _vt_file_response(malicious: int = 0) -> dict[str, Any]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 70,
                }
            }
        }
    }


def _abuse_response(confidence: int = 0) -> dict[str, Any]:
    return {
        "data": {
            "ipAddress": "198.51.100.42",
            "abuseConfidenceScore": confidence,
            "totalReports": 3 if confidence else 0,
            "countryCode": "US",
            "domain": "evil.example",
        }
    }


def _fake_response(status: int, payload: dict[str, Any]) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    return resp


# ---------------------------------------------------------------------------
# Graceful degradation: no keys
# ---------------------------------------------------------------------------


def test_enrich_skips_sources_when_keys_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    parsed = parse_eml(FIX / "phish_sample.eml")
    result = enrich_eml(parsed, cache_dir=tmp_path / "cache")
    assert result.vt_url_results == []
    assert result.vt_file_results == []
    assert result.abuseipdb_results == []
    assert any("VirusTotal" in n for n in result.notes)
    assert any("AbuseIPDB" in n for n in result.notes)
    # Score is still computed from signals.
    assert result.score > 0
    assert result.verdict in {"suspicious", "malicious"}


# ---------------------------------------------------------------------------
# Happy path: phish fires malicious verdict with mocked enrichment
# ---------------------------------------------------------------------------


def test_phish_with_vt_hits_lands_malicious(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake-vt")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-abuse")
    parsed = parse_eml(FIX / "phish_sample.eml")

    def fake_get(url: str, *_, **__) -> MagicMock:
        if "/urls/" in url:
            return _fake_response(200, _vt_url_response(malicious=3))
        if "/files/" in url:
            return _fake_response(200, _vt_file_response(malicious=2))
        if "/check" in url:
            return _fake_response(200, _abuse_response(confidence=95))
        return _fake_response(404, {})

    with patch("phish_triage.enrich.requests.Session.get", side_effect=fake_get) as mocked:
        result = enrich_eml(parsed, cache_dir=tmp_path / "cache")

    assert mocked.called
    assert result.verdict == "malicious"
    assert result.score >= 70
    assert any("VirusTotal flagged URL" in r for r in result.rationale)
    assert any("AbuseIPDB" in r for r in result.rationale)


def test_benign_stays_benign(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    parsed = parse_eml(FIX / "benign.eml")

    def fake_get(url: str, *_, **__) -> MagicMock:
        return _fake_response(200, _vt_url_response(malicious=0))

    with patch("phish_triage.enrich.requests.Session.get", side_effect=fake_get):
        result = enrich_eml(parsed, cache_dir=tmp_path / "cache")

    assert result.verdict == "benign"
    assert result.score < 40


# ---------------------------------------------------------------------------
# Caching: a second call must not hit the network
# ---------------------------------------------------------------------------


def test_cache_avoids_second_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    parsed = parse_eml(FIX / "phish_sample.eml")
    cache = tmp_path / "cache"

    def fake_get(url: str, *_, **__) -> MagicMock:
        return _fake_response(200, _vt_url_response(malicious=1))

    with patch("phish_triage.enrich.requests.Session.get", side_effect=fake_get) as mocked:
        enrich_eml(parsed, cache_dir=cache)
        first_calls = mocked.call_count
        enrich_eml(parsed, cache_dir=cache)
        assert mocked.call_count == first_calls, (
            "second call should be served entirely from cache"
        )


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


def test_rate_limiter_sleeps_after_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    rl = RateLimiter(per_minute=2)
    slept: list[float] = []

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr("phish_triage.enrich.time.sleep", fake_sleep)
    rl.wait()
    rl.wait()
    rl.wait()  # third call within the same minute must sleep
    assert slept and slept[-1] > 0


# ---------------------------------------------------------------------------
# Scoring + verdict mapping
# ---------------------------------------------------------------------------


def test_verdict_mapping_boundaries() -> None:
    assert _verdict_for(0) == "benign"
    assert _verdict_for(39) == "benign"
    assert _verdict_for(40) == "suspicious"
    assert _verdict_for(69) == "suspicious"
    assert _verdict_for(70) == "malicious"
    assert _verdict_for(100) == "malicious"


def test_select_public_ips_filters_rfc1918() -> None:
    parsed = parse_eml(FIX / "phish_sample.eml")
    public = _select_public_ips(parsed)
    assert "198.51.100.42" in public
    assert "10.0.0.5" not in public
    assert "192.168.1.50" not in public


def test_signal_weights_cover_every_known_signal() -> None:
    parsed = parse_eml(FIX / "phish_sample.eml")
    for sig in parsed.signals:
        assert sig in SIGNAL_WEIGHTS, f"missing weight for {sig}"


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def test_report_renders_all_sections(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    parsed = parse_eml(FIX / "phish_sample.eml")
    result = enrich_eml(parsed, cache_dir=tmp_path / "cache")
    report = render_report(parsed, result)
    for header in (
        "# Phishing triage report",
        "## Summary",
        "## IOC table",
        "## Enrichment evidence",
        "## Rationale",
        "## Notes",
    ):
        assert header in report
    assert "Verdict:" in report


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_vt_404_treated_as_clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    parsed = parse_eml(FIX / "benign.eml")

    def fake_get(url: str, *_, **__) -> MagicMock:
        return _fake_response(404, {})

    with patch("phish_triage.enrich.requests.Session.get", side_effect=fake_get):
        result = enrich_eml(parsed, cache_dir=tmp_path / "cache")

    assert all(v.error is None for v in result.vt_url_results)
    assert result.verdict == "benign"


def test_vt_500_surfaces_as_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VT_API_KEY", "fake")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    parsed = parse_eml(FIX / "phish_sample.eml")

    def fake_get(url: str, *_, **__) -> MagicMock:
        return _fake_response(500, {})

    with patch("phish_triage.enrich.requests.Session.get", side_effect=fake_get):
        result = enrich_eml(parsed, cache_dir=tmp_path / "cache")

    assert any(v.error and "500" in v.error for v in result.vt_url_results)
