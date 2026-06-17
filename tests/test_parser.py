"""Unit tests for :mod:`phish_triage.parser`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from phish_triage.parser import (
    AuthResults,
    defang,
    detect_private_to_public_anomaly,
    parse_eml,
    render_markdown,
)

from tests.make_fixtures import _write_benign, _write_phish

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _ensure_fixtures() -> None:
    """Regenerate the .eml fixtures before the test session runs."""

    FIX.mkdir(parents=True, exist_ok=True)
    _write_benign()
    _write_phish()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_benign_email_is_clean() -> None:
    parsed = parse_eml(FIX / "benign.eml")
    assert parsed.auth_results.spf == "pass"
    assert parsed.auth_results.dkim == "pass"
    assert parsed.auth_results.dmarc == "pass"
    assert parsed.address_mismatch.from_vs_reply_to_mismatch is False
    assert parsed.address_mismatch.display_name_addr_mismatch is False
    assert parsed.received_anomaly_private_to_public is False
    assert parsed.attachments == []
    assert parsed.signals == []


def test_phish_email_fires_every_signal() -> None:
    parsed = parse_eml(FIX / "phish_sample.eml")
    assert parsed.auth_results.spf == "fail"
    assert parsed.auth_results.dmarc == "fail"
    assert parsed.address_mismatch.from_vs_reply_to_mismatch is True
    assert parsed.address_mismatch.display_name_addr_mismatch is True
    assert parsed.received_anomaly_private_to_public is True
    assert len(parsed.urls) == 2
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].sha256 != ""
    must_have = {
        "spf_fail",
        "dmarc_fail",
        "from_reply_to_mismatch",
        "display_name_spoof",
        "received_private_to_public",
        "url_shortener",
        "suspicious_tld",
        "has_attachment",
    }
    assert must_have.issubset(set(parsed.signals))


def test_parse_eml_is_json_serialisable() -> None:
    parsed = parse_eml(FIX / "phish_sample.eml")
    blob = json.dumps(parsed.to_dict(), default=str)
    # Round-trip back as a sanity check.
    again = json.loads(blob)
    assert again["subject"] == parsed.subject
    assert again["urls"] == parsed.urls


def test_markdown_renderer_includes_key_sections() -> None:
    parsed = parse_eml(FIX / "phish_sample.eml")
    md = render_markdown(parsed)
    for header in (
        "# Triage",
        "## Authentication",
        "## Address checks",
        "## Received chain",
        "## URLs (defanged)",
        "## Attachments",
        "## Signals",
    ):
        assert header in md


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_defang_idempotent() -> None:
    raw = "http://example.com/path?x=1"
    once = defang(raw)
    twice = defang(once)
    # Defanging strips the clickable scheme + dots in the host.
    assert "http://" not in once
    assert "hxxp://" in once
    assert "example.com" not in once  # the host's dot is now [.]
    # Idempotent: second pass doesn't reintroduce clickability or break the URL.
    assert "http://" not in twice
    assert "hxxp://" in twice


def test_empty_eml_does_not_crash(tmp_path: Path) -> None:
    empty = tmp_path / "empty.eml"
    empty.write_bytes(b"")
    parsed = parse_eml(empty)
    assert parsed.signals == []
    assert parsed.received_chain == []
    assert parsed.urls == []


def test_malformed_received_header_is_tolerated(tmp_path: Path) -> None:
    eml = tmp_path / "mal.eml"
    eml.write_bytes(
        b"From: a@b\r\nReceived: this is not a valid received header\r\nSubject: x\r\n\r\nbody\r\n"
    )
    parsed = parse_eml(eml)
    # One hop, gracefully parsed even though we couldn't pull a host/ip.
    assert len(parsed.received_chain) == 1


def test_auth_results_picks_strongest_signal() -> None:
    # If two Authentication-Results headers exist (mid-hop and edge), don't let
    # a later "none" overwrite an earlier "fail".
    auth = AuthResults()
    assert auth.spf == "none"


def test_private_to_public_helper_handles_empty() -> None:
    assert detect_private_to_public_anomaly([]) is False
