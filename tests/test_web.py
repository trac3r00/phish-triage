"""Tests for :mod:`phish_triage.web` — Flask test client only, no live server."""

from __future__ import annotations

from pathlib import Path

import pytest

from phish_triage.web import create_app

from tests.make_fixtures import _write_benign, _write_phish

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _ensure_fixtures() -> None:
    FIX.mkdir(parents=True, exist_ok=True)
    _write_benign()
    _write_phish()


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_home_renders(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert "phish" in body.lower()
    assert "phish_sample.eml" in body
    assert "benign.eml" in body


def test_healthz(client) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.data == b"ok"


def test_phish_sample_returns_malicious(client) -> None:
    response = client.post("/analyze", data={"sample": "phish_sample.eml"})
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert "MALICIOUS" in body
    assert "display_name_spoof" in body
    # Defanged URL should be rendered, not the live one.
    assert "hxxp://bit[.]ly" in body
    assert "http://bit.ly" not in body.split("hxxp://bit[.]ly", 1)[0]


def test_benign_sample_returns_benign(client) -> None:
    response = client.post("/analyze", data={"sample": "benign.eml"})
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert "BENIGN" in body
    assert "no suspicious signals fired" in body


def test_path_traversal_blocked(client) -> None:
    response = client.post(
        "/analyze", data={"sample": "../../../../etc/passwd"}
    )
    assert response.status_code == 400


def test_missing_sample_404s(client) -> None:
    response = client.post("/analyze", data={"sample": "does-not-exist.eml"})
    assert response.status_code == 404


def test_no_input_400s(client) -> None:
    response = client.post("/analyze", data={})
    assert response.status_code == 400


def test_eml_upload_round_trip(client) -> None:
    import io

    eml_bytes = (FIX / "phish_sample.eml").read_bytes()
    response = client.post(
        "/analyze",
        data={"eml": (io.BytesIO(eml_bytes), "uploaded.eml")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert "MALICIOUS" in body
    assert "uploaded.eml" in body
