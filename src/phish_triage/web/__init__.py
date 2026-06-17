"""Tiny Flask sample-tester for phish-triage.

Run locally::

    pip install -e ".[web]"
    python -m phish_triage.web

Then open http://127.0.0.1:5050 and either upload your own ``.eml`` or click
one of the bundled sample buttons.

This is intentionally a single-file Flask app — easy to skim, easy to drop
behind nginx for a portfolio demo, easy to delete if you don't want it.
"""

from __future__ import annotations

import io
from dataclasses import asdict
from pathlib import Path

try:
    from flask import Flask, abort, render_template, request, url_for
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "phish_triage.web requires Flask. Install with: pip install -e '.[web]'"
    ) from exc

from ..enrich import EnrichmentResult, enrich_eml, render_report
from ..parser import ParsedEmail, parse_eml


# __file__ = .../src/phish_triage/web/__init__.py → repo root is four levels up.
REPO_ROOT = Path(__file__).resolve().parents[3]
SAMPLE_DIR = REPO_ROOT / "tests" / "fixtures"
MAX_EML_BYTES = 1_000_000  # 1 MB — generous for an .eml


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_EML_BYTES

    @app.get("/")
    def index() -> str:
        samples = sorted(p.name for p in SAMPLE_DIR.glob("*.eml")) if SAMPLE_DIR.exists() else []
        return render_template("index.html", samples=samples)

    @app.post("/analyze")
    def analyze() -> str:
        eml_bytes, source_label = _read_input(request)
        if not eml_bytes:
            abort(400, "no .eml supplied (upload a file or pick a sample)")

        # parse_eml takes a path; cheapest fix is a temp file under /tmp.
        tmp = Path("/tmp") / f"phish_triage_web_{abs(hash(eml_bytes)) % 10**12}.eml"
        tmp.write_bytes(eml_bytes)
        try:
            parsed = parse_eml(tmp)
            # Web demo intentionally runs WITHOUT live API calls — the parser
            # signals alone are damning for the bundled phish sample, and we
            # don't want a public-facing demo burning anyone's VT quota.
            result = enrich_eml(parsed, cache_dir=None)
        finally:
            tmp.unlink(missing_ok=True)

        return render_template(
            "report.html",
            parsed=parsed,
            result=result,
            source_label=source_label,
            verdict_class=_verdict_css_class(result.verdict),
            markdown=render_report(parsed, result),
        )

    @app.get("/healthz")
    def healthz() -> tuple[str, int]:
        return ("ok", 200)

    return app


def _read_input(req) -> tuple[bytes, str]:
    """Return (eml_bytes, human-readable source label)."""

    sample = req.form.get("sample")
    if sample:
        # path-traversal guard: only allow plain filenames inside SAMPLE_DIR.
        if "/" in sample or "\\" in sample or sample.startswith("."):
            abort(400, "invalid sample")
        path = SAMPLE_DIR / sample
        if not path.exists() or not path.is_file():
            abort(404, f"sample not found: {sample}")
        return path.read_bytes(), f"sample: {sample}"

    upload = req.files.get("eml")
    if upload and upload.filename:
        data = upload.read()
        return data, f"upload: {upload.filename}"

    return b"", ""


def _verdict_css_class(verdict: str) -> str:
    return {
        "benign": "verdict-benign",
        "suspicious": "verdict-suspicious",
        "malicious": "verdict-malicious",
    }.get(verdict, "verdict-benign")


def main() -> None:  # pragma: no cover
    app = create_app()
    app.run(host="127.0.0.1", port=5050, debug=False)


if __name__ == "__main__":  # pragma: no cover
    main()
