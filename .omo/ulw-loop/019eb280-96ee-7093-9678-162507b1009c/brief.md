# phish-triage — Phishing Email Triage Toolkit

Build a complete, working Python CLI project in this repo (/home/claw/src/phish-triage).
Target audience for the repo: hiring managers for SOC Analyst / Threat Detection / SIEM Engineer roles.
The repo must look like a security practitioner's portfolio piece: clean code, real tests, strong READMEs.

## Constraints
- Python 3.11, stdlib-first. Stage 1 must be PURE stdlib (email, hashlib, re, json, argparse, pathlib).
- Stage 2 may use `requests` only. Manage deps with a minimal pyproject.toml (project name: phish-triage, CLI entry point: `phish-triage`).
- Type hints everywhere. `from __future__ import annotations` in new files.
- No eval/exec/shell=True. No hardcoded secrets — API keys via env vars (VT_API_KEY, ABUSEIPDB_API_KEY).
- Tests with pytest. Include sample .eml fixtures you generate yourself (benign + simulated-phish with SPF fail, reply-to mismatch, suspicious URLs, attachment). Do NOT include any real malware.
- Each stage gets its own README section + a docs/ writeup (see below).

## Stage 1 — Parser (src/phish_triage/parser.py + cli.py)
CLI: `phish-triage parse sample.eml [--json|--markdown]`
Extract:
- Authentication-Results: SPF/DKIM/DMARC pass/fail/none (parse the header robustly)
- From vs Reply-To mismatch detection, From display-name vs addr-spec mismatch
- Received chain: ordered hop list (host, IP, timestamp), flag private→public anomalies
- All URLs from text/html bodies (handle quoted-printable + base64 transfer encodings), defang output (hxxp, [.])
- Attachments: filename, content-type, size, MD5/SHA1/SHA256
- Output: structured JSON and a human-readable markdown summary

## Stage 2 — Enrichment (src/phish_triage/enrich.py)
CLI: `phish-triage enrich sample.eml [--output report.md]`
- VirusTotal v3 free API: lookup file hashes + URLs/domains (GET endpoints only, respect 4 req/min free tier — implement a simple rate limiter with backoff)
- AbuseIPDB check endpoint for Received-chain public IPs
- Graceful degradation: if API key missing, skip that source and note it in the report
- Verdict scoring: weighted score 0-100 from auth failures, mismatches, VT detections, AbuseIPDB confidence; map to verdict (benign/suspicious/malicious)
- Output: markdown triage report (analyst-style: summary, IOC table, enrichment evidence, verdict + rationale)
- Cache API responses in .cache/ (JSON, keyed by IOC) to avoid burning quota
- Unit tests must mock HTTP (no live API calls in tests).

## Stage 3 — Detection rules (detections/)
From the patterns the tool detects, write 8 detection rules, each in TWO formats:
- detections/spl/*.spl — Splunk SPL queries (assume standard email security / proxy log sourcetypes; document assumptions in comments)
- detections/sigma/*.yml — valid Sigma rules (correct schema: title, id (uuid4), status, description, logsource, detection, falsepositives, level, tags with attack.* technique IDs)
Rule ideas: SPF fail + reply-to mismatch, newly-seen sender domain with auth failure, lookalike display name (exec impersonation), URL shortener in mail, attachment hash matched VT, suspicious TLD links, base64-encoded HTML body with form, DMARC reject bypass attempt.
Add detections/README.md mapping each rule to MITRE ATT&CK (T1566.001/002 etc.) and to the parser feature that feeds it.

## Documentation (this is half the value)
- Root README.md: project overview, architecture diagram (ASCII or mermaid), quickstart, sample output screenshot-as-codeblock, stage-by-stage breakdown, MITRE mapping table
- docs/stage1-parsing-walkthrough.md: walk through a sample phish .eml end to end — what each header means, why each signal matters
- docs/stage2-enrichment-walkthrough.md: triage workflow with the APIs, rate-limit/quota notes
- docs/stage3-detection-engineering.md: how patterns became rules, SPL↔Sigma translation notes

## Verification (required before done)
- `pip install -e .` in a venv works
- `phish-triage parse tests/fixtures/phish_sample.eml --json` produces valid JSON
- `pytest -q` all green
- Commit in logical chunks (stage 1 / stage 2 / stage 3 / docs), then push to origin main.
