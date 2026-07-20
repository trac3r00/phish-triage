# Enrichment and scoring walkthrough

The enrichment layer in `src/phish_triage/enrich.py` accepts a parsed message, performs optional threat-intelligence lookups, and returns an `EnrichmentResult` containing provider results, a score, a verdict, rationale, and notes.

## Data sources

| Provider | Indicators | Request |
|---|---|---|
| VirusTotal v3 | Every extracted URL and every attachment SHA-256 | `GET /api/v3/urls/{url_id}` and `GET /api/v3/files/{sha256}` |
| AbuseIPDB v2 | Unique, non-private values matching a dotted-quad pattern in the `Received` chain | `GET /api/v2/check` with `maxAgeInDays=90` |

The code performs read-only lookups and does not submit message bodies or attachment content. It does disclose each queried URL, file hash, or IP address to the selected provider.

## Credentials

The CLI reads provider keys from these environment variables:

```bash
export VT_API_KEY="your-virus-total-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
```

Both variables are optional. If a key is absent, that provider is skipped and a note is included in the Markdown report. Parser signals are scored regardless of provider availability.

## HTTP behavior

`HTTPSession` wraps `requests.Session` with a 15-second request timeout, per-provider rate limiting, and an optional disk cache.

The code-defined request limits are:

- VirusTotal: 4 requests per minute;
- AbuseIPDB: 30 requests per minute.

These values are implementation defaults, not a guarantee about current provider plans. Confirm the quota associated with each API key before processing a message with many indicators.

Handled network failures and non-success HTTP statuses are recorded on the relevant verdict object instead of aborting the complete run. A VirusTotal 404 response is represented as a result with zero analysis counts and is cached.

## Cache

By default, successful provider payloads are stored under `.cache/` using filenames derived from the provider, indicator type, and a SHA-1 digest of the provider/indicator pair. Subsequent matching lookups read those JSON files before making a request.

```bash
phish-triage enrich message.eml --cache-dir /path/to/cache
phish-triage enrich message.eml --no-cache
```

In the current implementation, `--no-cache` passes no cache directory and therefore disables both cache reads and cache writes. Cache files can contain provider responses associated with investigated indicators; handle and retain them according to local policy.

## Score calculation

The parser signals have these weights:

| Signal | Points |
|---|---:|
| `spf_fail` | 15 |
| `dkim_fail` | 10 |
| `dmarc_fail` | 15 |
| `from_reply_to_mismatch` | 15 |
| `display_name_spoof` | 20 |
| `received_private_to_public` | 10 |
| `url_shortener` | 10 |
| `suspicious_tld` | 10 |
| `has_attachment` | 5 |

Provider evidence adds points as follows:

- a VirusTotal URL result with at least one malicious engine adds `min(30, 10 × malicious)`;
- otherwise, a VirusTotal URL result with at least two suspicious engines adds 10;
- a VirusTotal attachment result with at least one malicious engine adds `min(40, 15 × malicious)`;
- AbuseIPDB confidence from 25 through 74 adds 10;
- AbuseIPDB confidence of 75 or higher adds 20.

The score is clamped to 0–100 and mapped to a verdict:

| Score | Verdict |
|---:|---|
| 0–39 | `benign` |
| 40–69 | `suspicious` |
| 70–100 | `malicious` |

These values are deterministic heuristics, not a probability or substitute for analyst review. The result includes one rationale string for each contribution to the score.

## Output

Markdown is the default enrichment output:

```bash
phish-triage enrich tests/fixtures/phish_sample.eml
phish-triage enrich tests/fixtures/phish_sample.eml --output report.md
```

The report contains a summary, an IOC table, available provider evidence, score rationale, and notes about skipped providers. JSON output includes both the complete parser payload and the enrichment payload:

```bash
phish-triage enrich tests/fixtures/phish_sample.eml --json --output report.json
```

Without API keys, the bundled phishing fixture scores 100 from parser signals alone. This confirms the deterministic fixture behavior; it does not establish a general detection-accuracy rate.
