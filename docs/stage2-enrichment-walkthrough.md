# Stage 2 — Enrichment walkthrough

Stage 1 emits a structured `ParsedEmail` with a list of named signals.
Stage 2 layers external threat intelligence on top of that, then collapses
everything into a single 0-100 verdict.

## Sources

| Source | What we look up | Endpoint(s) | Free-tier quota |
|--------|-----------------|-------------|-----------------|
| **VirusTotal v3** | every URL + every attachment SHA-256 | `GET /urls/{base64id}`, `GET /files/{sha256}` | 4 req / min |
| **AbuseIPDB** | every **public** Received-chain IP | `GET /api/v2/check` | 1,000 req / day |

Both are read-only GETs.  We never submit content to either service — the
existing reports are enough, and submission would change the threat-intel
picture for everyone else.

## API key handling

Keys come from environment variables (`VT_API_KEY`, `ABUSEIPDB_API_KEY`).
If a key is missing:

* The corresponding source is **skipped entirely** (no half-attempted
  lookups, no leaked metadata).
* A line is added to the `Notes` section of the markdown report so the
  analyst sees the gap.
* Scoring continues with whatever sources *are* available — Stage 1 signals
  alone are usually enough to flag obvious phish (the fixture lands
  `MALICIOUS` at 100/100 with no API keys at all).

## Rate limiting

A small sliding-window `RateLimiter` enforces requests-per-minute on each
source.  VT defaults to 4 rpm (matching the free tier so a careless run
can't get the key suspended); AbuseIPDB defaults to 30 rpm.

```python
class RateLimiter:
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
```

It's tested deterministically by monkey-patching `time.sleep` and asserting
we got a positive sleep value once we crossed the quota.

## Caching

Responses are written to `.cache/<source>_<sha1(source:ioc)>.json` and read
on subsequent runs.  This:

* lets you iterate on the parser / scorer without re-paying for VT lookups
* makes the tool reproducible — re-running on the same `.eml` yields the
  same JSON byte-for-byte
* gives the test suite a clean way to assert "second call hit zero network
  endpoints"

`--no-cache` skips the cache reads (writes still happen).

## Verdict scoring

```python
SIGNAL_WEIGHTS = {
    "spf_fail":                     15,
    "dkim_fail":                    10,
    "dmarc_fail":                   15,
    "from_reply_to_mismatch":       15,
    "display_name_spoof":           20,
    "received_private_to_public":   10,
    "url_shortener":                10,
    "suspicious_tld":               10,
    "has_attachment":                5,
}
```

Then per-IOC contributions are added on top of the signal score:

* VT URL with `malicious >= 1` adds `min(30, 10 * malicious)`
* VT URL with `suspicious >= 2` adds 10
* VT file with `malicious >= 1` adds `min(40, 15 * malicious)`
* AbuseIPDB confidence ≥ 75 adds 20; ≥ 25 adds 10

The total is clamped to `[0, 100]` and bucketed:

| Score range | Verdict     |
|-------------|-------------|
| 0–39        | `benign`     |
| 40–69       | `suspicious` |
| 70–100      | `malicious`  |

These thresholds are calibrated against the fixtures and the assumption
that a single VT-malicious hit on its own should never auto-promote a
message to malicious — but a VT-malicious hit combined with even one Stage
1 signal will.  Tune for your environment.

## Rationale strings

Every weight that fires also pushes a string onto `rationale[]`, e.g.

```
- signal `display_name_spoof` (+20)
- VirusTotal flagged URL `https://paypa1-secure-login.zip/account` as malicious (3 engines) (+30)
- AbuseIPDB confidence 95 for IP 198.51.100.42 (+20)
```

This is the bit a human triager actually reads.  It's also the bit that
makes the tool defensible in a SOC review: the verdict is never a black
box.

## Markdown report

`render_report(parsed, result)` glues Stage 1 + Stage 2 into the analyst
output you'd hand to a ticket:

1. Summary block (verdict / score / From / Reply-To / Subject)
2. IOC table — URLs, attachment hashes, public IPs
3. Enrichment evidence — VT URL stats, VT file stats, AbuseIPDB per-IP
4. Rationale list — every weight that fired
5. Notes — skipped sources, deprecation warnings, etc.

## Try it yourself

```bash
export VT_API_KEY=...
export ABUSEIPDB_API_KEY=...
phish-triage enrich tests/fixtures/phish_sample.eml --output report.md
```

Or without any keys, to see graceful degradation:

```bash
phish-triage enrich tests/fixtures/phish_sample.eml
# verdict still MALICIOUS — Stage 1 signals alone are damning.
```
