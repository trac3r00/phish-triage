# Stage 3 — Detection engineering

The parser emits a list of named signals; the enrichment layer combines
those signals with VT / AbuseIPDB hits to produce a verdict.  Stage 3
takes the **same signals** and projects them into the two formats every
modern SIEM already speaks: Splunk SPL and Sigma YAML.

## Why both SPL and Sigma?

* **SPL** is the lingua franca of any Splunk shop, and many enterprises
  still maintain hand-written SPL even when a higher-level abstraction
  exists.  Shipping SPL means the rules can be dropped into a saved search
  /  notable event in minutes.
* **Sigma** is portable: the same rule can be converted into Elastic EQL,
  Microsoft Sentinel KQL, Chronicle YARA-L, etc.  Shipping Sigma means a
  non-Splunk shop can still benefit.

## Signal → rule mapping

The summary table lives in
[`detections/README.md`](../detections/README.md).  At a glance:

| Rule | Trigger | Confidence |
|------|---------|------------|
| R01 | SPF fail + From/Reply-To domain mismatch | medium |
| R02 | New sender domain + auth fail | high |
| R03 | Brand / exec display-name impersonation | high |
| R04 | URL shortener in inbound mail | medium |
| R05 | Attachment hash matched VT | high |
| R06 | Suspicious / disposable TLD link | medium |
| R07 | Base64-encoded HTML body with form | medium |
| R08 | DMARC reject / quarantine bypass attempt | high |

## SPL → Sigma translation notes

The SPL rules assume a CIM-shaped `index=email` with fields the secure
email gateway (Proofpoint / Mimecast / O365 / Cisco ESA / etc.) populates:

| SPL field name | Sigma field name |
|----------------|------------------|
| `authentication_results` | `authentication_results` |
| `from_addr` | `from_addr` |
| `reply_to_addr` | `reply_to_addr` |
| `sender` | `sender` |
| `recipient` | `recipient` |
| `extracted_url` | `url_host` |
| `attachment_sha256` | `attachment_sha256` |
| `dmarc_policy` | `dmarc_policy` |
| `final_disposition` | `final_disposition` |

Sigma uses logsource `product: email`, `category: email-gateway`.  If your
SIEM ships a vendor-specific Sigma backend (e.g. Proofpoint-on-Demand),
prefer that — it'll know the exact field names.

## Field assumptions per rule

| Rule | Required fields (gateway side) |
|------|--------------------------------|
| R01 | `authentication_results`, `from_addr`, `reply_to_addr` |
| R02 | `sender`, `authentication_results`, 30-day baseline |
| R03 | `from_addr` (with display name preserved) |
| R04 | `extracted_url` |
| R05 | `attachment_sha256` + `ti_vt` lookup (or EDR enrichment) |
| R06 | `extracted_url` |
| R07 | `mime_encoding`, `content_type`, `body_decoded` |
| R08 | `authentication_results`, `dmarc_policy`, `final_disposition` |

If a field is missing from your gateway, you have two reasonable options:

1. **Compute it at ingest time** with a Splunk `eval` or a Sigma rule's
   `expand` modifier (most of the rules already use this).
2. **Drop the rule** and instead alert on the parser output directly.
   `phish-triage parse --json` could feed a forwarder that pushes the
   parsed JSON into the SIEM; then each rule turns into a single `where
   signals="display_name_spoof"` filter.

## Tuning + false positives

Every Sigma rule has a `falsepositives` block.  The recurring offenders:

* Legitimate mailing-list forwarders that rewrite Reply-To (R01).
* Newsletter platforms that route brand-name email through a shortener
  (R04) or a non-aligned domain (R03).
* Internal apps that send via a transactional ESP with separate DKIM
  posture (R02 — usually first-class allowlists fix this).

The pragmatic deployment sequence is:

1. **Stage on warning** for two weeks; collect the FP list.
2. Promote rules into `allowlist`s (sender, recipient, content) keyed by
   the FP pattern.
3. Drop into production once the rate is ≤ 5 alerts / rule / day per analyst
   shift.

## Validating Sigma rules locally

```bash
pip install pyyaml
python -c "import yaml, glob, uuid; \
  [uuid.UUID(yaml.safe_load(open(f))['id']) for f in glob.glob('detections/sigma/*.yml')]; \
  print('ids ok')"
```

Or, if you have the official `sigma` tool installed:

```bash
sigma check detections/sigma/
```

## Coverage map

Stage 1 emits eight signals → Stage 3 ships eight rules.  Every signal
appears in at least one rule:

* `spf_fail` → R01, R02, R08
* `dkim_fail` → R02
* `dmarc_fail` → R02, R08
* `from_reply_to_mismatch` → R01
* `display_name_spoof` → R03
* `received_private_to_public` → (analyst-facing only — too noisy as a SIEM rule on its own)
* `url_shortener` → R04
* `suspicious_tld` → R06
* `has_attachment` → R05 (when paired with VT)
* base64-encoded HTML body (parser internal) → R07

The one signal **not** mapped to a SIEM rule is `received_private_to_public`,
because the gateway log usually doesn't carry the full Received chain in a
structured way; it's a better human-triage signal than a SIEM trigger.
