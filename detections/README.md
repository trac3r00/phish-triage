# Detection content

This directory contains eight example detection rules in two formats:

- `spl/`: Splunk SPL queries for a normalized `index=email` dataset.
- `sigma/`: Sigma YAML rules with `product: email` and `category: email-gateway` logsources.

These files are deployment templates, not rules executed by `phish-triage`. Secure email gateways use different schemas, so review the required fields, replace placeholders or unsupported modifiers, and validate each rule against representative events before enabling alerts.

## Rule mapping

| Rule | Detection | Related parser or enrichment evidence | ATT&CK references |
|---|---|---|---|
| R01 | SPF failure with From/Reply-To domain mismatch | `spf_fail`, `from_reply_to_mismatch` | T1566.001, T1566.002 |
| R02 | Newly observed sender domain with an authentication failure | `spf_fail`, `dkim_fail`, or `dmarc_fail`, plus external sender history | T1566 |
| R03 | Brand or executive display-name impersonation | `display_name_spoof` | T1566.001, T1566.002, T1656 |
| R04 | URL shortener in inbound email | `url_shortener` | T1566.002, T1204.001 |
| R05 | Attachment SHA-256 with a VirusTotal malicious result | `has_attachment` plus VirusTotal enrichment | T1566.001 |
| R06 | Link using a selected high-risk TLD | `suspicious_tld` | T1566.002, T1583.001 |
| R07 | Base64-encoded HTML body containing a form | Decoded MIME content; this is not a named parser signal | T1027, T1566.001 |
| R08 | Failed DMARC message delivered despite a reject or quarantine policy | `dmarc_fail` plus gateway policy and disposition fields | T1566 |

ATT&CK mappings are hypotheses for detection categorization and should be reviewed against local use cases. Links and tags are included in the individual Sigma files.

## Required data

The SPL queries expect `index=email` and `sourcetype=email:*`. The rules collectively reference these normalized fields:

| Area | Fields |
|---|---|
| Message identity | `sender`, `recipient`, `from_addr`, `reply_to_addr`, `from_display`, `from_domain` |
| Authentication | `authentication_results`, `dmarc_policy`, `final_disposition` |
| URLs and body | `extracted_url`, `url_host`, `url_tld`, `mime_encoding`, `content_type`, `body_decoded` |
| Attachments | `attachment_filename`, `attachment_sha256`, `vt_malicious` |

Additional dependencies:

- R02 needs a 30-day sender-domain baseline.
- R03 needs an environment-specific mapping from brand names to authorized domains.
- R05 expects a Splunk lookup named `ti_vt` or equivalent enrichment.
- R07 requires decoded message-body content, which may be unavailable or restricted for privacy reasons.

The Sigma rules use generalized field names and include `expand`, `gte`, and placeholder-style values that may not be supported by every Sigma backend. Treat successful YAML parsing as insufficient; validate the converted query with the selected backend.

## Deployment workflow

1. Map each required field to the email gateway or SIEM schema.
2. Replace lookup names, brand-domain mappings, and other environment-specific values.
3. Validate the Sigma schema and backend conversion, or parse the SPL in a development search environment.
4. Replay known-positive and known-benign events.
5. Run in a non-notifying mode, measure false positives, and add narrowly scoped allowlists.
6. Enable alerting only after the query and operational response have been reviewed.

Common false positives include mailing-list Reply-To rewriting, legitimate first-time vendors, transactional email services, and marketing links that use URL shorteners. The individual rules contain more specific notes.
