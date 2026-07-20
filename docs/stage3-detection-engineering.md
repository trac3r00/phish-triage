# Detection engineering notes

The `detections/` directory provides eight example detections as Splunk SPL and Sigma YAML. They correspond to concepts surfaced by the parser and enrichment layer, but they are independent deployment artifacts: the CLI does not load, generate, or execute them.

## Formats

- `detections/spl/` contains searches for `index=email` and `sourcetype=email:*`.
- `detections/sigma/` contains rules with an email-gateway logsource and generalized field names.

The SPL assumes normalized secure-email-gateway events. The Sigma files require backend-specific conversion and may use modifiers or placeholders that are not portable to every backend. Neither format is ready for production without local schema mapping and validation.

## Coverage

| Rule | Purpose | Required evidence |
|---|---|---|
| R01 | SPF failure and From/Reply-To domain mismatch | Authentication result and both address domains |
| R02 | New sender domain with SPF, DKIM, or DMARC failure | Authentication result and a 30-day sender-domain baseline |
| R03 | Brand or executive display-name impersonation | Display name, sender domain, and an authorized-domain mapping |
| R04 | URL shortener in inbound email | Extracted URL host |
| R05 | Malicious VirusTotal result for an attachment hash | Attachment SHA-256 and VirusTotal lookup data |
| R06 | Link using a selected high-risk TLD | Extracted URL or TLD |
| R07 | Base64-encoded HTML body containing a form | MIME encoding, content type, and decoded body |
| R08 | DMARC policy bypass | DMARC result, published policy, and final disposition |

This is not a one-to-one map between parser signals and rules. In particular:

- `received_private_to_public` has no dedicated rule because the templates do not assume structured full-header data;
- R07 depends on decoded body fields that the parser uses internally but does not expose as a named signal;
- R02, R03, R05, and R08 require data or mappings outside the parser output.

See [`detections/README.md`](../detections/README.md) for the rule-to-evidence table and deployment workflow.

## Field mapping

Before using a rule, map every referenced field to the local gateway or SIEM schema. Common concepts include:

| Concept | Example fields in this repository |
|---|---|
| Sender and recipients | `sender`, `recipient`, `from_addr`, `reply_to_addr` |
| Authentication | `authentication_results`, `dmarc_policy`, `final_disposition` |
| URLs | `extracted_url`, `url_host`, `url_tld` |
| MIME body | `mime_encoding`, `content_type`, `body_decoded` |
| Attachments | `attachment_filename`, `attachment_sha256`, `vt_malicious` |

Field availability and semantics differ among gateways. Confirm whether fields contain scalar or multivalue data, whether addresses include display names, and whether message-body retention is permitted.

## Validation

YAML parsing alone does not establish Sigma schema validity or backend compatibility. A practical validation sequence is:

1. validate each Sigma file against the Sigma specification and the intended backend;
2. convert it with that backend's supported tooling;
3. inspect the generated query for unresolved placeholders and incorrect field names;
4. replay known-positive and known-benign events;
5. perform the equivalent checks for the SPL in a development Splunk environment;
6. measure alert volume before enabling notifications.

If `sigma-cli` and a suitable backend are installed separately, the repository's Sigma directory is the validation target:

```bash
sigma check detections/sigma/
```

The repository does not declare `sigma-cli`, a Sigma backend, or PyYAML as project dependencies.

## Tuning

Expected false-positive sources include mailing-list Reply-To rewriting, first-time legitimate vendors, transactional email providers, marketing shorteners, and legitimate domains using one of the selected TLDs. Prefer narrowly scoped allowlists based on validated business context.

R03's brand list and domain mapping, R05's `ti_vt` lookup name, and all thresholds are examples. Replace them with reviewed local values before deployment.
