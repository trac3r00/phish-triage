# Project rationale

Phishing investigations often involve three related but distinct tasks: extracting evidence from a message, checking indicators against external sources, and translating recurring patterns into SIEM detections. `phish-triage` keeps those concerns separate so each part can be reviewed and used independently.

## Design goals

### Deterministic local parsing

`src/phish_triage/parser.py` uses the Python standard library to parse one `.eml` file. It extracts authentication results, sender inconsistencies, delivery-chain details, URLs, and attachment hashes without network access.

The parser retains both structured values and analyst-oriented signals. URLs are kept in their original form for programmatic enrichment and separately defanged for display.

### Optional, explainable enrichment

`src/phish_triage/enrich.py` adds read-only VirusTotal and AbuseIPDB lookups. Provider credentials are optional, responses can be cached, and a missing provider does not prevent parser-based scoring.

The score is a bounded sum of documented weights. Every contribution produces a rationale entry, allowing an analyst to trace a verdict back to the evidence. The score is a prioritization heuristic, not a statistical confidence value.

### Portable detection examples

`detections/` contains the same eight detection concepts in SPL and Sigma formats. These are independent templates for teams that have secure-email-gateway telemetry. They document field assumptions and external dependencies rather than claiming direct portability across products.

## Why the parser avoids external dependencies

The standard library's `email` package already provides MIME decoding, transfer-encoding handling, address parsing, and RFC 2047 header decoding. Keeping this stage dependency-free makes its behavior easier to audit and prevents threat-intelligence availability from affecting message extraction.

The complete installed package still depends on `requests` because enrichment is part of the CLI. Flask is isolated in the optional `web` dependency.

## Address classification decision

The phishing fixture uses RFC 5737 documentation networks as stand-ins for public infrastructure. Python's `ipaddress` classification treats those reserved ranges as non-global, and its `is_private` behavior is broader than the parser needs.

The project therefore defines internal hops narrowly as RFC 1918 IPv4, IPv6 unique-local, loopback, and link-local addresses. This allows documentation addresses in fixtures to exercise the private-to-public transition heuristic. It is a fixture-oriented threat-model decision, not a claim that documentation ranges are publicly routable.

## Deliberate scope

The project does not attempt to provide:

- mailbox or mail-server integration;
- bulk or streaming message processing;
- attachment execution or sandboxing;
- Office document or archive inspection;
- automatic deployment of SIEM rules;
- machine-learning classification;
- production authentication, authorization, or hosting for the web interface.

The local web interface is intended for source-checkout evaluation. It binds to `127.0.0.1`, has no authentication, and should not be exposed as a public service without a separate deployment and security review.

## Suggested reading order

1. [README](../README.md) for installation and usage.
2. [Parsing walkthrough](stage1-parsing-walkthrough.md) for extracted fields and heuristics.
3. [Enrichment walkthrough](stage2-enrichment-walkthrough.md) for provider behavior and score weights.
4. [Detection engineering notes](stage3-detection-engineering.md) for deployment assumptions.
5. [Engineering retrospective](retrospective.md) for known limitations and future considerations.
