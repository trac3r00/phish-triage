# Engineering retrospective

This document records the implementation choices, limitations, and follow-up opportunities identified in the current `0.1.0` codebase. It is descriptive, not a roadmap or release commitment.

## Effective choices

### Separate parsing from enrichment

The parser produces a `ParsedEmail` without network access. Enrichment accepts that object and returns a separate `EnrichmentResult`. This boundary keeps message extraction deterministic and lets tests replace provider calls without mocking the parser.

### Use dataclasses for structured output

The parser and enrichment results are dataclasses. The CLI converts them with `dataclasses.asdict()`, tests assert on typed attributes, and the Flask templates consume the same objects. This keeps the command-line and web paths aligned without a separate serialization model.

### Build rationale during scoring

The scorer appends a rationale entry at the same point where it adds each weight. This reduces the chance that displayed explanations diverge from the score calculation and gives analysts evidence to review rather than only a verdict label.

### Keep test indicators inert

`tests/make_fixtures.py` generates the sample `.eml` files from text and a harmless HTML attachment. The test suite can exercise suspicious patterns without storing or executing malware.

## Known limitations

### Header parsing is heuristic

The `Authentication-Results` and `Received` parsers use regular expressions rather than complete header grammars. Complex vendor-specific headers may be parsed partially or incorrectly. Results should support, not replace, manual header analysis.

### Sender spoof checks use substring rules

Display-name spoofing is based on a fixed list of brand terms and substring presence in the address domain. It does not validate registrable domains, ownership, lookalike characters, or organizational allowlists.

### URL extraction is intentionally narrow

The parser recognizes explicit HTTP and HTTPS URLs in decoded `text/*` parts. It does not normalize redirect chains, parse every HTML edge case, extract bare domains, or use the Public Suffix List.

### Enrichment is synchronous

Provider requests run sequentially and are subject to code-defined per-minute limits. Messages with many URLs or attachments can take several minutes. Cache state is local JSON and has no expiration or concurrent-access coordination.

### The web interface is local-development software

The Flask server binds to loopback and has no authentication. Uploads are limited to 1 MB, but temporary files are named from Python's process-local hash and written under `/tmp`. The interface should not be exposed publicly without deployment hardening.

The web path calls `enrich_eml()` with caching disabled. Contrary to an earlier implementation comment, it does not force provider keys to `None`; API keys inherited from the environment enable live requests.

### Detection rules require adaptation

The SPL and Sigma files assume normalized gateway fields and include local placeholders, lookups, and backend-sensitive modifiers. They have no repository CI workflow or declared validator dependency. YAML syntax alone is not sufficient validation.

## Issues encountered

### Reserved-address classification

The fixtures use RFC 5737 ranges to represent public hops. A broad standard-library private-address check would classify those reserved examples in a way that prevents the intended test transition. The parser uses an explicit internal-address definition instead. The rationale is documented in [Project rationale](why.md#address-classification-decision).

### Template-language behavior

Jinja does not expose every Python built-in as a template filter. The current report template uses index-based access for parallel URL lists rather than relying on an unavailable `zip` filter.

### Schema validation versus YAML validation

A file can be valid YAML while violating the Sigma schema or failing conversion for a particular backend. Detection validation therefore needs the actual target tooling and representative events.

## Potential follow-up work

Future work should be prioritized by an actual deployment need. Candidate improvements include:

1. accept binary streams in addition to filesystem paths, removing the web interface's temporary-file step;
2. add an explicitly designed batch-processing command;
3. add cache expiration and clearer cache-control semantics;
4. validate Sigma rules against selected backends in CI;
5. create positive and negative fixtures for each detection rule;
6. add structured domain parsing and environment-specific brand mappings;
7. document and secure a production deployment model only if public hosting becomes a requirement.

Each item changes behavior or operational scope and should be designed and tested separately.
