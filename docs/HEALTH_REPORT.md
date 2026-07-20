# Project health report

Last reviewed: 2026-07-19

## Summary

The repository is a small Python 3.11 package with clear parser, enrichment, CLI, web, and detection-content boundaries. Its automated tests cover the Python behavior, but the repository has no CI workflow, formatter or linter configuration, type-checker configuration, packaging smoke test, or automated Sigma validation.

The appropriate maintenance strategy is incremental improvement. The codebase does not require a rebuild.

## Project map

| Area | Current implementation |
|---|---|
| Runtime | Python 3.11 or later |
| Packaging | `pyproject.toml`, setuptools, `src/` layout |
| CLI entry point | `phish-triage = phish_triage.cli:main` |
| Core modules | `parser.py`, `enrich.py`, `cli.py` |
| Optional interface | Flask application in `phish_triage.web` |
| External services | VirusTotal v3 and AbuseIPDB v2 |
| Detection content | Eight SPL queries and eight Sigma rules |
| Test command | `pytest` after installing `.[dev,web]` |
| CI | No workflow under `.github/workflows/` |
| Deployment | No deployment configuration |

## Strengths

- Parsing and enrichment are separated by dataclass-based interfaces.
- The parser performs no network access and uses only the standard library.
- Provider calls have timeouts, local caching, rate limiting, and graceful handling for missing keys.
- Tests mock enrichment network requests and exercise Flask routes with the test client.
- Sample messages are generated from inert content.
- Package metadata declares the Python version, dependencies, entry point, license, and repository URL.

## Risks and gaps

| Area | Risk | Evidence | Suggested action |
|---|---|---|---|
| CI | Regressions depend on local test execution. | No `.github/workflows/` directory is present. | Add CI only when repository policy permits workflow changes. |
| Detection validation | Sigma and SPL portability is not automatically checked. | No validator dependency or workflow is declared. | Select target backends and validate with their supported tooling. |
| Web deployment | The Flask interface has no production security model. | It binds to loopback, has no authentication, and uses temporary files in `/tmp`. | Keep it local unless a deployment design and security review are completed. |
| Parsing fidelity | Complex headers may exceed the regular-expression parsers. | `Authentication-Results` and `Received` use permissive regex extraction. | Add regression fixtures for observed real-world formats. |
| Domain heuristics | Brand and suspicious-TLD checks can produce false positives or false negatives. | Checks use fixed strings rather than registrable-domain parsing. | Add organization-specific mappings if operational use requires them. |
| Cache lifecycle | Cached provider responses do not expire. | JSON cache files have no timestamp-based invalidation. | Define retention and freshness requirements before adding expiration. |
| Version source | The version is repeated. | `pyproject.toml` and `src/phish_triage/__init__.py` both contain `0.1.0`. | Update both together for releases or adopt one authoritative source. |

## Recommended sequence

1. Preserve the current parser/enrichment boundary and add regression fixtures for any production message formats encountered.
2. Add a minimal CI test matrix before accepting behavior changes, if workflow modification is approved.
3. Choose specific Sigma backends before adding automated conversion checks.
4. Design authentication, temporary-file handling, and deployment controls before considering public web hosting.

## Rebuild decision

Decision: no.

The codebase is small and its boundaries are understandable. Identified gaps can be addressed independently without replacing the architecture.

## Review evidence

Repository surfaces inspected for this report:

```text
pyproject.toml
src/phish_triage/*.py
src/phish_triage/web/
tests/
detections/spl/
detections/sigma/
.github/
```

Validation commands for the current checkout are recorded in the task handoff under `docs/handoffs/`.
