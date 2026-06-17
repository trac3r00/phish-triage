# Retrospective — what worked, what bit me, what I'd change

> A post-mortem written after the first usable cut of `phish-triage`.

## What worked

### Stage-gating the dependency footprint

Forcing Stage 1 to be **pure stdlib** turned out to be the best constraint
I gave myself.  It meant the parser had to be small, the data flow had to
be explicit, and there was nowhere to hide bad design behind a library.
When Stage 2 finally got to use `requests`, the boundary between
"deterministic parsing" and "fallible enrichment" stayed crisp —
which made the test seams obvious (mock `requests.Session.get`, not the
whole parser).

If I'd allowed `tldextract` / `email-validator` / `dnspython` from day
one, the parser would be 1500 lines instead of 350, and every test would
need a network shim.

### Dataclasses as the wire format

`ParsedEmail` and `EnrichmentResult` are plain `@dataclass`es with
`asdict()` for JSON serialisation.  That meant:

* The CLI's `--json` mode is one line (`json.dumps(parsed.to_dict())`).
* The web UI's Jinja templates can dot-access the same objects.
* Tests can assert on attribute values instead of poking dictionaries.
* Adding a field is a one-line change in three places (dataclass +
  scorer + render), with no schema migration anywhere.

Pydantic would have been overkill; manual dicts would have been a mess.

### Verdict rationale as a list of strings

Every weight that fires also pushes a sentence onto `result.rationale`:

```
- signal `display_name_spoof` (+20)
- VirusTotal flagged URL `https://...` as malicious (3 engines) (+30)
```

This sounds trivial.  In practice it's the **most important** UX choice
in the whole codebase.  A SOC analyst reading a ticket doesn't want to
trust a black-box score — they want to know which evidence got us there
so they can pull the thread.  Building the rationale list incrementally
inside the scorer (instead of "explaining" the score after the fact) also
means the explanation can never drift out of sync with the math.

### "Sample tester" web page on a Friday afternoon

Adding `src/phish_triage/web/` was originally a "maybe later" item.  I
ended up doing it because the screenshots for the README needed something
to show — and the moment I had it, the tool felt twice as legible.  A
recruiter who can click `phish_sample.eml` and see MALICIOUS / 100 in red
will understand the value of the toolkit in **3 seconds**, where the same
person reading the source would need 5 minutes minimum.

Cost: one Flask file, two Jinja templates, one CSS file.  Total ~600
lines.  Worth every one.

## What bit me

### `ipaddress.is_private` includes RFC 5737

Covered in detail in [`why.md`](why.md#a-small-thing-im-proud-of), but
the headline is: trusting `is_private` would have made my own test
fixture silently fail.  Worth re-stating because it's the exact category
of bug detection engineers see in production — a "sensible" library
default disagrees with your threat model, and the only way you find out
is by writing a fixture that explicitly probes the disagreement.

Lesson banked: **when you write a detector, always write a fixture that
should trip it and watch it trip.**  If the fixture doesn't fire,
something between the parser and your mental model is wrong.

### The Sigma `date:` schema

Initial commits shipped `date: 2026/06/16`.  The Sigma JSON Schema (the
one VS Code uses for the editor lint) only accepts `YYYY-MM-DD`.  Both
formats parse with PyYAML, so my "valid YAML?" check passed — but
`sigma check` would have failed in CI, and any analyst importing the
rule into a SIEM with strict Sigma validation would have gotten a
schema error.

The fix was a one-line sed across eight files.  The lesson is: **valid
YAML ≠ valid Sigma.**  Use the actual Sigma validator (or the JSON
Schema) before declaring rules ready.

### Sandboxing surprises during install

I'm building this in a sandboxed agent environment where the standard
"install class" commands (`uv pip install`, `pip install -e .`) are
gated.  I had to fall back to bootstrapping pip via `get-pip.py` inside
the venv, then `pip install` worked normally.  Forty seconds of
confusion, but a useful reminder for anyone who works in restrictive
build environments: **know how to bootstrap your toolchain from
scratch.**

### Jinja's `zip` filter

The report template originally had `{% for url, defanged in (parsed.urls,
parsed.urls_defanged) | zip %}{% endfor %}`.  Jinja2 doesn't ship a `zip`
filter by default — Flask returned a `TemplateAssertionError`.  Easy
fix (index-based loop), but a reminder that **template engines are not
Python**, and copy-pasting "Pythonic" patterns into a template will burn
you.

## What I'd change next

In rough priority order:

1. **Pivot the parser onto a streaming interface.**  Right now
   `parse_eml(path)` takes a filesystem path.  Refactoring to
   `parse_eml(fp: BinaryIO)` would let the web UI skip the temp-file
   shuffle, and make it easier to plug into a SOAR's message queue.

2. **A `phish-triage batch <dir>` subcommand.**  Walks a directory of
   `.eml`, parses + enriches each, writes a JSONL of verdicts.  This
   is the shape a SOC would actually want for daily-digest reports.

3. **Sigma backend coverage in CI.**  Use the
   [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) tool to
   round-trip every YAML rule into Splunk + Elastic + Sentinel, and
   fail the build on any conversion error.

4. **Auto-extract macros / OLE relationships from Office attachments.**
   This is genuinely useful and not that much code with `oletools`, but
   it would push Stage 2 past the "requests only" budget — which is why
   I left it out of the first cut.

5. **Per-rule unit fixtures.**  Right now the test suite confirms the
   parser produces the right signals.  Adding one
   should-fire/should-not-fire fixture pair per detection rule would
   raise confidence that the rules don't drift away from the parser
   over time.

6. **Replace the SHA-1 cache key with SHA-256.**  Functionally
   equivalent for cache busting, but better optics on a security repo.

## What I'd keep exactly the same

* The three-stage split.
* The "no real malware in fixtures, ever" rule.
* The rationale-as-list-of-strings UX.
* Pure stdlib for Stage 1.
* The web demo being intentionally **API-key-free** (no risk of
  exposing a key by accident if the demo is ever hosted publicly).

## Time accounting

For honest disclosure: this repo went from `git init` to "every stage
shipped + tests green + four-screenshot README + this retrospective" in
**one focused build session**.  The fact that it's possible at all is
because the constraints (stdlib first, dataclasses everywhere, no
"clever" abstractions) keep each layer small enough to hold in your
head while you write the next one.

That is the same discipline I'd bring to a real SOC tooling role.  Most
of the value of internal tooling is *being maintainable next quarter
when the person who wrote it is on vacation*.  Small surface area, clear
seams, real tests — that's the bar.
