# Stage 1 — Parsing walkthrough

This walkthrough tracks the simulated phishing fixture
(`tests/fixtures/phish_sample.eml`) through `phish_triage.parser` one signal
at a time.

## 0. What's in the fixture

`tests/make_fixtures.py` synthesises an email that intentionally trips every
detector the parser knows about — without using any real malware.  Headers of
note:

```
From:    PayPal Security <security-team@paypa1-verify.top>
Reply-To: verify@evil-collector.country
Subject: Urgent: PayPal account suspended
Authentication-Results: mx.corp.example;
    spf=fail smtp.mailfrom=paypa1-verify.top;
    dkim=none;
    dmarc=fail header.from=paypa1-verify.top
Received: from internal-bot (internal-bot [192.168.1.50])
        by public-relay.example.net with ESMTPS id XXX;
        Tue, 10 Jun 2026 09:13:55 +0000
Received: from public-relay.example.net (public-relay.example.net [198.51.100.42])
        by mx.corp.example with ESMTPS id YYY;
        Tue, 10 Jun 2026 09:14:01 +0000
Received: from mx.corp.example (mx.corp.example [10.0.0.5])
        by inbox.corp.example with ESMTPS id ZZZ;
        Tue, 10 Jun 2026 09:14:05 +0000
```

…plus a body with a shortener (`bit.ly`) and a `.zip` link, and a small
`invoice.html` attachment.

## 1. Authentication-Results — `parse_auth_results`

The header arrives as one (or more) strings.  We run a single regex that
captures every `mech=result` token in the line:

```python
_AUTH_RE = re.compile(
    r"(?P<mech>spf|dkim|dmarc)\s*=\s*"
    r"(?P<result>pass|fail|none|neutral|softfail|...)",
    re.IGNORECASE,
)
```

Why a regex and not a header-grammar parser?  Real-world
`Authentication-Results` headers concatenate vendor extensions, comments, and
quoted values; a permissive regex over the known mechanism keywords is more
robust in practice — and `email.headerregistry` doesn't ship a parser for
this particular header.

We never let a later `none` overwrite an earlier `pass`/`fail`.  Two reasons:

1. A message can carry **multiple** `Authentication-Results` headers (every
   relay can stamp its own).
2. Some relays emit `dkim=none` as a placeholder when the message arrived
   before they got a chance to verify; the real verdict is from the edge
   gateway.

For our fixture the output is `spf=fail dkim=none dmarc=fail` — exactly what
the headers say.  Two derived signals: `spf_fail`, `dmarc_fail`.

## 2. From vs Reply-To & display-name spoofing — `parse_address_mismatch`

`email.utils.parseaddr` cleanly splits `"PayPal Security
<security-team@paypa1-verify.top>"` into the tuple
`('PayPal Security', 'security-team@paypa1-verify.top')`.

Two checks:

* **From vs Reply-To**: the addr-spec domains differ →
  `from_reply_to_mismatch`.
* **Display-name brand spoof**: the display name contains a brand keyword
  (`paypal`) but the addr-spec domain doesn't end in the brand's real domain
  →  `display_name_spoof`.

A second flavour of display-name spoof catches messages where the *display
name* is literally a different email address than the real From: the classic
`"alice@corp.com" <attacker@evil.tld>` pattern.

For our fixture both checks fire.

## 3. Received chain — `parse_received_chain`

The `Received` headers in an RFC 5322 message are written newest-first (last
hop at the top of the file).  Analysts read chains origin → recipient, so we
reverse them.  Each hop is parsed for the `from`-host/IP, the `by`-host, and
a timestamp (we re-encode timestamps to UTC ISO-8601 so they're sortable).

The privacy check is the interesting one.  Python's
`ipaddress.IPv4Address.is_private` returns **True** for RFC 5737
documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`).
Test fixtures use those ranges as *public* internet stand-ins — so trusting
`is_private` directly would mask real anomalies.  Instead we limit
"private" to RFC 1918, loopback, and link-local explicitly:

```python
_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
```

`detect_private_to_public_anomaly` walks the ordered hops and fires if a
private hop is ever followed by a public hop, which is the canonical
"internal bot leaked out to a public relay" tell.  Our fixture trips it:
`192.168.1.50` → `198.51.100.42` → `10.0.0.5`.

Note that the final 10.0.0.5 hop is the **destination** MX inside the
corporate network — that's why we only need the **first** public hop after a
private one to flag the anomaly.

## 4. URLs — `extract_urls`

We walk every `text/*` body part, decode using the part's declared charset
(falling back to UTF-8), and run a single URL regex.

Why a regex and not `urlextract` / a tokeniser?  We want to catch URLs
embedded in HTML attributes (`href="..."`), in plain text, and inside
base64-decoded payloads, all without dragging extra dependencies in.  The
regex is intentionally greedy enough to grab the path + query string but
strips trailing punctuation that's often appended by text formatters
(`. , ) ; ]`).

`defang(url)` then rewrites `http://` → `hxxp://` and dots → `[.]` to keep
the link unclickable in analyst tooling.

## 5. Attachments — `extract_attachments`

For each non-multipart, non-inline part we decode the payload to bytes and
compute MD5, SHA1, SHA256.  The hashes are what feed VirusTotal in Stage 2
and the Splunk attachment-hash detection (R05) in Stage 3.

## 6. Signal derivation — `_derive_signals`

The final step combines everything into a list of named signals — the
contract Stage 2 (`enrich.py`) and Stage 3 (`detections/`) consume.  For the
phishing fixture the parser emits all eight:

```
spf_fail
dmarc_fail
from_reply_to_mismatch
display_name_spoof
received_private_to_public
url_shortener
suspicious_tld
has_attachment
```

Stage 2 turns that list (plus VT and AbuseIPDB results) into a numeric
score; Stage 3 turns each signal into a SIEM rule.

## Try it yourself

```bash
phish-triage parse tests/fixtures/phish_sample.eml --json | jq .signals
```

Should print all eight signals as a JSON array.
