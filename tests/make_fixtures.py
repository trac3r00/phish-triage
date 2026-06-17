"""Generate the sample ``.eml`` fixtures used by the test suite.

Run this once to populate ``tests/fixtures/``::

    python -m tests.make_fixtures

Two fixtures are produced:

* ``benign.eml`` — boring multipart/alternative invoice email that passes auth.
* ``phish_sample.eml`` — simulated phishing email exhibiting every signal the
  parser is meant to catch.  **No real malware** is embedded.
"""

from __future__ import annotations

import sys
from email.message import EmailMessage
from pathlib import Path


FIX_DIR = Path(__file__).resolve().parent / "fixtures"


def _write_benign() -> Path:
    msg = EmailMessage()
    msg["Subject"] = "Your monthly invoice"
    msg["From"] = "Billing <billing@example.com>"
    msg["Reply-To"] = "billing@example.com"
    msg["To"] = "alice@corp.example"
    msg["Date"] = "Tue, 10 Jun 2026 12:00:00 +0000"
    msg["Message-ID"] = "<benign-001@example.com>"
    msg["Authentication-Results"] = (
        "mx.corp.example; spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    )
    msg["Received"] = (
        "from mail.example.com (mail.example.com [203.0.113.10]) "
        "by mx.corp.example with ESMTPS id ABCDEF; "
        "Tue, 10 Jun 2026 12:00:01 +0000"
    )
    msg.set_content("Hi Alice,\n\nYour invoice for May is attached.\n\nThanks,\nBilling")
    msg.add_alternative(
        "<html><body><p>Hi Alice,</p>"
        "<p>Your invoice for May is on the <a href=\"https://example.com/invoice/123\">portal</a>.</p>"
        "</body></html>",
        subtype="html",
    )
    out = FIX_DIR / "benign.eml"
    out.write_bytes(bytes(msg))
    return out


def _write_phish() -> Path:
    msg = EmailMessage()
    # Brand-keyword display name with unrelated addr-spec domain → spoofing tell.
    msg["Subject"] = "Urgent: PayPal account suspended"
    msg["From"] = "PayPal Security <security-team@paypa1-verify.top>"
    msg["Reply-To"] = "verify@evil-collector.country"
    msg["To"] = "bob@corp.example"
    msg["Date"] = "Tue, 10 Jun 2026 09:13:42 +0000"
    msg["Message-ID"] = "<phish-001@paypa1-verify.top>"
    msg["Authentication-Results"] = (
        "mx.corp.example; spf=fail smtp.mailfrom=paypa1-verify.top; "
        "dkim=none; dmarc=fail header.from=paypa1-verify.top"
    )
    # Received chain: origin is a private IP, next hop is public → anomaly.
    msg["Received"] = (
        "from mx.corp.example (mx.corp.example [10.0.0.5]) "
        "by inbox.corp.example with ESMTPS id ZZZ; "
        "Tue, 10 Jun 2026 09:14:05 +0000"
    )
    msg["Received"] = (
        "from public-relay.example.net (public-relay.example.net [198.51.100.42]) "
        "by mx.corp.example with ESMTPS id YYY; "
        "Tue, 10 Jun 2026 09:14:01 +0000"
    )
    msg["Received"] = (
        "from internal-bot (internal-bot [192.168.1.50]) "
        "by public-relay.example.net with ESMTPS id XXX; "
        "Tue, 10 Jun 2026 09:13:55 +0000"
    )
    body_text = (
        "Dear Customer,\n\n"
        "We detected unusual activity on your PayPal account.\n"
        "Please verify immediately: http://bit.ly/paypal-verify-now\n"
        "or visit https://paypa1-secure-login.zip/account\n\n"
        "Regards,\nPayPal Security"
    )
    msg.set_content(body_text)
    msg.add_alternative(
        "<html><body>"
        "<p>Dear Customer,</p>"
        "<p>Click <a href=\"http://bit.ly/paypal-verify-now\">here</a> to verify "
        "or <a href=\"https://paypa1-secure-login.zip/account\">log in</a>.</p>"
        "</body></html>",
        subtype="html",
    )
    # Attachment: a fake "invoice.html" — NOT real malware, just text bytes.
    msg.add_attachment(
        b"<html>fake credential harvester form would go here</html>",
        maintype="text",
        subtype="html",
        filename="invoice.html",
    )
    out = FIX_DIR / "phish_sample.eml"
    out.write_bytes(bytes(msg))
    return out


def main() -> int:
    FIX_DIR.mkdir(parents=True, exist_ok=True)
    paths = [_write_benign(), _write_phish()]
    for p in paths:
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
