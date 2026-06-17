# Detections — Splunk SPL + Sigma

Eight detection rules derived from the signals the
[`phish-triage`](../README.md) parser surfaces. Each rule ships in two formats:

* **SPL** (`spl/`) — Splunk queries assuming a CIM-shaped `index=email`
  populated by a secure-email-gateway adapter (Proofpoint / Mimecast / O365 /
  Cisco ESA / etc.).  Field names follow the
  [Splunk Common Information Model — Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email)
  data model where possible.
* **Sigma** (`sigma/`) — YAML rules with `logsource.product: email`,
  `category: email-gateway`.  Convert with `sigma convert` to deploy on your
  SIEM of choice (Elastic, Sentinel, Chronicle, …).

## Rule → parser signal → MITRE ATT&CK

| Rule | Title | Parser signal(s) | MITRE ATT&CK |
|------|-------|------------------|--------------|
| R01 | SPF fail + From / Reply-To mismatch | `spf_fail`, `from_reply_to_mismatch` | [T1566.001](https://attack.mitre.org/techniques/T1566/001/), [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| R02 | Newly observed sender domain with auth fail | `spf_fail` ∨ `dkim_fail` ∨ `dmarc_fail` + novel domain | [T1566](https://attack.mitre.org/techniques/T1566/) |
| R03 | Brand / executive display-name impersonation | `display_name_spoof` | [T1656](https://attack.mitre.org/techniques/T1656/), [T1566.001/002](https://attack.mitre.org/techniques/T1566/) |
| R04 | URL shortener in inbound email | `url_shortener` | [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1204.001](https://attack.mitre.org/techniques/T1204/001/) |
| R05 | Attachment hash matched VirusTotal | `has_attachment` + VT enrichment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) |
| R06 | Suspicious / disposable TLD link | `suspicious_tld` | [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1583.001](https://attack.mitre.org/techniques/T1583/001/) |
| R07 | Base64-encoded HTML body containing a form | URL extraction + body decode | [T1027](https://attack.mitre.org/techniques/T1027/), [T1566.001](https://attack.mitre.org/techniques/T1566/001/) |
| R08 | DMARC reject / quarantine policy bypass | `dmarc_fail` | [T1566](https://attack.mitre.org/techniques/T1566/), defense_evasion |

## Tuning notes

* These rules favour **recall** for an inbox where the analyst will manually
  triage hits.  Tighten with allowlists once a steady-state hit rate is
  established (typical: ≤ 5 events / day for R02 / R03 / R08, more for R01 / R04).
* All Sigma rules pin `logsource.product: email`.  If your gateway product
  ships its own Sigma backend (e.g. Proofpoint), swap that in.
* R02 and R05 require auxiliary state (rolling sender-domain baseline; VT
  lookup table `ti_vt`).  The SPL shows one common pattern; adjust to match
  whatever lookup/baseline plumbing your environment already has.
