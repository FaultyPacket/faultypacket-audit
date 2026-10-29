# FaultyPacket™ Audit

[![ci](https://github.com/FaultyPacket/faultypacket-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/FaultyPacket/faultypacket-audit/actions/workflows/ci.yml)
[![rules verified weekly](https://github.com/FaultyPacket/faultypacket-audit/actions/workflows/weekly-verify.yml/badge.svg)](https://github.com/FaultyPacket/faultypacket-audit/actions/workflows/weekly-verify.yml)
[![upstream watch](https://github.com/FaultyPacket/faultypacket-audit/actions/workflows/watch-upstream.yml/badge.svg)](https://github.com/FaultyPacket/faultypacket-audit/actions/workflows/watch-upstream.yml)
[![licence: AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0-blue)](LICENSE)
[![rules](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FFaultyPacket%2Ffaultypacket-audit%2Fmain%2Ffaultypacket_audit%2Fdata%2Frules.json&query=%24.rules_version&label=rules)](faultypacket_audit/data/rules.json)

**Is your domain's email set up to current rules? One command checks SPF, DMARC (RFC 9989), DKIM, MTA-STS, DNSSEC, DANE, CAA, BIMI and Google/Yahoo/Outlook sender requirements, and every finding cites the RFC section or provider page behind it.**

```
pip install git+https://github.com/FaultyPacket/faultypacket-audit
faultypacket-audit --doh europa.eu
faultypacket-audit --doh -f domains.txt --json out.json --sarif out.sarif
```

Sample output (live run, 2026-10-29 11:45 UTC, trimmed):

```
europa.eu: ERROR
  dmarc: error
    [error] no DMARC record at _dmarc.europa.eu and none found by the Tree Walk: DMARC does not apply (RFC 9989 4.10.1)
      rule dmarc.no_record | RFC 9989 4.10.1 | https://www.rfc-editor.org/rfc/rfc9989#section-4.10.1 | rules 2026.10.29.3
  bulk-sender: warning
    google: fail (not checkable from DNS: alignment, one_click_unsub, tls, spam_rate_max)
    outlook: fail (not checkable from DNS: alignment)
    yahoo: fail (not checkable from DNS: unsub_days_max)
```

Runs locally. No account, no upload. Also a [GitHub Action](#github-action), an [MCP server](#mcp-server-for-ai-agents) and a [weekly scan](#weekly-scan-in-your-own-repo) for your own repo. AI agents: see [AGENTS.md](AGENTS.md).

> Status: v1.1.0 (2026-10-29). JSON fields are stable within 1.x ([schema](schema/audit.schema.json)); rule changes bump `rules_version`.

## Checks

| Check | What it does | Main sources |
|---|---|---|
| `spf` | Expands the full SPF tree and counts DNS lookups, void lookups, MX/PTR fan-out, loops, duplicates, syntax, temperror vs permerror | RFC 7208 §2.6, §4.5, §4.6.4, §5, §6.1 |
| `dmarc` | Validates the record against RFC 9989: case-sensitive `v=DMARC1`, tags `np`/`psd`/`t`, `fo` syntax, historic `pct`/`rf`/`ri`, policy discovery, Tree Walk Organizational Domain (max 8 queries) compared with the legacy PSL method, external report destination authorisation | RFC 9989 §4.7, §4.8, §4.10, §5.2, §9.3, App. A.6; RFC 9990 §4; RFC 9991 §5 |
| `dkim` | Probes common selectors plus yours: RSA key size (from the key itself), Ed25519 length, `v=`, `k=`, `h=sha1`, `t=y`, revoked keys | RFC 6376 3.6.1; RFC 8301 3.1–3.2; RFC 8463 |
| `mx` | Null MX, MX pointing at a CNAME or an IP, unresolvable hosts | RFC 7505; RFC 2181 10.3; RFC 5321 5.1 |
| `mta-sts` | MTA-STS TXT and policy file, MX coverage, `max_age`, TLS-RPT; optional port-25 STARTTLS probe (`--smtp`) | RFC 8461; RFC 8460 |
| `dnssec` | DS at the parent, AD bit from a validating resolver | RFC 4035 3.2.3, 5.5; RFC 4034 5 |
| `dane` | TLSA at `_25._tcp.<mx>`: syntax, usage (DANE-TA/EE for SMTP), hash length, DNSSEC validation | RFC 7672 2.2, 3.1.3; RFC 6698 2.1 |
| `caa` | Tag syntax, `issue`/`issuewild`, `iodef`, critical flag | RFC 8659 3, 4.1–4.5 |
| `rdns` | Forward-confirmed reverse DNS for MX hosts and `--sending-ip` | RFC 1912 2.1; provider guidelines |
| `bimi` | BIMI record, DMARC enforcement prerequisite, SVG Tiny PS profile, `<title>`, 32 KB limit, certificate presence | draft-brand-indicators-for-message-identification-14; draft-svg-tiny-ps-abrotman-12 |
| `bulk-sender` | Major mailbox providers' published bulk-sender requirements, split into what DNS can verify and what it can't | provider guideline pages, linked per row |

## Install and run

```
pip install git+https://github.com/FaultyPacket/faultypacket-audit
faultypacket-audit example.com
faultypacket-audit -f domains.txt --json out.json --csv out.csv --sarif out.sarif
faultypacket-audit example.com --dkim-selector s1 --sending-ip 192.0.2.10
faultypacket-audit -f domains.txt --json new.json --baseline old.json --diff changes.md --fail-on-new
python -m faultypacket_audit --checks spf,dmarc --doh example.com
```

Exit codes: 0 means clean, 1 means the `--fail-on` threshold (default `error`) was reached or an input was invalid, 2 means a usage error.

## Output

* **Text** is the default.
* **JSON** gives one object per domain. Each check has a `status`, its `findings` and structured `data`.
* **CSV** gives one row per finding.
* **SARIF 2.1.0** works with GitHub code scanning. Each rule carries a `helpUri` that links to its source.

Each finding has these fields:

* `rule_id` (for example `dmarc.historic_pct`)
* `severity`
* `message`
* `citation` (for example `RFC 9989 9.3`)
* `url`
* `level`, which is `MUST`, `SHOULD`, `MAY`, `PROVIDER` or `TOOL`. `TOOL` covers the tool's own conditions, such as DNS errors.
* `rules_version` (for example `2026.10.29.3`), so a finding can be traced to the exact rule set that produced it. SARIF messages end with `[rule_id | citation | rules version]`.

## Provider verdicts

`bulk-sender` gives a separate verdict for Google, Yahoo and Outlook, with one row per published requirement and a link to the provider page. DKIM rows use the keys the `dkim` check found, including Google's rule that mail to personal Gmail accounts needs a DKIM key of 1024 bits or longer (support.google.com/a/answer/81126, checked 2026-10-29).

## Library use

The checks are pure functions that return data and never print.

```python
from faultypacket_audit import audit, load_rules, Resolver
report = audit("example.com", Resolver(), load_rules())
```

## GitHub Action

```yaml
- uses: FaultyPacket/faultypacket-audit@v1
  id: audit
  with:
    domains-file: domains.txt        # or domains: "example.com example.org"
    args: --dkim-selector s1         # any CLI flags
    fail-on: error                   # or warning
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: "${{ steps.audit.outputs.sarif }}"}
```

Outputs: `exit-code`, `json`, `sarif`. `@v1` follows the latest 1.x release; pin a tag such as `@v1.1.0` for fixed behaviour.

## MCP server for AI agents

```
faultypacket-audit mcp --doh
```

A stdio [Model Context Protocol](https://modelcontextprotocol.io) server with two tools, `audit_domain` and `list_rules`. See [AGENTS.md](AGENTS.md).

## Weekly scan in your own repo

Copy `templates/weekly-scan.yml` into your repo's `.github/workflows/` and add a `domains.txt` file. Once a week the workflow:

* uploads SARIF to the Security tab,
* keeps the JSON and CSV as an artifact,
* downloads the previous run's JSON and writes "What changed since the last run" (new problems, fixed, severity changes) to the job summary,
* opens one alert issue when there are warnings or errors (and comments on it on later runs), and closes it when all domains are clean.

For UK organisations that used NCSC Mail Check (retired 31 March 2026), this gives a weekly check you run and read yourself.

## What it cannot check from DNS

The bulk-sender check is deliberately honest about its scope. Each requirement row is reported as `pass`, `fail`, `unknown` or `not-dns-verifiable`.

* **Needs your input:**
  * Forward-confirmed reverse DNS needs your sending IPs (`--sending-ip`).
  * DKIM needs your selectors (`--dkim-selector`). Selectors can't be discovered from DNS.
* **Not visible from DNS at all:**
  * TLS on the actual connection
  * spam-complaint rates
  * one-click unsubscribe headers (RFC 8058)
  * message formatting
  * whether the From domain aligns on real mail

  Those show as `not-dns-verifiable` and are never counted as passes. A provider verdict is `fail`, `incomplete` or `dns-checks-pass`. It is never "compliant".
* **Other limits:**
  * SMTP STARTTLS is only checked with `--smtp`. Many networks (including GitHub-hosted runners and most clouds) block outbound port 25; the result is then reported as `not tested (port 25 blocked)`, never as a pass.
  * DKIM selectors can't be listed from DNS. A key found by probing a common selector may not be the one in use, so give your real selectors with `--dkim-selector`.
  * BIMI: the VMC/CMC certificate chain is not validated, only its presence.
  * DNSSEC validation relies on the resolver's AD bit (DoH, or `--validating-resolver`).
  * Tree Walk results depend on what intermediate domains publish. Where a public suffix has a DMARC record without `psd=y`, the Tree Walk and PSL methods can choose different Organizational Domains. The tool reports this as `dmarc.org_method_differs`.

## Rules and maintenance

* `maint/scripts/check_rules.py` runs in CI. It fails if any rule has no source, URL or verified date, or if a code constant disagrees with the rules.
* Weekly workflows run:
  * canary domains,
  * the test suite,
  * a watch on the RFC errata pages, the IANA DMARC registry and the provider guideline pages.

  A change opens an issue for review. Nothing updates itself.

More at https://faultypacket.co.uk


---

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright (c) 2026 FaultyPacket. FaultyPacket™ — https://faultypacket.co.uk
