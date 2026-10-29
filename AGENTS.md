# AGENTS.md: using faultypacket-audit from an AI agent

Read-only mail/DNS security audit. Every finding carries a `rule_id`, a
`citation` (RFC section or provider page) and a `url`, so you can quote the
source instead of paraphrasing.

## Install

```
pip install git+https://github.com/FaultyPacket/faultypacket-audit
```

Python 3.10+. Dependencies: dnspython, publicsuffixlist.

## Invoke (CLI)

```
faultypacket-audit --doh -q example.com --json -          # JSON to stdout, summary to stderr
faultypacket-audit --doh -q -f domains.txt --json out.json # batch
faultypacket-audit --doh --checks dmarc,spf example.com --json -
```

faultypacket-audit --doh --checks mx,blocklist,lookalike example.com --json -   # opt-in checks
faultypacket-audit --doh example.com --html report.html    # human report (print to PDF)
faultypacket-audit headers message.eml --json             # alignment verdict from saved headers
```

`blocklist` and `lookalike` run only when named in `--checks`. A blocklist
row with `tested: false` means the list refused the resolver: report it as
"not tested", never as "not listed". Lookalike rows are observations; never
call a registered lookalike malicious.

```
: many block outbound port 53. Add `--dkim-selector`
and `--sending-ip` when the user knows them; DKIM selectors can't be listed from DNS.

## Invoke (MCP, stdio)

```
faultypacket-audit mcp --doh
```

Tools: `audit_domain {domain, checks?, dkim_selectors?, sending_ips?, bulk?}`
returns one audit report object; `list_rules {}` returns the rule set.
Example client config:

```json
{"mcpServers": {"faultypacket-audit": {"command": "faultypacket-audit", "args": ["mcp", "--doh"]}}}
```

## Output contract

* JSON Schema: [`schema/audit.schema.json`](schema/audit.schema.json) (stable within 1.x; fields may be added).
* Rules: [`faultypacket_audit/data/rules.json`](faultypacket_audit/data/rules.json)
  ([raw](https://raw.githubusercontent.com/FaultyPacket/faultypacket-audit/main/faultypacket_audit/data/rules.json)),
  each with `id`, `level`, `source`, `url`, `verified` date. Also attached to every GitHub Release.
* `severity`: `info` | `warning` | `error`; check/report `status` adds `ok`.
* `level`: `MUST` | `SHOULD` | `MAY` (RFC keywords) | `PROVIDER` (mailbox-provider page) | `TOOL` (DNS errors etc.).
* Bulk-sender rows can be `not-dns-verifiable`. Never present those as passes,
  and never call a domain "compliant"; the verdicts are `fail`, `incomplete` or `dns-checks-pass`.

* `fixes`: per report, `{rule_id, name, type, value, note}`; `type` is `TXT`, `MX`, `CAA`, `FILE` (name is the URL to publish at) or `STEPS` (numbered instructions). Values containing `REPLACE-` need the owner's input; say so when you pass them on.

## Exit codes

| code | meaning |
|---|---|
| 0 | below the `--fail-on` threshold (default `error`); with `--fail-on-new`, nothing new or worse |
| 1 | threshold reached, regression found, or an input was invalid |
| 2 | usage error |

## Guidance for agents

* Report findings as observations with their citation; don't speculate about intent.
* Quote `checked_at_utc` and `rules_version` with any result. DNS changes.
* For fixes, link the finding's `url`. Hands-on help: https://faultypacket.co.uk
