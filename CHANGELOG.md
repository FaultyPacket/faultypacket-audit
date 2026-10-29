# Changelog


## 1.1.0 (2026-10-29)

- GitHub Action: `uses: FaultyPacket/faultypacket-audit@v1` (composite `action.yml`, outputs `exit-code`, `json`, `sarif`), with a self-test workflow.
- MCP server: `faultypacket-audit mcp` (stdio) with `audit_domain` and `list_rules` tools.
- JSON Schema for `--json` output at `schema/audit.schema.json`, tested against real output.
- AGENTS.md, llms.txt, SECURITY.md, CONTRIBUTING.md, CITATION.cff, issue templates.
- No rule changes (rules 2026.10.29.3).
## 1.0.0 (2026-10-29)
- Licence changed from MIT to AGPL-3.0-or-later; added NOTICE.
- New checks: `dkim` (common-selector probe, RSA/Ed25519 key size from the key, `t=y`, `h=sha1`, revoked keys), `mx` (null MX, CNAME/IP targets), `dnssec` (DS + AD bit), `dane` (TLSA for SMTP), `caa`, `rdns` (FCrDNS), `bimi` (record, DMARC prerequisite, SVG Tiny PS), and a rebuilt `mta-sts` with TLS-RPT.
- `--smtp` optional port-25 STARTTLS probe; reported as "not tested" where port 25 is blocked.
- Per-provider (Google/Yahoo/Outlook) verdicts now include DKIM key size, including Google's 1024-bit minimum for personal Gmail.
- Every finding carries `rules_version` alongside rule ID and citation, in JSON, CSV, text and SARIF.
- `--baseline`, `--diff` and `--fail-on-new`: a "what changed since the last run" report.
- Weekly scan template rewritten: baseline diff, job summary, SARIF, one alert issue opened/updated/closed automatically.
- Rules 2026.10.29.3 (193 rules). Citation style normalised to "RFC 8301 3.2".
- Fixes: TLSA records in multi-line presentation form; probed DKIM selectors no longer misread wildcard TXT records (e.g. DMARC) as keys.

## 0.1.0 (not released separately)
- Initial release of the combined tool: `spf`, `dmarc` and `bulk-sender` checks behind one CLI and library API.
- The SPF engine is ported unchanged from spf-tree 1.0.0 (its original test suite passes).
- DMARC follows RFC 9989/9990/9991:
  - Tree Walk Organizational Domain, with a legacy PSL comparison
  - historic tags
  - `psd`, `np` and `t`
  - errata 9150 citations for report authorisation (RFC 9990 §4)
- Versioned rule set (`rules.json`, schema `faultypacket-rules/1`). Every finding has a citation and a link.
- Output: text, JSON, CSV and SARIF 2.1.0. Batch mode with a concurrency setting, plus a GitHub Actions weekly-scan template.
