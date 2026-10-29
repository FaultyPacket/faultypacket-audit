# Changelog



## Unreleased

- `security-txt` check (opt-in, RFC 9116): location, HTTPS, media type, syntax, Contact, Encryption, Expires, Canonical, Preferred-Languages, signature. See docs/security-txt.md.

- `analyse` command and `headers --verify`: local DKIM re-verification (RFC 6376 canonicalisation, h= bottom-up selection, i= within d=, t=s, l=, x=/t=, key-record checks, RFC 8301 algorithm and key-size rules, RFC 8463 ed25519), with DMARC alignment of verified signatures. See docs/analyse.md.

- Fix: a `_dmarc` TXT record that starts with `v=DMARC1` but does not parse (e.g. `v=DMARC1 p=reject sp=reject`, no `;`) was reported as `dmarc.no_record`. It now raises the new error `dmarc.unparseable_record` (RFC 9989 4.8), which says the record is published but invalid and names the likely cause.
- New `faultypacket-audit reports`: offline DMARC aggregate (RFC 7489 7.2 / RFC 9990) and TLS-RPT (RFC 8460) report reader for .xml, .gz, .zip and .json. Per-source-IP and per-domain SPF, DKIM and alignment pass/fail, failing and unauthorised senders, TLS failure types; Markdown or JSON. DTDs refused, 64 MiB decompression cap. See docs/reports.md.
- `reports` now validates each report against its RFC and lists problems under "Report conformance" (JSON key `conformance`, rule ids `rpt.*`, each citing its section). DMARC aggregate (RFC 9990 3.1.1 to 3.5.2): element order and multiplicity, at least one record, namespaced extensions, version 1.0, pass/fail evaluated values, RFC 8601 result values, SPF scope, the required `reason` when the disposition differs from the policy, at most 100 DKIM results per row, a single policy domain, date range, Report-ID ABNF, filename ABNF, duplicate Report-IDs and overlapping periods across files. TLS-RPT (RFC 8460 4 to 5.3): required fields, `policies` as an array, RFC 3339 dates, full UTC day, policy-type/result-type/count values, failure-reason-code, filename. `.eml` input: subject ABNF, media types, TLS-Report-Domain/Submitter headers and the contact-info match, DKIM signature presence by the reporting domain, and a `dmarc=fail` on the report message itself. New `--fail-on-nonconformant`.
- `reports` reads RFC 9991 DMARC failure reports (ARF `.eml`): source IP, From domain, Identity-Alignment, delivery result and DKIM fields, and checks the REQUIRED fields (Identity-Alignment ABNF, DKIM-Domain/Identity/Selector for aligned DKIM failures, SPF-DNS for aligned SPF failures).
- New `faultypacket-audit alert`: daily change and new-failure alerts to Slack, Teams or a generic JSON webhook. URL from an environment variable/secret only. GitHub Action inputs `alert-format` and `alert-state`; example in examples/alerts.yml. See docs/alerts.md.
- New `faultypacket-audit spf-drift`: compares a flattened SPF record with the current resolution of its source includes and lists missing and extra ranges. See docs/spf-drift.md.
- SPF: `spf.record_size` (name + TXT >= 450 octets, RFC 7208 3.4), `spf.rr_type_99` (discontinued SPF RR still published, RFC 7208 3.1/14.1), `spf.exp_target` (exp= target missing, multiple or not a valid macro-string, RFC 7208 6.2/7.1).
- DMARC: `dmarc.cname` / `dmarc.cname_dangling` when `_dmarc` is served through a CNAME chain that resolves, loops or dangles.
- DKIM key tags: `dkim.strict_subdomain` (t=s), `dkim.unknown_flag`, `dkim.service_type` (s= without email or *), `dkim.granularity` (g=, RFC 6376 C.2) (RFC 6376 3.6.1).
- BIMI mark certificates (VMC/CMC): chain order and signatures, expiry, BIMI EKU, SAN, and the embedded logotype hash compared with l=. Needs `pip install faultypacket-audit[crypto]`; without it the check reports "not tested". Root trust is not judged.

## 1.4.0 (2026-10-29)

Bugs found by differential testing against real published records (details in docs/differential-findings.md):

- SPF: mechanisms after `all` are no longer counted towards the 10-lookup limit (RFC 7208 5.1); they are still syntax-checked (new info finding `spf.after_all`).
- SPF: a qualified modifier such as `-allgoogle-site-verification=...` (TXT strings joined without a space) is now a syntax permerror (RFC 7208 12) instead of being accepted.
- DMARC: a report URI containing whitespace (e.g. `ruf=mailto:x@example.org fo=1`, a missing `;`) or more than one `@` is now an error.
- DMARC: control characters, empty tags, tag names that are not letters only (`+p=`, `p ct=`), empty values and empty `rua`/`ruf` list entries now raise a `syntax` warning; malformed tags are discarded as RFC 9989 4.8 requires, with a hint when they look like a known tag.
- TLS-RPT: URIs with whitespace, empty list items or not exactly one `@` are now `tlsrpt_bad_uri`.

Tests: 510 to 13,282 collected. 12,743 frozen corpus cases (6,087 anonymised real records, 2,790 census edge records, 3,866 synthetic mutations), 13 hypothesis property tests, 14 regression tests, plus the existing suite. Rules 2026.10.29.5 (207 rules).

## 1.3.0 (2026-10-29)

- HTML report: `--html FILE`, one self-contained file (no scripts or remote assets) with executive summary, per-provider verdicts, findings with linked sources and suggested fixes; prints to PDF. Optional `--pdf FILE` with `pip install fpdf2`. The GitHub Action now also writes `audit.html` (output `html`).
- Suggested fixes for every fixable finding class: SPF lookup-limit steps (heaviest includes, when flattening is safe), void lookups, `~all`/`?all`/`+all`/no `all`, `ptr`, missing include targets, multiple records; DMARC `p=none` staging, missing `rua`, `t=y`, third-party report authorisation record; DKIM weak-key rotation; MTA-STS policy file and TXT; TLS-RPT; MX CNAME; CAA; DNSSEC; BIMI. New fix types `MX`, `CAA`, `FILE`, `STEPS`.
- New opt-in check `blocklist`: Spamhaus ZEN/DBL, SpamCop, PSBL via DNS, with RFC 5782 test-point probing so a refused resolver is "not tested", never "clean".
- New opt-in check `lookalike`: typo, homoglyph and TLD-swap candidates (max 60), reporting which resolve and which have MX.
- New subcommand `faultypacket-audit headers msg.eml`: Authentication-Results (RFC 8601), ARC (RFC 8617), DKIM-Signature, Received chain, and a DMARC alignment verdict (RFC 9989 3.2.10, 4.4).
- New SPF findings: `spf.all_pass`, `spf.all_neutral`, `spf.all_softfail`, `spf.no_all` (RFC 7208 4.7, 5.1, 8.2, 8.5).
- Tests: 239 to 510, including hypothesis property tests on the SPF, DMARC and header parsers and golden fixtures from RFC 7208 App. A, RFC 9989 App. B and RFC 8601 App. B.
- Rules 2026.10.29.4 (206 rules).

## 1.2.0 (2026-10-29)

- Suggested fixes: each report has a `fixes` list of copy-paste TXT records where the correct record follows from the standard (missing DMARC, RFC 9989 retired tags / invalid `fo` / obsolete `!size`, missing TLS-RPT). Owner-specific values are `REPLACE-` placeholders. Shown in text output, JSON and MCP.
- Release workflow moves the `v1` tag to each new 1.x release.
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
