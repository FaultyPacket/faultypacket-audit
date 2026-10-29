# `faultypacket-audit reports`: DMARC and TLS-RPT report reader

Reads DMARC aggregate reports (RFC 7489 7.2 and Appendix C; RFC 9990) and SMTP TLS reports (RFC 8460 4) on your machine. Nothing is uploaded and no network access is used.

```
faultypacket-audit reports google.com!example.com!1798675200!1798761599.zip report.xml.gz tlsrpt.json
faultypacket-audit reports *.zip --format json -o summary.json
faultypacket-audit reports *.gz --fail-on-unauthorised   # exit 1 if a source never passed DMARC
```

Accepted: `.xml`, `.gz`, `.zip` (every member), `.json`. Format is detected from content, not the file name.

Output (Markdown by default, or `--format json`):

- per sending domain (header From) and per source IP: messages, SPF pass, DKIM pass, aligned (DMARC pass) and fail counts, quarantined and rejected;
- failing senders: sources with any DMARC-failing messages; **unauthorised** marks those that never passed;
- TLS-RPT: successful and failed sessions per policy domain, with failure result types.

SPF/DKIM "pass" counts are the raw `auth_results`; "aligned" is the receiver's `policy_evaluated` verdict, which is what DMARC uses.

Safety: DTDs and entity declarations are refused (no XXE or entity expansion), and each decompressed report is capped at 64 MiB.

## Report conformance (RFC 9990, RFC 8460, RFC 9991)

Each report is checked against the rules for its format. Problems are listed under "Report conformance" and in the JSON `conformance` array. Each entry has a severity, a `rpt.*` rule id and the RFC section. These problems are the report generator's fault, not yours, but a report that breaks a MUST may be unreliable, so read its numbers with care. `--fail-on-nonconformant` exits 1 if any report has a conformance error.

You can pass whole report emails (`.eml`) as well as attachments. The email-level checks are:

- the Subject ABNF;
- the attachment media type and filename;
- the `TLS-Report-Domain` and `TLS-Report-Submitter` headers (RFC 8460 5.3);
- that a DKIM signature from the reporting domain is present (RFC 8460 3). This checks the d= domain only, not the signature itself;
- whether the report message failed DMARC itself.

A filename that doesn't match the ABNF is only `info` when you pass a local file, because you may have renamed it. It is a `warning` when the file came from an email attachment.

RFC 9991 failure reports (`multipart/report; report-type=feedback-report`) are summarised in their own table: source IP, From domain, which methods failed alignment, the delivery result and the DKIM d=/s=. They are also checked for the REQUIRED ARF fields.
