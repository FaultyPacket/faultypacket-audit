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
