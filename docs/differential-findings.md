# Differential testing findings (v1.4.0)

## Method

- **Inputs.** SPF, DMARC, MTA-STS and TLS-RPT records were fetched over DNS-over-HTTPS for the Tranco top 4,000 domains plus 369 UK council domains. We added the edge-record file from the FaultyPacket census (6,574,611 domains scanned as of 29 Oct 2026) and synthetic mutations of both sets (`maint/corpus/mutate.py`).
- **Anonymisation** (`maint/corpus/anonymise.py`) is applied before anything is committed:
  - host names become `hXXXXXX.example`;
  - mail and report addresses become `reports@example.org`;
  - IPv4 addresses move into 198.18.0.0/15 and IPv6 addresses into 2001:db8::/32;
  - verification tokens are redacted, and long alphanumeric runs are hashed.
  
  Edge records containing non-ASCII text are dropped, because mis-decoded text can split a name past the anonymiser. The raw scan is not in the repository.
- **Oracle.** We used [checkdmarc](https://github.com/domainaware/checkdmarc) 6.0.4 (Sean Whalen, Apache-2.0) as an independent reference implementation, run offline against the same fake zone (`maint/corpus/oracle.py`). Our thanks to its authors.
- **What gets frozen.** Where both tools agree on validity, the record and our result are frozen as a golden case. Where they disagree, each case was decided against RFC 9989, 7208, 8461 and 8460 (`maint/corpus/classify.py`, `tests/corpus/reviewed.json`):
  - our bugs were fixed and gained a regression test;
  - cases where we already follow the RFC are frozen with the RFC reason;
  - cases the RFCs do not decide are left out.
- **Deduplication.** No two cases share the same normalised (record, expected) pair, and a test enforces this.

## Numbers

12,743 frozen cases:

| Source | Cases |
| --- | --- |
| Real records | 6,087 |
| Census edge records | 2,790 |
| Mutations | 3,866 |

There were 1,130 disagreements:

- 644 are frozen as RFC-reviewed;
- 485 are duplicate DMARC tags, which are not frozen;
- 1 is unreviewed and not frozen.

## Bugs fixed in faultypacket-audit

1. **SPF: terms after `all` were counted towards the lookup limit.** RFC 7208 5.1 says mechanisms after `all` will never be tested and MUST be ignored. They are now syntax-checked only, and we report the info finding `spf.after_all`.
2. **SPF: qualified modifiers were accepted.** An example is `-allgoogle-site-verification=...`, which comes from TXT strings joined with no space. Under the RFC 7208 12 ABNF a modifier has no qualifier, so this is a permerror. In practice such records have no `all` at all.
3. **DMARC: report URIs containing whitespace were accepted.** An example is `ruf=mailto:x@example.org fo=1`, where a missing `;` swallows the next tag. Such a value is not an RFC 3986 URI.
4. **DMARC: some malformed syntax passed silently.** This covered control characters, empty tags (`;;`), non-alphabetic tag names (`+p=`, `p ct=`, `pct-=`), empty values and empty `rua` list entries. These are now `syntax` warnings. Malformed tags are discarded (RFC 9989 4.8), with a hint when the tag looks like a known one. For example, a record whose only policy tag is `+p=reject` has no policy.
5. **TLS-RPT: some bad report URIs were accepted.** This covered URIs with whitespace, empty list items, or a `mailto:` without exactly one `@` (RFC 8460 3).

## Disagreements where we follow the RFC text

These are frozen as `rfc-reviewed`.

### DMARC

| Case | RFC 9989 basis |
| --- | --- |
| `fo=0:1`: one value only | `dmarc-fo` (4.8) |
| Out-of-range values such as `adkim=strict` or `aspf=s.` are flagged | 4.8 Table 2 |
| Tags with syntax errors are discarded, but the record still applies | 4.8 |
| Unknown tags are ignored, and the record still applies | 4.7 and 4.8 |
| Report URIs with no scheme or an unsupported scheme (`ruf=afrf`, `rua=reports@...`) are ignored, and the record still applies | 4.6 |
| A malformed `pct` cannot invalidate a record | 9.3: `pct` is historic |
| A literal `"` before `v=DMARC1` means the record is not DMARC | 4.7 |

### SPF

| Case | RFC 7208 basis |
| --- | --- |
| `v=SPF1` and `V=spf1` are valid | 4.5: ABNF literals are case-insensitive |
| `v=spf1-all` is not an SPF record | 4.5: the version ends at SP or end of record |
| A line break inside the record joins terms into a syntax error | 12 |
| A syntax error or unknown term after `all` is still a permerror; this includes modifier names starting with `_` | 4.6 |
| `mx:a` is invalid | 7.1: `domain-end` needs a dot and a top label |
| `ptr` void lookups depend on the sender IP, so they are not counted statically | 5.5 |

## Not decided by the RFCs

- **Duplicate DMARC tags.** RFC 9989 does not say what a receiver should do. We warn and use the first occurrence; checkdmarc rejects the record. These cases are excluded from the corpus.
