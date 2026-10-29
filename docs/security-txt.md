# security-txt (RFC 9116)

Opt-in, because it makes HTTPS requests to the audited host:

```
faultypacket-audit --checks security-txt example.com
```

Fetches `https://<domain>/.well-known/security.txt`, falling back to `/security.txt`
(flagged: RFC 9116 §3), with certificate validation. Checks, each tagged with its section:
location (§3), HTTPS and redirects off-host (§3, §3.1, §5.7), `Content-Type: text/plain; charset=utf-8`
and UTF-8 (§3, §4), `Name: value` syntax and no chained values (§2, §4), Contact present and
https (§2.5.3), Encryption is a URI not a key (§2.5.4), Expires exactly once, RFC 3339,
not passed, under a year (§2.5.5), Canonical lists the retrieval URI (§2.5.2),
Preferred-Languages once with valid tags (§2.5.8), https web URIs in every URI field,
and an OpenPGP cleartext signature (§2.3, info only; the signature itself is not verified).
