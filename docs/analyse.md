# `analyse`: header analysis with DKIM re-verification

```
faultypacket-audit analyse message.eml          # re-verifies every DKIM-Signature
faultypacket-audit headers --verify message.eml # same, from the headers command
```

`analyse` is `headers` with `--verify` switched on. It re-verifies each
`DKIM-Signature` (RFC 6376 §6) locally rather than trusting Authentication-Results:

* simple and relaxed canonicalisation for headers and body (§3.4), l= (§3.4.5, warned per §8.2);
* `h=` selection bottom-up, with unmatched names treated as null headers (§5.4.2); From must be signed (§5.4);
* `i=` must be within `d=` (§3.5) and in `d=` exactly when the key has `t=s` (§3.6.1);
* key-record `h=`, `s=`, `k=`, revoked keys (empty `p=`), and multiple TXT records (§3.6.2.2);
* `t=` / `x=` (§3.5); rsa-sha1 refused and RSA keys under 1024 bits rejected (RFC 8301 §3.1, §3.2);
* ed25519-sha256 (RFC 8463).

Each finding has a rule id (`dkim.sig_*`, `dkim.key_syntax`) and an RFC section.
Verified signatures are checked for DMARC alignment against the From domain. When the
message has no Authentication-Results, the verdict comes from the verified signatures.

Keys come from DNS (DoH when `--doh` is given). Verification needs the optional
`crypto` extra (`pip install faultypacket-audit[crypto]`).
