# SPF drift: `faultypacket-audit spf-drift`

If you flattened an SPF record (replaced `include:` terms with the `ip4:`/`ip6:` they resolved to), providers can change their ranges and the copy goes stale. This compares the flattened record's pass-qualified `ip4`/`ip6` terms with what the source includes resolve to now (following `include`, `redirect`, `a` and `mx`, RFC 7208 5.2-5.6, 6.1).

```
faultypacket-audit spf-drift example.com --include _spf.example.org --include _spf.example.net
faultypacket-audit spf-drift --record "v=spf1 ip4:192.0.2.0/24 -all" --include _spf.example.org --json
```

- **missing**: addresses the includes now authorise that the flattened record does not (that mail would fail SPF).
- **extra**: addresses in the flattened record the includes no longer publish (over-authorisation).
- Ranges are compared as address sets, so `192.0.2.0/24` equals two `/25`s.
- Exit 0 = no drift, 1 = drift or lookup problem, 2 = no SPF record found. Add it to a daily job next to `alert`.
