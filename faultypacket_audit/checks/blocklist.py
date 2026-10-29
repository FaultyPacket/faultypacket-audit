"""DNS blocklist (DNSBL) lookups: MX IPv4 addresses and the domain itself.

Opt-in (``--checks blocklist``): it sends queries to third-party lists.
Each list's RFC 5782 5 test point is queried first; if the list does not
return a 127.0.0.0/8 answer for it (for example Spamhaus returns
127.255.255.254 to queries via large public resolvers), that list is
reported as not tested rather than clean. Results are observations, not
verdicts on deliverability. Free use of these lists is subject to each
operator's terms (``terms`` in the data)."""
import ipaddress

from ._common import mx_hosts, result

NAME = "blocklist"


def _is_listing(vals):
    """RFC 5782 2.1: a listing is an A record in 127.0.0.0/8; Spamhaus uses
    127.255.255.0/24 for error codes, which is never a listing."""
    out = []
    for v in vals:
        try:
            ip = ipaddress.IPv4Address(v)
        except ValueError:
            continue
        if ip in ipaddress.IPv4Network("127.0.0.0/8") and not str(ip).startswith("127.255.255."):
            out.append(str(ip))
    return out


def reverse_ip(ip):
    return ".".join(reversed(ip.split(".")))


def probe(res, zone):
    """-> (usable, detail). Queries the zone's documented test point."""
    name = (reverse_ip(zone["test"]) if zone["type"] == "ip" else zone["test"]) + "." + zone["zone"]
    vals, st = res.query(name, "A")
    if st.startswith("error"):
        return False, f"test point DNS {st}"
    hits = _is_listing(vals)
    if not hits:
        return False, ("test point answered " + ",".join(vals)) if vals else "test point not listed (list unusable from this resolver)"
    return True, "test point " + ",".join(hits)


def check(domain, res, R, options=None):
    zones = R.value("blocklist.zones")
    results = (options or {}).get("results") or {}
    mxdata = results.get("mx") or {}
    ips = []
    if mxdata.get("mx"):
        for r in mxdata["mx"]:
            ips += [a for a in r.get("addresses") or [] if ":" not in a]
    else:
        hosts, _ = mx_hosts(domain, res)
        for _p, h in hosts or []:
            v, _ = res.query(h, "A")
            ips += v
    ips = sorted(set(a for a in ips if _valid4(a)))
    findings, rows = [], []
    for z in zones:
        ok, detail = probe(res, z)
        row = {"zone": z["zone"], "type": z["type"], "terms": z["terms"], "tested": ok, "probe": detail, "listed": []}
        rows.append(row)
        if not ok:
            findings.append(R.finding(NAME, "info", "blocklist.not_tested",
                                      f"{z['zone']} not tested: {detail}", zone=z["zone"]))
            continue
        targets = ips if z["type"] == "ip" else [domain]
        for t in targets:
            q = (reverse_ip(t) if z["type"] == "ip" else t) + "." + z["zone"]
            vals, st = res.query(q, "A")
            hits = _is_listing(vals)
            if hits:
                row["listed"].append({"target": t, "codes": hits})
                rid = "blocklist.listed_ip" if z["type"] == "ip" else "blocklist.listed_domain"
                findings.append(R.finding(NAME, "warning", rid,
                                          f"{t} is listed on {z['zone']} ({','.join(hits)}); see {z['terms']}",
                                          target=t, zone=z["zone"], codes=hits))
    if not ips:
        findings.append(R.finding(NAME, "info", "blocklist.no_ipv4",
                                  "no IPv4 MX addresses to test; IPv6 DNSBLs (RFC 5782 2.4) are not queried"))
    return result(NAME, domain, findings, {"ips": ips, "lists": rows})


def _valid4(a):
    try:
        ipaddress.IPv4Address(a)
        return True
    except ValueError:
        return False
