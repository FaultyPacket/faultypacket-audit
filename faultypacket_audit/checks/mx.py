"""MX sanity: null MX (RFC 7505 3), MX targets that are CNAMEs (RFC 2181 10.3)
or IP literals, and that every target resolves (RFC 5321 5.1)."""
import ipaddress

from ._common import mx_hosts, result

NAME = "mx"


def check(domain, res, R, options=None):
    F = lambda sev, rid, msg, **e: R.finding(NAME, sev, rid, msg, **e)
    mx, st = mx_hosts(domain, res)
    if mx is None:
        return result(NAME, domain, [F("error", "mx.dns_error", f"MX lookup failed: {st}")], {"mx": None})
    fs, rows = [], []
    if not mx:
        a, _ = res.query(domain, "A")
        fs.append(F("info", "mx.none", f"no MX; senders fall back to the A/AAAA of {domain}"
                    + (" (it has one, so mail is attempted there)" if a else " (none either: undeliverable)")))
        return result(NAME, domain, fs, {"mx": [], "null_mx": False})
    nulls = [m for m in mx if m[1] in ("", ".")]
    if nulls:
        if len(mx) > 1:
            fs.append(F("error", "mx.null_mx", "null MX published alongside other MX records; a null MX MUST be the only MX"))
        elif nulls[0][0] != 0:
            fs.append(F("error", "mx.null_mx", f"null MX must have preference 0, got {nulls[0][0]}"))
        else:
            fs.append(F("info", "mx.null_mx", "null MX: this domain declares it accepts no mail"))
        return result(NAME, domain, fs, {"mx": [{"preference": p, "host": h} for p, h in mx], "null_mx": True})
    for pref, host in mx:
        row = {"preference": pref, "host": host, "addresses": [], "cname": None}
        try:
            ipaddress.ip_address(host)
            fs.append(F("error", "mx.ip_literal", f"MX target {host} is an IP address; MX must name a host"))
            rows.append(row); continue
        except ValueError:
            pass
        cn, _ = res.query(host, "CNAME")
        if cn:
            row["cname"] = cn[0].rstrip(".")
            fs.append(F("warning", "mx.cname", f"MX target {host} is an alias (CNAME to {row['cname']}); MX targets must not be aliases"))
        a, sa = res.query(host, "A")
        aaaa, s6 = res.query(host, "AAAA")
        row["addresses"] = a + aaaa
        if not row["addresses"]:
            if sa.startswith("error") or s6.startswith("error"):
                fs.append(F("warning", "mx.dns_error", f"MX target {host}: address lookup failed ({sa}/{s6})"))
            else:
                fs.append(F("error", "mx.unresolvable", f"MX target {host} has no A/AAAA record; mail to it cannot be delivered"))
        rows.append(row)
    if len(mx) > R.value("spf.mx_limit"):
        fs.append(F("warning", "mx.spf_mx_limit", f"{len(mx)} MX hosts; an SPF 'mx' mechanism for this domain is a permerror beyond {R.value('spf.mx_limit')}"))
    return result(NAME, domain, fs, {"mx": rows, "null_mx": False})
