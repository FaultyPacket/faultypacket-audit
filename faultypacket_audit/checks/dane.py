"""DANE for SMTP (RFC 7672): TLSA at _25._tcp.<mx>, record syntax (RFC 6698
2.1), usages 2/3 only (RFC 7672 3.1), and the DNSSEC dependency: TLSA is
only usable when the MX host's zone validates (RFC 7672 2.2)."""
import re

from ._common import mx_hosts, result

NAME = "dane"
HASHLEN = {0: None, 1: 64, 2: 128}


def check(domain, res, R, options=None):
    F = lambda sev, rid, msg, **e: R.finding(NAME, sev, rid, msg, **e)
    mx, st = mx_hosts(domain, res)
    if mx is None:
        return result(NAME, domain, [F("warning", "dane.dns_error", f"MX lookup failed: {st}")], {})
    qa = getattr(res, "query_ad", None)
    rows, fs = [], []
    for _, host in mx[:10]:
        if host in ("", "."):
            continue
        name = f"_25._tcp.{host}"
        if qa:
            tl, s, ad = qa(name, "TLSA")
        else:
            (tl, s), ad = res.query(name, "TLSA"), False
        row = {"host": host, "tlsa": tl, "validated": ad}
        rows.append(row)
        if s.startswith("error") or not tl:
            continue
        for rr in tl:
            m = re.fullmatch(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f\s]+)", re.sub(r"[()]", " ", rr))
            if not m:
                fs.append(F("error", "dane.syntax", f"{name}: unparseable TLSA {rr!r}")); continue
            u, sel, mt, h = int(m.group(1)), int(m.group(2)), int(m.group(3)), re.sub(r"\s", "", m.group(4))
            if u > 3 or sel > 1 or mt > 2:
                fs.append(F("error", "dane.syntax", f"{name}: TLSA {u} {sel} {mt} has an undefined field value"))
            elif HASHLEN[mt] and len(h) != HASHLEN[mt]:
                fs.append(F("error", "dane.syntax", f"{name}: matching type {mt} needs {HASHLEN[mt]//2} bytes, got {len(h)//2}"))
            if u in (0, 1):
                fs.append(F("warning", "dane.smtp_usage", f"{name}: usage {u} (PKIX) SHOULD NOT be used for SMTP; use 3 (DANE-EE) or 2 (DANE-TA)"))
        if not ad:
            fs.append(F("error", "dane.dnssec_required", f"{name}: TLSA published but not DNSSEC-validated; senders ignore it"))
    if not any(r["tlsa"] for r in rows):
        fs.append(F("info", "dane.absent", "no TLSA records for any MX: DANE not deployed (MTA-STS is the non-DNSSEC alternative)"))
    return result(NAME, domain, fs, {"mx": rows})
