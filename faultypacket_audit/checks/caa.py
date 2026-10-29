"""CAA (RFC 8659): relevant RRset by climbing the tree (3), property syntax (4.1),
issue/issuewild/iodef (4.2-4.4), unknown critical properties (4.5).
CAA governs who may issue certificates, including for mta-sts.<domain>."""
import re

from ._common import result

NAME = "caa"
KNOWN = ("issue", "issuewild", "iodef")


def relevant(domain, res):
    labels = domain.rstrip(".").split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        v, st = res.query(name, "CAA")
        if st.startswith("error"):
            return name, None, st
        if v:
            return name, v, st
    return None, [], "void"


def parse(rr):
    m = re.fullmatch(r'\s*(\d+)\s+([A-Za-z0-9]+)\s+"?(.*?)"?\s*', rr)
    if not m:
        return None
    return int(m.group(1)), m.group(2), m.group(3)


def check(domain, res, R, options=None):
    F = lambda sev, rid, msg, **e: R.finding(NAME, sev, rid, msg, **e)
    at, rrs, st = relevant(domain, res)
    if rrs is None:
        return result(NAME, domain, [F("warning", "caa.dns_error", f"CAA lookup at {at} failed: {st}; CAs must refuse to issue on lookup failure")], {})
    if not rrs:
        return result(NAME, domain, [F("info", "caa.absent", "no CAA records up the tree: any public CA may issue certificates for this domain")],
                      {"at": None, "records": []})
    fs, parsed = [], []
    for rr in rrs:
        p = parse(rr)
        if not p:
            fs.append(F("error", "caa.syntax", f"unparseable CAA record {rr!r}")); continue
        flags, tag, val = p
        parsed.append({"flags": flags, "tag": tag, "value": val})
        if tag.lower() not in KNOWN:
            if flags & 128:
                fs.append(F("error", "caa.critical_unknown", f"unknown property {tag!r} has the critical flag: CAs MUST NOT issue at all"))
            continue
        if tag != tag.lower():
            fs.append(F("info", "caa.tags", f"property tag {tag!r}: tags are matched case-insensitively but lower case is canonical"))
        if tag.lower() == "iodef" and not re.match(r"^(mailto:|https?://)", val):
            fs.append(F("error", "caa.iodef", f"iodef value {val!r} must be a mailto: or http(s) URL"))
    issuers = [p["value"].split(";")[0].strip() for p in parsed if p["tag"].lower() == "issue"]
    if parsed and not issuers and not any(p["tag"].lower() == "issuewild" for p in parsed):
        fs.append(F("info", "caa.no_issue", "CAA set has no issue/issuewild property, so it restricts no CA"))
    if at != domain:
        fs.append(F("info", "caa.inherited", f"CAA inherited from {at}"))
    return result(NAME, domain, fs, {"at": at, "records": parsed, "issuers": issuers})
