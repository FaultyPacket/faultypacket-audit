"""Small shared helpers for the DNS checks."""


def tags(record):
    """DKIM-style tag=value list (RFC 6376 3.2) -> ordered dict, lower-case names.
    Duplicate names: first wins, duplicates listed under '__dup__'."""
    out, dup = {}, []
    for part in record.split(";"):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip().lower(), "".join(v.split())
        if k in out:
            dup.append(k)
            continue
        out[k] = v
    if dup:
        out["__dup__"] = dup
    return out


def mx_hosts(domain, res):
    """-> (list of (pref, host) or None on DNS error, status)."""
    vals, st = res.query(domain, "MX")
    if st.startswith("error"):
        return None, st
    out = []
    for v in vals:
        p = v.split()
        if len(p) == 2 and p[0].isdigit():
            out.append((int(p[0]), p[1].lower().rstrip(".")))
    return sorted(out), st


def result(name, domain, findings, data):
    return {"check": name, "domain": domain, "findings": findings, "data": data}
