"""Lookalike-domain observations: typo, homoglyph and TLD-swap candidates.

Opt-in (``--checks lookalike``). For each candidate (at most
``lookalike.max_candidates``) it asks DNS for NS, A and MX. A candidate with
NS or A is reported as registered; with MX it can receive mail. These are
observations only: a registered lookalike may be yours, parked, or
unrelated. Nothing here says a domain is malicious."""
from ._common import result

NAME = "lookalike"
HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l"], "m": ["rn"],
              "w": ["vv"], "e": ["3"], "a": ["4"], "s": ["5"], "g": ["q"], "q": ["g"], "b": ["d"], "d": ["b"]}
PAIRS = {"rn": "m", "vv": "w", "cl": "d"}
KEYS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
TLDS = ["com", "co.uk", "uk", "org.uk", "net", "org", "io", "co", "info", "biz", "online", "eu"]


def _adjacent(c):
    for row in KEYS:
        i = row.find(c)
        if i >= 0:
            return [row[j] for j in (i - 1, i + 1) if 0 <= j < len(row)]
    return []


def split(domain, org=None):
    """-> (label, suffix) of the registrable domain."""
    od = org or domain
    label, _, suffix = od.partition(".")
    return label, suffix


def candidates(domain, org=None, limit=60):
    """Deterministic, de-duplicated list of (kind, name), most plausible first."""
    label, suffix = split(domain.lower().rstrip("."), org)
    out, seen = [], {f"{label}.{suffix}"}

    def add(kind, lab, suf=suffix):
        if not lab or lab.startswith("-") or lab.endswith("-") or len(lab) > 63:
            return
        n = f"{lab}.{suf}"
        if n not in seen:
            seen.add(n)
            out.append((kind, n))

    for i, c in enumerate(label):
        for h in HOMOGLYPHS.get(c, []):
            add("homoglyph", label[:i] + h + label[i + 1:])
    for p, r in PAIRS.items():
        j = label.find(p)
        if j >= 0:
            add("homoglyph", label[:j] + r + label[j + len(p):])
    for t in TLDS:
        if t != suffix:
            add("tld-swap", label, t)
    for i in range(len(label)):
        add("omission", label[:i] + label[i + 1:])
    for i in range(len(label) - 1):
        add("transposition", label[:i] + label[i + 1] + label[i] + label[i + 2:])
    for i, c in enumerate(label):
        add("repetition", label[:i] + c + label[i:])
    for i, c in enumerate(label):
        for k in _adjacent(c):
            add("keyboard", label[:i] + k + label[i + 1:])
    for i in range(1, len(label)):
        add("hyphenation", label[:i] + "-" + label[i:])
    return out[:limit]


def check(domain, res, R, options=None):
    limit = int(R.value("lookalike.max_candidates"))
    try:
        from .dmarc import org_domain_psl
        org = org_domain_psl(domain)
    except Exception:
        org = domain
    rows, findings = [], []
    for kind, name in candidates(domain, org, limit):
        ns, st_ns = res.query(name, "NS")
        a, st_a = res.query(name, "A")
        mx, st_mx = res.query(name, "MX")
        reg = bool(ns) or bool(a)
        row = {"name": name, "kind": kind, "registered": reg, "ns": bool(ns), "a": bool(a),
               "mx": [m for m in mx if m.split()[-1] != "."], "errors": [s for s in (st_ns, st_a, st_mx) if s.startswith("error")]}
        rows.append(row)
        if reg:
            findings.append(R.finding(NAME, "info", "lookalike.registered",
                                      f"{name} ({kind}) resolves" + (" and has MX: can receive mail" if row["mx"] else ""),
                                      name=name, kind=kind, mx=bool(row["mx"])))
    return result(NAME, domain, findings, {"org_domain": org, "tested": len(rows),
                                           "registered": sum(r["registered"] for r in rows),
                                           "with_mx": sum(bool(r["mx"]) for r in rows), "candidates": rows})
