"""Differential oracle: run every corpus record through faultypacket-audit and,
independently, through checkdmarc (https://github.com/domainaware/checkdmarc,
used here as the reference oracle - with thanks), entirely offline against the
anonymised fake zone.  Records where both agree on the comparable verdicts are
frozen as golden cases in tests/corpus/cases.jsonl; disagreements go to
tests/corpus/disagreements.jsonl for review against the RFC text.

Usage: python maint/corpus/oracle.py   (needs: pip install checkdmarc)
"""
import json, pathlib, re, sys
import dns.rdata, dns.rdataclass, dns.rdatatype, dns.resolver, dns.name

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from faultypacket_audit.checks import dmarc as D, spf as S
from faultypacket_audit.checks import _mtasts_engine as M

CORPUS = ROOT / "tests" / "corpus"
APEX = "subject.example"
REVIEWED = CORPUS / "reviewed.json"   # disagreements resolved by hand against the RFC


class FakeZone:
    """faultypacket-audit resolver interface over the anonymised zone."""
    servers = ["fake"]

    def __init__(self, base, overlay):
        self.base, self.overlay = base, overlay

    def get(self, name, rtype):
        k = f"{name.lower().rstrip('.')}|{rtype}"
        return self.overlay.get(k, self.base.get(k))

    def query(self, name, rtype):
        v = self.get(name, rtype)
        return (list(v), "ok") if v else ([], "void")

    def query_ad(self, name, rtype):
        v, st = self.query(name, rtype)
        return v, st, False


def ours(kind, rec, base, apex=APEX):
    if kind == "dmarc":
        tags, issues = D.validate(rec)
        codes = sorted({c for _, c, _ in issues})
        valid = not any(s == "error" for s, _, _ in issues)
        p = (tags.get("p") or "none").lower()  # RFC 9989 4.7: absent p is treated as none
        return {"valid": valid, "policy": p if valid else None, "codes": codes}
    if kind == "spf":
        z = FakeZone(base, {f"{apex}|TXT": [rec]})
        r = S.analyse(apex, z)
        codes = sorted({i["code"] for i in r["issues"]})
        return {"valid": r["result"] != "permerror", "lookups": r["lookups"],
                "verdict": r["result"], "codes": codes}
    if kind == "mtasts":
        z = FakeZone(base, {f"_mta-sts.{APEX}|TXT": [rec]})
        r = M.check_txt(APEX, z)
        codes = sorted({i["code"] for i in r["issues"]})
        return {"valid": not codes, "codes": codes}
    if kind == "tlsrpt":
        z = FakeZone(base, {f"_smtp._tls.{APEX}|TXT": [rec]})
        r = M.check_tlsrpt(APEX, z)
        codes = sorted({i["code"] for i in r["issues"]})
        return {"valid": not any(i["severity"] == "error" for i in r["issues"]) and r["record"] is not None,
                "codes": codes}
    raise ValueError(kind)


# ------------------------------------------------------------- checkdmarc side
_CUR = {}


def _fake_resolve(domain, record_type, **kw):
    name = str(domain).lower().rstrip(".")
    rt = record_type.upper()
    v = _CUR["zone"].get(name, rt)
    if name == "example.org" and rt == "MX":
        v = ["10 mx.example.org."]
    if not v:
        if any(_CUR["zone"].get(name, t) for t in ("TXT", "MX", "A", "AAAA")):
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NXDOMAIN()
    out = []
    for x in v:
        if rt == "TXT":
            chunks = [x[i:i + 255] for i in range(0, len(x.encode()), 255)] or [""]
            txt = " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)
            out.append(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, txt))
        else:
            out.append(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rt), x,
                                           origin=dns.name.root))
    return out


def install_checkdmarc():
    import checkdmarc.utils as U
    U._resolve_with_failover = _fake_resolve
    return U


def theirs(kind, rec, base, apex=APEX):
    import checkdmarc.utils as U
    import checkdmarc.dmarc as CD, checkdmarc.spf as CS
    import checkdmarc.mta_sts as CM, checkdmarc.smtp_tls_reporting as CT
    U.DNS_CACHE.clear() if hasattr(U.DNS_CACHE, "clear") else None
    try:
        if kind == "dmarc":
            _CUR["zone"] = FakeZone(base, {})
            r = CD.parse_dmarc_record(rec, "example.org")
            p = r["tags"]["p"]["value"] if "p" in r["tags"] else None
            return {"valid": True, "policy": p and p.lower()}
        if kind == "spf":
            _CUR["zone"] = FakeZone(base, {f"{apex}|TXT": [rec]})
            r = CS.parse_spf_record(rec, apex)
            return {"valid": True, "lookups": r["dns_lookups"]}
        if kind == "mtasts":
            CM.parse_mta_sts_record(rec)
            return {"valid": True}
        if kind == "tlsrpt":
            CT.parse_smtp_tls_reporting_record(rec)
            return {"valid": True}
    except Exception as e:  # checkdmarc reports invalid records by raising
        return {"valid": False, "error": type(e).__name__, "detail": str(e)[:200]}


def compare(kind, o, t):
    """-> list of differing comparable fields."""
    diff = []
    if o["valid"] != t["valid"]:
        diff.append("valid")
    elif o["valid"] and kind == "dmarc" and o["policy"] != t["policy"]:
        diff.append("policy")
    elif o["valid"] and kind == "spf" and o["lookups"] != t["lookups"]:
        diff.append("lookups")
    return diff


def load_inputs():
    seen, out = set(), []
    for fn, origin in (("real.jsonl", "real"), ("edge.jsonl", "census-edge"), ("mutations.jsonl", "mutation")):
        p = CORPUS / fn
        if not p.exists():
            continue
        for line in open(p):
            j = json.loads(line)
            key = (j["kind"], j["record"])
            if key in seen or not j["record"].strip():
                continue
            seen.add(key)
            out.append(dict(j, origin=j.get("origin", origin)))
    return out


def main():
    base = json.load(open(CORPUS / "zone.json"))
    install_checkdmarc()
    reviewed = json.load(open(REVIEWED)) if REVIEWED.exists() else {}
    cases, dis, keys = [], [], set()
    for j in load_inputs():
        k, rec = j["kind"], j["record"]
        apex = j.get("domain") or APEX
        o = ours(k, rec, base, apex)
        t = theirs(k, rec, base, apex)
        d = compare(k, o, t)
        rid = f"{k}:{rec}"
        status = "agree" if not d else reviewed.get(rid, {}).get("verdict")
        row = {"kind": k, "record": rec, "domain": apex, "origin": j["origin"], "expected": o}
        dedupe = (k, re.sub(r"\s+", " ", rec.strip()), json.dumps(o, sort_keys=True))
        if dedupe in keys:
            continue
        keys.add(dedupe)
        if status in ("agree", "ours-correct", "fixed"):
            row["oracle"] = "agree" if status == "agree" else "rfc-reviewed"
            cases.append(row)
        if d:
            dis.append({"kind": k, "record": rec, "origin": j["origin"], "fields": d,
                        "ours": o, "checkdmarc": t, "review": reviewed.get(rid)})
    with open(CORPUS / "cases.jsonl", "w") as f:
        for c in cases:
            f.write(json.dumps(c, sort_keys=True) + "\n")
    with open(CORPUS / "disagreements.jsonl", "w") as f:
        for x in dis:
            f.write(json.dumps(x, sort_keys=True) + "\n")
    import collections
    print("cases", len(cases), collections.Counter((c["kind"], c["origin"]) for c in cases))
    print("disagreements", len(dis), collections.Counter((x["kind"], tuple(x["fields"]), x["checkdmarc"].get("error")) for x in dis).most_common(40))


if __name__ == "__main__":
    main()
