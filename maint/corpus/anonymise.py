"""Build the anonymised differential-testing corpus from a private DNS scan.

Input (never committed): a JSON scan of public TXT/MX/A/AAAA answers.
Output: tests/corpus/real.jsonl (one TXT record per line, by kind) and
tests/corpus/zone.json (the anonymised answers SPF expansion needs).

Every hostname is replaced by a stable pseudonym under .example, every e-mail
address by reports@example.org, every IPv4 address by one in 198.18.0.0/15
(RFC 2544 benchmarking space) and every IPv6 address by one in 2001:db8::/32,
so record structure, lookup counts and syntax faults survive but nobody is
identifiable.  Usage: python maint/corpus/anonymise.py RAW.json
       python maint/corpus/anonymise.py --edge edge_records.jsonl
"""
import hashlib, ipaddress, json, pathlib, re, sys

OUT = pathlib.Path(__file__).resolve().parents[2] / "tests" / "corpus"
EMAIL = re.compile(r"[A-Za-z0-9._%+!#$&'*/=?^`{|}~-]+@[A-Za-z0-9_.-]+")
HOST = re.compile(r"(?<![A-Za-z0-9_%{}-])((?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z][A-Za-z0-9-]*[A-Za-z0-9])\.?(?![A-Za-z0-9_-])")
KEEP = {"example.org", "example.com", "example.net"}


def h(s, n=6):
    return hashlib.sha256(s.lower().encode()).hexdigest()[:n]


def anon_host(name):
    name = name.lower().rstrip(".")
    if name in KEEP or name.endswith(".example"):
        return name
    labels = name.split(".")
    pre = [l for l in labels[:-2] if l.startswith("_")]  # keep _spf, _dmarc, _domainkey shape
    return ".".join(pre + ["h" + h(name)]) + ".example"


def anon_ip4(s):
    try:
        ipaddress.IPv4Address(s)
    except ValueError:
        return s
    x = int(h(s, 4), 16)
    return f"198.{18 + (x >> 15) % 2}.{(x >> 8) % 128}.{x % 256}"


def anon_ip6(s):
    try:
        ipaddress.IPv6Address(s)
    except ValueError:
        return s
    return str(ipaddress.IPv6Address("2001:db8::") + int(h(s, 12), 16))


def anon_text(t):
    t = re.sub(r"(?i)([A-Za-z0-9_-]*(?:verification|verify|validation|site-key)[A-Za-z0-9_-]*)=[^\s;\"\\]+", r"\1=redacted", t)
    t = EMAIL.sub(lambda m: "reports@example.org", t)
    t = re.sub(r"(?i)(https://)([^/;,\s!]+)", lambda m: m.group(1) + "reports.example.org", t)
    t = re.sub(r"(?i)\b(ip4:)([0-9.]+)", lambda m: m.group(1) + anon_ip4(m.group(2)), t)
    t = re.sub(r"(?i)\b(ip6:)([0-9a-f:.]+?)(?=/|\s|$)", lambda m: m.group(1) + anon_ip6(m.group(2)), t)
    t = re.sub(r"[A-Za-z0-9]{20,}", lambda m: (hashlib.sha256(m.group(0).encode()).hexdigest() * 2)[:len(m.group(0))], t)
    return HOST.sub(lambda m: m.group(0) if m.group(1).lower() in ("reports.example.org",) or
                    m.group(1)[0].isdigit() and re.fullmatch(r"[0-9.]+", m.group(1)) else anon_host(m.group(1)) +
                    ("." if m.group(0).endswith(".") else ""), t)


def kind(name, txt):
    l = txt.lstrip().lower()
    if name.startswith("_dmarc.") and l.startswith("v") and "dmarc" in l[:12]:
        return "dmarc"
    if name.startswith("_mta-sts.") and "sts" in l[:12]:
        return "mtasts"
    if name.startswith("_smtp._tls.") and "tlsrpt" in l[:14]:
        return "tlsrpt"
    if not name.startswith("_") and l.startswith("v=spf1"):
        return "spf"
    return None


def unescape(x):
    """DNS presentation escapes (\\DDD, \\X) from DoH answers -> raw characters."""
    return re.sub(r"\\(\d{3}|.)", lambda m: chr(int(m.group(1))) if m.group(1).isdigit() else m.group(1), x)


def main(raw):
    d = json.load(open(raw))
    for row in d["cache"]:
        if row[1] == "TXT":
            row[2] = [x for x in (unescape(y) for y in row[2]) if x.isascii()]  # drop mis-decoded text
    zone, real = {}, {}
    for name, rt, vals, st in d["cache"]:
        an = anon_host(name)
        if rt == "TXT":
            v = [anon_text(x) for x in vals if x.lower().lstrip().startswith("v=spf1")]
            for x, orig in zip([anon_text(y) for y in vals], vals):
                k = kind(name, orig)
                if k and name.split(".", 1)[-1] != "":
                    apex = re.sub(r"^(_dmarc|_mta-sts|_smtp\._tls)\.", "", name.lower())
                    real.setdefault((k, x), anon_host(apex))
        elif rt == "MX":
            v = [anon_text(x) for x in vals]
        elif rt == "A":
            v = [anon_ip4(x) for x in vals]
        else:
            v = [anon_ip6(x) for x in vals]
        if st == "ok" and v:
            zone[f"{an}|{rt}"] = v
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "real.jsonl", "w") as f:
        for (k, x), dom in sorted(real.items()):
            f.write(json.dumps({"kind": k, "record": x, "domain": dom}) + "\n")
    json.dump(dict(sorted(zone.items())), open(OUT / "zone.json", "w"), indent=0)
    print(len(real), "unique real records;", len(zone), "zone entries")




def edge(path):
    """Census edge records (faultypacket-site ops/census/edge_records.jsonl, already
    anonymised upstream) -> tests/corpus/edge.jsonl, re-anonymised with the same scheme."""
    seen = set()
    with open(OUT / "edge.jsonl", "w") as f:
        for line in open(path):
            j = json.loads(line)
            k = {"DMARC": "dmarc", "SPF": "spf", "MTA-STS": "mtasts", "TLS-RPT": "tlsrpt"}.get(j["type"])
            if not k:
                continue
            if not unescape(j["record"]).isascii():
                continue  # non-ASCII (zero-width / mis-decoded) text can split names past anonymisation
            rec = anon_text(unescape(j["record"]))
            if (k, rec) in seen:
                continue
            seen.add((k, rec))
            f.write(json.dumps({"kind": k, "record": rec, "domain": "subject.example"}) + "\n")
    print(len(seen), "census edge records")


if __name__ == "__main__":
    if sys.argv[1] == "--edge":
        edge(sys.argv[2])
    else:
        main(sys.argv[1])
