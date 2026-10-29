"""SPF drift: compare a flattened SPF record's ip4/ip6 terms with what its
source includes resolve to now (RFC 7208 5.2, 5.3, 5.4, 5.6, 6.1).

``faultypacket-audit spf-drift DOMAIN --include _spf.example.org [...]``
"""
import ipaddress, json, re, sys

DUAL = re.compile(r"(?:/(\d{1,2}))?(?://(\d{1,3}))?$")
MAX_DEPTH = 10  # RFC 7208 4.6.4 lookup limit is a sane recursion bound


class Expander:
    def __init__(self, res):
        self.res, self.errors, self.lookups = res, [], 0

    def spf(self, domain):
        vals, st = self.res.query(domain, "TXT")
        recs = [v for v in vals if v.lower() == "v=spf1" or v.lower().startswith("v=spf1 ")]
        if st != "ok" or len(recs) != 1:
            self.errors.append({"domain": domain, "error": st if st != "ok" else f"{len(recs)} SPF records"})
            return None
        return recs[0]

    def _addrs(self, name, cidr4, cidr6):
        out = []
        for rt, c in (("A", cidr4), ("AAAA", cidr6)):
            vals, st = self.res.query(name, rt)
            if st.startswith("error"):
                self.errors.append({"domain": name, "error": st})
            for v in vals:
                try:
                    out.append(ipaddress.ip_network(f"{v}/{c}", strict=False))
                except ValueError:
                    pass
        return out

    def expand(self, domain, stack=()):
        """-> list of networks the domain's SPF authorises with a pass qualifier."""
        domain = domain.lower().rstrip(".")
        if domain in stack or len(stack) > MAX_DEPTH:
            self.errors.append({"domain": domain, "error": "loop or too deep"})
            return []
        rec = self.spf(domain)
        return [] if rec is None else self.terms(rec, domain, stack + (domain,))

    def terms(self, rec, domain, stack=()):
        nets, redirect, seen_all = [], None, False
        for t in rec.split()[1:]:
            q = t[0] if t[0] in "+-~?" else "+"
            body = t[1:] if t[0] in "+-~?" else t
            low = body.lower()
            if low.startswith("redirect="):
                redirect = body.split("=", 1)[1]
                continue
            if "=" in low.split(":", 1)[0] or seen_all:
                continue
            if low == "all":
                seen_all = True
                continue
            if q != "+":
                continue
            mech, _, arg = body.partition(":")
            mech = mech.lower()
            cidr4, cidr6 = 32, 128
            if mech.split("/")[0] in ("a", "mx"):
                m = DUAL.search(arg or mech)
                if m:
                    cidr4 = int(m.group(1)) if m.group(1) else 32
                    cidr6 = int(m.group(2)) if m.group(2) else 128
                    if arg:
                        arg = arg[:m.start()]
                    else:
                        mech = mech[:m.start()]
            if mech in ("ip4", "ip6"):
                try:
                    n = ipaddress.ip_network(arg, strict=False)
                    if n.version != int(mech[2]):
                        raise ValueError
                    nets.append(n)
                except ValueError:
                    self.errors.append({"domain": domain, "error": f"bad {t}"})
            elif mech == "include":
                nets += self.expand(arg, stack)
            elif mech == "a":
                nets += self._addrs(arg or domain, cidr4, cidr6)
            elif mech == "mx":
                mxs, _ = self.res.query(arg or domain, "MX")
                for m in mxs[:10]:
                    nets += self._addrs(m.split()[-1].rstrip("."), cidr4, cidr6)
        if redirect and not seen_all:
            nets += self.expand(redirect, stack)
        return nets


def _collapse(nets):
    out = []
    for v in (4, 6):
        out += list(ipaddress.collapse_addresses([n for n in nets if n.version == v]))
    return out


def _uncovered(a, b):
    """Parts of networks in a not covered by any network in b."""
    left = _collapse(a)
    for n in _collapse(b):
        nxt = []
        for x in left:
            if x.version != n.version or not x.overlaps(n):
                nxt.append(x)
            elif not x.subnet_of(n):
                nxt += list(x.address_exclude(n))
        left = nxt
    return [str(n) for n in _collapse(left)]


def flattened_nets(record):
    out = []
    for t in record.split()[1:]:
        q = t[0] if t[0] in "+-~?" else "+"
        body = (t[1:] if t[0] in "+-~?" else t)
        if q == "+" and body.lower().startswith(("ip4:", "ip6:")):
            try:
                out.append(ipaddress.ip_network(body.split(":", 1)[1], strict=False))
            except ValueError:
                pass
    return out


def drift(record, includes, res):
    ex = Expander(res)
    expected = []
    for inc in includes:
        expected += ex.expand(inc)
    have = flattened_nets(record)
    missing, extra = _uncovered(expected, have), _uncovered(have, expected)
    return {"record": record, "includes": list(includes), "missing": missing, "extra": extra,
            "errors": ex.errors, "status": "error" if ex.errors else ("drift" if missing or extra else "ok")}


def main(argv, stdin=None, stdout=None, stderr=None, res=None):
    import argparse
    from .core.resolver import Resolver, DEFAULT_DOH
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    p = argparse.ArgumentParser(prog="faultypacket-audit spf-drift",
                                description="Compare a flattened SPF record with the current resolution of its source includes.")
    p.add_argument("domain", nargs="?", help="domain whose published SPF is the flattened record")
    p.add_argument("--record", help="flattened SPF record to check instead of the published one")
    p.add_argument("--include", action="append", default=[], required=True, help="source include the record was flattened from; repeatable")
    p.add_argument("--json", action="store_true")
    p.add_argument("--doh", action="store_true")
    p.add_argument("--doh-url", default=DEFAULT_DOH)
    p.add_argument("--resolver")
    a = p.parse_args(argv)
    if not a.domain and not a.record:
        p.error("give a domain or --record")
    res = res or Resolver(a.resolver, 5.0, a.doh_url if a.doh else None)
    rec = a.record
    if not rec:
        rec = Expander(res).spf(a.domain)
        if rec is None:
            print(f"{a.domain}: no single SPF record", file=stderr)
            return 2
    r = drift(rec, a.include, res)
    if a.json:
        print(json.dumps(r, indent=2), file=stdout)
    else:
        print(f"SPF drift: {r['status']}", file=stdout)
        for k, lbl in (("missing", "missing from flattened record (senders would fail SPF)"),
                       ("extra", "in flattened record but no longer published by the includes")):
            for n in r[k]:
                print(f"  {lbl}: {n}", file=stdout)
        for e in r["errors"]:
            print(f"  lookup problem: {e['domain']}: {e['error']}", file=stdout)
    return 0 if r["status"] == "ok" else 1
