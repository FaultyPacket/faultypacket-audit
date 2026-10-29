"""Bulk-sender verdict: which of the large mailbox providers' published sender
requirements can be checked from DNS, and whether this domain meets them.

It is honest about scope. Every requirement row in rules.json (check
"bulk-sender") is reported as one of:
  pass | fail | unknown (needs input: sending IPs or DKIM selectors) |
  not-dns-verifiable (alignment, one-click unsubscribe, spam rate, TLS ...)
A provider verdict is "fail" if any checkable row fails, "dns-checks-pass"
only if every DNS-checkable row passed, otherwise "incomplete".
Never prints.
"""
import ipaddress

from . import dkim as dkim_check, dmarc as dmarc_check, spf as spf_check

NAME = "bulk-sender"
POLICIES = ("none", "quarantine", "reject")


def dkim_status(domain, res, selectors):
    """-> ("pass"|"fail"|"unknown", detail). RFC 6376 3.6.2.1 key location;
    an empty p= means revoked (3.6.1)."""
    if not selectors:
        return "unknown", "no DKIM selector given"
    seen = []
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txts, st = res.query(name, "TXT")
        if st.startswith("error"):
            seen.append(f"{name}: {st}")
            continue
        for t in txts:
            tags = dict((k.strip().lower(), v.strip()) for k, _, v in
                        (p.partition("=") for p in t.split(";") if "=" in p))
            if tags.get("p"):
                return "pass", f"key published at {name}"
        seen.append(f"{name}: no usable key" + (" (revoked: empty p=)" if any("p=" in t.replace(" ", "") for t in txts) else ""))
    if all(": error" in s for s in seen):
        return "unknown", "; ".join(seen)
    return "fail", "; ".join(seen)


def fcrdns(ip, res):
    """Forward-confirmed reverse DNS for one IP -> ("pass"|"fail"|"unknown", detail)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown", f"{ip!r} is not an IP address"
    ptrs, st = res.query(addr.reverse_pointer, "PTR")
    if st.startswith("error"):
        return "unknown", f"PTR {ip}: {st}"
    if not ptrs:
        return "fail", f"{ip} has no PTR record"
    rtype = "A" if addr.version == 4 else "AAAA"
    for name in ptrs:
        vals, st2 = res.query(name.rstrip("."), rtype)
        if any(ipaddress.ip_address(v) == addr for v in vals if _is_ip(v)):
            return "pass", f"{ip} -> {name.rstrip('.')} -> {ip}"
    return "fail", f"{ip} PTR {', '.join(p.rstrip('.') for p in ptrs)} does not resolve back to {ip}"


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def dmarc_status(d):
    """From DMARC check data: a valid policy (any p) applies to the domain?"""
    if not d.get("policy_source"):
        return "fail", "no DMARC policy applies to this domain (RFC 9989 4.10.1)"
    if d.get("record"):
        p = (d.get("tags") or {}).get("p")
        if p is not None and p.lower() not in POLICIES:
            return "fail", f"p={p!r} is invalid"
        return "pass", f"p={p or 'none (missing, treated as none)'} at _dmarc.{d['policy_source']}"
    return "pass", f"policy inherited from _dmarc.{d['policy_source']}"


def evaluate(req, ctx):
    spf_ok = ctx["spf"]["result"] == "ok"
    spf_unknown = ctx["spf"]["result"] == "temperror"
    dk, dk_detail = ctx["dkim"]
    spf_txt = f"SPF {ctx['spf']['result']}"
    if req in ("spf_or_dkim",):
        if spf_ok or dk == "pass":
            return "pass", f"{spf_txt}; DKIM {dk}"
        if spf_unknown or dk == "unknown":
            return "unknown", f"{spf_txt}; DKIM {dk} ({dk_detail})"
        return "fail", f"{spf_txt}; DKIM {dk} ({dk_detail})"
    if req == "spf_and_dkim":
        if not spf_ok and not spf_unknown:
            return "fail", f"{spf_txt}"
        if dk == "fail":
            return "fail", f"DKIM: {dk_detail}"
        if spf_unknown or dk == "unknown":
            return "unknown", f"{spf_txt}; DKIM {dk} ({dk_detail})"
        return "pass", f"{spf_txt}; DKIM pass"
    if req == "dkim_min_bits":
        keys = ctx["dkim_keys"]
        if not keys:
            return "unknown", "no DKIM key found (give --dkim-selector)"
        weak = [f"{k['name']} RSA {k['bits']}-bit" for k in keys if k.get("k", "rsa") == "rsa" and k.get("bits") and k["bits"] < ctx["dkim_min"]]
        if weak:
            return "fail", "key under 1024 bits: " + ", ".join(weak)
        return "pass", ", ".join(f"{k['name']} {k.get('k', 'rsa')} {k['bits']}-bit" for k in keys)
    if req == "dmarc_min":
        return ctx["dmarc"]
    if req in ("fcrdns", "rdns"):
        ips = ctx["ips"]
        if not ips:
            return "unknown", "no sending IP given"
        res = [fcrdns(ip, ctx["res"]) for ip in ips]
        if any(s == "fail" for s, _ in res):
            return "fail", "; ".join(d for _, d in res)
        if any(s == "unknown" for s, _ in res):
            return "unknown", "; ".join(d for _, d in res)
        return "pass", "; ".join(d for _, d in res)
    return "not-dns-verifiable", ""


def check(domain, res, rules, options=None):
    options = options or {}
    prior = options.get("results", {})
    spf_d = prior.get("spf") or spf_check.check(domain, res, rules)["data"]
    dm_d = prior.get("dmarc") or dmarc_check.check(domain, res, rules)["data"]
    dk_d = prior.get("dkim")
    if dk_d is None:     # standalone: look only at the selectors the user named
        dk_d = dkim_check.check(domain, res, rules, {"dkim_selectors": options.get("dkim_selectors") or [],
                                                     "probe_common": False})["data"]
    sels = list(dict.fromkeys(list(options.get("dkim_selectors") or []) + list(dk_d.get("usable_selectors") or [])))
    ctx = {"res": res, "spf": spf_d, "ips": list(options.get("sending_ips") or []),
           "dkim": dkim_status(domain, res, sels),
           "dkim_keys": [k for k in dk_d.get("keys") or [] if not k.get("revoked") and k.get("bits")],
           "dkim_min": rules.value("bulk.google.all.dkim_1024"),
           "dmarc": dmarc_status(dm_d)}
    strict = bool(options.get("bulk"))
    findings, providers = [], {}
    for r in sorted(rules.for_check(NAME), key=lambda r: r["id"]):
        if "provider" not in r:
            continue
        status, detail = (evaluate(r["requirement"], ctx) if r.get("dns_verifiable")
                          else ("not-dns-verifiable", ""))
        prov = providers.setdefault(r["provider"], {"provider": r["provider"], "url": r["url"],
                                                    "effective": r.get("effective"), "requirements": []})
        prov["requirements"].append({"rule_id": r["id"], "requirement": r["requirement"],
                                     "audience": r["audience"], "status": status, "detail": detail})
        who = "all senders" if r["audience"] == "all" else "senders of 5,000+ messages a day" \
            if r["audience"] == "5k" else "bulk senders"
        if status == "fail":
            sev = "error" if (r["audience"] == "all" or strict) else "warning"
            findings.append(rules.finding(NAME, sev, r["id"],
                            f"{r['provider']}: '{r['requirement']}' (applies to {who}) fails: {detail}",
                            provider=r["provider"], requirement=r["requirement"]))
        elif status == "unknown":
            findings.append(rules.finding(NAME, "info", "bulk.needs_input",
                            f"{r['provider']}: '{r['requirement']}' not verified: {detail}"
                            + (f"; needs {r['needs']}" if r.get("needs") else ""),
                            provider=r["provider"], requirement=r["requirement"], rule=r["id"]))
        elif status == "not-dns-verifiable":
            findings.append(rules.finding(NAME, "info", "bulk.not_dns_verifiable",
                            f"{r['provider']}: '{r['requirement']}' (applies to {who}) cannot be checked from DNS; "
                            f"check your sending platform or postmaster data (source: {r['url']})",
                            provider=r["provider"], requirement=r["requirement"], rule=r["id"]))
    for p in providers.values():
        st = [q["status"] for q in p["requirements"]]
        p["verdict"] = "fail" if "fail" in st else "incomplete" if "unknown" in st else "dns-checks-pass"
        p["not_dns_verifiable"] = [q["requirement"] for q in p["requirements"] if q["status"] == "not-dns-verifiable"]
    return {"check": NAME, "domain": domain, "findings": findings,
            "data": {"providers": list(providers.values()), "dkim": ctx["dkim"][0],
                     "sending_ips": ctx["ips"], "strict_bulk": strict}}
