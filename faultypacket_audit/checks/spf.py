"""SPF check (ported from spf-tree 1.0.0): expand an SPF record recursively
and count DNS lookups the way RFC 7208 section 4.6.4 does.

analyse(domain, res) -> raw result (tree, lookup log, issues), unchanged from
spf-tree so its tests keep passing. check(domain, res, rules) -> CheckResult
with cited findings. Neither prints.
"""
import ipaddress, re

LOOKUP_LIMIT = 10   # RFC 7208 4.6.4: DNS-querying terms per evaluation (MUST)
VOID_LIMIT = 2      # RFC 7208 4.6.4: void lookups (SHOULD)
MX_LIMIT = 10       # RFC 7208 4.6.4: MX records per mx term (MUST, else permerror)
PTR_LIMIT = 10      # RFC 7208 4.6.4: PTR names used per ptr term (extras ignored)
MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
NAME = "spf"

# spf-tree severities -> audit severities
SEVERITY = {"permerror": "error", "temperror": "error", "none": "warning",
            "warning": "warning", "info": "info", "error": "error"}


def get_spf(res, domain):
    """RFC 7208 4.5: records starting 'v=spf1' (case-insensitive) then space or end."""
    txts, status = res.query(domain, "TXT")
    recs = [t.strip() for t in txts
            if re.match(r"(?i)^v=spf1( |$)", t.strip())]
    return recs, status


# ------------------------------------------------------------------ parsing
def parse_term(term):
    """-> (kind, name, arg, cidr, qualifier). RFC 7208 4.6.1 / 12."""
    qual = "+"
    if term[0] in "+-~?":
        qual, term = term[0], term[1:]
        explicit = True
    else:
        explicit = False
    m = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$", term)
    if m:
        if explicit:  # RFC 7208 12: modifiers take no qualifier (e.g. "-allfoo=bar" from joined TXT strings)
            return "invalid", term, None, None, qual
        return "modifier", m.group(1).lower(), m.group(2), None, qual
    m = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)(.*)$", term)
    if not m:
        return "invalid", term, None, None, qual
    name, rest = m.group(1).lower(), m.group(2)
    arg = cidr = None
    if name in ("ip4", "ip6"):
        return "mechanism", name, rest[1:] if rest.startswith(":") else None, None, qual
    if rest.startswith(":"):
        rest = rest[1:]
        # domain-spec then optional dual-cidr; macros may contain '/' only inside %{...}
        cm = re.search(r"(/\d+)?(//\d+)?$", rest) if name in ("a", "mx") else None
        if cm and cm.group(0):
            arg, cidr = rest[:cm.start()], cm.group(0)
        else:
            arg = rest
        if arg == "":
            return "invalid", term, None, None, qual
    elif rest:
        if name in ("a", "mx") and re.fullmatch(r"(/\d+)?(//\d+)?", rest):
            cidr = rest
        else:
            return "invalid", term, None, None, qual
    return "mechanism", name, arg, cidr, qual


def valid_cidr(cidr):
    if not cidr:
        return True
    m = re.fullmatch(r"(?:/(\d+))?(?://(\d+))?", cidr)
    return bool(m) and (m.group(1) is None or int(m.group(1)) <= 32) and \
        (m.group(2) is None or int(m.group(2)) <= 128)


def valid_ip(name, arg):
    try:
        net = ipaddress.ip_network(arg, strict=False)
    except (ValueError, TypeError):
        return False
    return net.version == (4 if name == "ip4" else 6)


# ---------------------------------------------------------------- expansion
class Expander:
    def __init__(self, res):
        self.res, self.lookups, self.voids = res, 0, 0
        self.issues, self.rows, self.seen = [], [], {}

    def issue(self, sev, code, msg):
        self.issues.append({"severity": sev, "code": code, "message": msg})

    def count(self, path, term, status):
        """One DNS-querying term (RFC 7208 4.6.4)."""
        self.lookups += 1
        void = status == "void"
        self.voids += void
        self.rows.append({"lookup_no": self.lookups, "path": path, "term": term,
                          "void": void, "status": status})
        if self.lookups == LOOKUP_LIMIT + 1:
            self.issue("permerror", "lookup_limit",
                       f"more than {LOOKUP_LIMIT} DNS-querying terms; exceeded at '{term}' ({path})")
        if void and self.voids == VOID_LIMIT + 1:
            self.issue("permerror", "void_limit",
                       f"more than {VOID_LIMIT} void lookups; exceeded at '{term}' ({path})")
        if status.startswith("error"):
            self.issue("temperror", "dns_error", f"'{term}' ({path}): DNS {status}")

    def expand(self, domain, stack=(), qualifier="+", via="root"):
        domain = domain.rstrip(".").lower()
        node = {"domain": domain, "via": via, "qualifier": qualifier, "record": None,
                "lookups_subtree": 0, "children": []}
        path = " > ".join(list(stack) + [domain])
        start = self.lookups
        if stack:  # the TXT fetch of an include/redirect target is the counted lookup
            recs, status = get_spf(self.res, domain)
            self.count(" > ".join(stack), f"{via}:{domain}", status)
        else:
            recs, status = get_spf(self.res, domain)
        if domain in stack:
            self.issue("permerror", "loop", f"loop: {path}")
            node["error"] = "loop"
            node["lookups_subtree"] = self.lookups - start
            return node
        if domain in self.seen:
            self.issue("warning", "duplicate", f"{domain} evaluated more than once (via {path})")
            node["duplicate"] = True
        self.seen[domain] = self.seen.get(domain, 0) + 1
        if status.startswith("error"):
            node["error"] = status
            if not stack:
                self.issue("temperror", "dns_error", f"{domain}: DNS {status}")
            node["lookups_subtree"] = self.lookups - start
            return node
        if not recs:
            node["error"] = "no SPF record"
            if stack:  # RFC 7208 5.2 (include) / 6.1 (redirect): permerror
                self.issue("permerror", "missing_record",
                           f"{domain}: no SPF record at {via} target ({path})")
            else:
                self.issue("none", "no_record", f"{domain}: no SPF record published")
            node["lookups_subtree"] = self.lookups - start
            return node
        if len(recs) > 1:  # RFC 7208 4.5
            self.issue("permerror", "multiple_records", f"{domain}: {len(recs)} SPF records")
            node["records"] = recs
        rec = recs[0]
        node["record"] = rec
        terms = rec.split()[1:]
        mods = {}
        has_all = after_all_noted = False
        for term in terms:
            kind, name, arg, cidr, qual = parse_term(term)
            if kind == "invalid" or (kind == "mechanism" and name not in MECHANISMS):
                self.issue("permerror", "syntax", f"{domain}: invalid or unknown term '{term}'")
                continue
            if kind == "modifier":
                if name in ("redirect", "exp"):
                    if name in mods:  # RFC 7208 6
                        self.issue("permerror", "duplicate_modifier",
                                   f"{domain}: '{name}' appears more than once")
                    mods.setdefault(name, arg)
                if "%" in arg:
                    self.issue("info", "macro", f"{domain}: macro in '{term}'")
                continue
            if has_all and name != "all" and not after_all_noted:
                # RFC 7208 5.1: mechanisms after "all" are never tested, so they cost no lookups
                self.issue("info", "after_all", f"{domain}: '{term}' and any later mechanisms follow 'all' and are never evaluated")
                after_all_noted = True
            skip = has_all
            if name == "all":
                has_all = True
            elif name in ("ip4", "ip6"):
                if not valid_ip(name, arg):
                    self.issue("permerror", "syntax", f"{domain}: invalid address in '{term}'")
            elif name in ("include", "exists") and not arg:  # RFC 7208 5.2, 5.7
                self.issue("permerror", "syntax", f"{domain}: '{term}' needs a domain")
            elif arg and "%" not in arg and not re.fullmatch(
                    r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9-]+\.?", arg):
                self.issue("permerror", "syntax", f"{domain}: invalid domain in '{term}'")  # RFC 7208 7.1
            elif not valid_cidr(cidr):
                self.issue("permerror", "syntax", f"{domain}: invalid CIDR length in '{term}'")
            elif skip:
                pass
            elif arg and "%" in arg:
                # RFC 7208 7: macros expand per message; we never guess an expansion
                self.issue("info", "macro",
                           f"{domain}: macro in '{term}'; counted as 1 lookup, not resolved")
                self.count(path, term, "dynamic")
            elif name == "include":
                node["children"].append(self.expand(arg, tuple(stack) + (domain,), qual, "include"))
            elif name == "exists":
                _, st = self.res.query(arg, "A")  # RFC 7208 5.7: always A
                self.count(path, term, st)
            elif name == "ptr":
                self.issue("warning", "ptr", f"{domain}: 'ptr' is deprecated (RFC 7208 5.5); "
                           f"its cost depends on the sender IP, counted as 1")
                self.count(path, term, "dynamic")
            elif name == "a":
                target = arg or domain
                vals, st = self.res.query(target, "A")
                vals6, st6 = self.res.query(target, "AAAA")
                # a receiver queries A or AAAA per the sender's IP family; void only if both are
                if st == "ok" or st6 == "ok":
                    st = "ok"
                elif st.startswith("error") or st6.startswith("error"):
                    st = st if st.startswith("error") else st6
                self.count(path, term, st)
            elif name == "mx":
                target = arg or domain
                mx, st = self.res.query(target, "MX")
                self.count(path, term, st)
                if len(mx) > MX_LIMIT:
                    self.issue("permerror", "mx_limit",
                               f"{domain}: '{term}' returns {len(mx)} MX records (> {MX_LIMIT})")
        if "redirect" in mods:
            if has_all:  # RFC 7208 6.1
                self.issue("info", "redirect_ignored",
                           f"{domain}: redirect ignored because 'all' is present")
            elif "%" in mods["redirect"]:
                self.count(path, "redirect=" + mods["redirect"], "dynamic")
            else:
                node["children"].append(
                    self.expand(mods["redirect"], tuple(stack) + (domain,), "+", "redirect"))
        node["lookups_subtree"] = self.lookups - start
        return node


def verdict(issues):
    sevs = {i["severity"] for i in issues}
    for v in ("permerror", "temperror", "none"):
        if v in sevs:
            return v
    return "ok"


def analyse(domain, res):
    e = Expander(res)
    tree = e.expand(domain)
    return {"domain": domain, "lookups": e.lookups, "lookup_limit": LOOKUP_LIMIT,
            "void_lookups": e.voids, "void_limit": VOID_LIMIT,
            "result": verdict(e.issues), "issues": e.issues,
            "lookup_log": e.rows, "tree": tree}


def all_qualifier(record):
    """Qualifier of the top-level 'all' term ('+', '-', '~', '?'), 'redirect'
    when there is no 'all' but a redirect, or None when neither is present."""
    if not record:
        return None
    q, redirect = None, False
    for term in record.split()[1:]:
        kind, name, _arg, _cidr, qual = parse_term(term)
        if kind == "mechanism" and name == "all" and q is None:
            q = qual
        elif kind == "modifier" and name == "redirect":
            redirect = True
    return q if q is not None else ("redirect" if redirect else None)


def check(domain, res, rules, options=None):
    """-> CheckResult dict. Every finding is created through rules.finding()."""
    r = analyse(domain, res)
    findings = [rules.finding(NAME, SEVERITY[i["severity"]], "spf." + i["code"], i["message"],
                              spf_result=i["severity"])
                for i in r["issues"]]
    rec = (r["tree"] or {}).get("record")
    q = all_qualifier(rec) if rec and r["result"] != "permerror" else "n/a"
    if q == "+":
        restricted = any(t[0] in "-~" and t.lstrip("-~").lower() != "all" for t in rec.split()[1:])
        findings.append(rules.finding(NAME, "warning" if restricted else "error", "spf.all_pass",
                                      "'+all' passes every host not matched earlier" +
                                      ("; earlier '-'/'~' terms restrict it (RFC 7208 A.4), check this is intended"
                                       if restricted else ": every host on the internet may send as this domain")))
    elif q == "?":
        findings.append(rules.finding(NAME, "warning", "spf.all_neutral",
                                      "'?all' gives no assertion about unlisted hosts (neutral)"))
    elif q == "~":
        findings.append(rules.finding(NAME, "info", "spf.all_softfail",
                                      "'~all' (softfail): unlisted hosts are 'probably not authorised'; "
                                      "'-all' asserts they are not"))
    elif q is None:
        findings.append(rules.finding(NAME, "warning", "spf.no_all",
                                      "no 'all' term and no redirect: unlisted hosts get the default result 'neutral'"))
    findings += record_checks(domain, res, rules, rec)
    return {"check": NAME, "domain": domain, "findings": findings,
            "data": {"result": r["result"], "lookups": r["lookups"], "all": q, "lookup_limit": LOOKUP_LIMIT,
                     "void_lookups": r["void_lookups"], "void_limit": VOID_LIMIT,
                     "record": (r["tree"] or {}).get("record"),
                     "lookup_log": r["lookup_log"], "tree": r["tree"]}}


EXP_MACRO = re.compile(r"%(\{[slodiphcrtv][0-9]*r?[-.+,/_=]*\}|%|_|-)", re.I)


def macro_string_ok(txt):
    """RFC 7208 7.1 macro-string: every '%' starts %%, %_, %- or a valid %{...}."""
    i = 0
    while i < len(txt):
        if txt[i] != "%":
            i += 1
            continue
        m = EXP_MACRO.match(txt, i)
        if not m:
            return False
        i = m.end()
    return True


def txt_size(name, txts):
    """RFC 7208 3.4 guideline: DNS name plus the text of all TXT records."""
    return len(name.rstrip(".")) + sum(len(t.encode("utf-8", "replace")) for t in txts)


def record_checks(domain, res, rules, rec):
    """RFC 7208 3.4 size, 3.1 type 99, 6.2 exp= target, 6.1 redirect position,
    5.5 ptr position, 3.5 wildcard coverage."""
    F = lambda sev, rid, msg, **e: rules.finding(NAME, sev, rid, msg, **e)
    out = []
    for sev, rid, msg in term_order_issues(rec):
        out.append(F(sev, rid, msg))
    out += wildcard_coverage(domain, res, F)
    txts, st = res.query(domain, "TXT")
    if st == "ok":
        size, lim = txt_size(domain, txts), rules.value("spf.record_size")
        if size >= lim:
            out.append(F("warning", "spf.record_size",
                         f"name + all TXT records at {domain} are {size} octets (guideline < {lim}); the answer may not fit a "
                         "512-octet UDP response and some verifiers will not retry over TCP", octets=size))
    v99, st99 = res.query(domain, "SPF")
    if st99 == "ok" and v99:
        out.append(F("warning", "spf.rr_type_99",
                     f"{domain} still publishes the discontinued SPF RR type (99); verifiers only read TXT. "
                     "Remove it so the two cannot drift" + ("" if v99 == [t for t in txts if t.lower().startswith("v=spf1")]
                                                            else "; it already differs from the TXT record")))
    if not rec:
        return out
    exps = [t.split("=", 1)[1] for t in rec.split()[1:] if t.lower().startswith("exp=")]
    if not exps:
        return out
    target = exps[0]
    if "%" in target:
        out.append(F("info", "spf.exp_target", f"exp={target} uses macros; target not checked"))
        return out
    vals, st = res.query(target, "TXT")
    if st.startswith("error"):
        out.append(F("info", "spf.exp_target", f"exp={target}: DNS {st}"))
    elif not vals:
        out.append(F("warning", "spf.exp_target", f"exp={target} has no TXT record; receivers will give no explanation"))
    elif len(vals) > 1:
        out.append(F("warning", "spf.exp_target", f"exp={target} has {len(vals)} TXT records; RFC 7208 6.2 treats this as no explanation"))
    else:
        txt = vals[0]
        bad = not txt.isascii() or not macro_string_ok(txt)
        if bad:
            out.append(F("warning", "spf.exp_target", f"exp={target} text is not valid macro-string (US-ASCII, valid %{{...}} macros); "
                                                      "receivers will ignore it"))
    return out


def term_order_issues(rec):
    """RFC 7208 6.1: redirect SHOULD be the last term; 5.5: ptr SHOULD be one of
    the last mechanisms checked (only 'all' or other ptr terms after it)."""
    if not rec:
        return []
    terms = rec.split()[1:]
    out = []
    names = [re.split(r"[:=/]", t.lstrip("+-~?"), maxsplit=1)[0].lower() for t in terms]
    if "redirect" in names and names.index("redirect") != len(names) - 1:
        out.append(("info", "spf.redirect_position", "redirect= is not the last term; for clarity it SHOULD be (RFC 7208 6.1)"))
    if "ptr" in names:
        after = [n for n in names[names.index("ptr") + 1:] if n not in ("ptr", "all", "exp", "redirect")
                 and n in ("a", "mx", "ip4", "ip6", "include", "exists")]
        if after:
            out.append(("info", "spf.ptr_position", f"ptr is checked before {', '.join(after)}; it SHOULD be one of the last mechanisms (RFC 7208 5.5)"))
    return out


WILDCARD_PROBE = "fpa-wildcard-probe"


def wildcard_coverage(domain, res, F):
    """RFC 7208 3.5: a host with any RRs needs its own SPF declaration. Wildcard
    MX/A at *.<domain> creates such hosts; probe one random-looking label."""
    if not domain or getattr(res, "query", None) is None:
        return []
    probe = f"{WILDCARD_PROBE}.{domain}"
    has = []
    for t in ("MX", "A", "AAAA"):
        v, st = res.query(probe, t)
        if st == "ok" and v:
            has.append(t)
    if not has:
        return []
    txt, st = res.query(probe, "TXT")
    if st == "ok" and any(x.lower().startswith("v=spf1") for x in txt or []):
        return []
    return [F("warning", "spf.wildcard_coverage",
              f"*.{domain} has wildcard {'/'.join(has)} records but no wildcard SPF: every such name can be used as a "
              f"sender with no SPF policy; publish '*.{domain} TXT \"v=spf1 -all\"' (RFC 7208 3.5)")]
