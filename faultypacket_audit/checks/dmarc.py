"""DMARC audit per RFC 9989 (May 2026; obsoletes RFC 7489 and RFC 9091),
with external report destination verification per RFC 9990 section 4 (rua)
and RFC 9991 section 5 (ruf). Ported from dmarc-rua-classifier 1.2.0.

check_domain(domain, res) -> raw result (issues as severity/code/message).
check(domain, res, rules) -> CheckResult with cited findings. Never prints.
"""
import re, urllib.parse

from ..core.resolver import Cached

NAME = "dmarc"
# RFC 9989 9.3 DMARC Tags registry
ACTIVE_TAGS = {"v", "p", "sp", "np", "psd", "t", "rua", "ruf", "adkim", "aspf", "fo"}
HISTORIC_TAGS = {"pct", "rf", "ri"}
TREE_WALK_MAX = 8   # RFC 9989 4.10: at most eight DNS queries


# ------------------------------------------------ organizational domain
_PSL = None
def org_domain_psl(name):
    """Legacy RFC 7489 3.2 Organizational Domain via the Public Suffix List.
    Kept only to compare with the RFC 9989 DNS Tree Walk."""
    global _PSL
    if _PSL is None:
        from publicsuffixlist import PublicSuffixList
        _PSL = PublicSuffixList()
    return _PSL.privatesuffix(name.lower().rstrip(".")) or name.lower().rstrip(".")


def walk_targets(domain, include_start=True):
    """RFC 9989 4.10 steps 3-7: names to query, at most 8."""
    labels = domain.lower().rstrip(".").split(".")
    out = [".".join(labels)] if include_start else []
    x = len(labels)
    cur = labels[1:] if x < 8 else labels[x - 7:]
    while cur:
        out.append(".".join(cur))
        cur = cur[1:]
    return out[:TREE_WALK_MAX]


def valid_record_at(name, res):
    """-> (record or None, status). RFC 9989 4.10 step 2: more than one
    DMARC record at a name means all are discarded."""
    txts, st = res.query("_dmarc." + name, "TXT")
    if st.startswith("error"):
        return None, st
    recs = dmarc_records(txts)
    return (recs[0], "ok") if len(recs) == 1 else (None, "multiple" if recs else "none")


def psd_value(record):
    tags, _ = parse_tags(record)
    for k, v in tags:
        if k == "psd":
            return v.strip().lower()
    return None


def tree_walk(domain, res, include_start=True):
    """RFC 9989 4.10 DNS Tree Walk. -> {queried, found{name: record}, errors}."""
    found, queried, errors = {}, [], []
    for name in walk_targets(domain, include_start):
        rec, st = valid_record_at(name, res)
        queried.append(name)
        if st.startswith("error"):
            errors.append(f"_dmarc.{name}: {st}")
            continue
        if rec:
            found[name] = rec
            if psd_value(rec) in ("y", "n"):
                break
    return {"queried": queried, "found": found, "errors": errors}


def org_domain(domain, res):
    """RFC 9989 4.10.2 Organizational Domain selection from a Tree Walk
    starting at domain. -> (org_domain, walk)."""
    d = domain.lower().rstrip(".")
    w = tree_walk(d, res)
    names = sorted(w["found"], key=lambda n: -n.count("."))   # longest first
    for n in names:
        if psd_value(w["found"][n]) == "n":
            return n, w
        if psd_value(w["found"][n]) == "y" and n != d:
            one_below = ".".join(d.split(".")[-(n.count(".") + 2):])
            return one_below, w
    if names:
        return names[-1], w
    return d, w


# ------------------------------------------------------------ DMARC parsing
def dmarc_records(txts):
    """RFC 9989 4.7: v is REQUIRED, MUST be first, and its value "DMARC1" is
    case-sensitive; any other TXT at _dmarc is not a DMARC record."""
    return [t for t in txts if re.match(r"^\s*[vV]\s*=\s*DMARC1\s*(;|$)", t)]


def unparseable_records(txts):
    """TXT records that begin with v=DMARC1 but do not match the RFC 9989 4.8
    dmarc-record ABNF at the first separator (e.g. 'v=DMARC1 p=reject')."""
    return [t for t in txts if re.match(r"^\s*[vV]\s*=\s*DMARC1", t) and not re.match(r"^\s*[vV]\s*=\s*DMARC1\s*(;|$)", t)]


def unparseable_cause(t):
    rest = re.sub(r"^\s*[vV]\s*=\s*DMARC1", "", t)
    if re.match(r"\s*[,:]", rest):
        return "the likely cause is a ',' or ':' used instead of ';' after v=DMARC1"
    if re.match(r"\s+[A-Za-z]+\s*=", rest) or (";" not in t and re.search(r"\s[A-Za-z]+=", t)):
        return "the likely cause is a missing ';' between tags (write 'v=DMARC1; p=reject; ...')"
    return "the version tag must be followed by ';' or end the record"


def near_miss_records(txts):
    """TXT that look like DMARC but fail the case-sensitive version check."""
    return [t for t in txts if re.match(r"^\s*v\s*=\s*dmarc1\s*(;|$)", t, re.I) and t not in dmarc_records([t])]


def parse_tags(record):
    """-> (ordered list of (tag, value), issues). Tag names case-insensitive."""
    tags, issues = [], []
    parts = record.split(";")
    for n, part in enumerate(parts):
        part = part.strip()
        if not part:
            if 0 < n < len(parts) - 1 and not any(c == "syntax" and "empty" in m for _, c, m in issues):
                issues.append(("warning", "syntax", "empty tag between ';' separators; receivers discard it (RFC 9989 4.8 ABNF: one trailing ';' only)"))
            continue
        if "=" not in part:
            issues.append(("error", "syntax", f"tag without '=': {part!r} (RFC 9989 4.8)"))
            continue
        k, v = part.split("=", 1)
        tags.append((k.strip().lower(), v.strip()))
    return tags, issues


def parse_uris(value):
    """RFC 9989 4.6/4.8 DMARC URI list (a !size suffix is obs-dmarc-report-size) -> list of dicts {uri, scheme, address, host, size}."""
    out = []
    for raw in value.split(","):
        raw = raw.strip()
        if not raw:
            continue
        uri, size = raw, None
        m = re.match(r"^(.*)!(\d+[kmgt]?)$", raw, re.I)
        if m:
            uri, size = m.group(1), m.group(2)
        scheme = uri.split(":", 1)[0].lower() if ":" in uri else ""
        addr = urllib.parse.unquote(uri.split(":", 1)[1]) if scheme else uri
        addr = addr.split("?", 1)[0]
        host = addr.rsplit("@", 1)[1].strip().lower().rstrip(".") if "@" in addr else ""
        out.append({"uri": raw, "scheme": scheme, "address": addr, "host": host, "size": size})
    return out


def rua_domains(record):
    """v1.0 behaviour: unique rua host domains in order."""
    tags, _ = parse_tags(record)
    doms = []
    for k, v in tags:
        if k == "rua":
            for u in parse_uris(v):
                if u["host"] and u["host"] not in doms:
                    doms.append(u["host"])
            break
    return doms


POLICIES = ("none", "quarantine", "reject")


def valid_fo(value):
    """RFC 9989 4.8 dmarc-fo: 0/1 mutually exclusive, d and s at most once."""
    opts = [o.strip().lower() for o in value.split(":")]
    if not opts or not all(o in ("0", "1", "d", "s") for o in opts):
        return False
    if "0" in opts and "1" in opts:
        return False
    return all(opts.count(o) <= 1 for o in opts)


def validate(record):
    """Syntax/semantics per RFC 9989 4.7/4.8/9.3. -> (tags dict, issues list).
    Never prints; issues are (severity, code, message)."""
    tags, issues = parse_tags(record)
    if re.search(r"[\x00-\x08\x0a-\x1f\x7f]", record):
        issues.append(("warning", "syntax", "record contains a control character (e.g. a line break); only space and tab may separate tags, and receivers may discard the affected tag (RFC 9989 4.8)"))
    d = {}
    if not tags or tags[0][0] != "v" or tags[0][1] != "DMARC1":
        issues.append(("error", "version", "v=DMARC1 must be the first tag; the value is case-sensitive, otherwise the record is ignored (RFC 9989 4.7)"))
    for k, v in tags:
        if not re.fullmatch(r"[a-z]+", k):
            near = re.sub(r"[^a-z]", "", k)
            hint = f"; it looks like {near!r}, which therefore does not apply" if near in ACTIVE_TAGS | HISTORIC_TAGS else ""
            issues.append(("warning", "syntax", f"tag name {k!r} is not letters only, so receivers discard it{hint} (RFC 9989 4.8: dmarc-tag = 1*ALPHA equals 1*dmarc-value)"))
            continue
        if v == "" and k not in ("rua", "ruf"):
            issues.append(("warning", "syntax", f"tag {k} has no value, so receivers discard it (RFC 9989 4.8)"))
            continue
        if k in d:
            issues.append(("warning", "duplicate_tag", f"tag {k} appears more than once; first value used"))
            continue
        d[k] = v
        if k in HISTORIC_TAGS:
            if k == "pct" and v.strip() == "0":
                issues.append(("warning", "historic_pct", "pct=0 is historic and ignored by RFC 9989 receivers, so the full policy now applies; t=y is the replacement (RFC 9989 9.3, A.6)"))
            elif k == "pct" and v.strip() != "100":
                issues.append(("warning", "historic_pct", f"pct={v} is historic and ignored by RFC 9989 receivers: the policy now applies to all failing mail, not {v}% (RFC 9989 9.3, A.6)"))
            else:
                issues.append(("info", "historic_tag", f"tag {k!r} is historic in the DMARC Tags registry and ignored by RFC 9989 receivers; safe to remove (RFC 9989 9.3)"))
        elif k not in ACTIVE_TAGS:
            issues.append(("warning", "unknown_tag", f"unknown tag {k!r} MUST be ignored by receivers (RFC 9989 4.7)"))
    rua_ok = any(u["scheme"] == "mailto" and u["host"] for u in parse_uris(d.get("rua", "")))
    p = d.get("p")
    if p is None:
        issues.append(("warning", "no_p", "p is missing: treated as p=none (RFC 9989 4.7); publish p explicitly"))
    elif p.lower() not in POLICIES:
        issues.append(("error", "bad_p", f"p={p!r} is not none|quarantine|reject; receivers act as p=none if rua holds a valid URI, otherwise skip DMARC (RFC 9989 4.10.1)"))
    for k in ("sp", "np"):
        if k in d and d[k].lower() not in POLICIES:
            issues.append(("error", "bad_" + k, f"{k}={d[k]!r} is not none|quarantine|reject (RFC 9989 4.7, 4.10.1)"))
    for k in ("adkim", "aspf"):
        if k in d and d[k].lower() not in ("r", "s"):
            issues.append(("error", "bad_" + k, f"{k}={d[k]!r} is not r|s; default r applies (RFC 9989 4.7, 4.8)"))
    if "psd" in d and d["psd"].lower() not in ("y", "n", "u"):
        issues.append(("error", "bad_psd", f"psd={d['psd']!r} is not y|n|u; default u applies (RFC 9989 4.7)"))
    if "t" in d:
        if d["t"].lower() not in ("y", "n"):
            issues.append(("error", "bad_t", f"t={d['t']!r} is not y|n; default n applies (RFC 9989 4.7)"))
        elif d["t"].lower() == "y":
            issues.append(("info", "test_mode", "t=y: test mode; receivers are asked to apply one level below the stated policy (reject->quarantine, quarantine->none) (RFC 9989 4.7)"))
    if "fo" in d:
        if not valid_fo(d["fo"]):
            issues.append(("error", "bad_fo", f"fo={d['fo']!r}: options 0,1,d,s separated by ':', 0 and 1 mutually exclusive, d and s at most once (RFC 9989 4.8)"))
        if "ruf" not in d:
            issues.append(("info", "fo_without_ruf", "fo has no effect without ruf (RFC 9989 4.7)"))
    for k in ("rua", "ruf"):
        if k in d:
            uris = parse_uris(d[k])
            if uris and any(not x.strip() for x in d[k].split(",")):
                issues.append(("warning", "syntax", f"{k} has an empty entry (stray or doubled comma); strict receivers may discard the whole {k} tag (RFC 9989 4.8 dmarc-urilist)"))
            if not uris:
                issues.append(("error", "empty_" + k, f"{k} is present but empty (RFC 9989 4.7)"))
            for u in uris:
                if u["scheme"] != "mailto":
                    issues.append(("warning", "scheme_" + k, f"{k} URI {u['uri']!r} is not mailto; mailto is the scheme receivers MUST support (RFC 9989 4.6)"))
                elif not u["host"]:
                    issues.append(("error", "bad_uri_" + k, f"{k} URI {u['uri']!r} has no domain (RFC 9989 4.6)"))
                elif re.search(r"\s", u["uri"]) or u["address"].count("@") != 1:
                    issues.append(("error", "bad_uri_" + k, f"{k} URI {u['uri']!r} is not a valid mailto URI: no spaces and exactly one '@' (RFC 9989 4.8; RFC 3986; RFC 6068)"))
                if u["size"]:
                    issues.append(("info", "obsolete_size", f"{k} URI {u['uri']!r}: the !size suffix is obsolete and ignored (RFC 9989 4.8)"))
    if "rua" not in d:
        issues.append(("warning", "no_rua", "no rua: you receive no aggregate reports (RFC 9989 4.7; RFC 9990)"))
    if p and p.lower() == "none":
        issues.append(("info", "p_none", "p=none: monitoring only, no enforcement requested (RFC 9989 4.7)"))
    return d, issues


def org_compare(name, res):
    """Tree Walk Organizational Domain vs legacy PSL. -> dict."""
    tw, walk = org_domain(name, res)
    try:
        psl = org_domain_psl(name)
    except Exception as e:          # PSL package missing or broken
        psl = f"error:{type(e).__name__}"
    # with no record anywhere DMARC does not apply (4.10.1), so no comparison
    return {"name": name, "tree_walk": tw, "psl": psl,
            "differs": bool(walk["found"]) and tw != psl,
            "queries": len(walk["queried"]), "walk_errors": walk["errors"]}


def external_check(domain, uris, res, tag, policy_org=None):
    """RFC 9990 4 (rua) / RFC 9991 5 (ruf): when the Organizational Domain at
    which the policy was found differs from the destination host's, query
    <domain>._report._dmarc.<host> TXT; at least one record whose first tag
    is v=DMARC1 authorises it. Organizational Domains use the RFC 9989 4.10
    Tree Walk; the legacy PSL answer is reported when it disagrees.
    -> (rows, issues)."""
    cite = "RFC 9990 4" if tag == "rua" else "RFC 9991 5; RFC 9990 4"
    out, issues = [], []
    od = policy_org or org_domain(domain, res)[0]
    od_psl = org_domain_psl(domain)
    for u in uris:
        if u["scheme"] != "mailto" or not u["host"]:
            continue
        host_od = org_domain(u["host"], res)[0]
        ext = host_od != od
        ext_psl = org_domain_psl(u["host"]) != od_psl
        row = {"tag": tag, "uri": u["uri"], "host": u["host"], "external": ext,
               "external_psl": ext_psl, "query": None, "authorised": None, "status": "same-org"}
        if ext != ext_psl:
            issues.append(("info", "org_method_differs",
                           f"{tag} {u['host']}: Tree Walk says {'external' if ext else 'same organization'}, "
                           f"legacy PSL says {'external' if ext_psl else 'same organization'} (RFC 9989 4.10.2)"))
        if ext:
            q = f"{domain}._report._dmarc.{u['host']}"
            row["query"] = q
            if len(q) > 253 or any(len(l) > 63 for l in q.split(".")):
                row["status"] = "name-too-long"
                issues.append(("error", "verify_too_long_" + tag, f"{q} exceeds DNS limits; authorisation cannot be confirmed ({cite} step 4)"))
                out.append(row); continue
            txts, st = res.query(q, "TXT")
            if st.startswith("error"):
                row["status"] = st
                issues.append(("error", "verify_error_" + tag,
                               f"could not verify {tag} destination {u['host']}: {st} querying {q}"))
            else:
                ok = bool(dmarc_records(txts))
                row["authorised"] = ok
                row["status"] = "authorised" if ok else "missing"
                if not ok:
                    issues.append(("error", "unauthorised_" + tag,
                                   f"{tag} destination {u['host']} has not authorised {domain}: no v=DMARC1 TXT at {q}; "
                                   f"compliant receivers MUST ignore this URI ({cite})"))
        out.append(row)
    return out, issues


def check_domain(domain, res):
    """Own-domain check per RFC 9989 4.10.1 policy discovery. Never prints."""
    res = res if isinstance(res, Cached) else Cached(res)
    domain = domain.lower().rstrip(".")
    issues, record, tags, dests, applied_from = [], None, {}, [], None
    txts, st = res.query("_dmarc." + domain, "TXT")
    org = org_compare(domain, res)
    if org["differs"]:
        issues.append(("info", "org_method_differs",
                       f"Organizational Domain: Tree Walk {org['tree_walk']} vs legacy PSL {org['psl']} (RFC 9989 4.10.2)"))
        if org["psl"].endswith("." + org["tree_walk"]):
            issues.append(("warning", "parent_psd_without_psd_y",
                           f"the Tree Walk climbs to _dmarc.{org['tree_walk']}, a public suffix whose record lacks psd=y "
                           f"(a PSO MUST publish psd=y, RFC 9989 5.2), so RFC 9989 receivers treat {org['tree_walk']} as your "
                           f"Organizational Domain; add psd=n to your own record (RFC 9989 11.8)"))
    if st.startswith("error"):
        issues.append(("error", "dns_error", f"_dmarc.{domain} TXT lookup failed: {st}"))
    else:
        recs = dmarc_records(txts)
        for t in near_miss_records(txts):
            issues.append(("error", "version_case", f"_dmarc.{domain} has {t[:40]!r}...: 'DMARC1' is case-sensitive, receivers ignore this record (RFC 9989 4.7)"))
        if len(recs) > 1:
            issues.append(("error", "multiple_records", f"{len(recs)} DMARC records at _dmarc.{domain}: all are discarded (RFC 9989 4.10 step 2)"))
        elif recs:
            record, applied_from = recs[0], domain
        else:
            bad = unparseable_records(txts)
            for t in bad:
                issues.append(("error", "unparseable_record", f"_dmarc.{domain} publishes {t[:60]!r}, which starts with v=DMARC1 "
                                                              f"but is not a valid DMARC record, so receivers ignore it; {unparseable_cause(t)} "
                                                              "(RFC 9989 4.8)"))
            # 4.10.1: Organizational Domain record, then PSD record
            od = org["tree_walk"]
            walk = tree_walk(domain, res, include_start=False)
            if od != domain and od in walk["found"]:
                applied_from = od
                issues.append(("warning", "no_record_sub", f"no DMARC record at _dmarc.{domain}; receivers use the Organizational Domain record at _dmarc.{od} (sp or np applies) (RFC 9989 4.10.1)"))
            elif walk["found"]:
                applied_from = sorted(walk["found"], key=lambda n: n.count("."))[0]
                issues.append(("warning", "psd_policy", f"no DMARC record for {domain} or its Organizational Domain; a Public Suffix Domain record at _dmarc.{applied_from} applies (RFC 9989 4.10.1)"))
            elif not bad:
                issues.append(("error", "no_record", f"no DMARC record at _dmarc.{domain} and none found by the Tree Walk: DMARC does not apply (RFC 9989 4.10.1)"))
        if record:
            tags, iss = validate(record)
            issues += iss
            for t in ("rua", "ruf"):
                if t in tags:
                    rows, iss = external_check(domain, parse_uris(tags[t]), res, t, org["tree_walk"])
                    dests += rows; issues += iss
    issues += cname_issues(domain, res, record)
    issues = [{"severity": s, "code": c, "message": m} for s, c, m in issues]
    return {"domain": domain, "record": record, "policy": tags.get("p"),
            "policy_source": applied_from, "org_domain": org, "tags": tags,
            "destinations": dests, "issues": issues, "result": verdict(issues)}


def cname_issues(domain, res, record):
    """_dmarc.<domain> reached through a CNAME (common when a provider hosts the policy)."""
    name = "_dmarc." + domain
    out, seen, cur = [], [], name
    for _ in range(8):
        vals, st = res.query(cur, "CNAME")
        if st != "ok" or not vals:
            break
        cur = vals[0].lower().rstrip(".")
        if cur in seen or cur == name:
            return [("error", "cname_dangling", f"{name} CNAME chain loops at {cur}; receivers get no record")]
        seen.append(cur)
    if not seen:
        return []
    chain = " -> ".join([name] + seen)
    if record:
        out.append(("info", "cname", f"DMARC record is served through a CNAME ({chain}); whoever controls {seen[-1]} controls your policy"))
    else:
        txts, st = res.query(seen[-1], "TXT")
        if not st.startswith("error"):
            out.append(("error", "cname_dangling", f"{chain}: the CNAME target has no valid DMARC record, so the policy is lost "
                                                   "(check the provider still hosts it, or replace the CNAME with a TXT record)"))
    return out


def verdict(issues):
    sev = {i["severity"] for i in issues}
    return "fail" if "error" in sev else "warn" if "warning" in sev else "ok"


def check(domain, res, rules, options=None):
    """-> CheckResult dict; every issue becomes a cited finding (rule dmarc.<code>)."""
    r = check_domain(domain, res)
    findings = [rules.finding(NAME, i["severity"], "dmarc." + i["code"], i["message"])
                for i in r["issues"]]
    data = {k: r[k] for k in ("record", "policy", "policy_source", "org_domain", "destinations")}
    data["tags"] = r.get("tags", {})
    return {"check": NAME, "domain": domain, "findings": findings, "data": data}
