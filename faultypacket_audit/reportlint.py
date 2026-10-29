"""Conformance checks for received reports: DMARC aggregate (RFC 9990),
TLS-RPT (RFC 8460) and DMARC failure reports (RFC 9991 / RFC 6591 ARF).

Each check returns a list of findings (severity, rule_id, message). Rule ids
live in data/rules.json with check "reports" and cite the RFC section, so
the reader can tell a malformed report (the generator's fault) from a
real authentication problem."""
import datetime as dt
import email
import email.policy
import re
import xml.etree.ElementTree as ET

NS_DMARC2 = "urn:ietf:params:xml:ns:dmarc-2.0"
DOMAIN = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}\.?"
ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
DOT_ATOM = rf"{ATEXT}(?:\.{ATEXT})*"
RIDFMT = rf"{DOT_ATOM}(?:@{DOT_ATOM})?"
RIDTXT = re.compile(rf"<{RIDFMT}>|{RIDFMT}")
DMARC_FILENAME = re.compile(rf"({DOMAIN})!({DOMAIN})!(\d+)!(\d+)(?:![A-Za-z0-9]+)?\.(xml|xml\.gz)")
TLS_FILENAME = re.compile(rf"({DOMAIN})!({DOMAIN})!(\d+)!(\d+)(?:![A-Za-z0-9]+)?\.(json|json\.gz)")
DMARC_SUBJECT = re.compile(rf"Report\s+Domain:\s+({DOMAIN})\s+Submitter:\s+({DOMAIN})(?:\s+Report-ID:\s+(\S+))?\s*")
TLS_SUBJECT = re.compile(rf"Report\s+Domain:\s+({DOMAIN})\s+Submitter:\s+({DOMAIN})\s+Report-ID:\s+<[^<>@\s]+@[^<>@\s]+>\s*")

# RFC 9990 3.1.1.x tables: (element, multiplicity) in the order they MUST appear
ORDER = {
    "feedback": [("version", "O"), ("report_metadata", "R"), ("policy_published", "R"), ("extension", "O"), ("record", "+")],
    "report_metadata": [("org_name", "R"), ("email", "R"), ("extra_contact_info", "O"), ("report_id", "R"),
                        ("date_range", "R"), ("error", "*"), ("generator", "O")],
    "date_range": [("begin", "R"), ("end", "R")],
    "policy_published": [("domain", "R"), ("discovery_method", "O"), ("p", "R"), ("sp", "O"), ("np", "O"), ("fo", "O"),
                         ("adkim", "O"), ("aspf", "O"), ("testing", "O")],
    "record": [("row", "R"), ("identifiers", "R"), ("auth_results", "R")],
    "row": [("source_ip", "R"), ("count", "R"), ("policy_evaluated", "R")],
    "policy_evaluated": [("disposition", "R"), ("dkim", "R"), ("spf", "R"), ("reason", "*")],
    "identifiers": [("header_from", "R"), ("envelope_from", "O"), ("envelope_to", "O")],
    "auth_results": [("dkim", "*"), ("spf", "O")],
    "dkim": [("domain", "R"), ("selector", "R"), ("result", "R"), ("human_result", "O")],
    "spf": [("domain", "R"), ("scope", "O"), ("result", "R"), ("human_result", "O")],
    "reason": [("type", "R"), ("comment", "O")],
}
SECTION = {"feedback": "3.1.1.2", "report_metadata": "3.1.1.3", "date_range": "3.1.1.4", "policy_published": "3.1.1.5",
           "record": "3.1.1.7", "row": "3.1.1.8", "policy_evaluated": "3.1.1.9", "identifiers": "3.1.1.10",
           "auth_results": "3.1.1.11", "dkim": "3.1.1.12", "spf": "3.1.1.13", "reason": "3.1.1.14"}
DKIM_RESULTS = {"none", "pass", "fail", "policy", "neutral", "temperror", "permerror"}       # RFC 8601 2.7.1
SPF_RESULTS = {"none", "neutral", "pass", "fail", "softfail", "temperror", "permerror"}     # RFC 8601 2.7.2
REASONS = {"local_policy", "mailing_list", "other", "policy_test_mode", "trusted_forwarder"}  # RFC 9990 3.1.6
# RFC 7489 Appendix C also allowed these two; accept with a note
REASONS_7489 = {"forwarded", "sampled_out"}
TLS_RESULTS = {"starttls-not-supported", "certificate-host-mismatch", "certificate-expired", "certificate-not-trusted",
               "validation-failure", "tlsa-invalid", "dnssec-invalid", "dane-required", "sts-policy-fetch-error",
               "sts-policy-invalid", "sts-webpki-invalid"}                                  # RFC 8460 4.3
TLS_POLICY_TYPES = {"tlsa", "sts", "no-policy-found"}                                        # RFC 8460 4.4/4.5
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})")


def _local(tag):
    return tag.split("}", 1)[1] if isinstance(tag, str) and "}" in tag else tag


def _ns(tag):
    return tag[1:].split("}", 1)[0] if isinstance(tag, str) and tag.startswith("{") else ""


def _txt(el):
    return (el.text or "").strip() if el is not None else ""


def _structure(el, root_ns, path, out, parent=None):
    """Order and multiplicity per the RFC 9990 tables, then recurse."""
    name = _local(el.tag)
    spec = ORDER.get(name)
    if spec is None or (name in ("dkim", "spf") and parent != "auth_results"):
        return
    known = [n for n, _ in spec]
    kids = [k for k in el if isinstance(k.tag, str)]
    sec = SECTION[name]
    seq, ext = [], []
    for k in kids:
        ln = _local(k.tag)
        foreign = root_ns and _ns(k.tag) != root_ns
        if ln in known and not foreign:
            seq.append(ln)
        elif name in ("feedback", "record"):
            ext.append(k)
        else:
            out.append(("warning", "rpt.dmarc_unknown_element", f"{path}: unexpected element <{ln}> (RFC 9990 {sec})"))
    for n, m in spec:
        c = seq.count(n)
        if (m == "R" and c != 1) or (m == "+" and c < 1) or (m == "O" and c > 1):
            want = {"R": "exactly one", "+": "at least one", "O": "at most one"}[m]
            rid = "rpt.dmarc_no_record" if (name, n) == ("feedback", "record") else "rpt.dmarc_required"
            out.append(("error", rid, f"{path}: <{n}> appears {c} time(s), needs {want} (RFC 9990 {sec})"))
    idx = [known.index(n) for n in seq]
    if idx != sorted(idx):
        out.append(("warning", "rpt.dmarc_order", f"{path}: elements out of order ({', '.join(seq)}); they MUST appear as "
                                                  f"{', '.join(n for n in known if n in seq)} (RFC 9990 {sec})"))
    for k in ext:
        if name == "feedback" and _local(k.tag) == "extension":
            continue
        if not _ns(k.tag) or _ns(k.tag) == root_ns:
            out.append(("warning", "rpt.dmarc_ext_namespace", f"{path}: extension element <{_local(k.tag)}> is not in its own XML "
                                                              "namespace (RFC 9990 3.1.1.7, 5)"))
    if name == "feedback":
        for e in el:
            if _local(e.tag) == "extension":
                for k in e:
                    if isinstance(k.tag, str) and (not _ns(k.tag) or _ns(k.tag) == root_ns):
                        out.append(("warning", "rpt.dmarc_ext_namespace", f"extension/<{_local(k.tag)}> MUST be namespaced (RFC 9990 3.1.1.6)"))
    for i, k in enumerate(kids):
        if _local(k.tag) in ORDER and not (root_ns and _ns(k.tag) != root_ns):
            _structure(k, root_ns, f"{path}/{_local(k.tag)}", out, name)


def _org(d):
    """Rough organisational-domain match used only for 3.1.2 (no PSL lookups)."""
    return ".".join(d.lower().rstrip(".").split(".")[-2:])


def validate_dmarc(data, filename=None, from_email=False):
    """RFC 9990 conformance of one aggregate report (raw XML bytes)."""
    out = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return out  # parse_dmarc already reports this
    root_ns = _ns(root.tag)
    if not root_ns:
        out.append(("info", "rpt.dmarc_legacy", "report has no XML namespace: RFC 7489 format, not RFC 9990 (RFC 9990 3.1.1.1)"))
    elif root_ns != NS_DMARC2:
        out.append(("warning", "rpt.dmarc_namespace", f"root namespace {root_ns!r} is not {NS_DMARC2} (RFC 9990 3.1.1.1)"))
    _structure(root, root_ns, "feedback", out)
    q = lambda el, p: el.find("/".join(f"{{{root_ns}}}{x}" if root_ns else x for x in p.split("/"))) if el is not None else None
    qa = lambda el, p: el.findall(f"{{{root_ns}}}{p}" if root_ns else p) if el is not None else []
    v = q(root, "version")
    if v is not None and _txt(v) != "1.0":
        out.append(("warning", "rpt.dmarc_version", f"<version> is {_txt(v)!r}; MUST be 1.0 (RFC 9990 3.1.1.2)"))
    md, pp = q(root, "report_metadata"), q(root, "policy_published")
    rid = _txt(q(md, "report_id"))
    if rid and not RIDTXT.fullmatch(rid):
        out.append(("info", "rpt.dmarc_report_id", f"report_id {rid[:60]!r} does not follow the ridtxt ABNF (RFC 9990 3.5.1)"))
    b, e = _txt(q(md, "date_range/begin")), _txt(q(md, "date_range/end"))
    if (b or e) and not (b.isdigit() and e.isdigit()):
        out.append(("error", "rpt.dmarc_date_range", f"date_range begin/end must be seconds since the epoch ({b!r}, {e!r}) (RFC 9990 3.1.1.4)"))
    elif b and int(b) >= int(e):
        out.append(("error", "rpt.dmarc_date_range", f"date_range begin {b} is not before end {e} (RFC 9990 3.1.1.4)"))
    pdom = _txt(q(pp, "domain")).lower().rstrip(".")
    pol = {k: _txt(q(pp, k)).lower() for k in ("p", "sp", "np", "testing", "discovery_method")}
    dm = pol["discovery_method"]
    if dm and dm not in ("psl", "treewalk"):
        out.append(("warning", "rpt.dmarc_value", f"discovery_method {dm!r} is not psl or treewalk (RFC 9990 3.1.1.5)"))
    for i, rec in enumerate(qa(root, "record"), 1):
        where = f"record {i}"
        pe = q(rec, "row/policy_evaluated")
        hf = _txt(q(rec, "identifiers/header_from")).lower().rstrip(".")
        if hf and pdom and hf != pdom and not hf.endswith("." + pdom) and _org(hf) != _org(pdom):
            out.append(("error", "rpt.dmarc_policy_domain", f"{where}: header_from {hf} is outside policy domain {pdom}; a report "
                                                            "MUST cover one DMARC Policy Domain (RFC 9990 3.1.2)"))
        ev = {k: _txt(q(pe, k)).lower() for k in ("disposition", "dkim", "spf")}
        for k in ("dkim", "spf"):
            if ev[k] and ev[k] not in ("pass", "fail"):
                out.append(("warning", "rpt.dmarc_value", f"{where}: policy_evaluated/{k} is {ev[k]!r}; MUST be pass or fail, the "
                                                          "DMARC-evaluated value (RFC 9990 3.1.1.9)"))
        if ev["disposition"] and ev["disposition"] not in ("none", "quarantine", "reject"):
            out.append(("warning", "rpt.dmarc_value", f"{where}: disposition {ev['disposition']!r} is not none/quarantine/reject (RFC 9990 3.1.1.9)"))
        reasons = [_txt(q(r, "type")).lower() for r in qa(pe, "reason")]
        for t in reasons:
            if t in REASONS_7489:
                out.append(("info", "rpt.dmarc_reason_type", f"{where}: reason type {t!r} is RFC 7489 only (RFC 9990 3.1.6)"))
            elif t not in REASONS:
                out.append(("warning", "rpt.dmarc_reason_type", f"{where}: reason type {t!r} is not one of {', '.join(sorted(REASONS))} (RFC 9990 3.1.6)"))
        sub = hf and pdom and hf != pdom
        want = (pol["sp"] or pol["p"]) if sub else pol["p"]
        if pol["testing"] == "y" and want in ("quarantine", "reject"):
            want = {"reject": "quarantine", "quarantine": "none"}[want]  # RFC 9989 4.7 t=y
        if ev["dkim"] == "fail" and ev["spf"] == "fail" and want and ev["disposition"] and ev["disposition"] != want and not reasons:
            out.append(("warning", "rpt.dmarc_reason_missing", f"{where}: alignment failed and disposition {ev['disposition']} differs "
                                                               f"from the published policy {want}, but no <reason> is given (RFC 9990 3.1.1.9)"))
        sigs = qa(q(rec, "auth_results"), "dkim")
        if len(sigs) > 100:
            out.append(("warning", "rpt.dmarc_too_many_sigs", f"{where}: {len(sigs)} DKIM results; SHOULD be at most 100 (RFC 9990 3.1.3)"))
        for s in sigs:
            r = _txt(q(s, "result"))
            if r and r not in DKIM_RESULTS:
                out.append(("warning", "rpt.dmarc_auth_value", f"{where}: DKIM result {r!r} is not a lowercase RFC 8601 2.7.1 value (RFC 9990 3.1.1.12)"))
        for s in qa(q(rec, "auth_results"), "spf"):
            r, sc = _txt(q(s, "result")), _txt(q(s, "scope"))
            if r and r not in SPF_RESULTS:
                out.append(("warning", "rpt.dmarc_auth_value", f"{where}: SPF result {r!r} is not a lowercase RFC 8601 2.7.2 value (RFC 9990 3.1.1.13)"))
            if sc and sc != "mfrom":
                out.append(("warning", "rpt.dmarc_auth_value", f"{where}: SPF scope {sc!r}; the only valid value is mfrom (RFC 9990 3.1.1.13)"))
    if filename:
        m = DMARC_FILENAME.fullmatch(filename.rsplit("/", 1)[-1])
        if not m:
            out.append(("warning" if from_email else "info", "rpt.dmarc_filename",
                        f"filename {filename.rsplit('/', 1)[-1]!r} does not follow receiver!policy-domain!begin!end[!id].xml[.gz] "
                        "(RFC 9990 3.5.2)" + ("" if from_email else "; may simply have been renamed locally")))
        else:
            if pdom and m.group(2).lower().rstrip(".") != pdom:
                out.append(("warning", "rpt.dmarc_filename", f"filename policy-domain {m.group(2)} differs from the report's {pdom} "
                                                             "(RFC 9990 3.5.2); the report body is authoritative"))
            if b.isdigit() and e.isdigit() and (m.group(3), m.group(4)) != (b, e):
                out.append(("warning", "rpt.dmarc_filename", f"filename timestamps {m.group(3)}!{m.group(4)} differ from date_range {b}!{e} (RFC 9990 3.5.2)"))
    return out


def _tls_time(s):
    if not isinstance(s, str) or not RFC3339.fullmatch(s):
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None


def validate_tlsrpt(j, filename=None, from_email=False):
    """RFC 8460 4.4 schema and value checks for one parsed JSON report (dict)."""
    out = []
    E = lambda sev, rid, msg: out.append((sev, rid, msg))
    for k in ("organization-name", "date-range", "contact-info", "report-id", "policies"):
        if k not in j:
            E("error", "rpt.tls_required", f"missing required field {k!r} (RFC 8460 4.4)")
    if "policies" in j and not isinstance(j["policies"], list):
        E("error", "rpt.tls_policies_array", "\"policies\" MUST be an array even for one policy (RFC 8460 4)")
    dr = j.get("date-range") or {}
    s, e = _tls_time(dr.get("start-datetime")), _tls_time(dr.get("end-datetime"))
    if dr and (s is None or e is None):
        E("error", "rpt.tls_datetime", "date-range start/end must be RFC 3339 date-times (RFC 8460 4.4)")
    elif s and e:
        if s >= e:
            E("error", "rpt.tls_datetime", "date-range start is not before end (RFC 8460 4.4)")
        su, eu = s.astimezone(dt.timezone.utc), e.astimezone(dt.timezone.utc)
        if (su.time(), eu.time()) != (dt.time(0), dt.time(0)) or (eu - su) != dt.timedelta(days=1):
            E("info", "rpt.tls_full_day", f"report covers {su:%Y-%m-%d %H:%M} to {eu:%Y-%m-%d %H:%M} UTC; SHOULD be one full UTC day (RFC 8460 4.1)")
    ci = j.get("contact-info")
    for p in j.get("policies") or [] if isinstance(j.get("policies"), list) else []:
        if not isinstance(p, dict):
            continue
        pol, summ = p.get("policy") or {}, p.get("summary") or {}
        pd = pol.get("policy-domain", "?")
        for k in ("policy-type", "policy-domain"):
            if k not in pol:
                E("error", "rpt.tls_required", f"policy missing {k!r} (RFC 8460 4.4)")
        if pol.get("policy-type") and pol["policy-type"] not in TLS_POLICY_TYPES:
            E("warning", "rpt.tls_value", f"{pd}: policy-type {pol['policy-type']!r} is not tlsa, sts or no-policy-found (RFC 8460 4.5)")
        for k in ("total-successful-session-count", "total-failure-session-count"):
            v = summ.get(k)
            if v is None:
                E("error", "rpt.tls_required", f"{pd}: summary missing {k!r} (RFC 8460 4.4)")
            elif not isinstance(v, int) or isinstance(v, bool) or v < 0:
                E("error", "rpt.tls_value", f"{pd}: {k} must be a non-negative integer (RFC 8460 4.4)")
        for f in p.get("failure-details") or []:
            if not isinstance(f, dict):
                continue
            rt = f.get("result-type")
            if rt not in TLS_RESULTS:
                E("info", "rpt.tls_value", f"{pd}: result-type {rt!r} is not one of the RFC 8460 4.3 types (may be a later registration)")
            if rt in ("validation-failure", "certificate-not-trusted") and not f.get("failure-reason-code"):
                E("info", "rpt.tls_reason_code", f"{pd}: {rt} without failure-reason-code; reporters SHOULD include one (RFC 8460 4.3.1, 4.3.3)")
    if filename:
        m = TLS_FILENAME.fullmatch(filename.rsplit("/", 1)[-1])
        if not m:
            E("warning" if from_email else "info", "rpt.tls_filename",
              f"filename {filename.rsplit('/', 1)[-1]!r} does not follow sender!policy-domain!begin!end[!id].json[.gz] (RFC 8460 5.1)"
              + ("" if from_email else "; may simply have been renamed locally"))
    return out


def cross_checks(reports):
    """Across all parsed DMARC reports: duplicate Report-IDs and overlapping periods (RFC 9990 3.1.1.4, 3.5.1)."""
    out, seen, periods = [], {}, {}
    for r in reports:
        if r.get("type") != "dmarc":
            continue
        key = (r["org_name"].lower(), r["policy_domain"])
        rid = r.get("report_id")
        if rid:
            sig = (r["begin"], r["end"], len(r["records"]))
            if (key, rid) in seen and seen[(key, rid)] != sig:
                out.append(("warning", "rpt.dmarc_duplicate_id", f"{r['org_name']}: report_id {rid!r} is reused for different data about "
                                                                 f"{r['policy_domain']}; it MUST be unique (RFC 9990 3.5.1)"))
            seen[(key, rid)] = sig
        if r["begin"].isdigit() and r["end"].isdigit():
            periods.setdefault(key, []).append((int(r["begin"]), int(r["end"]), rid))
    for (org, dom), ps in periods.items():
        ps = sorted(set(ps))
        for (b1, e1, i1), (b2, e2, i2) in zip(ps, ps[1:]):
            if b2 < e1 and i1 != i2:
                out.append(("info", "rpt.dmarc_overlap", f"{org} reports for {dom} overlap ({i1} and {i2}); reporting periods SHOULD NOT "
                                                         "overlap (RFC 9990 3.1.1.4)"))
    return out


# ------------------------------------------------------------- email wrappers
def _addr_domain(v):
    m = re.search(r"@([^>\s]+)", v or "")
    return m.group(1).lower().rstrip(".") if m else ""


def _dkim_domains(msg):
    out = []
    for h in msg.get_all("DKIM-Signature") or []:
        m = re.search(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", str(h))
        if m:
            out.append(m.group(1).lower().rstrip("."))
    return out


def _aligned(a, b):
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a) or _org(a) == _org(b))


def parse_email(data):
    """Classify an .eml: -> {"kind": "dmarc"|"tlsrpt"|"failure"|"other", "attachments": [(name, ctype, bytes)],
    "issues": [...], "failure": {...}}"""
    msg = email.message_from_bytes(data, policy=email.policy.compat32)
    out = {"kind": "other", "attachments": [], "issues": [], "failure": None}
    I = lambda sev, rid, m: out["issues"].append((sev, rid, m))
    ctype = msg.get_content_type()
    subj = re.sub(r"\s+", " ", str(msg.get("Subject", ""))).strip()
    sender = _addr_domain(str(msg.get("From", "")))
    if ctype == "multipart/report" and (msg.get_param("report-type") or "").lower() == "feedback-report":
        out["kind"] = "failure"
        out["failure"], iss = parse_failure(msg)
        out["issues"] += iss
        return out
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        pct = part.get_content_type()
        if fn or pct in ("application/gzip", "application/zip", "text/xml", "application/xml",
                         "application/tlsrpt+json", "application/tlsrpt+gzip"):
            out["attachments"].append((fn or "", pct, payload))
    tls = ctype == "multipart/report" and (msg.get_param("report-type") or "").lower() == "tlsrpt" or msg.get("TLS-Report-Domain")
    out["kind"] = "tlsrpt" if tls else "dmarc" if out["attachments"] else "other"
    if out["kind"] == "dmarc":
        if subj and not DMARC_SUBJECT.fullmatch(subj):
            I("warning", "rpt.dmarc_subject", f"Subject {subj[:80]!r} does not follow 'Report Domain: <d> Submitter: <d> [Report-ID: <id>]' (RFC 9990 3.5.2)")
        for fn, pct, payload in out["attachments"]:
            gz = payload[:2] == b"\x1f\x8b"
            want = "application/gzip" if gz else "text/xml"
            if payload[:4] != b"PK\x03\x04" and pct != want:
                I("warning", "rpt.dmarc_media_type", f"attachment {fn or '(unnamed)'} is {pct}; MUST be {want} (RFC 9990 3.5.2)")
            elif payload[:4] == b"PK\x03\x04":
                I("info", "rpt.dmarc_media_type", f"attachment {fn or '(unnamed)'} is a zip; RFC 9990 3.5.2 specifies gzip (application/gzip)")
    else:
        if out["kind"] == "tlsrpt":
            rd, rs = msg.get("TLS-Report-Domain"), msg.get("TLS-Report-Submitter")
            if not rd or not rs:
                I("warning", "rpt.tls_headers", "TLS-Report-Domain and TLS-Report-Submitter header fields MUST be included (RFC 8460 5.3)")
            out["submitter"] = (rs or "").strip().lower().rstrip(".")
            if subj and not TLS_SUBJECT.fullmatch(subj):
                I("info", "rpt.tls_subject", f"Subject {subj[:80]!r} does not follow the tlsrpt-subject ABNF (RFC 8460 5.3)")
            for fn, pct, payload in out["attachments"]:
                want = "application/tlsrpt+gzip" if payload[:2] == b"\x1f\x8b" else "application/tlsrpt+json"
                if pct != want:
                    I("warning", "rpt.tls_media_type", f"attachment {fn or '(unnamed)'} is {pct}; SHOULD be {want} (RFC 8460 5.3)")
            ds = _dkim_domains(msg)
            if not any(_aligned(d, out["submitter"] or sender) for d in ds):
                I("warning", "rpt.tls_dkim", "no DKIM-Signature from the reporting domain; reports sent by SMTP MUST carry one and "
                                             "recipients MUST ignore reports without it (RFC 8460 3)")
    if out["kind"] in ("dmarc", "tlsrpt"):
        ar = " ".join(str(h) for h in msg.get_all("Authentication-Results") or [])
        if re.search(r"\bdmarc=fail\b", ar, re.I):
            I("warning", "rpt.transport_dmarc", "the report message itself failed DMARC; report mail streams MUST pass DMARC (RFC 9990 3.5.2)")
    return out


def tls_submitter_issues(j, submitter):
    ci = _addr_domain(str(j.get("contact-info", ""))) or str(j.get("contact-info", "")).lower()
    if submitter and ci and not _aligned(submitter, ci) and submitter != ci:
        return [("warning", "rpt.tls_headers", f"TLS-Report-Submitter {submitter} does not match the contact-info domain {ci} (RFC 8460 5.3)")]
    return []


# ------------------------------------------------------------- RFC 9991 failure reports
ID_ALIGN = re.compile(r"\s*(none|(?:dkim|spf)(?:\s*,\s*(?:dkim|spf))?)\s*", re.I)


def parse_failure(msg):
    """RFC 9991 4 / RFC 6591 / RFC 5965 failure report -> (summary dict, issues)."""
    issues, I = [], None
    I = lambda sev, rid, m: issues.append((sev, rid, m))
    fb, orig = None, None
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "message/feedback-report" and fb is None:
            p = part.get_payload()
            raw = p[0].as_string() if isinstance(p, list) and p else (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            fb = email.message_from_string(raw if raw.endswith("\n\n") else raw + "\n\n", policy=email.policy.compat32)
        elif ct in ("message/rfc822", "text/rfc822-headers", "message/rfc822-headers") and orig is None:
            p = part.get_payload()
            if isinstance(p, list) and p:
                orig = p[0]
            else:
                orig = email.message_from_bytes(part.get_payload(decode=True) or b"", policy=email.policy.compat32)
    if fb is None:
        I("error", "rpt.fr_format", "multipart/report without a message/feedback-report part (RFC 5965 2, RFC 9991 4)")
        return {}, issues
    g = lambda k: str(fb.get(k, "")).strip()
    s = {"feedback_type": g("Feedback-Type").lower(), "auth_failure": g("Auth-Failure").lower(),
         "identity_alignment": g("Identity-Alignment").lower(), "source_ip": g("Source-IP"),
         "reported_domain": g("Reported-Domain").lower(), "original_mail_from": g("Original-Mail-From"),
         "arrival_date": g("Arrival-Date"), "delivery_result": g("Delivery-Result").lower(),
         "dkim_domain": g("DKIM-Domain").lower(), "dkim_identity": g("DKIM-Identity"), "dkim_selector": g("DKIM-Selector"),
         "spf_dns": g("SPF-DNS"), "header_from": "", "subject": ""}
    for k in ("Feedback-Type", "User-Agent", "Version"):
        if not g(k):
            I("error", "rpt.fr_format", f"feedback report lacks required field {k} (RFC 5965 3.1)")
    if s["feedback_type"] and s["feedback_type"] != "auth-failure":
        I("warning", "rpt.fr_format", f"Feedback-Type is {s['feedback_type']!r}; DMARC failure reports use auth-failure (RFC 6591 3.1)")
    if s["auth_failure"] and s["auth_failure"] != "dmarc":
        I("info", "rpt.fr_auth_failure", f"Auth-Failure is {s['auth_failure']!r}; DMARC failures use the type dmarc (RFC 9991 4)")
    ia = s["identity_alignment"]
    if not ia:
        I("error", "rpt.fr_identity_alignment", "Identity-Alignment field is REQUIRED (RFC 9991 4)")
        methods = set()
    elif not ID_ALIGN.fullmatch(ia) or (ia.count("dkim") > 1 or ia.count("spf") > 1):
        I("error", "rpt.fr_identity_alignment", f"Identity-Alignment {ia!r} does not match the id-align ABNF (none, or dkim/spf at most once each) (RFC 9991 4)")
        methods = set()
    else:
        methods = set(re.findall(r"dkim|spf", ia))
    if orig is not None:
        s["header_from"] = _addr_domain(str(orig.get("From", "")))
        s["subject"] = str(orig.get("Subject", ""))[:120]
        sig_doms = _dkim_domains(orig)
    else:
        sig_doms = []
    hf = s["header_from"] or s["reported_domain"]
    if "dkim" in methods and any(_aligned(d, hf) for d in sig_doms):
        miss = [k for k, v in (("DKIM-Domain", s["dkim_domain"]), ("DKIM-Identity", s["dkim_identity"]), ("DKIM-Selector", s["dkim_selector"])) if not v]
        if miss:
            I("warning", "rpt.fr_dkim_fields", f"DKIM failure of an aligned signature but {', '.join(miss)} missing (REQUIRED, RFC 9991 4)")
    if "spf" in methods and _aligned(_addr_domain(s["original_mail_from"]), hf) and not s["spf_dns"]:
        I("warning", "rpt.fr_spf_dns", "SPF failure of an aligned MAIL FROM but SPF-DNS is missing (REQUIRED, RFC 9991 4)")
    if s["delivery_result"] and s["delivery_result"] not in ("delivered", "spam", "policy", "reject", "other"):
        I("info", "rpt.fr_format", f"Delivery-Result {s['delivery_result']!r} is not a registered value (RFC 6591 3.1)")
    ar = " ".join(str(h) for h in msg.get_all("Authentication-Results") or [])
    if re.search(r"\bdmarc=fail\b", ar, re.I):
        I("info", "rpt.fr_transport", "the failure report message itself failed DMARC; it SHOULD be DMARC-aligned (RFC 9991 5.1)")
    return s, issues
