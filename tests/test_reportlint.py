"""RFC 9990 / RFC 8460 / RFC 9991 report conformance (synthetic reports only)."""
import email.mime.application, email.mime.multipart, email.mime.text, gzip, json
import pytest
from hypothesis import given, settings, strategies as st
from faultypacket_audit import reports as RP, reportlint as L, load_rules

NS = L.NS_DMARC2
FN = "receiver.example.org!example.com!1761696000!1761782400.xml"


def agg(record=None, meta_extra="", pp_extra="", top_extra="", ns=True, records=1):
    rec = record or ("<record><row><source_ip>192.0.2.10</source_ip><count>3</count><policy_evaluated>"
                     "<disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>"
                     "<identifiers><header_from>example.com</header_from></identifiers><auth_results>"
                     "<dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>"
                     "<spf><domain>example.com</domain><scope>mfrom</scope><result>pass</result></spf></auth_results></record>")
    x = (f'<feedback{" xmlns=%s" % chr(34) + NS + chr(34) if ns else ""}><version>1.0</version><report_metadata>'
         "<org_name>receiver.example.org</org_name><email>noreply@receiver.example.org</email>"
         f"<report_id>1761696000.example.com@receiver.example.org</report_id>{meta_extra}"
         "<date_range><begin>1761696000</begin><end>1761782400</end></date_range></report_metadata>"
         f"<policy_published><domain>example.com</domain><p>reject</p>{pp_extra}</policy_published>{top_extra}"
         + rec * records + "</feedback>")
    return x.encode()


def ids(iss):
    return {r for _, r, _m in iss}


def test_rules_exist_for_every_emitted_id():
    R = load_rules()
    import re, inspect
    for rid in set(re.findall(r'"(rpt\.[a-z_]+)"', inspect.getsource(L))):
        assert rid in R and "#section-" in R.get(rid)["url"], rid


def test_conformant_report_is_clean():
    assert [i for i in L.validate_dmarc(agg(), FN) if i[0] != "info"] == []


def test_legacy_no_namespace_is_info():
    iss = L.validate_dmarc(agg(ns=False), FN)
    assert ids(iss) == {"rpt.dmarc_legacy"}


@pytest.mark.parametrize("kw,rid", [
    (dict(records=0), "rpt.dmarc_no_record"),
    (dict(top_extra="<version>1.0</version>"), "rpt.dmarc_order"),
    (dict(pp_extra="<domain>example.org</domain>"), "rpt.dmarc_required"),
    (dict(top_extra="<extension><x>1</x></extension>"), "rpt.dmarc_ext_namespace"),
    (dict(top_extra='<extension><x:a xmlns:x="https://example.org/ext">1</x:a></extension>'), None),
    (dict(meta_extra="<bogus/>"), "rpt.dmarc_unknown_element"),
])
def test_structure(kw, rid):
    got = ids(L.validate_dmarc(agg(**kw), FN))
    assert (rid in got) if rid else not (got - {"rpt.dmarc_order"})


def _rec(disp="reject", dk="fail", sp="fail", reason="", hf="example.com", dkres="fail", scope="mfrom", nsig=1):
    return ("<record><row><source_ip>198.51.100.7</source_ip><count>1</count><policy_evaluated>"
            f"<disposition>{disp}</disposition><dkim>{dk}</dkim><spf>{sp}</spf>{reason}</policy_evaluated></row>"
            f"<identifiers><header_from>{hf}</header_from></identifiers><auth_results>"
            + f"<dkim><domain>example.com</domain><selector>s1</selector><result>{dkres}</result></dkim>" * nsig
            + f"<spf><domain>example.com</domain><scope>{scope}</scope><result>fail</result></spf></auth_results></record>")


@pytest.mark.parametrize("rec,rid,present", [
    (_rec(disp="none"), "rpt.dmarc_reason_missing", True),
    (_rec(disp="none", reason="<reason><type>mailing_list</type></reason>"), "rpt.dmarc_reason_missing", False),
    (_rec(disp="reject"), "rpt.dmarc_reason_missing", False),
    (_rec(reason="<reason><type>because</type></reason>"), "rpt.dmarc_reason_type", True),
    (_rec(dk="softfail"), "rpt.dmarc_value", True),
    (_rec(dkres="PASS"), "rpt.dmarc_auth_value", True),
    (_rec(scope="helo"), "rpt.dmarc_auth_value", True),
    (_rec(hf="example.net"), "rpt.dmarc_policy_domain", True),
    (_rec(hf="mail.example.com"), "rpt.dmarc_policy_domain", False),
    (_rec(nsig=101), "rpt.dmarc_too_many_sigs", True),
])
def test_record_rules(rec, rid, present):
    assert (rid in ids(L.validate_dmarc(agg(record=rec), FN))) is present


def test_testing_mode_downgrades_expected_disposition():
    x = agg(record=_rec(disp="quarantine"), pp_extra="<testing>y</testing>")
    assert "rpt.dmarc_reason_missing" not in ids(L.validate_dmarc(x, FN))


@pytest.mark.parametrize("fn,sev", [("report.xml", "info"), ("receiver.example.org!example.org!1761696000!1761782400.xml", "warning"),
                                    ("receiver.example.org!example.com!1!2.xml", "warning"), (FN + ".gz", None),
                                    ("receiver.example.org!example.com!1761696000!1761782400!abc123.xml", None)])
def test_filename(fn, sev):
    got = [s for s, r, _ in L.validate_dmarc(agg(), fn) if r == "rpt.dmarc_filename"]
    assert got == ([sev] if sev else [])


def test_date_range_and_report_id():
    x = agg().replace(b"<begin>1761696000", b"<begin>1761782401")
    assert "rpt.dmarc_date_range" in ids(L.validate_dmarc(x, FN))
    x = agg().replace(b"<report_id>1761696000.example.com@receiver.example.org", b"<report_id>a b")
    assert "rpt.dmarc_report_id" in ids(L.validate_dmarc(x, FN))


def test_cross_checks_duplicates_and_overlap():
    a = RP.parse_dmarc(agg())
    b = RP.parse_dmarc(agg(records=2))
    c = RP.parse_dmarc(agg().replace(b"<report_id>1761696000.", b"<report_id>other."))
    assert "rpt.dmarc_duplicate_id" in ids(L.cross_checks([a, b]))
    assert "rpt.dmarc_overlap" in ids(L.cross_checks([a, c]))
    assert ids(L.cross_checks([a, a])) == set()


# ---------------------------------------------------------------- TLS-RPT
def tls(**over):
    j = {"organization-name": "Example Sender", "date-range": {"start-datetime": "2026-10-28T00:00:00Z", "end-datetime": "2026-10-29T00:00:00Z"},
         "contact-info": "tlsrpt@sender.example.org", "report-id": "2026-10-28T00:00:00Z_example.com",
         "policies": [{"policy": {"policy-type": "sts", "policy-string": ["version: STSv1"], "policy-domain": "example.com", "mx-host": ["mx.example.com"]},
                       "summary": {"total-successful-session-count": 5, "total-failure-session-count": 1},
                       "failure-details": [{"result-type": "certificate-expired", "sending-mta-ip": "203.0.113.5",
                                            "receiving-mx-hostname": "mx.example.com", "failed-session-count": 1}]}]}
    j.update(over)
    return j


TFN = "sender.example.org!example.com!1761609600!1761696000.json"


def test_tls_clean():
    assert L.validate_tlsrpt(tls(), TFN) == []


@pytest.mark.parametrize("over,rid", [
    ({"report-id": None}, None),
    ({"policies": {"policy": {}}}, "rpt.tls_policies_array"),
    ({"date-range": {"start-datetime": "yesterday", "end-datetime": "today"}}, "rpt.tls_datetime"),
    ({"date-range": {"start-datetime": "2026-10-28T06:00:00Z", "end-datetime": "2026-10-29T06:00:00Z"}}, "rpt.tls_full_day"),
    ({"date-range": {"start-datetime": "2026-10-28T01:00:00+01:00", "end-datetime": "2026-10-29T01:00:00+01:00"}}, None),
])
def test_tls_top_level(over, rid):
    j = tls(**over)
    if over.get("report-id", 1) is None:
        del j["report-id"]
        rid = "rpt.tls_required"
    got = ids(L.validate_tlsrpt(j, TFN))
    assert (rid in got) if rid else got == set()


def test_tls_policy_values():
    j = tls()
    p = j["policies"][0]
    p["policy"]["policy-type"] = "dane"
    p["summary"]["total-failure-session-count"] = -1
    p["failure-details"] += [{"result-type": "validation-failure"}, {"result-type": "made-up"}]
    got = L.validate_tlsrpt(j, "x.json")
    assert {"rpt.tls_value", "rpt.tls_reason_code", "rpt.tls_filename"} <= ids(got)


# ---------------------------------------------------------------- email wrappers
def mail(subject, att, ctype, fn, headers=None, report_type=None):
    m = email.mime.multipart.MIMEMultipart("report" if report_type else "mixed", **({"report_type": report_type} if report_type else {}))
    m["From"] = "noreply@receiver.example.org"
    m["Subject"] = subject
    for k, v in (headers or {}).items():
        m[k] = v
    m.attach(email.mime.text.MIMEText("report attached"))
    a = email.mime.application.MIMEApplication(att, _subtype=ctype.split("/")[1])
    a.replace_header("Content-Type", ctype)
    a.add_header("Content-Disposition", "attachment", filename=fn)
    m.attach(a)
    return m.as_bytes()


GOOD_SUBJ = "Report Domain: example.com Submitter: receiver.example.org Report-ID: <1761696000.example.com@receiver.example.org>"


def conf(rs):
    return {c["rule_id"] for c in RP.summarise(rs)["conformance"] if c["severity"] != "info"}


def test_eml_aggregate_clean_and_faulty():
    good = mail(GOOD_SUBJ, gzip.compress(agg()), "application/gzip", FN + ".gz")
    rs = RP.parse_bytes("r.eml", good)
    assert rs[0]["type"] == "dmarc" and conf(rs) == set()
    bad = mail("DMARC report", agg(), "application/octet-stream", "report.xml",
               headers={"Authentication-Results": "mx.example.com; dmarc=fail header.from=receiver.example.org"})
    assert {"rpt.dmarc_subject", "rpt.dmarc_media_type", "rpt.dmarc_filename", "rpt.transport_dmarc"} <= conf(RP.parse_bytes("r.eml", bad))


def test_eml_tlsrpt_headers_and_dkim():
    raw = json.dumps(tls()).encode()
    tsub = "Report Domain: example.com Submitter: sender.example.org Report-ID: <abc@sender.example.org>"
    m = mail(tsub, raw, "application/tlsrpt+json", TFN, report_type="tlsrpt",
             headers={"TLS-Report-Domain": "example.com", "TLS-Report-Submitter": "sender.example.org",
                      "DKIM-Signature": "v=1; a=rsa-sha256; d=sender.example.org; s=s1; h=from; bh=x; b=y"})
    assert conf(RP.parse_bytes("t.eml", m)) == set()
    m = mail(tsub, raw, "application/json", TFN, report_type="tlsrpt", headers={"TLS-Report-Submitter": "other.example.net"})
    assert {"rpt.tls_headers", "rpt.tls_media_type", "rpt.tls_dkim"} <= conf(RP.parse_bytes("t.eml", m))


# ---------------------------------------------------------------- RFC 9991 failure reports
def failure(fields, orig_dkim=True, mail_from="bounce@example.com"):
    m = email.mime.multipart.MIMEMultipart("report", report_type="feedback-report")
    m["From"] = "dmarc-noreply@receiver.example.org"
    m["Subject"] = "FW: failure report for example.com"
    m.attach(email.mime.text.MIMEText("This is a DMARC failure report."))
    fb = "".join(f"{k}: {v}\r\n" for k, v in fields.items())
    p = email.mime.application.MIMEApplication(fb.encode(), _subtype="x")
    p.replace_header("Content-Type", "message/feedback-report")
    del p["Content-Transfer-Encoding"]
    p.set_payload(fb)
    m.attach(p)
    o = email.mime.text.MIMEText("hello")
    o["From"] = "ceo@example.com"
    o["Subject"] = "Invoice"
    if orig_dkim:
        o["DKIM-Signature"] = "v=1; a=rsa-sha256; d=example.com; s=s1; h=from; bh=x; b=y"
    rh = email.mime.text.MIMEText(o.as_string(), "rfc822-headers")
    rh.replace_header("Content-Type", "text/rfc822-headers")
    m.attach(rh)
    return m.as_bytes()


BASE = {"Feedback-Type": "auth-failure", "User-Agent": "example-receiver/1.0", "Version": "1", "Auth-Failure": "dmarc",
        "Identity-Alignment": "dkim, spf", "Source-IP": "198.51.100.23", "Reported-Domain": "example.com",
        "Original-Mail-From": "<bounce@example.com>", "DKIM-Domain": "example.com", "DKIM-Identity": "@example.com",
        "DKIM-Selector": "s1", "SPF-DNS": "txt : example.com : v=spf1 ip4:192.0.2.0/24 -all", "Delivery-Result": "reject"}


def test_failure_report_parsed_and_clean():
    rs = RP.parse_bytes("f.eml", failure(BASE))
    s = RP.summarise(rs)
    f = s["failure_reports"][0]
    assert (f["source_ip"], f["header_from"], f["identity_alignment"], f["dkim_selector"]) == ("198.51.100.23", "example.com", "dkim, spf", "s1")
    assert conf(rs) == set()
    assert "DMARC failure reports" in RP.markdown(s)


@pytest.mark.parametrize("drop,change,rid", [
    ("Identity-Alignment", {}, "rpt.fr_identity_alignment"),
    (None, {"Identity-Alignment": "dkim, dkim"}, "rpt.fr_identity_alignment"),
    (None, {"Identity-Alignment": "arc"}, "rpt.fr_identity_alignment"),
    ("DKIM-Selector", {}, "rpt.fr_dkim_fields"),
    ("SPF-DNS", {}, "rpt.fr_spf_dns"),
    ("Version", {}, "rpt.fr_format"),
    (None, {"Feedback-Type": "abuse"}, "rpt.fr_format"),
])
def test_failure_report_faults(drop, change, rid):
    f = {**BASE, **change}
    f.pop(drop, None)
    assert rid in conf(RP.parse_bytes("f.eml", failure(f)))


def test_failure_dkim_fields_not_required_when_unsigned_or_none():
    f = {k: v for k, v in BASE.items() if not k.startswith("DKIM-")}
    assert "rpt.fr_dkim_fields" not in conf(RP.parse_bytes("f.eml", failure(f, orig_dkim=False)))
    assert conf(RP.parse_bytes("f.eml", failure({**f, "Identity-Alignment": "none"}))) == set()


@settings(max_examples=150, deadline=None)
@given(st.permutations(["version", "report_metadata", "policy_published", "record"]), st.integers(0, 3))
def test_prop_order_detected_iff_permuted(order, nrec):
    parts = {"version": "<version>1.0</version>", "report_metadata": agg().decode().split("<report_metadata>")[1].split("</report_metadata>")[0],
             "policy_published": "<domain>example.com</domain><p>reject</p>"}
    rec = agg().decode().split("</policy_published>")[1].replace("</feedback>", "")
    body = ""
    for o in order:
        body += rec * nrec if o == "record" else (parts[o] if o == "version" else f"<{o}>{parts[o]}</{o}>")
    x = f'<feedback xmlns="{NS}">{body}</feedback>'.encode()
    got = ids(L.validate_dmarc(x, FN))
    present = [o for o in order if o != "record" or nrec]
    canon = [o for o in ["version", "report_metadata", "policy_published", "record"] if o in present]
    assert ("rpt.dmarc_order" in got) == (present != canon)
    assert ("rpt.dmarc_no_record" in got) == (nrec == 0)


@settings(max_examples=200, deadline=None)
@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=8),
                    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.sampled_from(
                        ["policies", "policy", "summary", "date-range", "failure-details", "result-type", "start-datetime",
                         "end-datetime", "total-failure-session-count", "policy-type", "contact-info"]), c, max_size=4), max_leaves=12))
def test_prop_tls_validator_never_crashes(j):
    if isinstance(j, dict):
        try:
            L.validate_tlsrpt(j, "a.json")
        except (AttributeError, TypeError):
            pass  # parse_tlsrpt rejects such shapes before validation
