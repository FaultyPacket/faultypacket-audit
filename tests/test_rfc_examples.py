"""Golden fixtures taken from the RFC texts themselves. Each case names the
RFC section it comes from; expected values follow the RFC's own counting or
syntax rules."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from faultypacket_audit import audit, load_rules
from faultypacket_audit.checks import spf, dmarc
from faultypacket_audit import headers as H
from tests.zone import Zone

R = load_rules()
FIX = os.path.join(os.path.dirname(__file__), "fixtures", "headers")

# RFC 7208 Appendix A zone (A records are illustrative)
A_ZONE = {
    ("example.com", "A"): ["192.0.2.10", "192.0.2.11"], ("amy.example.com", "A"): ["192.0.2.65"],
    ("bob.example.com", "A"): ["192.0.2.66"], ("mail-a.example.com", "A"): ["192.0.2.129"],
    ("mail-b.example.com", "A"): ["192.0.2.130"], ("www.example.com", "CNAME"): ["example.com."],
    ("example.com", "MX"): ["10 mail-a.example.com.", "20 mail-b.example.com."],
    ("example.org", "MX"): ["10 mail-c.example.org."], ("mail-c.example.org", "A"): ["192.0.2.140"],
    ("example.org", "A"): ["192.0.2.200"],
}

# RFC 7208 A.1 "Simple Examples": (record, DNS-querying terms per 4.6.4, extra issue code)
A1 = [
    ("v=spf1 +all", 0, None), ("v=spf1 a -all", 1, None), ("v=spf1 a:example.org -all", 1, None),
    ("v=spf1 mx -all", 1, None), ("v=spf1 mx:example.org -all", 1, None),
    ("v=spf1 mx mx:example.org -all", 2, None), ("v=spf1 mx/30 mx:example.org/30 -all", 2, None),
    ("v=spf1 ptr -all", 1, "ptr"), ("v=spf1 ip4:192.0.2.128/28 -all", 0, None),
]


@pytest.mark.parametrize("rec,lookups,code", A1, ids=[a[0] for a in A1])
def test_rfc7208_a1_simple_examples(rec, lookups, code):
    r = spf.analyse("example.com", Zone({**A_ZONE, ("example.com", "TXT"): [rec]}))
    assert r["lookups"] == lookups
    codes = {i["code"] for i in r["issues"]}
    assert (code in codes) if code else not (codes - {"ptr"})


def test_rfc7208_a2_multiple_domain_example():
    z = {**A_ZONE, ("example.org", "TXT"): ["v=spf1 include:example.com include:example.net -all"],
         ("example.com", "TXT"): ["v=spf1 mx -all"], ("example.net", "TXT"): ["v=spf1 a -all"],
         ("example.net", "A"): ["192.0.2.50"]}
    r = spf.analyse("example.org", Zone(z))
    assert r["lookups"] == 4 and r["result"] == "ok"


@pytest.mark.parametrize("sub", ["la", "ny", "sf"])
def test_rfc7208_a2_redirect_examples(sub):
    z = {**A_ZONE, (f"{sub}.example.org", "TXT"): ["v=spf1 redirect=example.org"],
         ("example.org", "TXT"): ["v=spf1 mx -all"]}
    r = spf.analyse(f"{sub}.example.org", Zone(z))
    assert r["lookups"] == 2 and r["tree"]["children"][0]["via"] == "redirect"


@pytest.mark.parametrize("rec", ["v=spf1 exists:%{l1r+}.%{d}", "v=spf1 exists:%{ir}.%{l1r+}.%{d}",
                                 "v=spf1 exists:_h.%{h}._l.%{l}._o.%{o}._i.%{i}._spf.%{d} ?all",
                                 "v=spf1 mx ?exists:%{ir}.whitelist.example.org -all",
                                 "v=spf1 mx exists:%{l}._spf_verify.%{d} -all",
                                 "v=spf1 mx redirect=%{l1r+}._at_.%{o}._spf.%{d}"])
def test_rfc7208_a3_a5_macro_examples_counted_not_resolved(rec):
    r = spf.analyse("example.com", Zone({**A_ZONE, ("example.com", "TXT"): [rec]}))
    assert "macro" in {i["code"] for i in r["issues"]} and r["result"] == "ok"


def test_rfc7208_a4_restrictive_plus_all_is_warning_not_error():
    z = {("example.com", "TXT"): ["v=spf1 -include:ip4._spf.example.com -include:ptr._spf.example.com +all"],
         ("ip4._spf.example.com", "TXT"): ["v=spf1 -ip4:192.0.2.0/24 +all"],
         ("ptr._spf.example.com", "TXT"): ["v=spf1 -ptr +all"]}
    c = next(c for c in audit("example.com", Zone(z), R, ["spf"])["checks"])
    f = [f for f in c["findings"] if f.rule_id == "spf.all_pass"]
    assert f and f[0].severity == "warning"


def test_plain_plus_all_is_error():
    c = audit("x.test", Zone({("x.test", "TXT"): ["v=spf1 +all"]}), R, ["spf"])["checks"][0]
    assert [f.severity for f in c["findings"] if f.rule_id == "spf.all_pass"] == ["error"]


@pytest.mark.parametrize("rec,q", [("v=spf1 -all", "-"), ("v=spf1 ~all", "~"), ("v=spf1 ?all", "?"),
                                   ("v=spf1 all", "+"), ("v=spf1 mx", None), ("v=spf1 redirect=x.test", "redirect"),
                                   ("v=spf1 -ALL", "-"), ("v=spf1 mx ~all -all", "~")])
def test_all_qualifier(rec, q):
    assert spf.all_qualifier(rec) == q


# RFC 7208 4.5 / 4.6 / 5 / 12 syntax cases
SYNTAX = [
    ("v=spf1 ip4:192.0.2.0/33 -all", "syntax"), ("v=spf1 ip6:2001:db8::/129 -all", "syntax"),
    ("v=spf1 ip4:300.1.1.1 -all", "syntax"), ("v=spf1 ip4:2001:db8::1 -all", "syntax"),
    ("v=spf1 ip6:192.0.2.1 -all", "syntax"), ("v=spf1 include: -all", "syntax"),
    ("v=spf1 exists: -all", "syntax"), ("v=spf1 foo -all", "syntax"), ("v=spf1 a/33 -all", "syntax"),
    ("v=spf1 a//129 -all", "syntax"), ("v=spf1 redirect=a.test redirect=b.test", "duplicate_modifier"),
    ("v=spf1 exp=a.test exp=b.test -all", "duplicate_modifier"), ("v=spf1 a:-bad-.test -all", "syntax"),
]


@pytest.mark.parametrize("rec,code", SYNTAX, ids=[s[0] for s in SYNTAX])
def test_rfc7208_syntax_errors(rec, code):
    r = spf.analyse("x.test", Zone({("x.test", "TXT"): [rec], ("a.test", "TXT"): ["v=spf1 -all"],
                                    ("b.test", "TXT"): ["v=spf1 -all"]}))
    assert code in {i["code"] for i in r["issues"]} and r["result"] == "permerror"


VALID = ["v=spf1 ip4:192.0.2.0/24 -all", "v=spf1 ip6:2001:db8::/32 -all", "v=spf1 a/24 -all",
         "v=spf1 a//64 -all", "v=spf1 a/24//64 -all", "v=spf1 mx/28 -all", "v=spf1 ip4:192.0.2.1 ?all",
         "v=spf1 unknown-mod=foo -all", "v=spf1 IP4:192.0.2.1 -ALL", "v=spf1 -all"]


@pytest.mark.parametrize("rec", VALID)
def test_rfc7208_valid_syntax(rec):
    z = Zone({("x.test", "TXT"): [rec], ("x.test", "A"): ["192.0.2.1"], ("x.test", "MX"): ["10 x.test."]})
    assert spf.analyse("x.test", z)["result"] == "ok"


@pytest.mark.parametrize("txt,n", [(["v=spf10 -all"], 0), (["v=spf1"], 1), (["V=SPF1 -all"], 1),
                                   (["v=spf1 -all", "v=spf1 ~all"], 2), (["spf1 -all"], 0)])
def test_rfc7208_4_5_record_selection(txt, n):
    recs, _ = spf.get_spf(Zone({("x.test", "TXT"): txt}), "x.test")
    assert len(recs) == n


def test_rfc7208_4_5_multiple_records_permerror():
    r = spf.analyse("x.test", Zone({("x.test", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]}))
    assert "multiple_records" in {i["code"] for i in r["issues"]}


def test_rfc7208_4_6_4_eleventh_lookup_is_permerror():
    z = {("x.test", "TXT"): ["v=spf1 " + " ".join(f"include:i{n}.test" for n in range(11)) + " -all"]}
    for n in range(11):
        z[(f"i{n}.test", "TXT")] = ["v=spf1 -all"]
    assert "lookup_limit" in {i["code"] for i in spf.analyse("x.test", Zone(z))["issues"]}


def test_rfc7208_4_6_4_ten_lookups_is_fine():
    z = {("x.test", "TXT"): ["v=spf1 " + " ".join(f"include:i{n}.test" for n in range(10)) + " -all"]}
    for n in range(10):
        z[(f"i{n}.test", "TXT")] = ["v=spf1 -all"]
    assert spf.analyse("x.test", Zone(z))["result"] == "ok"


def test_rfc7208_4_6_4_third_void_lookup_is_permerror():
    z = {("x.test", "TXT"): ["v=spf1 a:v1.test a:v2.test a:v3.test -all"]}
    assert "void_limit" in {i["code"] for i in spf.analyse("x.test", Zone(z))["issues"]}


def test_rfc7208_4_6_4_two_voids_ok():
    z = {("x.test", "TXT"): ["v=spf1 a:v1.test a:v2.test -all"]}
    assert "void_limit" not in {i["code"] for i in spf.analyse("x.test", Zone(z))["issues"]}


# ---------------------------------------------------------------- RFC 9989 Appendix B records
B = {
    "B.2.1": "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com",
    "B.2.2": "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@example.com",
    "B.2.3": "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@thirdparty.example.net",
    "B.2.4a": "v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net; t=y",
    "B.2.4b": "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net",
    "B.3.1": "v=DMARC1; p=reject; aspf=r; rua=mailto:dmarc-feedback@example.com",
}


@pytest.mark.parametrize("sec", list(B))
def test_rfc9989_appendix_b_records_are_valid(sec):
    d, issues = dmarc.validate(B[sec])
    assert not [i for i in issues if i[0] == "error"], issues
    assert d["v"] == "DMARC1" and d["p"] in ("none", "quarantine", "reject")


def test_rfc9989_b24_test_mode_flagged():
    _, issues = dmarc.validate(B["B.2.4a"])
    assert "test_mode" in {i[1] for i in issues}


def test_rfc9989_b23_third_party_ruf_needs_authorisation():
    z = Zone({("_dmarc.example.com", "TXT"): [B["B.2.3"]]})
    codes = {f.rule_id for f in audit("example.com", z, R, ["dmarc"])["checks"][0]["findings"]}
    assert "dmarc.unauthorised_ruf" in codes


def test_rfc9989_b23_authorised_when_report_record_published():
    z = Zone({("_dmarc.example.com", "TXT"): [B["B.2.3"]],
              ("example.com._report._dmarc.thirdparty.example.net", "TXT"): ["v=DMARC1;"]})
    codes = {f.rule_id for f in audit("example.com", z, R, ["dmarc"])["checks"][0]["findings"]}
    assert "dmarc.unauthorised_ruf" not in codes


@pytest.mark.parametrize("rec,code", [
    ("v=DMARC1; p=bogus", "bad_p"), ("v=DMARC1; p=none; sp=x", "bad_sp"), ("v=DMARC1; p=none; np=x", "bad_np"),
    ("v=DMARC1; p=none; adkim=x", "bad_adkim"), ("v=DMARC1; p=none; aspf=q", "bad_aspf"),
    ("v=DMARC1; p=none; psd=x", "bad_psd"), ("v=DMARC1; p=none; t=maybe", "bad_t"),
    ("v=DMARC1; p=none; fo=0:1", "bad_fo"), ("v=DMARC1; p=none; fo=d:d", "bad_fo"), ("v=DMARC1; p=none; fo=x", "bad_fo"),
    ("p=none; v=DMARC1", "version"), ("v=dmarc1; p=none", "version"), ("v=DMARC1; p=none; rua=", "empty_rua"),
    ("v=DMARC1; p=none; rua=mailto:nobody", "bad_uri_rua"), ("v=DMARC1; p=none; rua=https://x.test/r", "scheme_rua"),
    ("v=DMARC1; p=none; rua=mailto:r@x.test!10m", "obsolete_size"), ("v=DMARC1; p=none; pct=50", "historic_pct"),
    ("v=DMARC1; p=none; pct=0", "historic_pct"), ("v=DMARC1; p=none; rf=afrf", "historic_tag"),
    ("v=DMARC1; p=none; ri=3600", "historic_tag"), ("v=DMARC1; p=none; zz=1", "unknown_tag"),
    ("v=DMARC1; p=none; p=reject", "duplicate_tag"), ("v=DMARC1", "no_p"), ("v=DMARC1; p=none", "no_rua"),
    ("v=DMARC1; p=none", "p_none"), ("v=DMARC1; p=none; fo=1", "fo_without_ruf"), ("v=DMARC1; p=none; junk", "syntax"),
])
def test_rfc9989_4_7_4_8_tag_rules(rec, code):
    _, issues = dmarc.validate(rec)
    assert code in {i[1] for i in issues}


@pytest.mark.parametrize("name,targets", [
    ("a.b.c.d.e.f.g.h.i.j.example.com", 8), ("mail.example.com", 3), ("example.com", 2), ("com", 1)])
def test_rfc9989_4_10_tree_walk_target_count(name, targets):
    assert len(dmarc.walk_targets(name)) == targets


def test_rfc9989_4_10_tree_walk_skips_to_eight_labels():
    t = dmarc.walk_targets("a.b.c.d.e.f.g.h.i.j.example.com")
    assert t[0] == "a.b.c.d.e.f.g.h.i.j.example.com" and t[1].count(".") == 6


# ---------------------------------------------------------------- RFC 8601 Appendix B
AR = [
    ("B.2", "example.org 1; none", "example.org", []),
    ("B.3", "example.com; spf=pass smtp.mailfrom=example.net", "example.com", [("spf", "pass")]),
    ("B.4a", "example.com; auth=pass (cram-md5) smtp.auth=sender@example.net; spf=pass smtp.mailfrom=example.net",
     "example.com", [("auth", "pass"), ("spf", "pass")]),
    ("B.4b", "example.com; iprev=pass policy.iprev=192.0.2.200", "example.com", [("iprev", "pass")]),
    ("B.5a", "example.com; dkim=pass (good signature) header.d=example.com", "example.com", [("dkim", "pass")]),
    ("B.5b", "example.com; auth=pass (cram-md5) smtp.auth=sender@example.com; spf=fail smtp.mailfrom=example.com",
     "example.com", [("auth", "pass"), ("spf", "fail")]),
    ("B.6a", 'example.com; dkim=pass reason="good signature" header.i=@mail-router.example.net; '
             'dkim=fail reason="bad signature" header.i=@newyork.example.com',
     "example.com", [("dkim", "pass"), ("dkim", "fail")]),
    ("B.6b", "example.net; dkim=pass (good signature) header.i=@newyork.example.com", "example.net", [("dkim", "pass")]),
    ("B.7", "foo.example.net (foobar) 1 (baz); dkim (Because I like it) / 1 (One yay) = (wait for it) fail "
            "policy (A dot can go here) . (like that) expired (this surprised me) = (as I wasn't expecting it) 1362471462",
     "foo.example.net", [("dkim", "fail")]),
]


@pytest.mark.parametrize("sec,value,authserv,results", AR, ids=[a[0] for a in AR])
def test_rfc8601_appendix_b_examples(sec, value, authserv, results):
    r = H.parse_ar(value)
    assert r["authserv_id"] == authserv
    assert [(x["method"], x["result"]) for x in r["results"]] == results


def test_rfc8601_b7_property_through_comments():
    r = H.parse_ar(AR[-1][1])
    assert r["results"][0]["props"] == {"policy.expired": "1362471462"} and r["version"] == "1"


def test_rfc8601_b6_reason_and_identity():
    r = H.parse_ar(AR[6][1])["results"]
    assert r[0]["reason"] == "good signature" and r[1]["props"]["header.i"] == "@newyork.example.com"


def test_rfc9989_b31_alignment_example():
    # Author example.com, SPF id mail.example.com, DKIM id example.com, aspf=r: both align
    assert H.aligned("mail.example.com", "example.com", "r") and H.aligned("example.com", "example.com", "s")
    assert not H.aligned("mail.example.com", "example.com", "s")
