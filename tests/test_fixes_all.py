"""One test per fix class: the fix exists, names its rule, keeps unknowns as
REPLACE- placeholders, and (for DNS records) is itself valid when re-audited."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from faultypacket_audit import audit, load_rules
from faultypacket_audit.checks import spf, dmarc
from tests.zone import Zone, GOOD
from tests.keys import RSA1024, RSA512

R = load_rules()
RULE_IDS = {r["id"] for r in R.data["rules"]} if hasattr(R, "data") else None


def fx(z, d="good.test", checks=None, opts=None):
    return audit(d, Zone({**GOOD, **z}), R, checks, opts)["fixes"]


def by(fixes, rid):
    return [f for f in fixes if f["rule_id"] == rid]


def test_every_fix_names_a_real_rule_and_has_fields():
    z = {("bad.test", "TXT"): ["v=spf1 ptr a:v1.bad.test a:v2.bad.test a:v3.bad.test ~all"]}
    for f in fx(z, "bad.test"):
        assert f["rule_id"] in R and f["type"] in ("TXT", "MX", "CAA", "CNAME", "FILE", "STEPS")
        assert f["name"] and f["value"] and f["note"]


def test_spf_no_record_fix():
    f = by(fx({}, "none.test"), "spf.no_record")
    assert f and "REPLACE-" in f[0]["value"] and f[0]["value"].endswith("-all")


def test_spf_softfail_to_fail_keeps_terms_and_is_valid():
    f = by(fx({("x.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 include:i.test ~all"], ("i.test", "TXT"): ["v=spf1 -all"]}, "x.test"),
           "spf.all_softfail")
    assert f[0]["value"] == "v=spf1 ip4:192.0.2.0/24 include:i.test -all"
    r = spf.analyse("x.test", Zone({("x.test", "TXT"): [f[0]["value"]], ("i.test", "TXT"): ["v=spf1 -all"]}))
    assert r["result"] == "ok" and spf.all_qualifier(f[0]["value"]) == "-"


@pytest.mark.parametrize("rec,rid", [("v=spf1 ip4:192.0.2.1 +all", "spf.all_pass"), ("v=spf1 ip4:192.0.2.1 ?all", "spf.all_neutral"),
                                     ("v=spf1 ip4:192.0.2.1", "spf.no_all")])
def test_spf_permissive_all_fixed(rec, rid):
    f = by(fx({("x.test", "TXT"): [rec]}, "x.test"), rid)
    assert f and f[0]["value"] == "v=spf1 ip4:192.0.2.1 -all"


def test_spf_lookup_limit_flattening_steps_name_heaviest_include():
    z = {("x.test", "TXT"): ["v=spf1 include:big.test " + " ".join(f"include:i{n}.test" for n in range(3)) + " -all"],
         ("big.test", "TXT"): ["v=spf1 " + " ".join(f"include:b{n}.test" for n in range(8)) + " -all"]}
    for n in range(8):
        z[(f"b{n}.test", "TXT")] = ["v=spf1 -all"]
    for n in range(3):
        z[(f"i{n}.test", "TXT")] = ["v=spf1 -all"]
    f = by(fx(z, "x.test"), "spf.lookup_limit")
    assert f and f[0]["type"] == "STEPS" and "big.test (9)" in f[0]["value"] and "ip4:" in f[0]["value"]
    assert not by(fx(z, "x.test"), "spf.all_softfail")


def test_spf_void_lookup_fix_lists_void_terms():
    f = by(fx({("x.test", "TXT"): ["v=spf1 a:v1.test a:v2.test a:v3.test -all"]}, "x.test"), "spf.void_limit")
    assert f and all(t in f[0]["value"] for t in ("a:v1.test", "a:v2.test", "a:v3.test"))


def test_spf_multiple_records_fix():
    assert by(fx({("x.test", "TXT"): ["v=spf1 -all", "v=spf1 mx -all"]}, "x.test"), "spf.multiple_records")


def test_spf_ptr_and_missing_include_fixes():
    f = fx({("x.test", "TXT"): ["v=spf1 ptr include:gone.test -all"]}, "x.test")
    assert by(f, "spf.ptr") and by(f, "spf.missing_record")


def test_dmarc_no_record_fix_is_valid_dmarc():
    f = by(fx({}, "none.test"), "dmarc.no_record")[0]
    d, issues = dmarc.validate(f["value"])
    assert d["p"] == "none" and not [i for i in issues if i[0] == "error"] and "REPLACE-" in f["value"]


def test_dmarc_p_none_staged_steps():
    f = by(fx({("_dmarc.good.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@good.test"]}), "dmarc.p_none")
    assert f and "p=quarantine" in f[0]["value"] and "p=reject" in f[0]["value"]


def test_dmarc_no_rua_added_with_placeholder():
    f = [x for x in fx({("_dmarc.good.test", "TXT"): ["v=DMARC1; p=reject"]}) if x["name"] == "_dmarc.good.test" and x["type"] == "TXT"]
    assert f and "rua=mailto:REPLACE-dmarc-reports@good.test" in f[0]["value"]


def test_dmarc_fixed_record_revalidates_clean():
    rec = "v=DMARC1; p=reject; pct=25; fo=0:1; rua=mailto:d@good.test!10m; ri=3600"
    f = [x for x in fx({("_dmarc.good.test", "TXT"): [rec]}) if x["name"] == "_dmarc.good.test" and x["type"] == "TXT"][0]
    _, issues = dmarc.validate(f["value"])
    assert not [i for i in issues if i[0] in ("error", "warning")]
    assert {i[1] for i in issues} <= {"p_none"}


def test_dmarc_test_mode_removed():
    f = [x for x in fx({("_dmarc.good.test", "TXT"): ["v=DMARC1; p=reject; t=y; rua=mailto:d@good.test"]})
         if x["name"] == "_dmarc.good.test" and x["type"] == "TXT"]
    assert f and "t=y" not in f[0]["value"]


def test_dmarc_unauthorised_rua_names_exact_record():
    f = by(fx({("_dmarc.good.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@reports.example"]}), "dmarc.unauthorised_rua")
    assert f and f[0]["name"] == "good.test._report._dmarc.reports.example" and f[0]["value"] == "v=DMARC1"


@pytest.mark.parametrize("key,rid", [(RSA1024, "dkim.recommended_rsa_bits"), (RSA512, "dkim.min_rsa_bits")])
def test_dkim_weak_key_rotation_steps(key, rid):
    f = by(fx({("s1._domainkey.good.test", "TXT"): ["v=DKIM1; k=rsa; p=" + key]}), rid)
    assert f and f[0]["name"] == "s1._domainkey.good.test" and "2048" in f[0]["value"] and "p=" in f[0]["value"]
    assert "7 days" in f[0]["value"]


def test_mta_sts_policy_file_and_txt_use_real_mx():
    f = fx({("good.test", "MX"): ["10 mail.good.test."]})
    pol = [x for x in f if x["type"] == "FILE"][0]
    assert pol["name"] == "https://mta-sts.good.test/.well-known/mta-sts.txt"
    assert pol["value"].startswith("version: STSv1\nmode: testing\n") and "mx: mail.good.test\n" in pol["value"]
    txt = [x for x in f if x["name"] == "_mta-sts.good.test"][0]
    assert txt["value"].startswith("v=STSv1; id=")


def test_mta_sts_policy_fix_parses_with_engine():
    from faultypacket_audit.checks import _mtasts_engine as E
    pol = [x for x in fx({("good.test", "MX"): ["10 mail.good.test."]}) if x["type"] == "FILE"][0]["value"]
    p, issues = E.parse_policy(pol)
    assert not [i for i in issues if i["severity"] == "error"], issues
    assert p["mode"] == "testing" and p["mx"] == ["mail.good.test"]
    txt = [x for x in fx({("good.test", "MX"): ["10 mail.good.test."]}) if x["name"] == "_mta-sts.good.test"][0]["value"]
    fields, iss = E.parse_sts_txt(txt)
    assert fields and not [i for i in iss if i["severity"] == "error"], iss


def test_tlsrpt_fix():
    f = by(fx({}), "tlsrpt.absent")
    assert f and f[0]["value"].startswith("v=TLSRPTv1; rua=mailto:REPLACE-")


def test_mx_cname_fix_points_at_canonical():
    z = {("good.test", "MX"): ["10 alias.good.test."], ("alias.good.test", "CNAME"): ["real.good.test."],
         ("real.good.test", "A"): ["192.0.2.30"]}
    f = by(fx(z), "mx.cname")
    assert f and f[0]["type"] == "MX" and f[0]["value"] == "10 real.good.test."


def test_caa_absent_and_iodef_fixes():
    assert by(fx({}), "caa.absent")[0]["value"] == '0 issue "REPLACE-your-ca.example"'
    f = by(fx({("good.test", "CAA"): ['0 issue "letsencrypt.org"', '0 iodef "security@good.test"']}), "caa.iodef")
    assert f and f[0]["value"].startswith('0 iodef "mailto:REPLACE-')


def test_dnssec_unsigned_pointer():
    f = by(fx({}), "dnssec.unsigned")
    assert f and "DS" in f[0]["value"] and "registrar" in f[0]["value"]


def test_bimi_absent_fix_and_enforcement_step():
    assert by(fx({}), "bimi.absent")[0]["name"] == "default._bimi.good.test"
    z = {("_dmarc.good.test", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@good.test"],
         ("default._bimi.good.test", "TXT"): ["v=BIMI1; l=https://good.test/l.svg; a="]}
    assert by(fx(z, checks=["dmarc", "bimi"]), "bimi.dmarc_enforcement")


def test_good_domain_has_no_record_fixes_for_spf_or_dmarc():
    f = fx({})
    assert not [x for x in f if x["rule_id"].startswith(("spf.", "dmarc."))]


def test_fixes_never_crash_audit(monkeypatch):
    from faultypacket_audit import fixes
    monkeypatch.setattr(fixes, "suggest", lambda d, c: 1 / 0)
    assert audit("good.test", Zone(GOOD), R)["fixes"] == []
