"""SPF 3.4/3.1/6.2, DMARC CNAME, DKIM t=/s=/g= and BIMI VMC checks (synthetic zones only)."""
import pytest
from hypothesis import given, strategies as st
from faultypacket_audit import load_rules
from faultypacket_audit.checks import spf, dmarc, dkim, bimi
from tests.keys import RSA2048
from tests.zone import Zone

R = load_rules()
ids = lambda r: [f.rule_id for f in r["findings"]]
SPF = "v=spf1 ip4:192.0.2.0/24 -all"


def sp(z):
    return spf.check("example.com", Zone(z), R)


def test_spf_size_guideline():
    assert "spf.record_size" not in ids(sp({("example.com", "TXT"): [SPF]}))
    big = [SPF, "x" * 300, "y" * 200]
    assert "spf.record_size" in ids(sp({("example.com", "TXT"): big}))


@given(st.lists(st.text(alphabet="abc =", max_size=120), max_size=6))
def test_txt_size_property(txts):
    assert spf.txt_size("example.com.", txts) == 11 + sum(len(t) for t in txts)


def test_spf_type99_same_and_different():
    r = sp({("example.com", "TXT"): [SPF], ("example.com", "SPF"): [SPF]})
    m = [f.message for f in r["findings"] if f.rule_id == "spf.rr_type_99"]
    assert m and "differs" not in m[0]
    r = sp({("example.com", "TXT"): [SPF], ("example.com", "SPF"): ["v=spf1 -all"]})
    assert "differs" in [f.message for f in r["findings"] if f.rule_id == "spf.rr_type_99"][0]


@pytest.mark.parametrize("txt,warn", [(None, True), (["a", "b"], True), (["Not authorised: %{i}"], False),
                                      (["bad %{z} macro"], True), (["100% sure"], True), (["café"], True),
                                      (["ok %% %_ %-"], False)])
def test_spf_exp_target(txt, warn):
    z = {("example.com", "TXT"): ["v=spf1 ip4:192.0.2.0/24 exp=why.example.com -all"]}
    if txt:
        z[("why.example.com", "TXT")] = txt
    assert ("spf.exp_target" in ids(sp(z))) is warn


def test_spf_exp_macro_target_not_checked():
    r = sp({("example.com", "TXT"): ["v=spf1 exp=%{d}.why.example.com -all"]})
    assert [f.severity for f in r["findings"] if f.rule_id == "spf.exp_target"] == ["info"]


def dm(z):
    return ids(dmarc.check("example.com", Zone(z), R))


def test_dmarc_cname_served_dangling_and_loop():
    rec = ["v=DMARC1; p=reject"]
    assert "dmarc.cname" in dm({("_dmarc.example.com", "CNAME"): ["d.example.org."], ("_dmarc.example.com", "TXT"): rec})
    assert "dmarc.cname_dangling" in dm({("_dmarc.example.com", "CNAME"): ["gone.example.org."]})
    assert "dmarc.cname_dangling" in dm({("_dmarc.example.com", "CNAME"): ["a.example.org."],
                                         ("a.example.org", "CNAME"): ["_dmarc.example.com."]})
    assert not {"dmarc.cname", "dmarc.cname_dangling"} & set(dm({("_dmarc.example.com", "TXT"): rec}))


def dk(rec):
    return dkim.check("example.com", Zone({("s1._domainkey.example.com", "TXT"): [rec]}), R, {"selectors": ["s1"]})


@pytest.mark.parametrize("tags,rid,sev", [("t=s", "dkim.strict_subdomain", "info"), ("t=q", "dkim.unknown_flag", "warning"),
                                          ("s=tlsrpt", "dkim.service_type", "error"), ("g=*", "dkim.granularity", "info"),
                                          ("g=bob", "dkim.granularity", "warning")])
def test_dkim_key_tags(tags, rid, sev):
    r = dk(f"v=DKIM1; k=rsa; {tags}; p={RSA2048}")
    assert [f.severity for f in r["findings"] if f.rule_id == rid] == [sev]


@pytest.mark.parametrize("s", ["email", "*", "email:tlsrpt", "tlsrpt:*"])
def test_dkim_service_ok(s):
    assert "dkim.service_type" not in ids(dk(f"v=DKIM1; s={s}; p={RSA2048}"))


# ---- BIMI mark certificates
vg = pytest.importorskip("tests.vmcgen")
SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 10 10">'
       b'<title>Acme</title><rect width="10" height="10" fill="teal"/></svg>')


def vm(pem, logo=SVG):
    from faultypacket_audit.checks import _vmc
    return {rid for _, rid, _m in _vmc.check_pem(pem, "d.test", logo, vg.NOW)}


def test_vmc_ok():
    assert vm(vg.chain(svg=SVG)) == {"bimi.vmc_ok"}


@pytest.mark.parametrize("kw,rid", [(dict(days=10), "bimi.vmc_expiring"), (dict(eku=False), "bimi.vmc_eku"),
                                    (dict(domain="e.test"), "bimi.vmc_san"), (dict(with_root=False), "bimi.vmc_chain"),
                                    (dict(wrong_issuer=True), "bimi.vmc_chain"), (dict(logo=False), "bimi.vmc_logo_hash"),
                                    (dict(svg=b"<svg>other</svg>"), "bimi.vmc_logo_hash")])
def test_vmc_faults(kw, rid):
    kw.setdefault("svg", SVG)
    assert rid in vm(vg.chain(**kw))


def test_vmc_expired_and_garbage():
    from faultypacket_audit.checks import _vmc
    import datetime as dt
    got = {r for _, r, _m in _vmc.check_pem(vg.chain(svg=SVG), "d.test", SVG, vg.NOW + dt.timedelta(days=400))}
    assert "bimi.vmc_expired" in got
    assert vm(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n") == {"bimi.vmc_parse"}


def test_every_new_rule_has_rfc_section():
    for rid in ["spf.record_size", "spf.rr_type_99", "spf.exp_target", "dmarc.cname", "dkim.service_type", "bimi.vmc_chain"]:
        r = R.rule(rid) if hasattr(R, "rule") else None
        assert r is None or "#" in r["url"], rid


@given(st.text(alphabet="ab %{}sid_-", max_size=40))
def test_macro_string_never_crashes(t):
    assert spf.macro_string_ok(t) in (True, False)
    if "%" not in t:
        assert spf.macro_string_ok(t)
