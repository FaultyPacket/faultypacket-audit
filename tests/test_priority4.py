"""Priority-4 RFC gaps: SPF 3.5/5.5/6.1, DKIM 3.5/3.6.2.2, RFC 9989 11.7, RFC 9991 2, BIMI 6.3."""
from faultypacket_audit import load_rules
from faultypacket_audit.checks import spf, dkim, dmarc, bimi
from tests.zone import Zone

R = load_rules()
ids = lambda r: [f.rule_id for f in r["findings"]]
KEY = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="


def spf_ids(rec, extra=None):
    z = Zone({("example.com", "TXT"): [rec], ("example.net", "TXT"): ["v=spf1 -all"], **(extra or {})})
    return ids(spf.check("example.com", z, R))


def test_redirect_position():
    assert "spf.redirect_position" in spf_ids("v=spf1 redirect=example.net ip4:192.0.2.1")
    assert "spf.redirect_position" not in spf_ids("v=spf1 ip4:192.0.2.1 redirect=example.net")


def test_ptr_position():
    assert "spf.ptr_position" in spf_ids("v=spf1 ptr ip4:192.0.2.1 -all")
    assert "spf.ptr_position" not in spf_ids("v=spf1 ip4:192.0.2.1 ptr -all")


def test_wildcard_coverage():
    probe = "fpa-wildcard-probe.example.com"
    assert "spf.wildcard_coverage" in spf_ids("v=spf1 -all", {(probe, "MX"): ["10 mx.example.com"]})
    assert "spf.wildcard_coverage" not in spf_ids("v=spf1 -all", {(probe, "MX"): ["10 mx.example.com"], (probe, "TXT"): ["v=spf1 -all"]})
    assert "spf.wildcard_coverage" not in spf_ids("v=spf1 -all")


def test_dkim_idn_selector_alabel():
    sel = "sélecteur"
    al = sel.encode("idna").decode()
    z = Zone({(f"{al}._domainkey.example.com", "TXT"): [KEY]})
    r = dkim.check("example.com", z, R, {"dkim_selectors": [sel], "probe_common": False})
    assert "dkim.selector_alabel" in ids(r) and "dkim.no_key" not in ids(r)
    assert r["data"]["keys"][0]["selector"] == al


def test_dkim_multiple_records():
    z = Zone({("s1._domainkey.example.com", "TXT"): [KEY, KEY]})
    assert "dkim.multiple_records" in ids(dkim.check("example.com", z, R, {"dkim_selectors": ["s1"], "probe_common": False}))


def test_dmarc_unencrypted_and_ruf_psd():
    codes = lambda rec: [i[1] for i in dmarc.validate(rec)[1]]
    assert "unencrypted_uri" in codes("v=DMARC1; p=none; rua=http://example.com/r")
    assert "unencrypted_uri" not in codes("v=DMARC1; p=none; rua=mailto:r@example.com")
    assert "ruf_psd" in codes("v=DMARC1; p=reject; psd=y; rua=mailto:r@example.com; ruf=mailto:f@example.com")
    assert "ruf_psd" not in codes("v=DMARC1; p=reject; rua=mailto:r@example.com; ruf=mailto:f@example.com")


def test_bimi_shared_cname():
    name = "default._bimi.example.com"
    z = Zone({(name, "TXT"): ["v=BIMI1; l=; a="], (name, "CNAME"): ["default._bimi.example.org."]})
    r = bimi.check("example.com", z, R, {})
    assert "bimi.shared_cname" in ids(r) and r["data"]["shared_via"] == "default._bimi.example.org"


def test_new_rules_cite_sections():
    for rid in ["dmarc.unencrypted_uri", "dmarc.ruf_psd", "spf.redirect_position", "spf.ptr_position", "spf.wildcard_coverage",
                "dkim.selector_alabel", "dkim.multiple_records", "bimi.shared_cname"]:
        assert "#section-" in R.get(rid)["url"], rid
