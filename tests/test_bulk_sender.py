import pytest
from faultypacket_audit import audit, load_rules
from faultypacket_audit.checks import bulk_sender as B
from tests.zone import Zone, GOOD

R = load_rules()


def run(z, **opts):
    return B.check("good.test", Zone(z), R, opts)


def prov(r, name):
    return next(p for p in r["data"]["providers"] if p["provider"] == name)


def req(r, rule_id):
    for p in r["data"]["providers"]:
        for q in p["requirements"]:
            if q["rule_id"] == rule_id:
                return q
    raise KeyError(rule_id)


def test_full_inputs_all_dns_rows_pass():
    r = run(GOOD, sending_ips=["192.0.2.10"], dkim_selectors=["s1"])
    assert {p["verdict"] for p in r["data"]["providers"]} == {"dns-checks-pass"}
    assert not [f for f in r["findings"] if f.severity != "info"]


def test_without_inputs_is_incomplete_not_pass():
    r = run(GOOD)
    assert {p["verdict"] for p in r["data"]["providers"]} == {"incomplete"}
    assert req(r, "bulk.google.all.fcrdns")["status"] == "unknown"
    assert req(r, "bulk.google.5k.spf_and_dkim")["status"] == "unknown"
    assert req(r, "bulk.google.all.spf_or_dkim")["status"] == "pass"   # SPF alone satisfies "or"


def test_non_dns_requirements_always_listed():
    r = run(GOOD, sending_ips=["192.0.2.10"], dkim_selectors=["s1"])
    assert set(prov(r, "google")["not_dns_verifiable"]) >= {"one_click_unsub", "spam_rate_max", "alignment", "tls"}
    assert any(f.rule_id == "bulk.not_dns_verifiable" for f in r["findings"])


def test_no_dmarc_fails_dmarc_min_as_warning_unless_bulk():
    z = {k: v for k, v in GOOD.items() if not k[0].startswith("_dmarc")}
    r = run(z, sending_ips=["192.0.2.10"], dkim_selectors=["s1"])
    f = [f for f in r["findings"] if f.rule_id == "bulk.google.5k.dmarc_min"]
    assert f and f[0].severity == "warning" and prov(r, "google")["verdict"] == "fail"
    r = run(z, sending_ips=["192.0.2.10"], dkim_selectors=["s1"], bulk=True)
    assert [f for f in r["findings"] if f.rule_id == "bulk.google.5k.dmarc_min"][0].severity == "error"


def test_all_sender_rule_failure_is_error():
    z = {k: v for k, v in GOOD.items() if k[1] != "PTR"}
    r = run(z, sending_ips=["192.0.2.10"])
    f = [f for f in r["findings"] if f.rule_id == "bulk.google.all.fcrdns"]
    assert f and f[0].severity == "error" and "no PTR" in f[0].message


def test_fcrdns_mismatch_fails():
    z = dict(GOOD); z[("mail.good.test", "A")] = ["198.51.100.1"]
    assert B.fcrdns("192.0.2.10", Zone(z))[0] == "fail"


def test_fcrdns_ipv6_and_bad_input():
    z = {("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "PTR"): ["m6.good.test."],
         ("m6.good.test", "AAAA"): ["2001:db8::1"]}
    assert B.fcrdns("2001:db8::1", Zone(z))[0] == "pass"
    assert B.fcrdns("not-an-ip", Zone({}))[0] == "unknown"


def test_dkim_revoked_key_fails():
    z = dict(GOOD); z[("s1._domainkey.good.test", "TXT")] = ["v=DKIM1; p="]
    st, detail = B.dkim_status("good.test", Zone(z), ["s1"])
    assert st == "fail" and "revoked" in detail


def test_dkim_dns_error_is_unknown():
    z = dict(GOOD); z[("s1._domainkey.good.test", "TXT")] = "err"
    assert B.dkim_status("good.test", Zone(z), ["s1"])[0] == "unknown"


def test_spf_permerror_fails_and_requirement():
    z = dict(GOOD); z[("good.test", "TXT")] = ["v=spf1 include:nowhere.test -all"]
    r = run(z, sending_ips=["192.0.2.10"], dkim_selectors=["s1"])
    assert req(r, "bulk.google.5k.spf_and_dkim")["status"] == "fail"
    assert req(r, "bulk.google.all.spf_or_dkim")["status"] == "pass"   # DKIM carries "or"


def test_inherited_org_policy_counts():
    z = dict(GOOD); z[("sub.good.test", "TXT")] = ["v=spf1 -all"]
    r = B.check("sub.good.test", Zone(z), R, {})
    assert req(r, "bulk.yahoo.bulk.dmarc_min")["status"] == "pass"


def test_reuses_prior_results_from_audit():
    z = Zone(GOOD)
    rep = audit("good.test", z, R, options={"dkim_selectors": ["s1"]})
    assert [c["check"] for c in rep["checks"]] == ["spf", "dmarc", "dkim", "mx", "mta-sts", "dnssec", "dane", "caa", "rdns", "bimi", "bulk-sender"]
    assert sum(1 for q in z.asked if q == ("good.test", "TXT")) == 1
