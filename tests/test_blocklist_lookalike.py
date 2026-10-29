import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from faultypacket_audit import audit, load_rules
from faultypacket_audit.audit import ORDER, ALL
from faultypacket_audit.checks import blocklist as B, lookalike as L
from tests.zone import Zone, GOOD

R = load_rules()
ZONES = R.value("blocklist.zones")
WORKING = {("2.0.0.127." + z["zone"] if z["type"] == "ip" else "dbltest.com." + z["zone"], "A"): ["127.0.0.2"] for z in ZONES}
MXZ = {("shop.test", "MX"): ["10 mx.shop.test."], ("mx.shop.test", "A"): ["192.0.2.25"]}


def bl(extra, d="shop.test"):
    return audit(d, Zone({**MXZ, **extra}), R, ["mx", "blocklist"])["checks"][1]


def test_opt_in_checks_not_in_default_order():
    assert "blocklist" not in ORDER and "lookalike" not in ORDER and set(ALL) - set(ORDER) == {"blocklist", "lookalike"}
    assert [c["check"] for c in audit("good.test", Zone(GOOD), R)["checks"]] == ORDER


def test_zones_have_terms_and_test_points():
    assert {z["zone"] for z in ZONES} >= {"zen.spamhaus.org", "dbl.spamhaus.org"}
    assert all(z["terms"].startswith("https://") and z["test"] for z in ZONES)


@pytest.mark.parametrize("ip,rev", [("192.0.2.25", "25.2.0.192"), ("127.0.0.2", "2.0.0.127"), ("10.0.0.1", "1.0.0.10")])
def test_reverse_ip_rfc5782_2_1(ip, rev):
    assert B.reverse_ip(ip) == rev


@pytest.mark.parametrize("vals,hits", [
    (["127.0.0.2"], ["127.0.0.2"]), (["127.0.0.4", "127.0.0.10"], ["127.0.0.4", "127.0.0.10"]),
    (["127.255.255.254"], []), (["127.255.255.252"], []), (["192.0.2.1"], []), (["nonsense"], []), ([], [])])
def test_is_listing(vals, hits):
    assert B._is_listing(vals) == hits


def test_refused_resolver_means_not_tested_not_clean():
    z = {("2.0.0.127." + zz["zone"] if zz["type"] == "ip" else "dbltest.com." + zz["zone"], "A"): ["127.255.255.254"] for zz in ZONES}
    c = bl(z)
    assert all(not r["tested"] for r in c["data"]["lists"])
    assert {f.rule_id for f in c["findings"]} == {"blocklist.not_tested"}


def test_no_answer_for_test_point_is_not_tested():
    c = bl({})
    assert all(not r["tested"] for r in c["data"]["lists"])


def test_dns_error_on_test_point_is_not_tested():
    c = bl({k: "err" for k in WORKING})
    assert all("DNS error" in r["probe"] for r in c["data"]["lists"])


def test_clean_when_lists_work_and_nothing_listed():
    c = bl(WORKING)
    assert all(r["tested"] for r in c["data"]["lists"]) and not c["findings"] and c["data"]["ips"] == ["192.0.2.25"]


def test_listed_ip_reported_with_terms():
    z = {**WORKING, ("25.2.0.192.zen.spamhaus.org", "A"): ["127.0.0.4"]}
    f = [f for f in bl(z)["findings"] if f.rule_id == "blocklist.listed_ip"]
    assert len(f) == 1 and f[0].severity == "warning" and "spamhaus.org/blocklists" in f[0].message


def test_listed_domain_on_dbl():
    z = {**WORKING, ("shop.test.dbl.spamhaus.org", "A"): ["127.0.1.2"]}
    assert "blocklist.listed_domain" in {f.rule_id for f in bl(z)["findings"]}


def test_spamhaus_error_code_on_target_is_not_a_listing():
    z = {**WORKING, ("25.2.0.192.zen.spamhaus.org", "A"): ["127.255.255.254"]}
    assert not bl(z)["findings"]


def test_ipv6_only_mx_noted():
    z = {("shop.test", "MX"): ["10 mx.shop.test."], ("mx.shop.test", "AAAA"): ["2001:db8::25"], **WORKING}
    c = audit("shop.test", Zone(z), R, ["mx", "blocklist"])["checks"][1]
    assert "blocklist.no_ipv4" in {f.rule_id for f in c["findings"]}


def test_blocklist_without_mx_check_resolves_itself():
    c = audit("shop.test", Zone({**MXZ, **WORKING}), R, ["blocklist"])["checks"][0]
    assert c["data"]["ips"] == ["192.0.2.25"]


# ---------------------------------------------------------------- lookalike
def test_candidates_deterministic_capped_unique():
    a = L.candidates("faultypacket.co.uk", "faultypacket.co.uk", 60)
    assert a == L.candidates("faultypacket.co.uk", "faultypacket.co.uk", 60)
    assert len(a) == 60 and len({n for _, n in a}) == 60 and "faultypacket.co.uk" not in {n for _, n in a}


@pytest.mark.parametrize("name,kind,cand", [
    ("google.com", "homoglyph", "g0ogle.com"), ("paypal.com", "homoglyph", "paypa1.com"),
    ("modern.com", "homoglyph", "rnodern.com"), ("barn.com", "homoglyph", "bam.com"),
    ("shop.co.uk", "tld-swap", "shop.com"), ("shop.com", "tld-swap", "shop.co.uk"),
    ("shop.com", "omission", "sho.com"), ("shop.com", "transposition", "hsop.com"),
    ("shop.com", "repetition", "shhop.com"), ("shop.com", "keyboard", "ahop.com"),
    ("shop.com", "hyphenation", "sh-op.com")])
def test_candidate_kinds(name, kind, cand):
    c = L.candidates(name, name, 500)
    assert (kind, cand) in c


@pytest.mark.parametrize("name", ["a.com", "x-y.org", "123.net", "verylonglabelname.co.uk"])
def test_candidates_are_valid_hostnames(name):
    import re
    for _k, n in L.candidates(name, name, 500):
        lab = n.split(".")[0]
        assert re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", lab) and len(lab) <= 63


def test_subdomain_input_uses_org_domain():
    c = L.candidates("mail.shop.co.uk", "shop.co.uk", 500)
    assert all(not n.startswith("mail") for _, n in c)


def test_lookalike_check_reports_registered_and_mx():
    z = {("sh0p.test", "NS"): ["ns1.parking.example."], ("sh0p.test", "MX"): ["10 mx.parking.example."],
         ("shop.com", "A"): ["192.0.2.80"]}
    c = audit("shop.test", Zone(z), R, ["lookalike"])["checks"][0]
    reg = {f.evidence["name"]: f.evidence["mx"] for f in c["findings"]}
    assert reg == {"sh0p.test": True, "shop.com": False}
    assert all(f.severity == "info" for f in c["findings"]) and c["data"]["with_mx"] == 1


def test_null_mx_on_lookalike_not_counted_as_mail():
    z = {("sh0p.test", "NS"): ["ns.x."], ("sh0p.test", "MX"): ["0 ."]}
    c = audit("shop.test", Zone(z), R, ["lookalike"])["checks"][0]
    assert c["data"]["with_mx"] == 0 and c["data"]["registered"] == 1


def test_lookalike_respects_cap():
    c = audit("averyveryverylongname.test", Zone({}), R, ["lookalike"])["checks"][0]
    assert c["data"]["tested"] == R.value("lookalike.max_candidates")
