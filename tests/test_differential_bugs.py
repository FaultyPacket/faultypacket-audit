"""Regression tests for the bugs found by differential testing against
checkdmarc on real DNS records (docs/differential-findings.md)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from faultypacket_audit.checks import dmarc, spf
from faultypacket_audit.checks import _mtasts_engine as M
from tests.zone import Zone


def _spf(rec, extra=None):
    z = {("x.test", "TXT"): [rec]}
    z.update(extra or {})
    return spf.analyse("x.test", Zone(z))


def test_bug1_mechanisms_after_all_are_not_counted():  # RFC 7208 5.1
    inc = {(f"i{n}.test", "TXT"): ["v=spf1 include:deep.test -all"] for n in range(3)}
    inc[("deep.test", "TXT")] = ["v=spf1 -all"]
    r = _spf("v=spf1 include:i0.test -all include:i1.test include:i2.test", inc)
    assert r["lookups"] == 2 and "after_all" in {i["code"] for i in r["issues"]}


def test_bug1_after_all_cannot_trip_lookup_limit():
    inc = {(f"i{n}.test", "TXT"): ["v=spf1 -all"] for n in range(15)}
    r = _spf("v=spf1 -all " + " ".join(f"include:i{n}.test" for n in range(15)), inc)
    assert r["lookups"] == 0 and r["result"] == "ok"


def test_bug1_syntax_after_all_is_still_permerror():  # RFC 7208 4.6
    assert _spf("v=spf1 -all ip4:999.1.1.1")["result"] == "permerror"


def test_bug2_joined_txt_strings_qualified_modifier():  # RFC 7208 12
    r = _spf("v=spf1 ip4:192.0.2.1 -allgoogle-site-verification=abc")
    assert r["result"] == "permerror" and "syntax" in {i["code"] for i in r["issues"]}


def test_bug2_plain_unknown_modifier_still_fine():
    assert _spf("v=spf1 ip4:192.0.2.1 -all foo=bar")["result"] == "ok"


def test_bug3_dmarc_space_in_uri_swallows_next_tag():  # RFC 9989 4.8, RFC 3986
    _, iss = dmarc.validate("v=DMARC1; p=reject; ruf=mailto:a@example.org fo=1; rua=mailto:r@example.org")
    assert "bad_uri_ruf" in {c for _, c, _ in iss}


def test_bug3_dmarc_space_after_mailto_colon():
    _, iss = dmarc.validate("v=DMARC1; p=none; rua=mailto: r@example.org")
    assert "bad_uri_rua" in {c for _, c, _ in iss}


def test_bug3_dmarc_two_at_signs():
    _, iss = dmarc.validate("v=DMARC1; p=none; rua=mailto:a@b@example.org")
    assert "bad_uri_rua" in {c for _, c, _ in iss}


def test_bug3_dmarc_spaces_around_commas_still_valid():
    _, iss = dmarc.validate("v=DMARC1; p=none; rua=mailto:a@example.org , mailto:b@example.org")
    assert not [c for s, c, _ in iss if s == "error"]


def test_bug4_dmarc_control_character_warned():
    _, iss = dmarc.validate("v=DMARC1; p=reject;\nrua=mailto:r@example.org")
    assert ("warning", "syntax") in {(s, c) for s, c, _ in iss}


def test_bug4_dmarc_empty_tag_warned_trailing_sep_not():
    assert "syntax" in {c for _, c, _ in dmarc.validate("v=DMARC1; p=none;; rua=mailto:r@example.org")[1]}
    assert "syntax" not in {c for _, c, _ in dmarc.validate("v=DMARC1; p=none; rua=mailto:r@example.org;")[1]}


def _tls(rec):
    return {i["code"] for i in M.check_tlsrpt("x.test", Zone({("_smtp._tls.x.test", "TXT"): [rec]}))["issues"]}


def test_bug5_tlsrpt_bad_uris():  # RFC 8460 3
    assert "tlsrpt_bad_uri" in _tls("v=TLSRPTv1; rua=mailto: r@example.org")
    assert "tlsrpt_bad_uri" in _tls("v=TLSRPTv1;rua=,mailto:r@example.org")
    assert "tlsrpt_bad_uri" in _tls("v=TLSRPTv1;rua=mailto:a@b@example.org")
    assert not _tls("v=TLSRPTv1; rua=mailto:r@example.org, https://example.org/tls")


def test_bug6_malformed_tag_name_is_discarded_with_hint():  # RFC 9989 4.8
    d, iss = dmarc.validate("v=DMARC1; +p=reject; rua=mailto:r@example.org")
    assert "p" not in d
    assert any(i[1] == "syntax" and "'p'" in i[2] for i in iss)
    assert any(i[1] == "no_p" for i in iss)


def test_bug6_empty_value_and_stray_comma_warn():
    _, iss = dmarc.validate("v=DMARC1; p=none; pct=; rua=mailto:r@example.org,")
    assert sum(i[1] == "syntax" for i in iss) == 2
    assert not any(i[0] == "error" for i in iss)
