import io, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from faultypacket_audit import headers as H
from tests.zone import Zone

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "headers")


def load(n, **k):
    return H.analyse(open(os.path.join(FIX, n), "rb").read(), **k)


def test_relaxed_alignment_subdomains_pass():
    r = load("aligned_relaxed.eml")
    assert r["verdict"] == "pass" and all(i["aligned"] for i in r["identifiers"])
    assert r["from_domain"] == "shop.example.co.uk" and r["org_domain_method"] == "psl"


def test_strict_alignment_fails_for_subdomain_identifiers():
    r = load("aligned_relaxed.eml", adkim="s", aspf="s")
    assert r["verdict"] == "fail-unaligned" and not any(i["aligned"] for i in r["identifiers"])


def test_strict_note_when_receiver_disagrees():
    r = load("aligned_relaxed.eml", adkim="s", aspf="s")
    assert any("receiver recorded dmarc=pass" in n for n in r["notes"])


def test_esp_identifiers_unaligned():
    r = load("unaligned_esp.eml")
    assert r["verdict"] == "fail-unaligned" and r["receiver_dmarc"] == "fail"
    assert {i["domain"] for i in r["identifiers"]} == {"esp-mailer.example", "em.esp-mailer.example"}


def test_arc_chain_parsed_in_order():
    r = load("arc_forwarded.eml")
    assert r["arc"]["instances"] == [1, 2] and [s["cv"] for s in r["arc"]["sets"]] == ["none", "pass"]
    assert all(s["complete"] for s in r["arc"]["sets"]) and not [p for p in r["problems"] if "ARC" in p]


def test_arc_forwarded_dmarc_fail_but_reported():
    r = load("arc_forwarded.eml")
    assert r["verdict"] == "fail-unaligned" and r["arc"]["sets"][1]["sealer"] == "list.example"


def test_received_delays_oldest_first():
    r = load("arc_forwarded.eml")
    assert [h["by"] for h in r["received"]] == ["list.example", "mx.receiver.example"]
    assert r["received"][1]["delay_s"] == 300 and r["received"][0]["ip"] == "192.0.2.4"


def test_broken_message_problems():
    r = load("broken.eml")
    p = " ".join(r["problems"])
    assert "2 From headers" in p and "rsa-sha1" in p and "does not sign From" in p
    assert "missing or incomplete" in p and "cv=none" in p and "cv=fail" in p


def test_broken_message_notes_body_length_and_clock_skew():
    n = " ".join(load("broken.eml")["notes"])
    assert "l= (body length)" in n and "before the previous hop" in n


def test_dkim_signature_missing_tags_listed():
    s = H.parse_dkim_signature("v=1; a=rsa-sha1; d=x.example; s=old; h=subject:date; l=100; b=y")
    assert s["missing"] == ["bh"] and s["l"] == "100" and not s["signs_from"]


def test_no_ar_means_unknown_and_signature_not_verified():
    r = load("no_ar.eml")
    assert r["verdict"] == "unknown" and r["identifiers"][0]["result"] == "not-verified"


def test_only_topmost_ar_trusted_by_default():
    r = load("spoof_top_ar.eml")
    assert r["verdict"] == "fail" and r["trusted_authserv_id"] == "mx.receiver.example"
    assert not any(i["type"] == "dkim" for i in r["identifiers"])


def test_trust_option_selects_authserv_id():
    r = load("unaligned_esp.eml", trust="other.example")
    assert r["verdict"] == "unknown"


def test_tree_walk_org_domain_with_resolver():
    z = Zone({("_dmarc.shop.example.co.uk", "TXT"): ["v=DMARC1; p=reject; psd=n"]})
    r = load("aligned_relaxed.eml", res=z)
    assert r["org_domain_method"] == "tree_walk" and r["from_org_domain"] == "shop.example.co.uk"
    assert r["verdict"] == "pass"


@pytest.mark.parametrize("v,exp", [
    ("a (b) c", "a  c"), ("a (b (nested)) c", "a  c"), ('"(not a comment)"', '"(not a comment)"'),
    ("a \\( b", "a \\( b"), ("(x)", ""), ("no comments", "no comments")])
def test_strip_comments_cases(v, exp):
    assert H.strip_comments(v) == exp


@pytest.mark.parametrize("v,by,frm,ip", [
    ("from a.example (a.example [192.0.2.1]) by b.example with ESMTP id 1; Thu, 29 Oct 2026 10:00:00 +0000",
     "b.example", "a.example", "192.0.2.1"),
    ("from x ([IPv6:2001:db8::1]) by y with ESMTPS; Thu, 29 Oct 2026 10:00:00 +0000", "y", "x", "2001:db8::1"),
    ("by local.example with LMTP; Thu, 29 Oct 2026 10:00:00 +0000", "local.example", None, None),
    ("garbage with no date", None, None, None)])
def test_parse_received(v, by, frm, ip):
    h = H.parse_received(v)
    assert h.get("by") == by and h.get("from") == frm and h["ip"] == ip


def test_received_date_parsed():
    h = H.parse_received("from a by b; Thu, 29 Oct 2026 10:00:00 +0000")
    assert h["date"] == "2026-10-29T10:00:00+00:00"


@pytest.mark.parametrize("a,b,mode,ok", [
    ("example.com", "example.com", "s", True), ("mail.example.com", "example.com", "r", True),
    ("mail.example.com", "example.com", "s", False), ("example.net", "example.com", "r", False),
    ("a.example.co.uk", "b.example.co.uk", "r", True), ("example.co.uk", "other.co.uk", "r", False),
    ("", "example.com", "r", False), ("EXAMPLE.com.", "example.COM", "s", True)])
def test_alignment_table_rfc9989_3_2_10(a, b, mode, ok):
    assert H.aligned(a, b, mode) is ok


def test_render_mentions_citations_and_limits():
    t = H.render(load("aligned_relaxed.eml"))
    assert "RFC 9989 3.2.10" in t and "RFC 9989 4.4.1" in t and "not re-verified" in t


def test_cli_headers_json_and_exit_codes(capsys):
    out = io.StringIO()
    rc = H.main([os.path.join(FIX, "aligned_relaxed.eml"), "--json"], io.StringIO(), out, io.StringIO())
    assert rc == 0 and json.loads(out.getvalue())["verdict"] == "pass"
    rc = H.main([os.path.join(FIX, "unaligned_esp.eml")], io.StringIO(), io.StringIO(), io.StringIO())
    assert rc == 1


def test_cli_headers_stdin():
    class In(io.StringIO):
        buffer = io.BytesIO(open(os.path.join(FIX, "aligned_relaxed.eml"), "rb").read())
    out = io.StringIO()
    assert H.main(["-"], In(), out, io.StringIO()) == 0 and "PASS" in out.getvalue()
