"""Offline tests for the 1.0 modules: dkim, mx, caa, rdns, dnssec, dane, bimi,
mta-sts/tls-rpt wrapper, provider DKIM key length, citations, diff."""
import json
import pytest

from faultypacket_audit import audit, load_rules
from faultypacket_audit.checks import dkim, mx, caa, rdns, dnssec, dane, bimi, mtasts, bulk_sender
from faultypacket_audit.output import diff, jsonout, sarif, csvout
from tests.keys import RSA2048, RSA1024, RSA512
from tests.zone import Zone, GOOD

R = load_rules()
ED = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="   # RFC 8463 A.2 test key


def ids(r):
    return [f.rule_id for f in r["findings"]]


def sev(r, rid):
    return [f.severity for f in r["findings"] if f.rule_id == rid]


# ------------------------------------------------------------------ DKIM
def dk(records, **opt):
    return dkim.check("d.test", Zone(records), R, opt)


@pytest.mark.parametrize("key,bits,rid,s", [(RSA2048, 2048, None, None),
                                            (RSA1024, 1024, "dkim.recommended_rsa_bits", "warning"),
                                            (RSA512, 512, "dkim.min_rsa_bits", "error")])
def test_dkim_rsa_sizes(key, bits, rid, s):
    r = dk({("selector1._domainkey.d.test", "TXT"): [f"v=DKIM1; k=rsa; p={key}"]})
    assert r["data"]["keys"][0]["bits"] == bits
    if rid:
        assert sev(r, rid) == [s]
    else:
        assert [f for f in r["findings"] if f.severity != "info"] == []
    assert ("selector1" in r["data"]["usable_selectors"]) == (bits >= 1024)


def test_dkim_split_whitespace_in_p():
    k = RSA2048[:100] + " " + RSA2048[100:]
    r = dk({("google._domainkey.d.test", "TXT"): [f"v=DKIM1; p={k}"]})
    assert r["data"]["keys"][0]["bits"] == 2048


def test_dkim_revoked_empty_p_is_info_not_usable():
    r = dk({("s1._domainkey.d.test", "TXT"): ["v=DKIM1; k=rsa; p="]})
    assert sev(r, "dkim.revoked_empty_p") == ["info"] and r["data"]["usable_selectors"] == []


def test_dkim_testing_flag():
    r = dk({("s1._domainkey.d.test", "TXT"): [f"v=DKIM1; t=y; p={RSA2048}"]})
    assert sev(r, "dkim.testing") == ["warning"] and r["data"]["usable_selectors"] == []


def test_dkim_testing_flag_among_others():
    r = dk({("s1._domainkey.d.test", "TXT"): [f"v=DKIM1; t=s:y; p={RSA2048}"]})
    assert sev(r, "dkim.testing") == ["warning"]


def test_dkim_ed25519_ok_and_bad_length():
    r = dk({("s1._domainkey.d.test", "TXT"): [f"v=DKIM1; k=ed25519; p={ED}"],
            ("s2._domainkey.d.test", "TXT"): ["v=DKIM1; k=ed25519; p=AAAA"]})
    assert sev(r, "dkim.ed25519_key") == ["info", "error"]


def test_dkim_bad_version_sha1_unknown_k_no_p_bad_key():
    r = dk({("s1._domainkey.d.test", "TXT"): [f"v=DKIM2; p={RSA2048}"],
            ("s2._domainkey.d.test", "TXT"): [f"v=DKIM1; h=sha1; p={RSA2048}"],
            ("k1._domainkey.d.test", "TXT"): ["v=DKIM1; k=dsa; p=AAAA"],
            ("k2._domainkey.d.test", "TXT"): ["v=DKIM1; k=rsa"],
            ("k3._domainkey.d.test", "TXT"): ["v=DKIM1; p=bm90IGEga2V5"]})
    assert {"dkim.bad_version", "dkim.sha1_only", "dkim.unknown_k", "dkim.no_p", "dkim.bad_key"} <= set(ids(r))


def test_dkim_duplicate_tag_and_two_records():
    r = dk({("s1._domainkey.d.test", "TXT"): [f"v=DKIM1; p={RSA2048}; p={RSA1024}"],
            ("s2._domainkey.d.test", "TXT"): [f"v=DKIM1; p={RSA2048}", f"v=DKIM1; p={RSA1024}"]})
    assert ids(r).count("dkim.syntax") == 2


def test_dkim_none_found_is_info_but_named_selector_missing_is_error():
    assert sev(dk({}), "dkim.not_found") == ["info"]
    r = dk({}, dkim_selectors=["mine"])
    assert sev(r, "dkim.no_key") == ["error"]


def test_dkim_user_selector_dns_error_warns_common_errors_silent():
    r = dk({("mine._domainkey.d.test", "TXT"): "err", ("google._domainkey.d.test", "TXT"): "err"},
           dkim_selectors=["mine"])
    assert sev(r, "dkim.dns_error") == ["warning"]


def test_dkim_probe_list_from_rules_and_user_first():
    z = Zone({})
    dkim.check("d.test", z, R, {"dkim_selectors": ["zz"]})
    assert z.asked[0] == ("zz._domainkey.d.test", "TXT")
    assert len(z.asked) == 1 + len(R.value("dkim.common_selectors"))


def test_dkim_non_key_txt_ignored():
    r = dk({("s1._domainkey.d.test", "TXT"): ["google-site-verification=abc"]})
    assert r["data"]["keys"] == []


# ------------------------------------------------- Google DKIM >= 1024 row
def test_google_dkim_1024_fail_and_pass():
    z = dict(GOOD); z[("s1._domainkey.good.test", "TXT")] = [f"v=DKIM1; p={RSA512}"]
    r = bulk_sender.check("good.test", Zone(z), R, {"dkim_selectors": ["s1"]})
    row = [q for p in r["data"]["providers"] if p["provider"] == "google" for q in p["requirements"]
           if q["rule_id"] == "bulk.google.all.dkim_1024"][0]
    assert row["status"] == "fail" and "512" in row["detail"]
    assert sev(r, "bulk.google.all.dkim_1024") == ["error"]     # audience all -> error
    r2 = bulk_sender.check("good.test", Zone(GOOD), R, {"dkim_selectors": ["s1"]})
    row2 = [q for p in r2["data"]["providers"] for q in p["requirements"] if q["rule_id"] == "bulk.google.all.dkim_1024"][0]
    assert row2["status"] == "pass"


def test_google_dkim_1024_uses_discovered_selectors_in_full_audit():
    z = dict(GOOD); z.pop(("s1._domainkey.good.test", "TXT"))
    z[("selector1._domainkey.good.test", "TXT")] = [f"v=DKIM1; p={RSA2048}"]
    rep = audit("good.test", Zone(z), R, options={"sending_ips": ["192.0.2.10"]})
    b = [c for c in rep["checks"] if c["check"] == "bulk-sender"][0]
    st = {q["rule_id"]: q["status"] for p in b["data"]["providers"] for q in p["requirements"]}
    assert st["bulk.google.all.dkim_1024"] == "pass" and st["bulk.google.5k.spf_and_dkim"] == "pass"


def test_google_dkim_1024_unknown_without_key():
    r = bulk_sender.check("good.test", Zone(GOOD), R, {})
    row = [q for p in r["data"]["providers"] for q in p["requirements"] if q["rule_id"] == "bulk.google.all.dkim_1024"][0]
    assert row["status"] == "unknown"


def test_google_dkim_row_verified_against_live_page():
    r = R.get("bulk.google.all.dkim_1024")
    assert r["value"] == 1024 and r["url"] == "https://support.google.com/a/answer/81126" and r["dns_verifiable"]


# -------------------------------------------------------------------- MX
def test_mx_null_ok_and_with_others():
    assert sev(mx.check("n.test", Zone({("n.test", "MX"): ["0 ."]}), R), "mx.null_mx") == ["info"]
    assert sev(mx.check("n.test", Zone({("n.test", "MX"): ["0 .", "10 mx.n.test."]}), R), "mx.null_mx") == ["error"]
    assert sev(mx.check("n.test", Zone({("n.test", "MX"): ["10 ."]}), R), "mx.null_mx") == ["error"]


def test_mx_cname_unresolvable_ip_literal_and_ok():
    z = Zone({("d.test", "MX"): ["10 alias.d.test.", "20 gone.d.test.", "30 192.0.2.1.", "40 ok.d.test."],
              ("alias.d.test", "CNAME"): ["real.d.test."], ("alias.d.test", "A"): ["192.0.2.2"],
              ("ok.d.test", "AAAA"): ["2001:db8::1"]})
    r = mx.check("d.test", z, R)
    assert sev(r, "mx.cname") == ["warning"] and sev(r, "mx.unresolvable") == ["error"]
    assert sev(r, "mx.ip_literal") == ["error"] and len(r["data"]["mx"]) == 4


def test_mx_none_and_dns_error_and_spf_limit():
    assert ids(mx.check("d.test", Zone({}), R)) == ["mx.none"]
    assert sev(mx.check("d.test", Zone({("d.test", "MX"): "err"}), R), "mx.dns_error") == ["error"]
    z = {("d.test", "MX"): [f"{i} m{i}.d.test." for i in range(11)]}
    z.update({(f"m{i}.d.test", "A"): ["192.0.2.1"] for i in range(11)})
    assert sev(mx.check("d.test", Zone(z), R), "mx.spf_mx_limit") == ["warning"]


# ------------------------------------------------------------------- CAA
def test_caa_absent_inherited_critical_iodef():
    assert ids(caa.check("a.b.test", Zone({}), R)) == ["caa.absent"]
    r = caa.check("a.b.test", Zone({("b.test", "CAA"): ['0 issue "letsencrypt.org"']}), R)
    assert ids(r) == ["caa.inherited"] and r["data"]["issuers"] == ["letsencrypt.org"]
    r = caa.check("b.test", Zone({("b.test", "CAA"): ['128 tbs "x"', '0 iodef "ftp://x"', '0 issue ";"']}), R)
    assert sev(r, "caa.critical_unknown") == ["error"] and sev(r, "caa.iodef") == ["error"]


def test_caa_unknown_noncritical_ignored_and_no_issue_and_error():
    r = caa.check("b.test", Zone({("b.test", "CAA"): ['0 contactemail "a@b.test"']}), R)
    assert ids(r) == ["caa.no_issue"]
    assert sev(caa.check("b.test", Zone({("b.test", "CAA"): "err"}), R), "caa.dns_error") == ["warning"]


def test_caa_does_not_query_tld():
    z = Zone({}); caa.check("a.b.test", z, R)
    assert ("test", "CAA") not in z.asked


# ------------------------------------------------------------------ rDNS
def test_rdns_sending_ip_fail_is_error_mx_fail_is_warning():
    z = Zone({("d.test", "MX"): ["10 mx.d.test."], ("mx.d.test", "A"): ["192.0.2.5"],
              ("5.2.0.192.in-addr.arpa", "PTR"): ["other.test."]})
    r = rdns.check("d.test", z, R, {"sending_ips": ["192.0.2.9"]})
    assert [f.severity for f in r["findings"]] == ["error", "warning"]


def test_rdns_pass_and_no_targets():
    r = rdns.check("good.test", Zone(GOOD), R, {"sending_ips": ["192.0.2.10"]})
    assert r["findings"] == [] and r["data"]["targets"][0]["status"] == "pass"
    assert ids(rdns.check("x.test", Zone({}), R, {})) == ["rdns.no_targets"]


# ---------------------------------------------------------------- DNSSEC
class DoHZone(Zone):
    servers = ["https://cloudflare-dns.com/dns-query"]


def test_dnssec_unsigned_validated_not_validated_untested():
    assert ids(dnssec.check("d.test", Zone({}), R)) == ["dnssec.unsigned"]
    z = DoHZone({("d.test", "DS"): ["1 13 2 AB"]}); z.secure = {"d.test"}
    r = dnssec.check("d.test", z, R); assert r["findings"] == [] and r["data"]["validated"] is True
    assert sev(dnssec.check("d.test", DoHZone({("d.test", "DS"): ["1 13 2 AB"]}), R), "dnssec.not_validated") == ["error"]
    assert ids(dnssec.check("d.test", Zone({("d.test", "DS"): ["1 13 2 AB"]}), R)) == ["dnssec.not_tested"]
    assert ids(dnssec.check("d.test", Zone({("d.test", "DS"): ["1 13 2 AB"]}), R,
                            {"validating_resolver": True})) == ["dnssec.not_validated"]


def test_dnssec_bogus_servfail():
    class Bogus(DoHZone):
        def query_ad(self, n, t):
            return [], "error:rcode2", False
    assert sev(dnssec.check("d.test", Bogus({("d.test", "DS"): ["1 13 2 AB"]}), R), "dnssec.bogus") == ["error"]


# ------------------------------------------------------------------ DANE
H = "a" * 64


def test_dane_good_pkix_usage_bad_hash_unvalidated():
    z = Zone({("d.test", "MX"): ["10 mx.d.test.", "20 mx2.other.test."],
              ("_25._tcp.mx.d.test", "TLSA"): [f"3 1 1 {H}", f"1 0 1 {H}", "3 1 2 abcd", "9 1 1 ab"],
              ("_25._tcp.mx2.other.test", "TLSA"): [f"2 1 1 {H}"]})
    z.secure = {"d.test"}
    r = dane.check("d.test", z, R)
    assert sev(r, "dane.smtp_usage") == ["warning"] and ids(r).count("dane.syntax") == 2
    assert sev(r, "dane.dnssec_required") == ["error"]   # mx2 zone not validated


def test_dane_absent():
    assert ids(dane.check("good.test", Zone({("good.test", "MX"): ["10 mail.good.test."]}), R)) == ["dane.absent"]


# ------------------------------------------------------------------ BIMI
SVG_OK = (b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 10 10">'
          b'<title>Acme</title><rect width="10" height="10" fill="teal"/></svg>')
try:
    from vmcgen import chain, NOW
    PEM = chain(svg=SVG_OK)
except ImportError:  # cryptography not installed
    chain, NOW = None, None
    PEM = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def fetcher(docs):
    def f(url, **k):
        if url in docs:
            return {"status": 200, "content_type": "image/svg+xml", "body": docs[url], "error": None}
        return {"status": 404, "content_type": None, "body": b"", "error": None}
    return f


def bm(rec, dmarc_tags, docs=None):
    z = Zone({("default._bimi.d.test", "TXT"): rec} if rec else {})
    return bimi.check("d.test", z, R, {"results": {"dmarc": {"tags": dmarc_tags}}, "http_fetch": fetcher(docs or {}), "now": NOW})


def test_bimi_full_pass_with_certificate():
    r = bm(["v=BIMI1; l=https://x.test/l.svg; a=https://x.test/c.pem"], {"p": "reject"},
           {"https://x.test/l.svg": SVG_OK, "https://x.test/c.pem": PEM})
    assert [f.rule_id for f in r["findings"] if f.severity != "info"] == []
    assert "bimi.certificate_present" in ids(r)


def test_bimi_dmarc_prerequisites():
    for tags in ({"p": "none"}, {"p": "reject", "sp": "none"}, {"p": "quarantine", "pct": "50"}):
        assert "bimi.dmarc_enforcement" in ids(bm(["v=BIMI1; l=https://x.test/l.svg"], tags, {"https://x.test/l.svg": SVG_OK}))
    assert "bimi.dmarc_enforcement" not in ids(bm(["v=BIMI1; l=https://x.test/l.svg"], {"p": "quarantine", "pct": "100"},
                                                 {"https://x.test/l.svg": SVG_OK}))


def test_bimi_svg_profile_title_script_size():
    bad = b'<svg xmlns="http://www.w3.org/2000/svg" x="0"><script>1</script></svg>' + b" " * 33000
    r = bm(["v=BIMI1; l=https://x.test/l.svg"], {"p": "reject"}, {"https://x.test/l.svg": bad})
    got = set(ids(r))
    assert {"bimi.svg_profile", "bimi.svg_title", "bimi.svg_disallowed", "bimi.svg_size", "bimi.no_certificate"} <= got


def test_bimi_absent_declined_http_multiple_fetch_fail_not_pem():
    assert ids(bm(None, {})) == ["bimi.absent"]
    assert ids(bm(["v=BIMI1; l=; a=;"], {"p": "reject"})) == ["bimi.declined"]
    assert "bimi.record" in ids(bm(["v=BIMI1; l=http://x.test/l.svg"], {"p": "reject"}))
    assert ids(bm(["v=BIMI1; l=https://a", "v=BIMI1; l=https://b"], {"p": "reject"})) == ["bimi.record"]
    r = bm(["v=BIMI1; l=https://x.test/missing.svg; a=https://x.test/c.pem"], {"p": "reject"}, {"https://x.test/c.pem": b"nope"})
    assert "bimi.fetch" in ids(r) and "bimi.certificate_format" in ids(r)


def test_bimi_gzip_svg():
    import gzip
    r = bm(["v=BIMI1; l=https://x.test/l.svgz"], {"p": "reject"}, {"https://x.test/l.svgz": gzip.compress(SVG_OK)})
    assert not [f for f in r["findings"] if f.rule_id.startswith("bimi.svg")]


def test_bimi_wrong_case_version_is_absent():
    assert ids(bm(["v=bimi1; l=https://x"], {"p": "reject"})) == ["bimi.absent"]


# ---------------------------------------------------------- MTA-STS wrap
def sts_fetch(body, status=200, ct="text/plain"):
    def f(domain, timeout=10.0):
        return {"url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "status": status, "content_type": ct,
                "body": body, "truncated": False, "location": None, "cert_not_after": None, "error": None}
    return f


STS = {("_mta-sts.d.test", "TXT"): ["v=STSv1; id=20261029"], ("d.test", "MX"): ["10 mx.d.test."],
       ("_smtp._tls.d.test", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@d.test"]}


def test_mtasts_enforce_clean_and_every_code_has_rule():
    r = mtasts.check("d.test", Zone(STS), R, {"mtasts_fetch": sts_fetch("version: STSv1\nmode: enforce\nmx: mx.d.test\nmax_age: 1209600\n")})
    assert [f for f in r["findings"] if f.severity != "info"] == [] and r["data"]["mode"] == "enforce"
    assert all(f.rule_id != "core.internal" for f in r["findings"])


def test_mtasts_short_max_age_unmatched_mx_cited_separately():
    r = mtasts.check("d.test", Zone(STS), R, {"mtasts_fetch": sts_fetch("version: STSv1\nmode: enforce\nmx: other.test\nmax_age: 86400\n")})
    assert sev(r, "mtasts.policy_max_age_short") == ["warning"] and sev(r, "mtasts.mx_unmatched") == ["error"]
    assert R.get("mtasts.mx_unmatched")["source"].startswith("RFC 8461 4.1")


def test_mtasts_enforce_without_tlsrpt_and_absent():
    z = {k: v for k, v in STS.items() if not k[0].startswith("_smtp")}
    r = mtasts.check("d.test", Zone(z), R, {"mtasts_fetch": sts_fetch("version: STSv1\nmode: enforce\nmx: mx.d.test\nmax_age: 1209600\n")})
    assert sev(r, "tlsrpt.enforce_without_tlsrpt") == ["warning"]
    assert {f.severity for f in mtasts.check("x.test", Zone({}), R)["findings"]} == {"info"}


def test_mtasts_smtp_port25_blocked_is_not_tested():
    probe = lambda host, timeout: {"host": host, "starttls": None, "cert_valid": None, "names": [], "not_after": None,
                                   "error": "unreachable: TimeoutError"}
    r = mtasts.check("d.test", Zone(STS), R, {"smtp": True, "smtp_probe": probe,
                                             "mtasts_fetch": sts_fetch("version: STSv1\nmode: enforce\nmx: mx.d.test\nmax_age: 1209600\n")})
    assert r["data"]["smtp_status"] == "not tested (port 25 blocked)" and sev(r, "mtasts.smtp_unreachable") == ["info"]


def test_mtasts_smtp_no_starttls_is_error_in_enforce():
    probe = lambda host, timeout: {"host": host, "starttls": False, "cert_valid": None, "names": [], "not_after": None, "error": None}
    r = mtasts.check("d.test", Zone(STS), R, {"smtp": True, "smtp_probe": probe,
                                             "mtasts_fetch": sts_fetch("version: STSv1\nmode: enforce\nmx: mx.d.test\nmax_age: 1209600\n")})
    assert sev(r, "mtasts.smtp_no_starttls") == ["error"] and r["data"]["smtp_status"] == "tested"


def test_engine_codes_all_mapped():
    import re, pathlib
    src = pathlib.Path(mtasts.E.__file__).read_text()
    codes = set(re.findall(r'issue\("[a-z]+", "([a-z_]+)"', src)) | {"policy_max_age_short"}
    missing = [c for c in codes if mtasts.rule_for(c) not in R]
    assert not missing, missing


# ------------------------------------------------------ citations / output
def test_every_finding_carries_rule_citation_and_rules_version():
    rep = audit("good.test", Zone(GOOD), R, options={"dkim_selectors": ["s1"]})
    fs = [f for c in rep["checks"] for f in c["findings"]]
    assert fs and all(f.rule_id in R and f.citation and f.rules_version == R.version for f in fs)
    assert all(f.url.startswith("https://") for f in fs if f.level != "TOOL")


def test_every_check_rule_url_is_section_anchored_for_rfcs():
    for r in R.by_id.values():
        if "rfc-editor.org" in r.get("url", ""):
            assert "#section-" in r["url"] or "#appendix-" in r["url"], r["id"]


def test_sarif_has_citation_and_rules_version():
    z = dict(GOOD); z[("s1._domainkey.good.test", "TXT")] = [f"v=DKIM1; p={RSA512}"]
    rep = audit("good.test", Zone(z), R, options={"dkim_selectors": ["s1"]})
    s = sarif.build([rep], R, "1.0.0")
    res = s["runs"][0]["results"]
    hit = [x for x in res if x["ruleId"] == "dkim.min_rsa_bits"][0]
    assert "RFC 8301 3.2" in hit["message"]["text"] and R.version in hit["message"]["text"]
    assert hit["properties"]["rulesVersion"] == R.version and hit["properties"]["citationUrl"].endswith("section-3.2")
    assert "rules_version" in csvout.dumps([rep]).splitlines()[0]


# ------------------------------------------------------------------ diff
def _rep(records, **o):
    return jsonout.to_jsonable([audit("good.test", Zone(records), R, options=o)], "t")


def test_diff_new_resolved_and_regression():
    old = _rep(GOOD, dkim_selectors=["s1"])
    z = dict(GOOD); z[("s1._domainkey.good.test", "TXT")] = [f"v=DKIM1; p={RSA512}"]
    new = _rep(z, dkim_selectors=["s1"])
    d = diff.compare(old, new)
    assert any(f["rule_id"] == "dkim.min_rsa_bits" for f in d["added"]) and diff.has_regression(d)
    back = diff.compare(new, old)
    assert any(f["rule_id"] == "dkim.min_rsa_bits" for f in back["resolved"]) and not diff.has_regression(back)
    md = diff.markdown(d)
    assert "New problems" in md and "RFC 8301 3.2" in md


def test_diff_no_change_and_empty_baseline():
    a = _rep(GOOD, dkim_selectors=["s1"])
    assert "No changes" in diff.markdown(diff.compare(a, a))
    d = diff.compare([], a)
    assert d["domains_added"] == ["good.test"]


def test_diff_rules_version_bump_reported():
    a = _rep(GOOD); b = json.loads(json.dumps(a)); b[0]["rules_version"] = "2099.01.01.1"
    assert "Rule set updated" in diff.markdown(diff.compare(a, b))


def test_cli_baseline_diff_and_fail_on_new(tmp_path, monkeypatch):
    from faultypacket_audit import cli
    import io
    monkeypatch.setattr(cli, "Resolver", lambda *a, **k: Zone(GOOD))
    base = tmp_path / "b.json"; dfile = tmp_path / "d.md"
    out = io.StringIO()
    cli.main(["good.test", "--dkim-selector", "s1", "--json", str(base), "-q"], stdout=out, stderr=out)
    rc = cli.main(["good.test", "--dkim-selector", "s1", "--baseline", str(base), "--diff", str(dfile),
                   "--fail-on-new", "-q"], stdout=out, stderr=out)
    assert rc == 0 and "No changes" in dfile.read_text()


def test_cli_diff_requires_baseline():
    from faultypacket_audit import cli
    with pytest.raises(SystemExit):
        cli.main(["x.test", "--diff", "-"])


def test_tlsa_multiline_presentation_parses():
    from faultypacket_audit.checks import dane
    z = Zone({("e.example", "MX"): ["10 mx.e.example."], ("mx.e.example", "A"): ["192.0.2.1"],
              ("_25._tcp.mx.e.example", "TLSA"): ["3 1 1 ( " + "AB" * 32 + " )"]})
    r = dane.check("e.example", z, R, {})
    assert "dane.syntax" not in ids(r)


def test_probed_selector_ignores_wildcard_dmarc_txt():
    from faultypacket_audit.checks import dkim
    z = Zone({("default._domainkey.w.example", "TXT"): ["v=DMARC1; p=reject"]})
    r = dkim.check("w.example", z, R, {})
    assert not {"dkim.bad_version", "dkim.bad_key"} & set(ids(r))
