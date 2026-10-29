"""DMARC aggregate / TLS-RPT report reader (synthetic fixtures only)."""
import gzip, io, json, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from hypothesis import given, settings, strategies as st, HealthCheck
from faultypacket_audit import reports as R

FX = os.path.join(os.path.dirname(__file__), "fixtures", "reports")
XML = open(os.path.join(FX, "dmarc-example.org.xml"), "rb").read()
TLS = open(os.path.join(FX, "tlsrpt-example.org.json"), "rb").read()
S = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def test_dmarc_parse():
    (r,) = R.parse_bytes("a.xml", XML)
    assert r["type"] == "dmarc" and r["policy_domain"] == "example.com" and len(r["records"]) == 3
    assert r["records"][2]["source_ip"] == "2001:db8::25"


def test_summary_counts():
    s = R.summarise(R.parse_bytes("a.xml", XML))
    assert s["messages"] == 48 and s["dmarc_pass"] == 43
    ip = s["by_source_ip"]["198.51.100.7"]
    assert ip["dmarc_fail"] == 5 and ip["quarantined"] == 5 and ip["spf_fail"] == 5 and ip["dkim_fail"] == 5
    assert s["unauthorised_senders"] == ["198.51.100.7"]
    assert s["by_domain"]["mail.example.com"]["spf_pass"] == 3 and s["by_domain"]["mail.example.com"]["spf_aligned"] == 0


def test_gzip_and_zip():
    gz = gzip.compress(XML)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("r1.xml", XML)
        z.writestr("r2.json", TLS)
    assert len(R.parse_bytes("a.xml.gz", gz)) == 1
    out = R.parse_bytes("a.zip", buf.getvalue())
    assert [r["type"] for r in out] == ["dmarc", "tlsrpt"]


def test_tlsrpt():
    s = R.summarise(R.parse_bytes("t.json", TLS))
    assert s["tls"]["example.com"] == {"success": 90, "failure": 2, "result_types": {"certificate-expired": 2}}


def test_rejects_entities():
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><feedback>&a;</feedback>'
    with pytest.raises(R.ReportError):
        R.parse_bytes("x.xml", bomb)


@pytest.mark.parametrize("data", [b"", b"hello", b"<other/>", b"{}", b"{\"policies\": 3}", b"<feedback><record><row><source_ip>x</source_ip></row></record></feedback>",
                                  b"<feedback><record><row><source_ip>192.0.2.1</source_ip><count>-1</count></row></record></feedback>"])
def test_bad_inputs(data):
    with pytest.raises(R.ReportError):
        R.parse_bytes("x", data)


def test_size_cap(monkeypatch):
    monkeypatch.setattr(R, "MAX_BYTES", 100)
    with pytest.raises(R.ReportError):
        R.parse_bytes("a.gz", gzip.compress(b"<" + b"a" * 500))


def test_markdown_and_cli(tmp_path):
    p = tmp_path / "r.xml.gz"
    p.write_bytes(gzip.compress(XML))
    out, err = io.StringIO(), io.StringIO()
    assert R.main([str(p), str(os.path.join(FX, "tlsrpt-example.org.json")), "--fail-on-unauthorised"], stdout=out, stderr=err) == 1
    md = out.getvalue()
    assert "198.51.100.7 **unauthorised**" in md and "certificate-expired (2)" in md and "nothing was uploaded" in md
    out = io.StringIO()
    assert R.main([str(p), "--format", "json"], stdout=out, stderr=err) == 0
    assert json.loads(out.getvalue())["messages"] == 48


def test_cli_unreadable(tmp_path):
    err = io.StringIO()
    assert R.main([str(tmp_path / "missing.xml")], stdout=io.StringIO(), stderr=err) == 2


def test_namespaced_xml():
    ns = XML.replace(b"<feedback>", b'<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">')
    assert R.parse_bytes("a.xml", ns)[0]["policy_domain"] == "example.com"


ip = st.one_of(st.ip_addresses(v=4, network="192.0.2.0/24"), st.ip_addresses(v=4, network="198.51.100.0/24"),
               st.ip_addresses(v=6, network="2001:db8::/32")).map(str)
res = st.sampled_from(["pass", "fail", "softfail", "none", "neutral", "temperror"])
row = st.tuples(ip, st.integers(0, 10_000), st.sampled_from(["pass", "fail"]), st.sampled_from(["pass", "fail"]), res, res,
                st.sampled_from(["example.com", "example.org", "mail.example.com"]))


def _xml(rows):
    recs = "".join(
        f"<record><row><source_ip>{i}</source_ip><count>{c}</count><policy_evaluated><disposition>none</disposition>"
        f"<dkim>{pd}</dkim><spf>{ps}</spf></policy_evaluated></row><identifiers><header_from>{h}</header_from></identifiers>"
        f"<auth_results><dkim><domain>{h}</domain><result>{rd}</result></dkim><spf><domain>{h}</domain><result>{rs}</result></spf></auth_results></record>"
        for i, c, pd, ps, rd, rs, h in rows)
    return f"<feedback><policy_published><domain>example.com</domain><p>none</p></policy_published>{recs}</feedback>".encode()


@S
@given(st.lists(row, max_size=30))
def test_prop_totals_consistent(rows):
    s = R.summarise(R.parse_bytes("p.xml", _xml(rows)))
    total = sum(r[1] for r in rows)
    assert s["messages"] == total == sum(b["messages"] for b in s["by_source_ip"].values())
    for b in list(s["by_domain"].values()) + list(s["by_source_ip"].values()):
        assert b["spf_pass"] + b["spf_fail"] == b["dkim_pass"] + b["dkim_fail"] == b["dmarc_pass"] + b["dmarc_fail"] == b["messages"]
        assert b["spf_aligned"] <= b["messages"] and b["dmarc_pass"] >= max(b["spf_aligned"], b["dkim_aligned"])
    assert set(s["unauthorised_senders"]) <= {f["source_ip"] for f in s["failing_senders"]}


@S
@given(st.lists(row, max_size=10))
def test_prop_containers_equivalent(rows):
    x = _xml(rows)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.xml", x)
    a = R.summarise(R.parse_bytes("a.xml", x))
    assert a == R.summarise(R.parse_bytes("a.gz", gzip.compress(x))) == R.summarise(R.parse_bytes("a.zip", buf.getvalue()))
    R.markdown(a)


@S
@given(st.binary(max_size=400))
def test_prop_arbitrary_bytes_never_crash(b):
    for data in (b, b"<feedback>" + b, b"{" + b, gzip.compress(b)):
        try:
            R.summarise(R.parse_bytes("f", data))
        except (R.ReportError, zipfile.BadZipFile, EOFError, OSError):
            pass


@pytest.mark.parametrize("j", ['{"policies": [{"policy": [1], "summary": {}}]}', '{"policies": [{"summary": {"total-successful-session-count": "x"}}]}',
                               '{"policies": [{"failure-details": [{"failed-session-count": {"a": 1}}]}]}', '{"policies": ["x"]}'])
def test_tlsrpt_malformed(j):
    with pytest.raises(R.ReportError):
        R.parse_bytes("t.json", j.encode())


json_val = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=5),
                        lambda c: st.lists(c, max_size=3) | st.dictionaries(st.sampled_from(
                            ["policy", "summary", "failure-details", "policy-domain", "total-successful-session-count",
                             "failed-session-count", "result-type"]), c, max_size=4), max_leaves=12)


@S
@given(st.lists(json_val, max_size=3))
def test_prop_tlsrpt_shapes_never_crash(pols):
    try:
        R.summarise(R.parse_bytes("t.json", json.dumps({"policies": pols}).encode()))
    except R.ReportError:
        pass
