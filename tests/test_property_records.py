"""Hypothesis property tests for the DMARC, MTA-STS and TLS-RPT TXT parsers and
the SPF evaluator: arbitrary input never crashes them, and round-trips hold."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hypothesis import given, settings, strategies as st, HealthCheck
from faultypacket_audit.checks import dmarc, spf
from faultypacket_audit.checks import _mtasts_engine as M
from tests.zone import Zone

S = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
anytext = st.text(st.characters(blacklist_categories=("Cs",)), max_size=300)
printable = st.text(st.characters(min_codepoint=0x20, max_codepoint=0x7e), max_size=200)
label = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True)
host = st.builds(lambda a, b: f"{a}.{b}", label, st.sampled_from(["example", "example.org", "test"]))
mailto = st.builds(lambda l, h: f"mailto:{l}@{h}", label, host)
policy = st.sampled_from(["none", "quarantine", "reject"])
WS = st.sampled_from(["", " ", "  ", "\t"])


@S
@given(anytext)
def test_dmarc_validate_never_crashes(t):
    tags, issues = dmarc.validate(t)
    assert isinstance(tags, dict) and all(s in ("error", "warning", "info") for s, _, _ in issues)


@S
@given(policy, st.none() | policy, st.none() | st.sampled_from(["r", "s"]), st.lists(mailto, min_size=1, max_size=3), WS, WS)
def test_dmarc_round_trip_valid_records(p, sp, adkim, rua, w1, w2):
    tags = {"v": "DMARC1", "p": p}
    if sp:
        tags["sp"] = sp
    if adkim:
        tags["adkim"] = adkim
    tags["rua"] = ",".join(rua)
    rec = f"{w1};{w2}".join(f"{k}{w1}={w2}{v}" for k, v in tags.items())
    got, issues = dmarc.validate(rec)
    assert got == tags
    assert not [i for i in issues if i[0] == "error"], issues


@S
@given(policy, st.lists(mailto, min_size=1, max_size=3))
def test_dmarc_tag_order_after_v_is_irrelevant(p, rua):
    a = f"v=DMARC1; p={p}; rua={','.join(rua)}"
    b = f"v=DMARC1; rua={','.join(rua)}; p={p}"
    assert dmarc.validate(a)[0] == dmarc.validate(b)[0]
    assert sorted(dmarc.validate(a)[1]) == sorted(dmarc.validate(b)[1])


@S
@given(policy, st.sampled_from(["P", "Rua", "SP", "ADKIM"]))
def test_dmarc_tag_names_case_insensitive_version_value_not(p, name):
    assert dmarc.validate(f"v=DMARC1; {name}=x")[0].get(name.lower()) == "x"
    assert "version" in {c for _, c, _ in dmarc.validate(f"v=dmarc1; p={p}")[1]}


@S
@given(st.lists(mailto, min_size=1, max_size=4), st.none() | st.from_regex(r"[0-9]{1,4}[kmgt]?", fullmatch=True))
def test_parse_uris_round_trip(uris, size):
    raw = ",".join(u + (f"!{size}" if size else "") for u in uris)
    out = dmarc.parse_uris(raw)
    assert [o["scheme"] for o in out] == ["mailto"] * len(uris)
    assert [o["address"] for o in out] == [u[len("mailto:"):] for u in uris]
    assert all(o["size"] == size for o in out)


@S
@given(st.lists(mailto, min_size=1, max_size=3))
def test_dmarc_space_inside_uri_is_invalid(uris):
    rec = f"v=DMARC1; p=none; rua={uris[0].replace(':', ': ', 1)}"
    assert "bad_uri_rua" in {c for _, c, _ in dmarc.validate(rec)[1]}


@S
@given(printable)
def test_sts_txt_never_crashes(t):
    fields, issues = M.parse_sts_txt(t)
    assert fields is None or "id" in fields


@S
@given(st.from_regex(r"[A-Za-z0-9]{1,32}", fullmatch=True), WS)
def test_sts_txt_round_trip(i, w):
    fields, issues = M.parse_sts_txt(f"v=STSv1;{w}id={i}{w};")
    assert fields == {"v": "STSv1", "id": i} or fields == {"id": i} or fields.get("id") == i
    assert not issues


@S
@given(anytext)
def test_tlsrpt_never_crashes(t):
    r = M.check_tlsrpt("x.test", Zone({("_smtp._tls.x.test", "TXT"): [t]}))
    assert isinstance(r["issues"], list)


@S
@given(st.lists(st.one_of(mailto, st.builds(lambda h: f"https://{h}/tls", host)), min_size=1, max_size=3))
def test_tlsrpt_round_trip(uris):
    r = M.check_tlsrpt("x.test", Zone({("_smtp._tls.x.test", "TXT"): [f"v=TLSRPTv1; rua={','.join(uris)}"]}))
    assert r["rua"] == uris and not r["issues"]


@S
@given(anytext)
def test_spf_analyse_never_crashes(t):
    r = spf.analyse("x.test", Zone({("x.test", "TXT"): ["v=spf1 " + t]}))
    assert r["result"] in ("ok", "permerror", "temperror", "none")


@S
@given(st.lists(host, max_size=5), st.sampled_from(["-", "~", "?", "+"]), st.lists(host, min_size=1, max_size=4))
def test_spf_terms_after_all_cost_no_lookups(before, q, after):
    zone = {(h, "TXT"): ["v=spf1 -all"] for h in before + after}
    base = "v=spf1 " + " ".join(f"include:{h}" for h in before) + f" {q}all"
    a = spf.analyse("x.test", Zone({**zone, ("x.test", "TXT"): [base]}))
    b = spf.analyse("x.test", Zone({**zone, ("x.test", "TXT"): [base + " " + " ".join(f"include:{h}" for h in after)]}))
    assert a["lookups"] == b["lookups"]
    assert "after_all" in {i["code"] for i in b["issues"]}


@S
@given(st.sampled_from(["-", "~", "?", "+"]), st.from_regex(r"[a-z][a-z0-9-]{0,12}", fullmatch=True))
def test_spf_qualified_modifier_is_invalid(q, name):
    kind, *_ = spf.parse_term(f"{q}{name}=x")
    assert kind == "invalid"
    assert spf.parse_term(f"{name}=x")[0] == "modifier"
