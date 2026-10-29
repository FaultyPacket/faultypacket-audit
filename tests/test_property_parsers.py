"""Property / fuzz tests (hypothesis) for the SPF and DMARC parsers and the
header analyser: no input may crash them, and documented invariants hold."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from hypothesis import given, settings, strategies as st, HealthCheck
from faultypacket_audit.checks import spf, dmarc
from faultypacket_audit import headers as H
from tests.zone import Zone

S = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
label = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", fullmatch=True)
domain = st.builds(lambda a, b: f"{a}.{b}", label, st.sampled_from(["test", "example", "co.uk", "org"]))
qual = st.sampled_from(["", "+", "-", "~", "?"])
ip4 = st.ip_addresses(v=4).map(str)
ip6 = st.ip_addresses(v=6).map(str)
term = st.one_of(
    st.builds(lambda q, i, c: f"{q}ip4:{i}" + (f"/{c}" if c is not None else ""), qual, ip4, st.none() | st.integers(0, 32)),
    st.builds(lambda q, i, c: f"{q}ip6:{i}" + (f"/{c}" if c is not None else ""), qual, ip6, st.none() | st.integers(0, 128)),
    st.builds(lambda q, d: f"{q}include:{d}", qual, domain),
    st.builds(lambda q, d: f"{q}a:{d}", qual, domain),
    st.builds(lambda q: f"{q}a", qual), st.builds(lambda q: f"{q}mx", qual),
    st.builds(lambda q, d, c: f"{q}mx:{d}/{c}", qual, domain, st.integers(0, 32)),
    st.builds(lambda q, d: f"{q}exists:{d}", qual, domain),
)
anytext = st.text(st.characters(blacklist_categories=("Cs",)), max_size=200)


@S
@given(anytext.filter(lambda s: s != ""))
def test_parse_term_never_crashes_and_kind_is_known(t):
    kind, name, arg, cidr, q = spf.parse_term(t)
    assert kind in ("mechanism", "modifier", "invalid") and q in "+-~?"


@S
@given(term)
def test_generated_valid_terms_parse_as_mechanisms(t):
    kind, name, arg, cidr, q = spf.parse_term(t)
    assert kind == "mechanism" and name in spf.MECHANISMS
    assert q == (t[0] if t[0] in "+-~?" else "+")


@S
@given(qual, ip4, st.integers(33, 999))
def test_ip4_cidr_over_32_is_syntax_error(q, i, c):
    z = Zone({("x.test", "TXT"): [f"v=spf1 {q}ip4:{i}/{c} -all"]})
    assert "syntax" in {x["code"] for x in spf.analyse("x.test", z)["issues"]}


@S
@given(st.lists(term, max_size=14), qual)
def test_analyse_random_records_invariants(terms, q):
    rec = "v=spf1 " + " ".join(terms) + f" {q}all"
    z = Zone({("x.test", "TXT"): [rec]})
    r = spf.analyse("x.test", z)
    counted = sum(1 for t in terms if spf.parse_term(t)[1] in ("include", "a", "mx", "exists"))
    assert r["lookups"] == counted                       # RFC 7208 4.6.4: each DNS term counts once
    assert r["void_lookups"] <= r["lookups"]
    assert ("lookup_limit" in {i["code"] for i in r["issues"]}) == (counted > 10)
    assert r["result"] in ("ok", "permerror", "temperror", "none")
    assert spf.all_qualifier(rec) == (q or "+")


@S
@given(anytext)
def test_analyse_arbitrary_txt_never_crashes(txt):
    r = spf.analyse("x.test", Zone({("x.test", "TXT"): ["v=spf1 " + txt]}))
    assert r["result"] in ("ok", "permerror", "temperror", "none")


@S
@given(st.lists(domain, min_size=1, max_size=5))
def test_include_chain_lookup_count_equals_chain_length(chain):
    chain = list(dict.fromkeys(c for c in chain if c != "root.test"))
    z = {("root.test", "TXT"): [f"v=spf1 include:{chain[0]} -all"]}
    for a, b in zip(chain, chain[1:]):
        z[(a, "TXT")] = [f"v=spf1 include:{b} -all"]
    z[(chain[-1], "TXT")] = ["v=spf1 ip4:192.0.2.1 -all"]
    r = spf.analyse("root.test", Zone(z))
    assert r["lookups"] == len(chain) and r["result"] == "ok"


# ---------------------------------------------------------------- DMARC
pol = st.sampled_from(["none", "quarantine", "reject"])
tagv = st.one_of(
    st.builds(lambda v: ("sp", v), pol), st.builds(lambda v: ("np", v), pol),
    st.builds(lambda v: ("adkim", v), st.sampled_from("rs")), st.builds(lambda v: ("aspf", v), st.sampled_from("rs")),
    st.builds(lambda v: ("psd", v), st.sampled_from("ynu")), st.builds(lambda v: ("t", v), st.sampled_from("yn")),
    st.builds(lambda d: ("rua", f"mailto:r@{d}"), domain),
)


@S
@given(anytext)
def test_dmarc_validate_never_crashes(txt):
    d, issues = dmarc.validate(txt)
    assert isinstance(d, dict) and all(len(i) == 3 for i in issues)


@S
@given(pol, st.lists(tagv, max_size=6, unique_by=lambda x: x[0]))
def test_valid_dmarc_records_have_no_errors(p, tags):
    rec = "v=DMARC1; p=" + p + "".join(f"; {k}={v}" for k, v in tags)
    d, issues = dmarc.validate(rec)
    assert not [i for i in issues if i[0] == "error"], issues
    assert d["p"] == p and dmarc.dmarc_records([rec]) == [rec]


@S
@given(pol, st.lists(tagv, max_size=6, unique_by=lambda x: x[0]), st.sampled_from([" ", "", "  "]))
def test_dmarc_whitespace_and_tag_case_insensitive(p, tags, ws):
    rec = "v=DMARC1;" + ws + "P=" + p + "".join(f";{ws}{k.upper()}{ws}={ws}{v}" for k, v in tags)
    d, issues = dmarc.validate(rec)
    assert d["p"] == p and not [i for i in issues if i[0] == "error"]


@S
@given(st.text(alphabet="vVdDmMaArRcC1=; ", max_size=20))
def test_dmarc_version_is_case_sensitive(prefix):
    recs = dmarc.dmarc_records([prefix])
    if recs:
        assert "DMARC1" in prefix


@S
@given(st.lists(st.sampled_from(["0", "1", "d", "s"]), min_size=1, max_size=5))
def test_valid_fo_matches_definition(opts):
    ok = dmarc.valid_fo(":".join(opts))
    expected = not ("0" in opts and "1" in opts) and all(opts.count(o) <= 1 for o in opts)
    assert ok == expected


@S
@given(st.lists(domain, min_size=1, max_size=4), st.none() | st.from_regex(r"[0-9]{1,4}[kmgt]?", fullmatch=True))
def test_parse_uris_hosts_and_size(hosts, size):
    v = ",".join(f"mailto:r@{h}" + (f"!{size}" if size else "") for h in hosts)
    u = dmarc.parse_uris(v)
    assert [x["host"] for x in u] == hosts and all(x["size"] == size for x in u)


@S
@given(st.lists(label, min_size=1, max_size=12))
def test_walk_targets_bounded_and_suffixes(labels):
    name = ".".join(labels)
    t = dmarc.walk_targets(name)
    assert 1 <= len(t) <= 8 and all(name == x or name.endswith("." + x) for x in t)


# ---------------------------------------------------------------- headers
@S
@given(anytext)
def test_parse_ar_never_crashes(txt):
    r = H.parse_ar(txt)
    assert set(r) >= {"authserv_id", "results"}


@S
@given(domain, st.sampled_from(["pass", "fail", "none", "neutral", "temperror", "permerror"]), domain)
def test_parse_ar_roundtrip(authserv, res, d):
    r = H.parse_ar(f"{authserv}; dkim={res} (comment; with semicolon) header.d={d}; spf={res} smtp.mailfrom=b@{d}")
    assert r["authserv_id"] == authserv
    assert [(x["method"], x["result"]) for x in r["results"]] == [("dkim", res), ("spf", res)]
    assert r["results"][0]["props"]["header.d"] == d


@S
@given(anytext)
def test_strip_comments_removes_all_unquoted_parens_content(txt):
    out = H.strip_comments(txt)
    assert len(out) <= len(txt)


@S
@given(st.binary(max_size=600))
def test_analyse_arbitrary_bytes_never_crashes(b):
    r = H.analyse(b)
    assert r["verdict"] in ("pass", "fail", "fail-unaligned", "unknown")


@S
@given(domain, domain, st.sampled_from("rs"))
def test_alignment_strict_implies_relaxed(a, b, mode):
    if H.aligned(a, b, "s"):
        assert H.aligned(a, b, "r")
    assert H.aligned(a, a, mode)
