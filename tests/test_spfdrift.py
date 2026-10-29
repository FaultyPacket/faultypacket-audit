"""SPF drift check (synthetic zones, documentation ranges only)."""
import io, ipaddress, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hypothesis import given, settings, strategies as st, HealthCheck
from faultypacket_audit import spfdrift as D
from tests.zone import Zone

Z = {
    ("_spf.example.org", "TXT"): ["v=spf1 ip4:192.0.2.0/25 include:_s2.example.org a:mta.example.org/30 -all"],
    ("_s2.example.org", "TXT"): ["v=spf1 ip6:2001:db8:1::/48 ~all"],
    ("mta.example.org", "A"): ["198.51.100.8"],
    ("example.com", "TXT"): ["v=spf1 ip4:192.0.2.0/25 ip6:2001:db8:1::/48 ip4:198.51.100.8/30 -all"],
    ("loop.example.org", "TXT"): ["v=spf1 include:loop.example.org -all"],
    ("mx.example.org", "TXT"): ["v=spf1 mx/31 redirect=_s2.example.org"],
    ("mx.example.org", "MX"): ["10 m1.example.org."],
    ("m1.example.org", "A"): ["203.0.113.4"],
}


def test_ok():
    r = D.drift(Z[("example.com", "TXT")][0], ["_spf.example.org"], Zone(Z))
    assert r["status"] == "ok" and not r["missing"] and not r["extra"]


def test_missing_and_extra():
    rec = "v=spf1 ip4:192.0.2.0/26 ip6:2001:db8:1::/48 ip4:198.51.100.8/30 ip4:203.0.113.50 -all"
    r = D.drift(rec, ["_spf.example.org"], Zone(Z))
    assert r["status"] == "drift" and r["missing"] == ["192.0.2.64/26"] and r["extra"] == ["203.0.113.50/32"]


def test_mx_and_redirect():
    r = D.drift("v=spf1 ip4:203.0.113.4/31 ip6:2001:db8:1::/48 -all", ["mx.example.org"], Zone(Z))
    assert r["status"] == "ok"


def test_lookup_errors_reported():
    assert D.drift("v=spf1 -all", ["loop.example.org"], Zone(Z))["status"] == "error"
    assert D.drift("v=spf1 -all", ["none.example.org"], Zone(Z))["errors"][0]["error"] == "void"
    z = {**Z, ("bad.example.org", "TXT"): "err"}
    assert D.drift("v=spf1 -all", ["bad.example.org"], Zone(z))["status"] == "error"


def test_non_pass_qualifiers_ignored():
    z = {**Z, ("q.example.org", "TXT"): ["v=spf1 -ip4:192.0.2.1 ~ip4:192.0.2.2 ip4:192.0.2.3"]}
    assert D.drift("v=spf1 ip4:192.0.2.3 -ip4:192.0.2.9 -all", ["q.example.org"], Zone(z))["status"] == "ok"


def test_cli():
    out = io.StringIO()
    assert D.main(["example.com", "--include", "_spf.example.org", "--json"], stdout=out, res=Zone(Z)) == 0
    assert json.loads(out.getvalue())["status"] == "ok"
    out = io.StringIO()
    assert D.main(["--record", "v=spf1 ip4:192.0.2.0/24 -all", "--include", "_spf.example.org"], stdout=out, res=Zone(Z)) == 1
    assert "missing from flattened record" in out.getvalue() and "192.0.2.128/25" in out.getvalue()
    assert D.main(["nospf.example.com", "--include", "_spf.example.org"], stdout=io.StringIO(), stderr=io.StringIO(), res=Zone(Z)) == 2


S = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
net4 = st.builds(lambda a, p: ipaddress.ip_network(f"{a}/{p}", strict=False),
                 st.ip_addresses(v=4, network="198.51.100.0/24"), st.integers(24, 32))
net6 = st.builds(lambda a, p: ipaddress.ip_network(f"{a}/{p}", strict=False),
                 st.ip_addresses(v=6, network="2001:db8::/32"), st.integers(32, 128))
nets = st.lists(st.one_of(net4, net6), max_size=8)


def _rec(ns):
    return "v=spf1 " + " ".join(f"ip{n.version}:{n}" for n in ns) + " -all"


@S
@given(nets, nets)
def test_prop_drift_partition(src, flat):
    z = Zone({("src.example.org", "TXT"): [_rec(src)]})
    r = D.drift(_rec(flat), ["src.example.org"], z)
    S_, F = D._collapse(src), D._collapse(flat)
    cov = lambda ip, ns: any(ip in n for n in ns)
    for m in r["missing"]:
        n = ipaddress.ip_network(m)
        assert cov(n[0], S_) and not cov(n[0], F)
    for e in r["extra"]:
        n = ipaddress.ip_network(e)
        assert cov(n[0], F) and not cov(n[0], S_)
    assert (r["status"] == "ok") == (S_ == F)


@S
@given(nets)
def test_prop_flatten_of_self_is_ok(src):
    z = Zone({("src.example.org", "TXT"): [_rec(src)]})
    assert D.drift(_rec(src), ["src.example.org"], z)["status"] == "ok"


@S
@given(st.text(alphabet="v=spf1 ip46:./-+~?amxinclude0123456789abcdef", max_size=80))
def test_prop_garbage_never_crashes(t):
    z = Zone({("g.example.org", "TXT"): ["v=spf1 " + t]})
    D.drift("v=spf1 " + t, ["g.example.org"], z)
