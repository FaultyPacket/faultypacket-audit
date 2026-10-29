"""Change/failure alerts (synthetic zones; webhook is a fake opener)."""
import io, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from hypothesis import given, settings, strategies as st, HealthCheck
from faultypacket_audit import alerts as A
from tests.zone import Zone, GOOD

BASE = {("example.com", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all", "other"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
        ("example.com", "MX"): ["10 mx.example.com."]}


class Opener:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def __call__(self, req, timeout=10):
        if self.fail:
            raise OSError("boom")
        self.calls.append((req.full_url, json.loads(req.data)))
        return io.BytesIO(b"ok")


def test_snapshot_filters_and_errors():
    z = Zone({**BASE, ("_mta-sts.example.com", "TXT"): "err"})
    s = A.snapshot("example.com", z)
    assert s["records"]["spf"] == ["v=spf1 ip4:192.0.2.0/24 -all"] and s["records"]["mta-sts"] is None and s["records"]["bimi"] == []


def test_compare_events():
    a = {"example.com": A.snapshot("example.com", Zone(BASE))}
    z2 = {**BASE, ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"]}
    b = {"example.com": dict(A.snapshot("example.com", Zone(z2)), status="error", errors=["dmarc.policy"])}
    ev = A.compare(a, b)
    assert [e["type"] for e in ev] == ["record_changed", "started_failing"] and ev[0]["record"] == "dmarc"
    assert A.compare({}, b) == [] and A.compare(b, b) == []


def test_lookup_failure_is_not_change():
    a = {"example.com": A.snapshot("example.com", Zone(BASE))}
    b = {"example.com": A.snapshot("example.com", Zone({**BASE, ("example.com", "MX"): "err"}))}
    assert A.compare(a, b) == []


@pytest.mark.parametrize("fmt", ["slack", "teams", "json"])
def test_payload_shapes(fmt):
    ev = [{"type": "started_failing", "domain": "example.org", "status": "error", "new_errors": ["spf.permerror"]}]
    p = A.payload(ev, fmt)
    blob = json.dumps(p)
    assert "example.org" in blob and "spf.permerror" in blob
    assert {"slack": "text", "teams": "attachments", "json": "events"}[fmt] in p


def test_post_requires_https():
    with pytest.raises(ValueError):
        A.post("http://hooks.example.com/x", {}, Opener())


def _run(tmp_path, zone, env, opener, *extra):
    out, err = io.StringIO(), io.StringIO()
    rc = A.main(["example.com", "--state", str(tmp_path / "s.json"), "--no-audit", *extra],
                stdout=out, stderr=err, res=zone, environ=env, opener=opener)
    return rc, out.getvalue(), err.getvalue()


def test_cli_flow(tmp_path):
    env, op = {"FAULTYPACKET_WEBHOOK_URL": "https://hooks.example.com/T/1"}, Opener()
    assert _run(tmp_path, Zone(BASE), env, op, "--format", "slack")[1].strip() == "no changes"
    z2 = {**BASE, ("example.com", "TXT"): ["v=spf1 ip4:192.0.2.0/24 ~all"]}
    rc, out, _ = _run(tmp_path, Zone(z2), env, op, "--format", "slack")
    assert rc == 0 and "posted 1" in out and op.calls[0][0] == env["FAULTYPACKET_WEBHOOK_URL"]
    assert "~all" in op.calls[0][1]["text"]
    assert _run(tmp_path, Zone(z2), env, op)[1].strip() == "no changes"


def test_cli_missing_env_and_failure_hide_url(tmp_path):
    _run(tmp_path, Zone(BASE), {}, Opener())
    z2 = {**BASE, ("example.com", "MX"): ["20 mx2.example.com."]}
    rc, _, err = _run(tmp_path, Zone(z2), {}, Opener())
    assert rc == 1 and "not set" in err
    _run(tmp_path, Zone(BASE), {}, Opener())
    env = {"HOOK": "https://hooks.example.com/secret-token"}
    rc, _, err = _run(tmp_path, Zone(z2), env, Opener(fail=True), "--webhook-env", "HOOK")
    assert rc == 1 and "secret-token" not in err


def test_cli_dry_run_and_audit(tmp_path):
    out, err = io.StringIO(), io.StringIO()
    args = ["good.test", "--state", str(tmp_path / "s.json"), "--dry-run"]
    assert A.main(args, stdout=out, stderr=err, res=Zone(GOOD), environ={}) == 0
    bad = {**GOOD, ("good.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all", "v=spf1 -all"]}
    out = io.StringIO()
    assert A.main(args, stdout=out, stderr=err, res=Zone(bad), environ={}) == 0
    p = json.loads(out.getvalue())
    assert {e["type"] for e in p["events"]} == {"record_changed", "started_failing"}


def test_no_url_option():
    with pytest.raises(SystemExit):
        A.main(["example.com", "--state", "x", "--webhook", "https://hooks.example.com/x"], stderr=io.StringIO())


S = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
vals = st.none() | st.lists(st.sampled_from(["v=spf1 -all", "v=spf1 ~all", "10 mx.example.org.", "v=DMARC1; p=none"]), max_size=3).map(sorted)
snap = st.builds(lambda r, s, e: {"records": r, "status": s, "errors": sorted(set(e))},
                 st.fixed_dictionaries({k: vals for k, _, _ in A.RECORDS}),
                 st.sampled_from(["ok", "warning", "error", None]), st.lists(st.sampled_from(["a", "b", "c"]), max_size=3))
state = st.dictionaries(st.sampled_from(["example.com", "example.org"]), snap, max_size=2)


@S
@given(state, state)
def test_prop_compare(prev, cur):
    ev = A.compare(prev, cur)
    assert A.compare(cur, cur) == []
    for e in ev:
        assert e["domain"] in prev and e["domain"] in cur
        if e["type"] == "record_changed":
            assert e["before"] != e["after"] and None not in (e["before"], e["after"])
    for fmt in ("slack", "teams", "json"):
        json.dumps(A.payload(ev, fmt))
