import csv, io, json
import pytest
from unittest import mock
from faultypacket_audit import audit, load_rules, cli, __version__
from faultypacket_audit.output import csvout, jsonout, sarif, text
from tests.zone import Zone, GOOD

R = load_rules()
BAD = {("bad.test", "TXT"): ["v=spf1 include:gone.test -all"],
       ("_dmarc.bad.test", "TXT"): ["v=DMARC1; p=quarantine; pct=10; rua=mailto:r@vendor.test"]}


def reports(*doms, z=None):
    zz = Zone({**GOOD, **BAD, **(z or {})})
    return [audit(d, zz, R) for d in doms]


def test_audit_status_is_worst_and_every_finding_cited():
    rep = reports("good.test", "bad.test")
    assert rep[0]["status"] in ("ok", "info") and rep[1]["status"] == "error"
    for r in rep:
        for c in r["checks"]:
            for f in c["findings"]:
                assert f.citation and f.rule_id in R


def test_check_exception_isolated_to_that_check():
    with mock.patch("faultypacket_audit.checks.dmarc.check_domain", side_effect=RuntimeError("boom")):
        r = reports("good.test")[0]
    st = {c["check"]: c for c in r["checks"]}
    assert st["dmarc"]["status"] == "error" and st["dmarc"]["findings"][0].rule_id == "dmarc.internal"
    assert st["spf"]["status"] in ("ok", "info")


def test_subset_of_checks():
    r = audit("good.test", Zone(GOOD), R, checks=["dmarc"])
    assert [c["check"] for c in r["checks"]] == ["dmarc"]


def test_json_roundtrip_has_versions():
    data = json.loads(jsonout.dumps(reports("bad.test"), __version__))
    assert data[0]["tool"] == "faultypacket-audit" and data[0]["rules_version"] == R.version
    f = data[0]["checks"][0]["findings"][0]
    assert {"rule_id", "citation", "url", "level", "severity", "message"} <= set(f)


def test_csv_one_row_per_finding_and_ok_rows():
    rows = list(csv.DictReader(io.StringIO(csvout.dumps(reports("good.test", "bad.test")))))
    assert any(r["domain"] == "bad.test" and r["rule_id"] == "spf.missing_record" for r in rows)
    assert any(r["domain"] == "good.test" and r["check"] == "spf" and r["severity"] == "ok" for r in rows)
    assert all(r["citation"] for r in rows if r["severity"] != "ok")


def test_sarif_shape():
    s = sarif.build(reports("good.test", "bad.test"), R, __version__, artifact="d.txt", lines={"bad.test": 3})
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(res["ruleId"] in ids for res in run["results"])
    assert all(res["level"] in ("error", "warning", "note") for res in run["results"])
    bad = [x for x in run["results"] if x["properties"]["domain"] == "bad.test"]
    assert bad and bad[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    assert all(x["level"] != "note" for x in run["results"])      # info excluded by default
    assert run["tool"]["driver"]["informationUri"] == "https://faultypacket.co.uk"
    fps = [x["partialFingerprints"]["faultypacketFinding/v1"] for x in run["results"]]
    assert len(fps) == len(set(fps))


def test_sarif_include_info():
    s = sarif.build(reports("good.test"), R, __version__, include_info=True)
    assert any(x["level"] == "note" for x in s["runs"][0]["results"])


def test_text_render_and_summary():
    rep = reports("good.test", "bad.test")
    t = text.render(rep)
    assert "bad.test: ERROR" in t and "rule spf.missing_record | RFC 7208 5.2, 6.1" in t
    assert "good.test: OK" in t
    assert "bad.test" in text.summary(rep)


# ---- CLI
def _cli(argv, z=None, stdin=""):
    zone = Zone({**GOOD, **BAD, **(z or {})})
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(cli, "Resolver", lambda *a, **k: zone):
        rc = cli.main(argv, stdin=io.StringIO(stdin), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def test_cli_exit_codes():
    assert _cli(["good.test", "-q", "--dkim-selector", "s1", "--sending-ip", "192.0.2.10"])[0] == 0
    assert _cli(["good.test", "bad.test", "-q"])[0] == 1


def test_cli_fail_on_warning():
    z = {("_dmarc.good.test", "TXT"): ["v=DMARC1; p=reject"]}           # no rua -> warning
    assert _cli(["good.test", "-q", "--checks", "dmarc"], z)[0] == 0
    assert _cli(["good.test", "-q", "--checks", "dmarc", "--fail-on", "warning"], z)[0] == 1


def test_cli_batch_file_dedupe_and_outputs(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("# fleet\ngood.test\nbad.test\nGOOD.test\nhttps://bad.test/x\n")
    j, c, s = tmp_path / "o.json", tmp_path / "o.csv", tmp_path / "o.sarif"
    rc, out, _ = _cli(["-f", str(f), "-q", "--json", str(j), "--csv", str(c), "--sarif", str(s)])
    assert rc == 1
    assert [d["domain"] for d in json.loads(j.read_text())] == ["good.test", "bad.test"]
    assert "rule_id" in c.read_text().splitlines()[0]
    sr = json.loads(s.read_text())["runs"][0]["results"]
    assert sr[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(f)
    assert {x["locations"][0]["physicalLocation"]["region"]["startLine"] for x in sr} == {3}


def test_cli_json_stdout_pure():
    rc, out, err = _cli(["good.test", "--json", "-"])
    assert json.loads(out)[0]["domain"] == "good.test" and "good.test" in err


def test_cli_sarif_stdout_pure():
    rc, out, _ = _cli(["bad.test", "--sarif", "-"])
    assert json.loads(out)["version"] == "2.1.0"


def test_cli_bad_input_exit1_runs_rest():
    rc, out, err = _cli(["good.test", "192.0.2.1", "-q", "--dkim-selector", "s1", "--sending-ip", "192.0.2.10"])
    assert rc == 1 and "skipped input" in err and "good.test" in out


def test_cli_stdin():
    rc, out, _ = _cli(["-f", "-", "-q"], stdin="good.test\n")
    assert "good.test" in out


def test_cli_domain_crash_isolated():
    real = cli.audit
    def flaky(d, *a, **k):
        if d == "bad.test":
            raise RuntimeError("kaboom")
        return real(d, *a, **k)
    with mock.patch.object(cli, "audit", flaky):
        rc, out, _ = _cli(["good.test", "bad.test", "--json", "-"])
    data = json.loads(out)
    assert data[1]["status"] == "error" and data[1]["checks"][0]["findings"][0]["rule_id"] == "core.internal"
    assert data[0]["domain"] == "good.test"


@pytest.mark.parametrize("argv", [["--checks", "nope", "x.test"], ["-c", "0", "x.test"],
                                  ["--rules", "/nonexistent.json", "x.test"], ["--file", "/nonexistent"], []])
def test_cli_usage_errors(argv):
    with pytest.raises(SystemExit) as e:
        _cli(argv)
    assert e.value.code == 2


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0 and __version__ in capsys.readouterr().out
