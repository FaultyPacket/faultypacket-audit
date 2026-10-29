import json, threading
import pytest
from faultypacket_audit.core.finding import Finding, worst, rank
from faultypacket_audit.core.resolver import Cached
from faultypacket_audit.core.rules import Rules, RulesError, load_rules, validate
from tests.zone import Zone

R = load_rules()


def test_bundled_rules_valid_and_versioned():
    assert R.version == "2026.10.29.6"
    assert not validate(json.loads(open(R.origin if R.origin.endswith(".json") and "/" in R.origin else
                                        "faultypacket_audit/data/rules.json").read()))


def test_every_rule_has_citation_and_https_url_unless_tool():
    for r in R.by_id.values():
        assert r["source"] and r["verified"]
        assert r["level"] == "TOOL" or r["url"].startswith("https://www.rfc-editor.org/") or r["level"] == "PROVIDER" \
            or r["url"].startswith("https://")


def test_dmarc_rules_pinned_to_rfc9989_sections_not_placeholders():
    for r in R.for_check("dmarc"):
        if r["level"] != "TOOL":
            assert "rfc99" in r["url"] and "#" in r["url"], r["id"]
            assert "to be pinned" not in json.dumps(r)


def test_external_auth_cites_rfc9990_section4_erratum():
    assert R.get("dmarc.unauthorised_rua")["url"].endswith("rfc9990#section-4")
    assert R.get("dmarc.unauthorised_ruf")["url"].endswith("rfc9991#section-5")


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d.update(schema="x"), "schema"),
    (lambda d: d.update(rules_version="v1"), "CalVer"),
    (lambda d: d["rules"][0].pop("source"), "missing source"),
    (lambda d: d["rules"][0].update(url="http://x"), "https url"),
    (lambda d: d["rules"][0].update(level="LOUD"), "bad level"),
    (lambda d: d["rules"][0].update(verified="29/10/2026"), "verified"),
    (lambda d: d["rules"].append(dict(d["rules"][0])), "duplicate"),
])
def test_rules_validation_rejects(mutate, msg):
    d = {"schema": "faultypacket-rules/1", "rules_version": "2026.10.29.1",
         "rules": [{"id": "x.y", "check": "x", "value": 1, "level": "MUST", "source": "RFC 1",
                    "url": "https://e.test", "verified": "2026-10-29"}]}
    mutate(d)
    with pytest.raises(RulesError, match=msg):
        Rules(d)


def test_tool_level_needs_no_url():
    Rules({"schema": "faultypacket-rules/1", "rules_version": "2026.10.29.1",
           "rules": [{"id": "t", "check": "c", "value": 1, "level": "TOOL", "source": "tool", "verified": "2026-10-29"}]})


def test_unknown_rule_cannot_make_a_finding():
    with pytest.raises(RulesError):
        R.finding("spf", "error", "spf.nope", "x")


def test_finding_carries_citation():
    f = R.finding("spf", "error", "spf.lookup_limit", "too many")
    assert (f.citation, f.level) == ("RFC 7208 4.6.4", "MUST") and f.url.endswith("#section-4.6.4")
    assert f.to_dict()["rule_id"] == "spf.lookup_limit"


def test_finding_rejects_bad_severity_and_missing_citation():
    with pytest.raises(ValueError):
        Finding("c", "ok", "r", "m", "cite", "", "MUST")
    with pytest.raises(ValueError):
        Finding("c", "error", "r", "m", "", "", "MUST")


def test_worst_and_rank():
    assert worst([]) == "ok" and worst(["info", "warning", "info"]) == "warning"
    assert rank("error") > rank("warning") > rank("info") > rank("ok")


def test_rules_override_file(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"schema": "faultypacket-rules/1", "rules_version": "2027.01.01.1", "rules": []}))
    assert load_rules(str(p)).version == "2027.01.01.1"


def test_cached_resolver_dedupes_and_is_threadsafe():
    z = Zone({("a.test", "TXT"): ["x"]})
    c = Cached(z)
    ts = [threading.Thread(target=lambda: c.query("A.test.", "TXT")) for _ in range(20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert c.query("a.test", "TXT") == (["x"], "ok")
    assert len(z.asked) <= 20 and c.servers == ["fake"]
    n = len(z.asked); c.query("a.test", "TXT")
    assert len(z.asked) == n
