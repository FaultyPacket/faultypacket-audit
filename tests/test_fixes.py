from faultypacket_audit import audit, load_rules
from tests.zone import Zone, GOOD

R = load_rules()


def fixes(z, d):
    return audit(d, Zone({**GOOD, **z}), R)["fixes"]


def test_retired_tags_removed_keeping_order():
    fx = fixes({("_dmarc.old.test", "TXT"): ["v=DMARC1; p=quarantine; pct=50; rf=afrf; ri=86400; rua=mailto:r@old.test"],
                ("old.test", "TXT"): ["v=spf1 -all"]}, "old.test")
    d = [f for f in fx if f["name"] == "_dmarc.old.test"]
    assert d and d[0]["value"] == "v=DMARC1; p=quarantine; rua=mailto:r@old.test"
    assert d[0]["rule_id"] == "dmarc.historic_pct" and "pct, rf, ri" in d[0]["note"]


def test_missing_dmarc_gets_monitoring_record():
    fx = fixes({("none.test", "TXT"): ["v=spf1 -all"]}, "none.test")
    d = [f for f in fx if f["rule_id"] == "dmarc.no_record"]
    assert d and d[0]["value"].startswith("v=DMARC1; p=none; rua=mailto:REPLACE-")


def test_clean_domain_has_no_dmarc_fix():
    assert not [f for f in audit("good.test", Zone(GOOD), R)["fixes"] if f["name"].startswith("_dmarc")]
