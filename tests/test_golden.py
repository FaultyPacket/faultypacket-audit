"""Golden snapshots: the JSON for fixed fixture zones must not drift silently.
Regenerate deliberately with: UPDATE_GOLDEN=1 pytest tests/test_golden.py"""
import json, os, pathlib
import pytest
from faultypacket_audit import audit, load_rules
from faultypacket_audit.output.jsonout import to_jsonable
from tests.zone import Zone, GOOD
from tests.keys import RSA1024

HERE = pathlib.Path(__file__).parent / "golden"
FIXTURES = {
    "good": ("good.test", GOOD, {"dkim_selectors": ["s1"], "sending_ips": ["192.0.2.10"]}),
    "migration": ("council.gov.example", {
        ("council.gov.example", "TXT"): ["v=spf1 include:a.test include:a.test ptr ~all"],
        ("a.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("_dmarc.gov.example", "TXT"): ["v=DMARC1; p=reject; psd=y"],
        ("_dmarc.council.gov.example", "TXT"): ["v=DMARC1; p=quarantine; pct=0; ri=3600; fo=0:1; rua=mailto:r@reports.test!10m"],
    }, {}),
    # 1.0 modules: weak DKIM, CNAME MX, CAA, unsigned zone, testing MTA-STS, BIMI without certificate
    "modules": ("shop.example", {
        ("shop.example", "TXT"): ["v=spf1 mx -all"],
        ("shop.example", "MX"): ["10 mx1.shop.example.", "20 mx2.shop.example."],
        ("mx1.shop.example", "A"): ["192.0.2.25"], ("mx2.shop.example", "CNAME"): ["mx1.shop.example."],
        ("mx2.shop.example", "A"): ["192.0.2.25"],
        ("25.2.0.192.in-addr.arpa", "PTR"): ["mx1.shop.example."],
        ("_dmarc.shop.example", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:d@shop.example"],
        ("selector1._domainkey.shop.example", "TXT"): ["v=DKIM1; k=rsa; p=" + RSA1024],
        ("shop.example", "CAA"): ['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@shop.example"'],
        ("_smtp._tls.shop.example", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@shop.example"],
        ("default._bimi.shop.example", "TXT"): ["v=BIMI1; l=https://shop.example/logo.svg"],
    }, {"http_fetch": lambda url, **k: {"status": 200, "content_type": "image/svg+xml", "error": None,
        "body": b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>Shop</title></svg>'}}),
}


def normalise(rep):
    j = to_jsonable([rep], "golden")[0]
    j.pop("checked_at_utc"); j.pop("rules_version")
    return j


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_golden(name):
    dom, zone, opts = FIXTURES[name]
    got = normalise(audit(dom, Zone(zone), load_rules(), options=opts))
    p = HERE / f"{name}.json"
    if os.environ.get("UPDATE_GOLDEN") or not p.exists():
        p.write_text(json.dumps(got, indent=1, sort_keys=True) + "\n")
    assert got == json.loads(p.read_text())
