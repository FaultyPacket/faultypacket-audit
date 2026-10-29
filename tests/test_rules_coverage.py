"""Every issue code the checks can emit maps to a rule (so every finding is cited)."""
import re, pathlib
from faultypacket_audit.core.rules import load_rules

R = load_rules()
PKG = pathlib.Path(__file__).resolve().parent.parent / "faultypacket_audit"


def _codes(path, pattern):
    return set(re.findall(pattern, (PKG / path).read_text()))


def test_spf_codes_have_rules():
    codes = _codes("checks/spf.py", r'self\.issue\("[a-z]+", "([a-z_]+)"')
    assert codes and all(f"spf.{c}" in R for c in codes), [c for c in codes if f"spf.{c}" not in R]


def test_dmarc_codes_have_rules():
    src = (PKG / "checks/dmarc.py").read_text()
    codes = set(re.findall(r'\("(?:error|warning|info)", "([a-z_]+)"', src))
    dyn = set(re.findall(r'\("(?:error|warning|info)", "([a-z_]+_)" \+', src))
    full = {c for c in codes} | {d + t for d in dyn - {"bad_"} for t in ("rua", "ruf")} \
        | {"bad_" + k for k in ("sp", "np", "adkim", "aspf")}
    full -= {d for d in dyn}
    missing = [c for c in full if f"dmarc.{c}" not in R]
    assert not missing, missing


def test_bulk_rows_have_provider_fields_and_dates():
    rows = [r for r in R.for_check("bulk-sender") if "provider" in r]
    assert len(rows) >= 16
    for r in rows:
        assert r["level"] == "PROVIDER" and r["audience"] in ("all", "5k", "bulk") and r["effective"]
        assert isinstance(r["dns_verifiable"], bool)


def test_tls_not_claimed_as_dns_verifiable():
    assert R.get("bulk.google.all.tls")["dns_verifiable"] is False


def test_spf_constants_match_rules():
    from faultypacket_audit.checks import spf
    assert (spf.LOOKUP_LIMIT, spf.VOID_LIMIT, spf.MX_LIMIT) == \
        (R.value("spf.lookup_limit"), R.value("spf.void_limit"), R.value("spf.mx_limit"))


def test_dmarc_constants_match_rules():
    from faultypacket_audit.checks import dmarc
    assert dmarc.TREE_WALK_MAX == R.value("dmarc.tree_walk_max_queries")
    assert sorted(dmarc.HISTORIC_TAGS) == sorted(R.value("dmarc.historic_tags"))
    assert sorted(dmarc.ACTIVE_TAGS) == sorted(R.value("dmarc.active_tags"))


import pytest

LITERAL = r'(?:R|rules)\.finding\([^,]+,\s*(?:"[a-z]+"|[^,]+),\s*"([a-z0-9_.-]+)"'
F_CALL = r'\bF\(\s*"[a-z]+",\s*"([a-z0-9_.-]+)"'


@pytest.mark.parametrize("mod", ["spf", "blocklist", "lookalike", "mx", "caa", "bimi", "dnssec", "dane", "rdns", "dkim"])
def test_literal_rule_ids_in_module_exist(mod):
    src = (PKG / f"checks/{mod}.py").read_text()
    ids = set(re.findall(LITERAL, src)) | set(re.findall(F_CALL, src))
    ids = {i for i in ids if "." in i and not i.endswith(".")}
    missing = [i for i in ids if i not in R]
    assert not missing, missing


def test_fix_rule_ids_exist():
    src = (PKG / "fixes.py").read_text()
    ids = set(re.findall(r'_fix\(\s*"([a-z0-9_.-]+)"', src)) | set(re.findall(r'"((?:spf|dmarc|dkim|mtasts|tlsrpt|mx|caa|dnssec|bimi)\.[a-z_]+)"', src))
    missing = [i for i in ids if i not in R]
    assert ids and not missing, missing


@pytest.mark.parametrize("rid", ["spf.all_pass", "spf.all_neutral", "spf.all_softfail", "spf.no_all",
                                 "blocklist.listed_ip", "blocklist.listed_domain", "blocklist.not_tested",
                                 "blocklist.no_ipv4", "lookalike.registered"])
def test_new_rules_cite_a_url_and_date(rid):
    r = R.get(rid)
    assert r["verified"] == "2026-10-29" and r["url"].startswith("https://www.rfc-editor.org/rfc/")


def test_blocklist_terms_urls_are_operator_pages():
    for z in R.value("blocklist.zones"):
        assert z["terms"].split("/")[2] in ("www.spamhaus.org", "www.spamcop.net", "psbl.org")
