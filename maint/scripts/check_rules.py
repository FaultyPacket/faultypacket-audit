#!/usr/bin/env python3
"""Fail CI if rules.json is malformed, a rule lacks a source/url/date, or code
constants and rules disagree. Run from the repo root."""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from faultypacket_audit.core.rules import load_rules            # noqa: E402
from faultypacket_audit.checks import spf, dmarc                # noqa: E402


def main():
    try:
        r = load_rules()
    except ValueError as e:
        print(e); return 1
    bad = []
    pairs = [("spf.lookup_limit", spf.LOOKUP_LIMIT), ("spf.void_limit", spf.VOID_LIMIT),
             ("spf.mx_limit", spf.MX_LIMIT), ("spf.ptr_limit", spf.PTR_LIMIT),
             ("dmarc.tree_walk_max_queries", dmarc.TREE_WALK_MAX)]
    for rid, code in pairs:
        if r.value(rid) != code:
            bad.append(f"{rid}: code {code} != rules {r.value(rid)}")
    for rid, code in (("dmarc.historic_tags", dmarc.HISTORIC_TAGS), ("dmarc.active_tags", dmarc.ACTIVE_TAGS)):
        if sorted(r.value(rid)) != sorted(code):
            bad.append(f"{rid}: code {sorted(code)} != rules {sorted(r.value(rid))}")
    for row in r.for_check("bulk-sender"):
        if "provider" in row and not {"audience", "requirement", "dns_verifiable", "effective"} <= set(row):
            bad.append(f"{row['id']}: provider row missing audience/requirement/dns_verifiable/effective")
    print("\n".join(bad) or f"rules OK ({len(r.by_id)} rules, {r.version})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
