#!/usr/bin/env python3
"""Run the audit against canaries.json and compare with expected shapes.
Exit 1 if more than one canary drifts. Set CANARY_DOH to use DoH."""
import json, os, pathlib, sys
BASE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE.parent))
from faultypacket_audit import Resolver, audit, load_rules    # noqa: E402


def check(rep, exp):
    bad, by = [], {c["check"]: c for c in rep["checks"]}
    spf = by.get("spf", {}).get("data", {})
    if "spf_result" in exp and spf.get("result") != exp["spf_result"]:
        bad.append(f"spf {spf.get('result')} != {exp['spf_result']}")
    lo, hi = exp.get("lookups_range", [0, 99])
    if not lo <= (spf.get("lookups") if spf.get("lookups") is not None else -1) <= hi:
        bad.append(f"lookups {spf.get('lookups')} outside {lo}-{hi}")
    if exp.get("dmarc_record") and not by.get("dmarc", {}).get("data", {}).get("record"):
        bad.append("no DMARC record")
    if any(f.rule_id.endswith(".internal") for c in rep["checks"] for f in c["findings"]):
        bad.append("internal error")
    return bad


def main():
    rules, res = load_rules(), Resolver(None, 5.0, os.environ.get("CANARY_DOH") or None)
    fails = {}
    for c in json.loads((BASE / "canaries.json").read_text())["canaries"]:
        try:
            b = check(audit(c["domain"], res, rules, checks=["spf", "dmarc"]), c)
        except Exception as e:
            b = [f"error: {e}"]
        if b:
            fails[c["domain"]] = b
    print(json.dumps(fails, indent=1))
    return 1 if len(fails) > 1 else 0


if __name__ == "__main__":
    sys.exit(main())
