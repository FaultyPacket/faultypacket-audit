"""SARIF 2.1.0 for code-scanning dashboards. Each domain is a logical
location; the physical location is the domain list file (line of the domain
when known), because code-scanning uploads need one."""
import hashlib, json

LEVEL = {"error": "error", "warning": "warning", "info": "note"}
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def build(reports, rules, tool_version, artifact="domains.txt", lines=None, include_info=False):
    lines = lines or {}
    used, results = {}, []
    for r in reports:
        for c in r["checks"]:
            for f in c["findings"]:
                if f.severity == "info" and not include_info:
                    continue
                used[f.rule_id] = f
                fp = hashlib.sha256(f"{r['domain']}|{f.rule_id}|{f.message}".encode()).hexdigest()[:32]
                results.append({
                    "ruleId": f.rule_id,
                    "level": LEVEL[f.severity],
                    "message": {"text": f"{r['domain']}: {f.message} [{f.rule_id} | {f.citation} | rules {f.rules_version or rules.version}]"},
                    "locations": [{
                        "physicalLocation": {"artifactLocation": {"uri": artifact},
                                             "region": {"startLine": lines.get(r["domain"], 1)}},
                        "logicalLocations": [{"name": r["domain"], "fullyQualifiedName": r["domain"]}],
                    }],
                    "partialFingerprints": {"faultypacketFinding/v1": fp},
                    "properties": {"check": c["check"], "domain": r["domain"],
                                   "checkedAtUtc": r["checked_at_utc"], "citation": f.citation,
                                   "citationUrl": f.url, "requirementLevel": f.level,
                                   "rulesVersion": f.rules_version or rules.version},
                })
    driver_rules = []
    for rid in sorted(used):
        rule = rules.get(rid)
        d = {"id": rid, "shortDescription": {"text": str(rule["value"])[:200]},
             "fullDescription": {"text": f"{rule['source']} ({rule['level']})"},
             "properties": {"level": rule["level"], "verified": rule["verified"],
                            "citation": rule["source"], "check": rule["check"]}}
        if rule.get("url"):
            d["helpUri"] = rule["url"]
        driver_rules.append(d)
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "faultypacket-audit", "version": tool_version,
                            "informationUri": "https://faultypacket.co.uk",
                            "rules": driver_rules,
                            "properties": {"rulesVersion": rules.version}}},
        "results": results}]}


def dumps(*a, **k):
    return json.dumps(build(*a, **k), indent=2) + "\n"
