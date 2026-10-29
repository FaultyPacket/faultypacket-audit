"""Text, JSON, CSV, SARIF 2.1.0 and Markdown renderers. All pure."""
import csv, hashlib, io, json
from .. import __version__

SITE = "https://faultypacket.co.uk"
SARIF_LEVEL = {"error": "error", "warning": "warning", "info": "note", "unverified": "note"}
CSV_FIELDS = ["checked_at_utc", "domain", "check", "severity", "rule_id", "level",
              "citation", "message", "url", "rules_version", "tool_version"]
ORDER = {"error": 0, "warning": 1, "unverified": 2, "info": 3}


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n"


def to_csv(report):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for r in report["results"]:
        for f in r["findings"]:
            w.writerow({"checked_at_utc": r["checked_at_utc"], "domain": r["domain"],
                        "check": f["check"], "severity": f["severity"], "rule_id": f["rule_id"],
                        "level": f["level"], "citation": f["citation"], "message": f["message"],
                        "url": f["url"], "rules_version": r["rules_version"], "tool_version": r["version"]})
    return buf.getvalue()


def to_sarif(report, rules, artifact=None):
    used = {}
    results = []
    for r in report["results"]:
        for f in r["findings"]:
            if f["severity"] == "info" and f["rule_id"] == "core.internal":
                pass
            used[f["rule_id"]] = rules[f["rule_id"]]
            fp = hashlib.sha256(f"{r['domain']}|{f['rule_id']}|{f.get('code','')}|{f['message']}".encode()).hexdigest()[:32]
            results.append({
                "ruleId": f["rule_id"], "level": SARIF_LEVEL[f["severity"]],
                "message": {"text": f"{r['domain']}: {f['message']} [{f['citation']}]"},
                "locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": artifact or "domains.txt"},
                                         "region": {"startLine": r.get("input_line") or 1}},
                    "logicalLocations": [{"name": r["domain"], "kind": "resource"}]}],
                "partialFingerprints": {"faultypacketAudit/v1": fp},
                "properties": {"domain": r["domain"], "check": f["check"], "severity": f["severity"]}})
    drv_rules = [{"id": rid, "name": rid.replace(".", "_"),
                  "shortDescription": {"text": ru.get("summary") or ru["source"]},
                  "helpUri": ru["url"],
                  "properties": {"level": ru["level"], "source": ru["source"], "verified": ru["verified"]}}
                 for rid, ru in sorted(used.items())]
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "faultypacket-audit", "version": __version__,
                                         "informationUri": SITE, "rules": drv_rules}},
                     "properties": {"rules_version": report["rules_version"]},
                     "results": results}]}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _sorted(fs):
    return sorted(fs, key=lambda f: (ORDER[f["severity"]], f["check"], f["rule_id"]))


def to_text(report, verbose=False):
    out = []
    for r in report["results"]:
        out.append(f"{r['domain']}  worst={r['worst']}  (rules {r['rules_version']}, {r['checked_at_utc']})")
        c = r["checks"]
        if "spf" in c:
            s = c["spf"]
            out.append(f"  spf      {s.get('result')}  lookups {s.get('lookups')}/{s.get('lookup_limit')}  void {s.get('void_lookups')}/{s.get('void_limit')}")
        if "dmarc" in c:
            d = c["dmarc"]
            out.append(f"  dmarc    policy={d.get('effective_policy')}  from=_dmarc.{d.get('policy_domain')}  org(tree walk)={d.get('org_domain')}  org(PSL)={d.get('org_domain_psl')}")
        if "mta-sts" in c:
            m = c["mta-sts"]
            out.append(f"  mta-sts  {m.get('result')}  mode={(m.get('policy') or {}).get('mode')}")
        if "bulk-sender" in c:
            for p, v in (c["bulk-sender"].get("providers") or {}).items():
                n = sum(x["status"] == "unverified" for x in v["rows"])
                out.append(f"  bulk     {p:8} {v['verdict']}  ({n} rows DNS cannot verify)")
        for f in _sorted(r["findings"]):
            if f["severity"] in ("info", "unverified") and not verbose:
                continue
            out.append(f"   [{f['severity']}] {f['check']}: {f['message']}  ({f['citation']}; {f['rule_id']})")
        out.append("")
    for b in report.get("rejected_inputs", []):
        out.append(f"skipped input {b['input']!r}: {b['error']}")
    if not verbose:
        out.append("info/unverified findings hidden; use -v or --format json")
    return "\n".join(out) + "\n"


def to_markdown(report):
    """Weekly scan report (self-hosted Mail Check-style summary)."""
    rs = report["results"]
    out = [f"# Email DNS audit — {report['generated_at_utc'][:10]}", "",
           f"faultypacket-audit {__version__}, rules {report['rules_version']}. Domains: {len(rs)}.", "",
           "| Domain | Worst | SPF lookups | DMARC policy | MTA-STS | Errors | Warnings |",
           "|---|---|---|---|---|---|---|"]
    for r in rs:
        c = r["checks"]
        e = sum(f["severity"] == "error" for f in r["findings"])
        w = sum(f["severity"] == "warning" for f in r["findings"])
        out.append(f"| {r['domain']} | {r['worst']} | {(c.get('spf') or {}).get('lookups', '')} | "
                   f"{(c.get('dmarc') or {}).get('effective_policy') or ''} | "
                   f"{((c.get('mta-sts') or {}).get('policy') or {}).get('mode') or ''} | {e} | {w} |")
    out += ["", "## Errors and warnings", ""]
    for r in rs:
        for f in _sorted(r["findings"]):
            if f["severity"] in ("error", "warning"):
                out.append(f"- **{r['domain']}** [{f['severity']}] {f['message']} ([{f['citation']}]({f['url']}))")
    out += ["", f"Generated by faultypacket-audit ({SITE})."]
    return "\n".join(out) + "\n"
