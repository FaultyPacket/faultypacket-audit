"""CSV: one row per finding (domains with no findings get one 'ok' row per check)."""
import csv, io

FIELDS = ["checked_at_utc", "domain", "check", "severity", "rule_id", "level", "citation",
          "url", "message", "rules_version", "resolver"]


def dumps(reports):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
    w.writeheader()
    for r in reports:
        base = {"checked_at_utc": r["checked_at_utc"], "domain": r["domain"],
                "rules_version": r["rules_version"], "resolver": ",".join(r["resolvers"])}
        for c in r["checks"]:
            if not c["findings"]:
                w.writerow({**base, "check": c["check"], "severity": "ok"})
            for f in c["findings"]:
                w.writerow({**base, "check": c["check"], "severity": f.severity, "rule_id": f.rule_id,
                            "level": f.level, "citation": f.citation, "rules_version": f.rules_version or r["rules_version"], "url": f.url, "message": f.message})
    return buf.getvalue()
