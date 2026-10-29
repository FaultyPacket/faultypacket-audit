"""'What changed since last run': compare this run's reports with a previous
JSON output (--baseline). Findings are keyed by (domain, rule_id, message
fingerprint), so a reworded message for the same rule shows as changed."""
import json

SEV = {"error": 3, "warning": 2, "info": 1, "ok": 0}


def _key(domain, f):
    ev = f.get("evidence") or {}
    detail = ev.get("selector") or ev.get("ip") or ev.get("code") or ev.get("requirement") or ""
    return (domain, f["rule_id"], str(detail))


def index(json_reports, min_sev="warning"):
    out, status = {}, {}
    for r in json_reports:
        status[r["domain"]] = r.get("status", "ok")
        for c in r.get("checks", []):
            for f in c.get("findings", []):
                if SEV[f["severity"]] >= SEV[min_sev]:
                    out[_key(r["domain"], f)] = {"domain": r["domain"], "check": c["check"], **f}
    return out, status


def compare(old_json, new_json, min_sev="warning"):
    old, old_st = index(old_json, min_sev)
    new, new_st = index(new_json, min_sev)
    added = [new[k] for k in sorted(new) if k not in old]
    resolved = [old[k] for k in sorted(old) if k not in new]
    changed = [{"before": old[k], "after": new[k]} for k in sorted(new)
               if k in old and old[k]["severity"] != new[k]["severity"]]
    status = [{"domain": d, "before": old_st.get(d), "after": s} for d, s in sorted(new_st.items())
              if old_st.get(d) != s]
    return {"added": added, "resolved": resolved, "severity_changed": changed, "status_changed": status,
            "domains_added": sorted(set(new_st) - set(old_st)), "domains_removed": sorted(set(old_st) - set(new_st)),
            "rules_version": {"before": (old_json[0].get("rules_version") if old_json else None),
                              "after": (new_json[0].get("rules_version") if new_json else None)}}


def has_regression(d):
    return bool(d["added"] or any(SEV[c["after"]["severity"]] > SEV[c["before"]["severity"]] for c in d["severity_changed"]))


def _line(f):
    return (f"- `{f['domain']}` **{f['severity']}** {f['message']}  \n"
            f"  `{f['rule_id']}` · {f['citation']}" + (f" · {f['url']}" if f.get("url") else "")
            + (f" · rules {f['rules_version']}" if f.get("rules_version") else ""))


def markdown(d):
    rv = d["rules_version"]
    out = ["## What changed since the last run", ""]
    if rv["before"] != rv["after"]:
        out += [f"Rule set updated: `{rv['before']}` → `{rv['after']}`. New or changed rules can raise findings on unchanged DNS.", ""]
    if not any(d[k] for k in ("added", "resolved", "severity_changed", "status_changed", "domains_added", "domains_removed")):
        return "\n".join(out + ["No changes in warnings or errors."]) + "\n"
    for title, key in (("New problems", "added"), ("Fixed since last run", "resolved")):
        if d[key]:
            out += [f"### {title} ({len(d[key])})"] + [_line(f) for f in d[key]] + [""]
    if d["severity_changed"]:
        out += [f"### Severity changed ({len(d['severity_changed'])})"]
        out += [f"- `{c['after']['domain']}` `{c['after']['rule_id']}`: {c['before']['severity']} → {c['after']['severity']}"
                for c in d["severity_changed"]] + [""]
    if d["status_changed"]:
        out += ["### Domain status"] + [f"- `{s['domain']}`: {s['before'] or 'new'} → {s['after']}" for s in d["status_changed"]] + [""]
    if d["domains_removed"]:
        out += ["### No longer scanned"] + [f"- `{x}`" for x in d["domains_removed"]] + [""]
    return "\n".join(out) + "\n"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
