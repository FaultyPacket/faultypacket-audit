"""Human-readable report."""


def _st(s):
    return "ok" if s in ("ok", "info") else s


def render(reports, verbose=False):
    lines = []
    for r in reports:
        lines.append(f"{r['domain']}: {('OK' if r['status'] in ('ok', 'info') else r['status'].upper())}")
        for c in r["checks"]:
            shown = [f for f in c["findings"] if verbose or f.severity != "info"]
            lines.append(f"  {c['check']}: {_st(c['status'])}" + ("" if shown or not c["findings"] else
                                                               f" ({len(c['findings'])} info)"))
            for f in shown:
                lines.append(f"    [{f.severity}] {f.message}")
                lines.append(f"      rule {f.rule_id} | {f.citation}" + (f" | {f.url}" if f.url else "")
                             + (f" | rules {f.rules_version}" if f.rules_version else ""))
            if c["check"] == "bulk-sender":
                for p in c["data"].get("providers", []):
                    lines.append(f"    {p['provider']}: {p['verdict']}"
                                 + (f" (not checkable from DNS: {', '.join(p['not_dns_verifiable'])})"
                                    if p["not_dns_verifiable"] else ""))
        for fx in r.get("fixes", []):
            if "\n" in fx["value"]:
                lines.append(f"  suggested fix ({fx['rule_id']}): {fx['name']} {fx['type']}")
                lines += ["      | " + ln for ln in fx["value"].rstrip("\n").split("\n")]
            else:
                lines.append(f"  suggested fix ({fx['rule_id']}): {fx['name']} {fx['type']} \"{fx['value']}\"")
            lines.append(f"      {fx['note']}")
        lines.append("")
    return "\n".join(lines)


def summary(reports, worst_by_domain=True):
    w = max([6] + [len(r["domain"]) for r in reports])
    checks = []
    for r in reports:
        for c in r["checks"]:
            if c["check"] not in checks:
                checks.append(c["check"])
    lines = [f"{'domain':<{w}}  {'status':<7}  " + "  ".join(f"{c:<11}" for c in checks)]
    for r in reports:
        st = {c["check"]: _st(c["status"]) for c in r["checks"]}
        lines.append(f"{r['domain']:<{w}}  {_st(r['status']):<7}  " + "  ".join(f"{st.get(c, '-'):<11}" for c in checks))
    return "\n".join(lines)
