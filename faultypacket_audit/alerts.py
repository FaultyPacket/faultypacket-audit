"""Change and failure alerts: ``faultypacket-audit alert DOMAIN... --state FILE``.

Snapshots the published mail records and audit status, diffs them against the
previous run's state file, and POSTs a Slack, Microsoft Teams or generic JSON
webhook when a record changed or a domain started failing. The webhook URL is
read only from an environment variable (default FAULTYPACKET_WEBHOOK_URL), so
it can come from a CI secret; it is never taken from the command line.
"""
import json, os, sys, urllib.request

RECORDS = (("spf", "", "TXT"), ("dmarc", "_dmarc.", "TXT"), ("mta-sts", "_mta-sts.", "TXT"),
           ("tls-rpt", "_smtp._tls.", "TXT"), ("bimi", "default._bimi.", "TXT"), ("mx", "", "MX"))
DEFAULT_ENV = "FAULTYPACKET_WEBHOOK_URL"


def _g(o, k):
    return o.get(k) if isinstance(o, dict) else getattr(o, k, None)


def snapshot(domain, res, report=None):
    recs = {}
    for key, prefix, rt in RECORDS:
        vals, st = res.query(prefix + domain, rt)
        if key == "spf":
            vals = [v for v in vals if v.lower().startswith("v=spf1")]
        recs[key] = sorted(vals) if not st.startswith("error") else None  # None = lookup failed, not "removed"
    errs = []
    if report:
        errs = sorted({_g(f, "rule_id") for c in report.get("checks", []) for f in _g(c, "findings") or []
                       if _g(f, "severity") == "error"})
    return {"records": recs, "status": (report or {}).get("status"), "errors": errs}


def compare(prev, cur):
    events = []
    for d in sorted(cur):
        c, p = cur[d], (prev or {}).get(d)
        if p is None:
            continue  # first sight of a domain is the baseline, not an alert
        for k in sorted(c["records"]):
            a, b = p["records"].get(k), c["records"][k]
            if a is not None and b is not None and a != b:
                events.append({"type": "record_changed", "domain": d, "record": k, "before": a, "after": b})
        new_errs = sorted(set(c["errors"]) - set(p.get("errors", [])))
        if (c["status"] == "error" and p.get("status") != "error") or new_errs:
            events.append({"type": "started_failing", "domain": d, "status": c["status"], "new_errors": new_errs})
    return events


def _line(e):
    if e["type"] == "record_changed":
        return f"{e['domain']}: {e['record']} record changed: {' | '.join(e['before']) or '(none)'} -> {' | '.join(e['after']) or '(none)'}"
    return f"{e['domain']}: now failing ({e['status']}); new errors: {', '.join(e['new_errors']) or 'none'}"


def payload(events, fmt):
    title = f"faultypacket-audit: {len(events)} mail DNS change(s)"
    text = "\n".join(_line(e) for e in events)
    if fmt == "slack":
        return {"text": f"*{title}*\n{text}"}
    if fmt == "teams":
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                        "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True}] +
                                [{"type": "TextBlock", "text": _line(e), "wrap": True} for e in events]}}]}
    return {"source": "faultypacket-audit", "title": title, "events": events}


def post(url, body, opener=urllib.request.urlopen, timeout=10):
    if not url.lower().startswith("https://"):
        raise ValueError("webhook URL must be https")
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "faultypacket-audit"})
    with opener(req, timeout=timeout) as r:
        return getattr(r, "status", 200)


def main(argv, stdin=None, stdout=None, stderr=None, res=None, environ=None, opener=urllib.request.urlopen):
    import argparse
    from .audit import audit
    from .core.resolver import Cached, Resolver, DEFAULT_DOH
    from .core.rules import load_rules
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    environ = os.environ if environ is None else environ
    p = argparse.ArgumentParser(prog="faultypacket-audit alert",
                                description="Alert a webhook when mail DNS records change or a domain starts failing (run daily).",
                                allow_abbrev=False)
    p.add_argument("domains", nargs="+")
    p.add_argument("--state", required=True, help="JSON state file from the previous run (created if missing)")
    p.add_argument("--format", choices=["slack", "teams", "json"], default="json")
    p.add_argument("--webhook-env", default=DEFAULT_ENV, help="environment variable holding the webhook URL (default %(default)s)")
    p.add_argument("--dry-run", action="store_true", help="print the payload instead of posting")
    p.add_argument("--no-audit", action="store_true", help="only diff records; skip the audit status check")
    p.add_argument("--doh", action="store_true")
    p.add_argument("--doh-url", default=DEFAULT_DOH)
    p.add_argument("--resolver")
    a = p.parse_args(argv)
    res = Cached(res or Resolver(a.resolver, 5.0, a.doh_url if a.doh else None))
    rules = None if a.no_audit else load_rules()
    cur = {d.lower().rstrip("."): snapshot(d.lower().rstrip("."), res, None if a.no_audit else audit(d, res, rules))
           for d in a.domains}
    try:
        with open(a.state, encoding="utf-8") as f:
            prev = json.load(f)
    except FileNotFoundError:
        prev = {}
    except ValueError:
        print(f"{a.state}: unreadable state, starting a new baseline", file=stderr)
        prev = {}
    events = compare(prev, cur)
    rc = 0
    if events:
        body = payload(events, a.format)
        url = environ.get(a.webhook_env, "")
        if a.dry_run:
            print(json.dumps(body, indent=2), file=stdout)
        elif not url:
            print(f"{len(events)} event(s) but ${a.webhook_env} is not set; not posted", file=stderr)
            rc = 1
        else:
            try:
                post(url, body, opener)
                print(f"posted {len(events)} event(s)", file=stdout)
            except Exception as e:  # never print the URL: it is a secret
                print(f"webhook post failed: {type(e).__name__}", file=stderr)
                rc = 1
    else:
        print("no changes", file=stdout)
    merged = dict(prev)
    merged.update(cur)
    with open(a.state, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=1, sort_keys=True)
    return rc
