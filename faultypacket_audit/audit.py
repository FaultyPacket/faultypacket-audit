"""Run checks for one domain. Pure: returns a report dict, never prints."""
import datetime as dt

from .checks import spf, dmarc, dkim, bulk_sender, mx, mtasts, caa, rdns, dnssec, dane, bimi
from .core.finding import worst
from .core.resolver import Cached

CHECKS = {"spf": spf.check, "dmarc": dmarc.check, "dkim": dkim.check, "mx": mx.check,
          "mta-sts": mtasts.check, "dnssec": dnssec.check, "dane": dane.check, "caa": caa.check,
          "rdns": rdns.check, "bimi": bimi.check, "bulk-sender": bulk_sender.check}
# order matters: bulk-sender reuses spf, dmarc and dkim data; bimi reuses dmarc
ORDER = ["spf", "dmarc", "dkim", "mx", "mta-sts", "dnssec", "dane", "caa", "rdns", "bimi", "bulk-sender"]
INTERNAL = {"spf": "spf.internal", "dmarc": "dmarc.internal", "bulk-sender": "bulk.internal",
            "mta-sts": "mtasts.internal"}


def now_utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def audit(domain, res, rules, checks=None, options=None):
    """-> {domain, checked_at_utc, rules_version, status, checks: [CheckResult]}.
    Each check is isolated: an exception becomes a cited TOOL finding for that
    check only."""
    res = res if isinstance(res, Cached) else Cached(res)
    wanted = [c for c in ORDER if c in (checks or ORDER)]
    opts = dict(options or {})
    opts["results"] = {}
    out = []
    for name in wanted:
        try:
            r = CHECKS[name](domain, res, rules, opts)
        except Exception as e:    # per-check isolation
            r = {"check": name, "domain": domain, "data": {},
                 "findings": [rules.finding(name, "error", INTERNAL.get(name, "core.internal"),
                                            f"{type(e).__name__}: {e}")]}
        r["status"] = worst(f.severity for f in r["findings"])
        opts["results"][name] = r["data"]
        out.append(r)
    from .fixes import suggest
    try:
        fixes = suggest(domain, out)
    except Exception:              # a fix suggestion must never break an audit
        fixes = []
    return {"domain": domain, "checked_at_utc": now_utc(), "rules_version": rules.version,
            "resolvers": res.servers, "status": worst(c["status"] for c in out), "checks": out,
            "fixes": fixes}
