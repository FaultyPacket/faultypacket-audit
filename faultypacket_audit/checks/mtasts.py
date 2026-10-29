"""MTA-STS (RFC 8461) and TLS-RPT (RFC 8460), ported from mta-sts-audit 1.0.
Every engine issue code maps to its own rule (mtasts.<code> / tlsrpt.<code>).
The policy fetch uses HTTPS with full validation and the system resolver.
--smtp probes port 25 STARTTLS; where port 25 is blocked the result is
'not tested', never a pass or fail."""
from . import _mtasts_engine as E
from ._common import result

NAME = "mta-sts"
DOWNGRADE = {"txt_absent": "info", "tlsrpt_absent": "info"}  # optional; enforce_without_tlsrpt warns


def rule_for(code):
    if code.startswith("tlsrpt_") or code == "enforce_without_tlsrpt":
        return "tlsrpt." + code.replace("tlsrpt_", "")
    return "mtasts." + code


def check(domain, res, R, options=None):
    options = options or {}
    E.MAX_AGE_MAX = R.value("mtasts.max_age_max")
    E.POLICY_PATH = R.value("mtasts.policy_path")
    a = E.audit(domain, res, fetcher=options.get("mtasts_fetch"), smtp=bool(options.get("smtp")),
                smtp_probe=options.get("smtp_probe"), timeout=options.get("timeout", 10.0))
    fs = []
    for i in a["issues"]:
        sev = DOWNGRADE.get(i["code"], i["severity"])
        rid = rule_for(i["code"])
        fs.append(R.finding(NAME, sev, rid if rid in R else "core.internal", i["message"], code=i["code"]))
    smtp = a.get("smtp") or []
    tested = "not requested" if not options.get("smtp") else \
        "not tested (port 25 blocked)" if smtp and all((s.get("error") or "").startswith("unreachable") for s in smtp) else "tested"
    pol = a.get("policy") or {}
    return result(NAME, domain, fs, {"result": a["result"], "txt": a["txt"], "mode": pol.get("mode"),
                                     "max_age": pol.get("max_age_seconds"), "policy_mx": pol.get("mx"),
                                     "mx": a["mx"], "smtp": smtp, "smtp_status": tested, "tlsrpt": a["tlsrpt"]})
