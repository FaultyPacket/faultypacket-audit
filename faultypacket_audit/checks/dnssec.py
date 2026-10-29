"""DNSSEC: DS at the parent (RFC 4034 5) and a validated answer (AD bit,
RFC 4035 3.2.3) from a validating resolver. With a non-validating resolver
the AD result is reported as not tested rather than as a failure."""
from ._common import result

NAME = "dnssec"


def check(domain, res, R, options=None):
    F = lambda sev, rid, msg, **e: R.finding(NAME, sev, rid, msg, **e)
    qa = getattr(res, "query_ad", None)
    ds, st = res.query(domain, "DS")
    if st.startswith("error"):
        return result(NAME, domain, [F("warning", "dnssec.dns_error", f"DS lookup failed: {st}")], {})
    data = {"ds": ds, "signed": bool(ds), "validated": None}
    fs = []
    if not ds:
        fs.append(F("info", "dnssec.unsigned", "no DS record at the parent: the zone is not DNSSEC-signed, so DANE cannot be used and MX/TXT answers can be spoofed"))
        return result(NAME, domain, fs, data)
    v, st2, ad = qa(domain, "SOA") if qa else ([], "void", False)
    validating = any(str(x).startswith("https://") for x in getattr(res, "servers", [])) \
        or bool((options or {}).get("validating_resolver"))
    if st2.startswith("error") and "rcode2" in st2:
        fs.append(F("error", "dnssec.bogus", "DS published but the validating resolver returned SERVFAIL: the chain is broken (bogus) and the domain is unreachable for validating resolvers"))
        data["validated"] = False
    elif ad:
        data["validated"] = True
    elif validating:
        fs.append(F("error", "dnssec.not_validated", "DS is published but the validating resolver did not set AD: answers are not validating"))
        data["validated"] = False
    else:
        fs.append(F("info", "dnssec.not_tested", "DS published; validation not tested (resolver is not known to validate; use --doh)"))
    return result(NAME, domain, fs, data)
