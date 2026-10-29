"""Suggested fixes, one per fixable finding class.

A fix is either a DNS record (``type`` TXT/MX/CAA/CNAME), a file to publish
(``type`` FILE, ``name`` is its URL) or ordered steps (``type`` STEPS, with
``value`` holding the steps joined by newlines). Each names the rule it
answers. Anything only the owner knows is a ``REPLACE-`` placeholder and the
note says so. Fixes never invent the owner's senders, keys or CAs."""

import re

RETIRED = ("pct", "rf", "ri")      # RFC 9989 9.3 / Appendix A.6


def _ids(check):
    return {f.rule_id for f in check["findings"]}


def _ev(check, rid):
    return [f.evidence for f in check["findings"] if f.rule_id == rid]


def _fix(rule_id, name, typ, value, note):
    return {"rule_id": rule_id, "name": name, "type": typ, "value": value, "note": note}


def _steps(*lines):
    return "\n".join(f"{i}. {s}" for i, s in enumerate(lines, 1))


def _dmarc(domain, d, out, by=None):
    ids, data = _ids(d), d.get("data") or {}
    if "dmarc.no_record" in ids:
        out.append(_fix("dmarc.no_record", f"_dmarc.{domain}", "TXT",
                        f"v=DMARC1; p=none; rua=mailto:REPLACE-dmarc-reports@{domain}",
                        "Monitoring start point (RFC 9989 4.7). Replace the rua mailbox with one you read; "
                        "move to p=quarantine or p=reject once reports show all your senders pass."))
        return
    tags = dict(data.get("tags") or {})
    if not tags or data.get("policy_source") != domain:
        return
    changed, why = dict(tags), []
    gone = [t for t in RETIRED if t in changed]
    for t in gone:
        changed.pop(t)
    if gone:
        why.append(f"retired tags {', '.join(gone)} removed (RFC 9989 9.3)")
    if "dmarc.bad_fo" in ids:
        changed.pop("fo", None); why.append("invalid fo (RFC 9989 4.8)")
    if "dmarc.fo_without_ruf" in ids and "fo" in changed and "ruf" not in changed:
        changed.pop("fo"); why.append("fo, which has no effect without ruf (RFC 9989 4.7)")
    for k in ("rua", "ruf"):
        if k in changed and "!" in changed[k]:
            changed[k] = ",".join(u.split("!", 1)[0] for u in changed[k].split(","))
            why.append(f"obsolete !size on {k} (RFC 9989 4.8)")
    if "dmarc.no_rua" in ids and "rua" not in changed:
        changed["rua"] = f"mailto:REPLACE-dmarc-reports@{domain}"
        why.append("added rua so you receive aggregate reports (RFC 9989 4.7; replace the mailbox)")
    if "dmarc.no_p" in ids and "p" not in changed:
        changed = {"v": changed.get("v", "DMARC1"), "p": "none", **{k: v for k, v in changed.items() if k != "v"}}
        why.append("added p=none; p is required (RFC 9989 4.7)")
    if "dmarc.test_mode" in ids and changed.get("t") == "y":
        changed.pop("t"); why.append("t=y test mode removed once you are ready to enforce (RFC 9989 4.7)")
    if changed != tags:
        rid = next((r for r in ("dmarc.historic_pct", "dmarc.historic_tag", "dmarc.bad_fo", "dmarc.obsolete_size",
                                "dmarc.no_rua", "dmarc.no_p", "dmarc.fo_without_ruf", "dmarc.test_mode") if r in ids),
                   "dmarc.syntax")
        note = "Your record with: " + "; ".join(why) + "."
        if "pct" in tags:
            note += " Without pct the full policy applies to all mail; RFC 9989 receivers already do this."
        out.append(_fix(rid, f"_dmarc.{domain}", "TXT", "; ".join(f"{k}={v}" for k, v in changed.items()), note))
    if "dmarc.p_none" in ids:
        out.append(_fix("dmarc.p_none", f"_dmarc.{domain}", "STEPS", _steps(
            "Read a few weeks of aggregate (rua) reports and list every service that sends as this domain.",
            "Make each one pass SPF or DKIM aligned with this domain.",
            "Change p=none to p=quarantine, watch reports for a week, then p=reject."),
            "RFC 9989 4.7 / 5.1. Policy changes are your decision; this is the usual staged order."))
    for rid in ("dmarc.unauthorised_rua", "dmarc.unauthorised_ruf"):
        for f in d["findings"]:
            if f.rule_id == rid:
                m = re.search(r"([a-z0-9.-]+\._report\._dmarc\.[a-z0-9.-]+)", f.message)
                name = m.group(1) if m else f"{domain}._report._dmarc.REPLACE-report-host"
                out.append(_fix(rid, name, "TXT", "v=DMARC1",
                                "Published by the report receiver, not by you (RFC 9990 4 / RFC 9991 5). "
                                "Ask your report provider to add it, or remove that address."))


def _spf(domain, s, out, by=None):
    ids, data = _ids(s), s.get("data") or {}
    rec = data.get("record") or ""
    if "spf.no_record" in ids:
        out.append(_fix("spf.no_record", domain, "TXT", "v=spf1 include:REPLACE-your-mail-provider -all",
                        "RFC 7208 4. List every service that sends as this domain. If the domain sends no mail "
                        "at all, publish exactly 'v=spf1 -all'."))
    if "spf.multiple_records" in ids:
        out.append(_fix("spf.multiple_records", domain, "STEPS", _steps(
            "Merge the SPF records into one TXT record starting v=spf1 (RFC 7208 4.5).",
            "Keep one 'all' term, at the end.", "Delete the other v=spf1 records."),
            "Two SPF records make every SPF check a permerror."))
    if "spf.lookup_limit" in ids:
        heavy = sorted(((c.get("lookups_subtree", 0), c.get("domain")) for c in (data.get("tree") or {}).get("children", [])),
                       reverse=True)[:5]
        out.append(_fix("spf.lookup_limit", domain, "STEPS", _steps(
            f"Your record needs {data.get('lookups')} DNS lookups; the limit is {data.get('lookup_limit')} (RFC 7208 4.6.4).",
            "Heaviest includes: " + (", ".join(f"{d} ({n})" for n, d in heavy) or "see the lookup log") + ".",
            "Remove includes for services that no longer send for you.",
            "Replace 'a' and 'mx' terms with ip4:/ip6: where those addresses are stable.",
            "Move a bulk sender to its own subdomain (e.g. news.REPLACE) with its own SPF record.",
            "Only flatten an include into ip4:/ip6: if the provider documents fixed ranges, and re-check monthly."),
            "Over 10 lookups is a permerror: receivers treat SPF as failed."))
    if "spf.void_limit" in ids:
        voids = [r["term"] for r in data.get("lookup_log", []) if r.get("void")]
        out.append(_fix("spf.void_limit", domain, "STEPS", _steps(
            "Remove the terms that return no answer: " + ", ".join(voids) + ".",
            "Re-run the audit to confirm at most 2 void lookups (RFC 7208 4.6.4)."),
            "Void lookups often point at a service you no longer use."))
    if "spf.missing_record" in ids:
        out.append(_fix("spf.missing_record", domain, "STEPS", _steps(
            "Remove the include/redirect whose target publishes no SPF record (named in the finding).",
            "If you still use that service, ask it for its current SPF include."),
            "RFC 7208 5.2 / 6.1: a missing target is a permerror."))
    if "spf.ptr" in ids:
        out.append(_fix("spf.ptr", domain, "STEPS", _steps(
            "Replace 'ptr' with the ip4:/ip6: ranges or include: of the hosts it was meant to cover."),
            "RFC 7208 5.5: ptr SHOULD NOT be used."))
    q = data.get("all")
    if rec and q in ("+", "?", "~", None) and not ids & {"spf.lookup_limit", "spf.syntax", "spf.multiple_records"}:
        terms = [t for t in rec.split() if t.lower().lstrip("+?~-") != "all"]
        rid = {"+": "spf.all_pass", "?": "spf.all_neutral", "~": "spf.all_softfail", None: "spf.no_all"}[q]
        note = ("Change only once every sender is listed (check your DMARC reports first). "
                "With DMARC at p=quarantine/reject, ~all is a common, acceptable choice." if q == "~"
                else "Check your DMARC reports first that every sender is listed.")
        out.append(_fix(rid, domain, "TXT", " ".join(terms + ["-all"]), "RFC 7208 5.1 / 8.4. " + note))


def _dkim(domain, k, out, by=None):
    for rid, why in (("dkim.min_rsa_bits", "below 1024 bits: verifiers may treat mail as unsigned (RFC 8301 3.2)"),
                     ("dkim.recommended_rsa_bits", "below the recommended 2048 bits (RFC 8301 3.2)"),
                     ("dkim.sha1_only", "allows only rsa-sha1, which MUST NOT be used (RFC 8301 3.1)")):
        for ev in _ev(k, rid):
            sel = (ev or {}).get("selector") or f"REPLACE-selector._domainkey.{domain}"
            out.append(_fix(rid, sel, "STEPS", _steps(
                "In your mail provider, generate a new 2048-bit RSA DKIM key under a NEW selector (e.g. REPLACE-s2026).",
                f"Publish its TXT at REPLACE-s2026._domainkey.{domain} and switch signing to it.",
                "Wait at least 7 days (mail in transit is still verified with the old key).",
                f"Revoke the old key: set {sel} TXT to 'v=DKIM1; p=' (empty p = revoked, RFC 6376 3.6.1)."),
                f"Key {why}. Rotation steps follow M3AAWG DKIM key rotation practice."))
    if "dkim.testing" in _ids(k):
        out.append(_fix("dkim.testing", f"REPLACE-selector._domainkey.{domain}", "STEPS", _steps(
            "Remove 't=y' from the DKIM key record once signing is verified."),
            "RFC 6376 3.6.1: with t=y verifiers treat signed mail as unsigned for policy."))


def _mtasts(domain, m, out, by=None):
    ids, data = _ids(m), m.get("data") or {}
    mxrows = (((by or {}).get("mx") or {}).get("data") or {}).get("mx") or []
    mx = ([h if isinstance(h, str) else h.get("host") for h in data.get("mx") or []]
          or [r.get("host") for r in mxrows if r.get("host")] or [f"REPLACE-mx.{domain}"])
    null_mx = (((by or {}).get("mx") or {}).get("data") or {}).get("null_mx")
    if ("mtasts.txt_absent" in ids or "mtasts.policy_fetch" in ids) and not null_mx:
        out.append(_fix("mtasts.txt_absent", f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "FILE",
                        "version: STSv1\nmode: testing\n" + "".join(f"mx: {h}\n" for h in mx) + "max_age: 604800\n",
                        "RFC 8461 3.2. Serve over HTTPS with a valid certificate for mta-sts." + domain
                        + " (CRLF or LF line endings, text/plain). Start in testing; move to enforce after TLS-RPT is clean."))
        out.append(_fix("mtasts.txt_absent", f"_mta-sts.{domain}", "TXT", "v=STSv1; id=REPLACEwithYYYYMMDDhhmmss",
                        "RFC 8461 3.1. id is 1-32 letters or digits: use the date and time, and change it every time you change the policy file."))
    if "mtasts.mode_testing" in ids:
        out.append(_fix("mtasts.mode_testing", f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "STEPS", _steps(
            "Check TLS-RPT reports show no failures for 2+ weeks.",
            "Change 'mode: testing' to 'mode: enforce' and raise max_age (e.g. 1209600).",
            f"Update the id in _mta-sts.{domain}."), "RFC 8461 5."))
    for rid in ("tlsrpt.absent", "tlsrpt.no_rua"):
        if rid in ids:
            out.append(_fix(rid, f"_smtp._tls.{domain}", "TXT", f"v=TLSRPTv1; rua=mailto:REPLACE-tls-reports@{domain}",
                            "RFC 8460 3. Replace the mailbox with one you read."))


def _mx(domain, m, out, by=None):
    for r in (m.get("data") or {}).get("mx") or []:
        if r.get("cname"):
            out.append(_fix("mx.cname", domain, "MX", f"{r['preference']} {r['cname']}.",
                            f"Point the MX at the canonical name {r['cname']} instead of the alias {r['host']} "
                            "(RFC 2181 10.3; RFC 5321 5.1)."))


def _caa(domain, c, out, by=None):
    ids = _ids(c)
    if "caa.absent" in ids:
        out.append(_fix("caa.absent", domain, "CAA", '0 issue "REPLACE-your-ca.example"',
                        "RFC 8659 4.2. Add one issue record per CA you use (e.g. your web host's CA), plus "
                        f'0 iodef "mailto:REPLACE-security@{domain}" for violation reports. Check before publishing: '
                        "a wrong CAA blocks your own certificate renewals, including mta-sts." + domain + "."))
    if "caa.iodef" in ids:
        out.append(_fix("caa.iodef", domain, "CAA", f'0 iodef "mailto:REPLACE-security@{domain}"',
                        "RFC 8659 4.4: iodef must be a mailto: or http(s) URL."))


def _dnssec(domain, s, out, by=None):
    ids = _ids(s)
    if "dnssec.unsigned" in ids:
        out.append(_fix("dnssec.unsigned", domain, "STEPS", _steps(
            "Turn on DNSSEC signing at your DNS host.",
            "Copy the DS record it shows you to your registrar (the parent zone).",
            "Re-run the audit with --doh to confirm the AD bit (validated)."),
            "RFC 4033 / RFC 4035. Optional, but required for DANE."))
    if "dnssec.bogus" in ids:
        out.append(_fix("dnssec.bogus", domain, "STEPS", _steps(
            "Compare the DS at your registrar with the DNSKEY your DNS host publishes; remove stale DS records.",
            "If unsure, remove the DS at the registrar first (goes insecure, not broken), then re-enable."),
            "RFC 4035 5.5: validating resolvers return SERVFAIL for this domain."))


def _bimi(domain, b, out, by=None):
    ids = _ids(b)
    if "bimi.absent" in ids:
        out.append(_fix("bimi.absent", f"default._bimi.{domain}", "TXT",
                        f"v=BIMI1; l=https://REPLACE-{domain}/bimi/logo.svg; a=REPLACE-or-empty",
                        "draft-brand-indicators-for-message-identification-14 4.3. Needs DMARC at p=quarantine "
                        "or p=reject; most mailbox providers also need a VMC or CMC certificate (a=)."))
    if ids & {"bimi.svg_format", "bimi.svg_profile", "bimi.svg_title", "bimi.svg_disallowed"}:
        out.append(_fix("bimi.svg_profile", f"default._bimi.{domain}", "STEPS", _steps(
            "Export the logo as SVG Tiny Portable/Secure: root <svg version=\"1.2\" baseProfile=\"tiny-ps\">.",
            "Include a <title> with your brand name; no scripts, external references, x/y on root, or animation.",
            "Keep it under 32 KB and square."), "draft-svg-tiny-ps-abrotman-12 2."))
    if "bimi.dmarc_enforcement" in ids:
        out.append(_fix("bimi.dmarc_enforcement", f"_dmarc.{domain}", "STEPS", _steps(
            "Move DMARC to p=quarantine or p=reject (see the DMARC steps) before BIMI can show."),
            "draft-brand-indicators-for-message-identification-14 7.1."))


def suggest(domain, checks):
    by = {c["check"]: c for c in checks}
    out = []
    for name, fn in (("dmarc", _dmarc), ("spf", _spf), ("dkim", _dkim), ("mta-sts", _mtasts), ("mx", _mx),
                     ("caa", _caa), ("dnssec", _dnssec), ("bimi", _bimi)):
        if name in by:
            fn(domain, by[name], out, by)
    return out
