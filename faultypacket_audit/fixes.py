"""Copy-paste DNS fixes for findings where the correct record follows from the
standard alone. Each fix names the rule it answers; anything that needs the
owner's own facts (which servers send, which mailbox reads reports) uses a
clearly marked placeholder and says so in `note`."""

RETIRED = ("pct", "rf", "ri")      # RFC 9989 9.3 / Appendix A.6


def _ids(check):
    return {f.rule_id for f in check["findings"]}


def suggest(domain, checks):
    by = {c["check"]: c for c in checks}
    out = []
    d = by.get("dmarc")
    if d:
        ids, data = _ids(d), d.get("data") or {}
        if "dmarc.no_record" in ids:
            out.append({"rule_id": "dmarc.no_record", "name": f"_dmarc.{domain}", "type": "TXT",
                        "value": f"v=DMARC1; p=none; rua=mailto:REPLACE-dmarc-reports@{domain}",
                        "note": "Monitoring start point (RFC 9989 4.7). Replace the rua mailbox with one you read; "
                                "move to p=quarantine or p=reject once reports show all your senders pass."})
        tags = data.get("tags") or {}
        hit = [t for t in RETIRED if t in tags]
        if hit and data.get("policy_source") == domain and ids & {"dmarc.historic_tag", "dmarc.historic_pct"}:
            drop = set(RETIRED) | ({"fo"} if "dmarc.bad_fo" in ids else set())
            clean = {k: (",".join(u.split("!", 1)[0] for u in v.split(",")) if k in ("rua", "ruf") else v)
                     for k, v in tags.items() if k not in drop}
            kept = "; ".join(f"{k}={v}" for k, v in clean.items())
            out.append({"rule_id": "dmarc.historic_pct" if "pct" in hit else "dmarc.historic_tag",
                        "name": f"_dmarc.{domain}", "type": "TXT", "value": kept,
                        "note": f"Same record without {', '.join(hit)}, which RFC 9989 9.3 retired"
                                + (", the invalid fo value (RFC 9989 4.8)" if "fo" in drop else "")
                                + (" and the obsolete !size suffix (RFC 9989 4.8)" if clean != {k: v for k, v in tags.items() if k not in drop} else "")
                                + ". "
                                + ("Without pct the full policy applies to all mail; receivers following "
                                   "RFC 9989 already do this." if "pct" in hit else "")})
    m = by.get("mta-sts")
    if m and "tlsrpt.absent" in _ids(m):
        out.append({"rule_id": "tlsrpt.absent", "name": f"_smtp._tls.{domain}", "type": "TXT",
                    "value": f"v=TLSRPTv1; rua=mailto:REPLACE-tls-reports@{domain}",
                    "note": "RFC 8460 3. Replace the mailbox with one you read."})
    return out
