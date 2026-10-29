"""Offline message-header analyser: ``faultypacket-audit headers msg.eml``.

Parses Authentication-Results (RFC 8601), ARC sets (RFC 8617),
DKIM-Signature (RFC 6376 3.5) and the Received chain (RFC 5321 4.4), and
gives a DMARC identifier-alignment verdict (RFC 9989 3.2.10, 4.4).

It reads what the receiving server recorded; it does not re-verify DKIM or
ARC signatures (that needs the exact bytes as received and the public keys).
Organizational Domains come from the Public Suffix List offline, or from the
RFC 9989 4.10 DNS Tree Walk when a resolver is given."""
import email
import email.policy
import email.utils
import json
import re

CITE = {"alignment": "RFC 9989 3.2.10", "dkim_id": "RFC 9989 4.4.1", "spf_id": "RFC 9989 4.4.2",
        "tree_walk": "RFC 9989 4.10.2", "ar": "RFC 8601 2.2", "arc": "RFC 8617 4.1", "dkim": "RFC 6376 3.5",
        "received": "RFC 5321 4.4"}
URL = "https://www.rfc-editor.org/rfc/"


def strip_comments(s):
    """Remove RFC 5322 3.2.2 (nested) comments, honouring quoted strings."""
    out, depth, q, esc = [], 0, False, False
    for ch in s:
        if esc:
            esc = False
            if depth == 0:
                out.append(ch)
            continue
        if ch == "\\":
            esc = True
            if depth == 0:
                out.append(ch)
            continue
        if ch == '"' and depth == 0:
            q = not q
        elif not q and ch == "(":
            depth += 1
            continue
        elif not q and ch == ")" and depth:
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def _split(s, sep=";"):
    parts, cur, q = [], [], False
    for ch in s:
        if ch == '"':
            q = not q
        if ch == sep and not q:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def parse_ar(value):
    """RFC 8601 2.2 -> {authserv_id, version, results: [{method, result, reason, props}]}."""
    v = " ".join(strip_comments(value).split())
    parts = _split(v)
    if not parts:
        return {"authserv_id": "", "version": None, "results": []}
    head = parts[0].split()
    out = {"authserv_id": head[0].lower() if head else "", "version": head[1] if len(head) > 1 and head[1].isdigit() else None,
           "results": []}
    for p in parts[1:]:
        m = re.match(r"([A-Za-z0-9_.-]+)\s*(?:/\s*(\d+))?\s*=\s*([A-Za-z0-9_-]+)(.*)$", p, re.S)
        if not m:
            if p.lower() != "none":
                out.setdefault("unparsed", []).append(p)
            continue
        r = {"method": m.group(1).lower(), "result": m.group(3).lower(), "reason": None, "props": {}}
        rest = m.group(4)
        rm = re.search(r'reason\s*=\s*("([^"]*)"|\S+)', rest)
        if rm:
            r["reason"] = rm.group(2) if rm.group(2) is not None else rm.group(1)
            rest = rest[:rm.start()] + rest[rm.end():]
        for pm in re.finditer(r'([A-Za-z]+)\s*\.\s*([A-Za-z0-9_.-]+?)\s*=\s*("([^"]*)"|[^\s;]+)', rest):
            val = pm.group(4) if pm.group(4) is not None else pm.group(3)
            r["props"][f"{pm.group(1).lower()}.{pm.group(2).lower()}"] = val
        out["results"].append(r)
    return out


def parse_tags(value):
    """RFC 6376 3.2 tag-list -> dict (whitespace removed from values)."""
    out = {}
    for part in value.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip().lower()
            if k and k not in out:
                out[k] = "".join(v.split())
    return out


def parse_dkim_signature(value):
    t = parse_tags(value)
    return {"d": t.get("d", "").lower(), "s": t.get("s", ""), "a": t.get("a", ""), "i": t.get("i", ""),
            "c": t.get("c", "simple/simple"), "h": [h.strip().lower() for h in t.get("h", "").split(":") if h.strip()],
            "t": t.get("t"), "x": t.get("x"), "l": t.get("l"), "b_len": len(t.get("b", "")),
            "missing": [k for k in ("v", "a", "b", "bh", "d", "h", "s") if k not in t],
            "signs_from": "from" in [h.strip().lower() for h in t.get("h", "").split(":")]}


def parse_received(value):
    v = " ".join(value.split())
    body, _, date = v.rpartition(";")
    if not body:
        body, date = v, ""
    body = " " + strip_comments(body)
    hop = {}
    for kw in ("from", "by", "via", "with", "id", "for"):
        m = re.search(rf"\s{kw}\s+(\S+)", body, re.I)
        if m:
            hop[kw] = m.group(1).strip("<>;")
    ip = re.search(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", value)
    hop["ip"] = ip.group(1) if ip else None
    ts = None
    try:
        ts = email.utils.parsedate_to_datetime(date.strip()) if date.strip() else None
    except (TypeError, ValueError, IndexError):
        ts = None
    hop["date"] = ts.isoformat() if ts else None
    hop["_ts"] = ts
    return hop


def _addr_domain(v):
    _n, a = email.utils.parseaddr(v or "")
    return a.rpartition("@")[2].lower().rstrip(".") if "@" in a else ""


def org_of(name, res=None):
    name = (name or "").lower().rstrip(".")
    if not name:
        return "", "none"
    if res is not None:
        from .checks.dmarc import org_domain
        od, _w = org_domain(name, res)
        return od, "tree_walk"
    from .checks.dmarc import org_domain_psl
    return org_domain_psl(name), "psl"


def aligned(a, b, mode, res=None):
    """RFC 9989 3.2.10.1 relaxed (same Organizational Domain) / 3.2.10.2 strict (identical)."""
    a, b = (a or "").lower().rstrip("."), (b or "").lower().rstrip(".")
    if not a or not b:
        return False
    if mode == "s":
        return a == b
    return org_of(a, res)[0] == org_of(b, res)[0]


def analyse(raw, res=None, adkim="r", aspf="r", trust=None):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    froms = msg.get_all("From") or []
    from_dom = _addr_domain(froms[0]) if froms else ""
    rp = _addr_domain(msg.get("Return-Path", ""))
    ars = [parse_ar(str(v)) for v in msg.get_all("Authentication-Results") or []]
    sigs = [parse_dkim_signature(str(v)) for v in msg.get_all("DKIM-Signature") or []]
    hops = [parse_received(str(v)) for v in msg.get_all("Received") or []]
    arc = {}
    for h, key in (("ARC-Seal", "seal"), ("ARC-Message-Signature", "ams"), ("ARC-Authentication-Results", "aar")):
        for v in msg.get_all(h) or []:
            v = str(v)
            if key == "aar":
                m = re.match(r"\s*i\s*=\s*(\d+)\s*;(.*)$", v, re.S)
                i, val = (int(m.group(1)), parse_ar(m.group(2))) if m else (None, parse_ar(v))
            else:
                t = parse_tags(v)
                i = int(t["i"]) if t.get("i", "").isdigit() else None
                val = t
            arc.setdefault(i, {})[key] = val
    notes, problems = [], []
    # RFC 8601 5: only trust results added by your own boundary; default = the topmost header
    trusted = [a for a in ars if (trust is None and a is ars[0]) or (trust and a["authserv_id"] == trust.lower())] if ars else []
    if len(froms) != 1:
        problems.append(f"{len(froms)} From headers: DMARC requires exactly one author domain (RFC 9989 4.4)")
    results = [r for a in trusted for r in a["results"]]
    spf = next((r for r in results if r["method"] == "spf"), None)
    dkims = [r for r in results if r["method"] == "dkim"]
    dmarc = next((r for r in results if r["method"] == "dmarc"), None)
    spf_dom = ""
    if spf:
        spf_dom = _addr_domain(spf["props"].get("smtp.mailfrom", "")) or spf["props"].get("smtp.mailfrom", "").lower() \
            or spf["props"].get("smtp.helo", "").lower()
    ids = []
    for r in dkims:
        d = (r["props"].get("header.d") or r["props"].get("header.i", "").rpartition("@")[2]).lower()
        ids.append({"type": "dkim", "domain": d, "result": r["result"], "source": "authentication-results",
                    "aligned": aligned(d, from_dom, adkim, res)})
    if not dkims:
        for s in sigs:
            ids.append({"type": "dkim", "domain": s["d"], "result": "not-verified", "source": "dkim-signature",
                        "aligned": aligned(s["d"], from_dom, adkim, res)})
    if spf:
        ids.append({"type": "spf", "domain": spf_dom or rp, "result": spf["result"], "source": "authentication-results",
                    "aligned": aligned(spf_dom or rp, from_dom, aspf, res)})
    passing = [i for i in ids if i["result"] == "pass" and i["aligned"]]
    if not trusted:
        verdict = "unknown"
        notes.append("no Authentication-Results header to read: results unknown (RFC 8601)")
    elif passing:
        verdict = "pass"
    elif any(i["result"] == "pass" for i in ids):
        verdict = "fail-unaligned"
    else:
        verdict = "fail"
    if dmarc and dmarc["result"] in ("pass", "fail") and verdict in ("pass", "fail", "fail-unaligned"):
        mine = "pass" if verdict == "pass" else "fail"
        if mine != dmarc["result"]:
            notes.append(f"receiver recorded dmarc={dmarc['result']} but alignment of the recorded results gives {mine}; "
                         "the receiver may use a different Organizational Domain, strict mode, or ARC override")
    for s in sigs:
        if s["missing"]:
            problems.append(f"DKIM-Signature d={s['d']} s={s['s']} lacks required tags: {', '.join(s['missing'])} (RFC 6376 3.5)")
        if not s["signs_from"]:
            problems.append(f"DKIM-Signature d={s['d']} does not sign From; it MUST (RFC 6376 5.4)")
        if s["a"] == "rsa-sha1":
            problems.append(f"DKIM-Signature d={s['d']} uses rsa-sha1, which MUST NOT be used (RFC 8301 3.1)")
        if s["l"] is not None:
            notes.append(f"DKIM-Signature d={s['d']} uses l= (body length): content can be appended (RFC 6376 8.2)")
    arc_out = {"instances": sorted(i for i in arc if i is not None), "sets": []}
    for i in arc_out["instances"]:
        st = arc[i]
        seal = st.get("seal") or {}
        arc_out["sets"].append({"i": i, "cv": seal.get("cv"), "complete": all(k in st for k in ("seal", "ams", "aar")),
                                "sealer": seal.get("d")})
    if arc_out["instances"]:
        n = max(arc_out["instances"])
        if arc_out["instances"] != list(range(1, n + 1)) or any(not s["complete"] for s in arc_out["sets"]):
            problems.append("ARC chain has missing or incomplete sets (RFC 8617 4.1, 5.1.1): chain is invalid")
        first = next((s for s in arc_out["sets"] if s["i"] == 1), None)
        if first and first["cv"] not in (None, "none"):
            problems.append("ARC set i=1 must have cv=none (RFC 8617 4.1.3)")
        if any(s["cv"] == "fail" for s in arc_out["sets"]):
            problems.append("an ARC-Seal records cv=fail: the chain is broken (RFC 8617 5.2)")
        arc_out["chain"] = "fail" if any(s["cv"] == "fail" for s in arc_out["sets"]) else "present (signatures not verified)"
    # Received: topmost is newest. Delays between consecutive hops.
    rx = []
    prev = None
    for h in reversed(hops):
        delay = None
        if prev is not None and h["_ts"] and prev["_ts"]:
            try:
                delay = int((h["_ts"] - prev["_ts"]).total_seconds())
            except TypeError:
                delay = None
        rx.append({k: v for k, v in h.items() if k != "_ts"} | {"delay_s": delay})
        prev = h
    for h in rx:
        if h["delay_s"] is not None and h["delay_s"] < -300:
            notes.append(f"Received hop by {h.get('by')} is dated {-h['delay_s']}s before the previous hop (clock skew or forged hop)")
    od, how = org_of(from_dom, res) if from_dom else ("", "none")
    return {"from_domain": from_dom, "from_org_domain": od, "org_domain_method": how, "return_path_domain": rp,
            "adkim": adkim, "aspf": aspf, "authentication_results": ars, "trusted_authserv_id": trusted[0]["authserv_id"] if trusted else None,
            "receiver_dmarc": dmarc["result"] if dmarc else None,
            "identifiers": ids, "verdict": verdict, "dkim_signatures": sigs, "arc": arc_out,
            "received": rx, "problems": problems, "notes": notes,
            "citations": {k: v for k, v in CITE.items()}}


def render(r):
    L = [f"From domain: {r['from_domain'] or '(none)'}  (Organizational Domain {r['from_org_domain'] or '-'} via {r['org_domain_method']})",
         f"DMARC alignment verdict: {r['verdict'].upper()}  [adkim={r['adkim']} aspf={r['aspf']}; RFC 9989 3.2.10, 4.4]"]
    if r["receiver_dmarc"]:
        L.append(f"Receiver recorded: dmarc={r['receiver_dmarc']} (authserv-id {r['trusted_authserv_id']})")
    for i in r["identifiers"]:
        L.append(f"  {i['type']:4} {i['domain'] or '(none)':30} {i['result']:13} {'aligned' if i['aligned'] else 'NOT aligned'}"
                 f"  [{CITE['dkim_id'] if i['type'] == 'dkim' else CITE['spf_id']}]")
    if r["arc"]["instances"]:
        L.append(f"ARC: {len(r['arc']['instances'])} set(s), " + ", ".join(f"i={s['i']} cv={s['cv']} by {s['sealer']}" for s in r["arc"]["sets"])
                 + f"; {r['arc'].get('chain')}")
    L.append(f"Received chain: {len(r['received'])} hop(s), oldest first")
    for h in r["received"]:
        L.append(f"  by {h.get('by') or '?'} from {h.get('from') or '?'} [{h.get('ip') or '-'}] with {h.get('with') or '-'}"
                 + (f" +{h['delay_s']}s" if h["delay_s"] is not None else ""))
    for p in r["problems"]:
        L.append(f"PROBLEM: {p}")
    for n in r["notes"]:
        L.append(f"note: {n}")
    L.append("Signatures are not re-verified: this reads what the receiving server recorded.")
    return "\n".join(L)


def main(argv, stdin, stdout, stderr):
    import argparse
    p = argparse.ArgumentParser(prog="faultypacket-audit headers",
                                description="Analyse a saved message's authentication headers (RFC 8601, RFC 8617, RFC 6376) "
                                            "and DMARC alignment (RFC 9989 3.2.10).")
    p.add_argument("file", help=".eml file ('-' = stdin)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--adkim", choices=["r", "s"], default="r")
    p.add_argument("--aspf", choices=["r", "s"], default="r")
    p.add_argument("--trust", metavar="AUTHSERV_ID", help="read only Authentication-Results from this authserv-id (default: the topmost)")
    p.add_argument("--doh", action="store_true", help="find Organizational Domains by RFC 9989 DNS Tree Walk over DoH (default: offline PSL)")
    a = p.parse_args(argv)
    raw = stdin.buffer.read() if a.file == "-" and hasattr(stdin, "buffer") else (
        stdin.read().encode() if a.file == "-" else open(a.file, "rb").read())
    res = None
    if a.doh:
        from .core.resolver import Cached, Resolver
        from .cli import DEFAULT_DOH
        res = Cached(Resolver(None, 5.0, DEFAULT_DOH))
    r = analyse(raw, res, a.adkim, a.aspf, a.trust)
    print(json.dumps(r, indent=1, default=str) if a.json else render(r), file=stdout)
    return 0 if r["verdict"] == "pass" else 1
