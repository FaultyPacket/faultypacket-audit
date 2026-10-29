"""BIMI (draft-brand-indicators-for-message-identification-14): assertion
record at default._bimi.<domain> (4.3, 4.3.1), HTTPS-only l=/a= (4.3), SVG
format (4.3.2) with SVG Tiny PS checks (draft-svg-tiny-ps-abrotman-12 2.1,
2.3, 2.4), mark certificate presence (3.5), and the DMARC enforcement
prerequisite (7.1 steps 7-9). The certificate chain itself is not validated."""
import re, urllib.request

from ._common import tags, result

NAME = "bimi"
LIMIT = 32 * 1024


def fetch(url, timeout=10.0, limit=256 * 1024):
    """-> {status, content_type, body(bytes), error}. HTTPS with validation."""
    out = {"status": None, "content_type": None, "body": None, "error": None}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "faultypacket-audit"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out["status"], out["content_type"] = r.status, r.headers.get("Content-Type")
            out["body"] = r.read(limit + 1)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def svg_issues(body):
    """SVG Tiny PS checks a mailbox provider applies before display."""
    out = []
    if body[:2] == b"\x1f\x8b":
        import gzip
        body = gzip.decompress(body)
    if len(body) > LIMIT:
        out.append(("warning", "bimi.svg_size", f"SVG is {len(body)} bytes uncompressed; SHOULD NOT exceed 32 KB"))
    t = body.decode("utf-8", "replace")
    root = re.search(r"<svg\b[^>]*>", t, re.S)
    if not root:
        return out + [("error", "bimi.svg_format", "l= document is not SVG")]
    r = root.group(0)
    if not re.search(r'baseProfile\s*=\s*["\']tiny-ps["\']', r):
        out.append(("error", "bimi.svg_profile", "root <svg> lacks baseProfile=\"tiny-ps\""))
    if not re.search(r'version\s*=\s*["\']1\.2["\']', r):
        out.append(("error", "bimi.svg_profile", "root <svg> lacks version=\"1.2\""))
    titles = re.findall(r"<title\b[^>]*>(.*?)</title>", t, re.S)
    if len(titles) != 1 or not titles[0].strip():
        out.append(("error", "bimi.svg_title", f"needs exactly one non-empty <title> (found {len(titles)})"))
    for el in ("script", "image", "switch", "a", "animate", "set", "foreignObject", "audio", "video"):
        if re.search(rf"<{el}\b", t):
            out.append(("error", "bimi.svg_disallowed", f"disallowed element <{el}>"))
    if re.search(r"\s(x\s*=|y\s*=)", r):
        out.append(("warning", "bimi.svg_profile", "root <svg> has x=/y= attributes, rejected by common validators"))
    if re.search(r'(xlink:)?href\s*=\s*["\']https?:', t):
        out.append(("error", "bimi.svg_disallowed", "external reference in SVG"))
    return out


def dmarc_ok(dm):
    """Draft 7.1 steps 7-9 from the dmarc check's data."""
    t = (dm or {}).get("tags") or {}
    p, sp, pct = (t.get("p") or "none").lower(), (t.get("sp") or "").lower(), t.get("pct")
    if p not in ("quarantine", "reject"):
        return False, f"DMARC p={p}; BIMI needs quarantine or reject"
    if sp == "none":
        return False, "DMARC sp=none; BIMI needs subdomain enforcement too"
    if p == "quarantine" and pct not in (None, "100"):
        return False, f"DMARC p=quarantine with pct={pct}; BIMI needs pct=100 (or no pct)"
    return True, f"DMARC p={p}"


def check(domain, res, R, options=None):
    options = options or {}
    F = lambda sev, rid, msg, **e: R.finding(NAME, sev, rid, msg, **e)
    name = f"default._bimi.{domain}"
    txts, st = res.query(name, "TXT")
    if st.startswith("error"):
        return result(NAME, domain, [F("warning", "bimi.dns_error", f"{name}: {st}")], {})
    recs = [x for x in txts if re.match(r"^v\s*=\s*BIMI1\s*(;|$)", x)]
    data = {"name": name, "record": None, "logo": None, "evidence": None}
    if not recs:
        return result(NAME, domain, [F("info", "bimi.absent", f"no BIMI record at {name}")], data)
    if len(recs) > 1:
        return result(NAME, domain, [F("error", "bimi.record", f"{len(recs)} BIMI records at {name}; ambiguous, receivers ignore them")], data)
    data["record"] = rec = recs[0]
    t, fs = tags(rec), []
    l, a = t.get("l"), t.get("a", "")
    if l is None:
        fs.append(F("error", "bimi.record", "l= is required"))
    if l == "" and a == "":
        fs.append(F("info", "bimi.declined", "explicit declination to publish (l= and a= empty)"))
        return result(NAME, domain, fs, data)
    for tag, v in (("l", l), ("a", a)):
        if v and not v.lower().startswith("https://"):
            fs.append(F("error", "bimi.record", f"{tag}= {v!r} must be an https:// URI"))
    ok, why = dmarc_ok((options.get("results") or {}).get("dmarc"))
    if not ok:
        fs.append(F("error", "bimi.dmarc_enforcement", f"logo will not be shown: {why}"))
    if not a:
        fs.append(F("warning", "bimi.no_certificate", "no a= mark certificate (VMC/CMC); Gmail and Apple Mail only show certified logos"))
    getter = options.get("http_fetch") or fetch
    if l and l.lower().startswith("https://"):
        f = getter(l)
        data["logo"] = {k: v for k, v in f.items() if k != "body"}
        if f["error"] or f["status"] != 200:
            fs.append(F("error", "bimi.fetch", f"logo {l}: {f['error'] or 'HTTP ' + str(f['status'])}"))
        else:
            for sev, rid, msg in svg_issues(f["body"]):
                fs.append(F(sev, rid, f"logo {l}: {msg}"))
    if a and a.lower().startswith("https://"):
        f = getter(a)
        data["evidence"] = {k: v for k, v in f.items() if k != "body"}
        if f["error"] or f["status"] != 200:
            fs.append(F("error", "bimi.fetch", f"certificate {a}: {f['error'] or 'HTTP ' + str(f['status'])}"))
        elif b"-----BEGIN CERTIFICATE-----" not in (f["body"] or b""):
            fs.append(F("error", "bimi.certificate_format", f"certificate {a}: not a PEM certificate"))
        else:
            fs.append(F("info", "bimi.certificate_present", "mark certificate is published (chain and logo binding not validated by this tool)"))
    return result(NAME, domain, fs, data)
