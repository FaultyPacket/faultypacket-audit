"""security.txt (RFC 9116), opt-in because it makes HTTPS requests to the domain.

Fetches https://<domain>/.well-known/security.txt (falling back to /security.txt,
RFC 9116 3) and checks: location (3), HTTPS (3, 5.7), Content-Type text/plain;
charset=utf-8 (3, 4), UTF-8 (4), field syntax / one field per line / no chained
values (2, 4), Contact present and https (2.5.3), Encryption is a URI not a key
(2.5.4), Expires exactly once, in the future, under a year (2.5.5), Canonical
https and listing the retrieval URI (2.5.2), Preferred-Languages once and
non-empty (2.5.8), https for Acknowledgments/Hiring/Policy (2.5.1, 2.5.6, 2.5.7),
and an OpenPGP cleartext signature (2.3)."""
import datetime as dt
import re
import ssl
import urllib.request

from ._common import result

NAME = "security-txt"
WELL_KNOWN = "/.well-known/security.txt"
LEGACY = "/security.txt"
URI_FIELDS = ("contact", "encryption", "acknowledgments", "canonical", "hiring", "policy", "csaf")
SECTION = {"acknowledgments": "2.5.1", "canonical": "2.5.2", "contact": "2.5.3", "encryption": "2.5.4",
           "hiring": "2.5.6", "policy": "2.5.7"}
FIELD_RE = re.compile(r"^([A-Za-z0-9!#$%&'*+\-.^_`|~]+):[ \t]*(.*?)[ \t]*$")
URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S+$")
LANG_RE = re.compile(r"^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


def fetch(url, timeout=10.0):
    """-> (status, content_type, body_bytes, final_url). Certificate validation on;
    redirects followed by urllib (the final URL is reported)."""
    req = urllib.request.Request(url, headers={"User-Agent": "faultypacket-audit"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as f:
            return f.status, f.headers.get("Content-Type", ""), f.read(65536), f.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", b"", url
    except Exception as e:  # network, TLS
        return None, "", str(e).encode(), url


def strip_signature(text):
    """-> (signed: bool, content). OpenPGP cleartext framework (RFC 4880 7)."""
    if not text.lstrip().startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return False, text
    lines = text.splitlines()
    i = next((k for k, l in enumerate(lines) if l.strip() == "-----BEGIN PGP SIGNED MESSAGE-----"), 0) + 1
    while i < len(lines) and lines[i].strip():   # armor headers (Hash: ...)
        i += 1
    out = []
    for l in lines[i + 1:]:
        if l.startswith("-----BEGIN PGP SIGNATURE-----"):
            break
        out.append(l[2:] if l.startswith("- ") else l)   # dash-escaping (RFC 4880 7.1)
    return True, "\n".join(out)


def parse(text):
    """-> (fields [(name_lower, value, lineno)], bad_lines [(lineno, line)])."""
    fields, bad = [], []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = FIELD_RE.match(line)
        if not m or not m.group(2):
            bad.append((n, line)); continue
        fields.append((m.group(1).lower(), m.group(2), n))
    return fields, bad


def parse_date(v):
    if not DATE_RE.match(v):
        return None
    try:
        return dt.datetime.fromisoformat(v.replace("Z", "+00:00").replace("z", "+00:00").replace("t", "T"))
    except ValueError:
        return None


def lint(body, url, content_type="text/plain; charset=utf-8", now=None):
    """Validate a retrieved file. -> list of (sev, rule_id, msg). Pure; used by tests."""
    now = now or dt.datetime.now(dt.timezone.utc)
    out = []
    add = lambda sev, rid, msg: out.append((sev, rid, msg))
    ct = (content_type or "").lower().replace(" ", "")
    if not ct.startswith("text/plain"):
        add("error", "sectxt.content_type", f"Content-Type is {content_type!r}; RFC 9116 3 requires text/plain; charset=utf-8")
    elif "charset=utf-8" not in ct:
        add("warning", "sectxt.content_type", f"Content-Type {content_type!r} lacks charset=utf-8 (RFC 9116 3)")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        add("error", "sectxt.encoding", "file is not valid UTF-8 (RFC 9116 4)")
        text = body.decode("utf-8", "replace")
    if "\r" in text.replace("\r\n", ""):
        add("error", "sectxt.syntax", "bare CR line ending: every line must end in CRLF or LF (RFC 9116 2.2)")
    signed, content = strip_signature(text)
    if not signed:
        add("info", "sectxt.unsigned", "file has no OpenPGP cleartext signature (RECOMMENDED, RFC 9116 2.3)")
    fields, bad = parse(content)
    for n, line in bad[:5]:
        add("error", "sectxt.syntax", f"line {n} is not 'Name: value' (RFC 9116 2, 4): {line[:80]!r}")
    by = {}
    for name, v, n in fields:
        by.setdefault(name, []).append((v, n))
    for name in URI_FIELDS:
        for v, n in by.get(name, []):
            sec = SECTION.get(name, "2.5")
            if name in ("contact", "encryption", "acknowledgments", "canonical", "hiring", "policy") and re.search(r",\s*\S+:", v):
                add("error", "sectxt.chained", f"line {n}: {name} chains several values; one value per field line (RFC 9116 2)")
            if name == "encryption" and ("BEGIN PGP" in v or (not URI_RE.match(v) and len(v) > 40)):
                add("error", "sectxt.encryption_key", f"line {n}: Encryption holds key material; it MUST be a URI to the key (RFC 9116 2.5.4)")
                continue
            if not URI_RE.match(v):
                add("error", "sectxt.syntax", f"line {n}: {name} value {v[:60]!r} is not a URI (RFC 9116 {sec})")
            elif v.lower().startswith("http:"):
                add("error", "sectxt.https_uri", f"line {n}: {name} web URI must begin with https:// (RFC 9116 {sec})")
    contacts = [v for v, _ in by.get("contact", [])]
    if not contacts:
        add("error", "sectxt.no_contact", "no Contact field: it MUST always be present (RFC 9116 2.5.3)")
    if any(c.lower().startswith("mailto:") for c in contacts) and not by.get("encryption"):
        add("info", "sectxt.contact_unencrypted", "Contact is an email address but no Encryption key is published (RECOMMENDED, RFC 9116 2.5.3, 2.5.4)")
    exp = by.get("expires", [])
    if not exp:
        add("error", "sectxt.expires", "no Expires field: it MUST be present exactly once (RFC 9116 2.5.5)")
    elif len(exp) > 1:
        add("error", "sectxt.duplicate", f"Expires appears {len(exp)} times; it MUST NOT appear more than once (RFC 9116 2.5.5)")
    if exp:
        d = parse_date(exp[0][0])
        if d is None:
            add("error", "sectxt.syntax", f"Expires {exp[0][0]!r} is not an RFC 3339 date-time (RFC 9116 2.5.5)")
        elif d <= now:
            add("error", "sectxt.expired", f"Expires {exp[0][0]} has passed: the file should be treated as stale (RFC 9116 2.5.5, 5.3)")
        elif (d - now).days > 365:
            add("warning", "sectxt.expires_far", f"Expires is {(d - now).days} days away; RECOMMENDED under a year (RFC 9116 2.5.5)")
    pl = by.get("preferred-languages", [])
    if len(pl) > 1:
        add("error", "sectxt.duplicate", "Preferred-Languages appears more than once (RFC 9116 2.5.8)")
    if pl:
        tags = [t.strip() for t in pl[0][0].split(",")]
        if not tags or not all(LANG_RE.match(t) for t in tags):
            add("error", "sectxt.languages", f"Preferred-Languages {pl[0][0]!r} must list at least one language tag (RFC 9116 2.5.8)")
    canon = [v for v, _ in by.get("canonical", [])]
    if canon and url not in canon:
        add("warning", "sectxt.canonical", f"retrieved from {url} but that URI is not listed in Canonical: contents SHOULD NOT be trusted (RFC 9116 2.5.2)")
    if signed and not canon:
        add("info", "sectxt.canonical", "signed file without a Canonical field (RECOMMENDED alongside a signature, RFC 9116 2.3)")
    return out


def check(domain, res, R, options=None):
    options = options or {}
    F = lambda sev, rid, msg, **e: R.finding(NAME, sev, rid, msg, **e)
    get = options.get("sectxt_fetch") or fetch
    host = domain.rstrip(".").lower()
    wk = f"https://{host}{WELL_KNOWN}"
    st, ct, body, final = get(wk)
    used = wk
    fs = []
    if st != 200:
        st2, ct2, body2, final2 = get(f"https://{host}{LEGACY}")
        if st2 != 200:
            why = f"HTTP {st}" if st else (body.decode("utf-8", "replace")[:120] or "unreachable")
            return result(NAME, domain, [F("info", "sectxt.absent", f"no security.txt at {wk} ({why}) or {LEGACY}")], {"url": None})
        fs.append(F("warning", "sectxt.location", f"security.txt only at {LEGACY}: it MUST be placed under /.well-known/ (RFC 9116 3)"))
        st, ct, body, final, used = st2, ct2, body2, final2, f"https://{host}{LEGACY}"
    if not final.lower().startswith("https://"):
        fs.append(F("error", "sectxt.https", f"retrieval ended at {final}: the file MUST be served over HTTPS (RFC 9116 3, 5.7)"))
    fhost = re.sub(r"^https?://([^/:]+).*$", r"\1", final.lower())
    if fhost != host:
        fs.append(F("warning", "sectxt.scope", f"redirected to {fhost}: a security.txt applies only to the host it was retrieved from, not {host} (RFC 9116 3.1)"))
    for sev, rid, msg in lint(body, used, ct, options.get("now")):
        fs.append(F(sev, rid, msg))
    if not any(f.severity in ("error", "warning") for f in fs):
        fs.append(F("info", "sectxt.ok", f"security.txt at {used} is valid"))
    return result(NAME, domain, fs, {"url": used, "final_url": final})
