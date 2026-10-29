#!/usr/bin/env python3
"""mta-sts-audit: check a domain's MTA-STS deployment against RFC 8461 and
its TLS reporting record against RFC 8460.

Check functions return plain dicts and never print, so they can be imported.
MIT licence. https://faultypacket.co.uk
"""
import argparse, csv, datetime as dt, http.client, ipaddress, json, os, re, smtplib, socket, ssl, sys
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

__version__ = "1.0.0"
MAX_AGE_MAX = 31557600          # RFC 8461 3.2
MAX_AGE_WEEK = 604800           # "range of weeks or greater" (RFC 8461 3.2)
BODY_LIMIT = 64 * 1024          # suggested maximum policy size (RFC 8461 3.3)
CERT_WARN_DAYS = 14
POLICY_PATH = "/.well-known/mta-sts.txt"
DOH_TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}

# --------------------------------------------------------------------- DNS
def parse_txt_presentation(s):
    """'"v=DMARC1; " "p=none"' -> 'v=DMARC1; p=none' (handles \\" and \\DDD)."""
    s = s.strip()
    if not s.startswith('"'):
        return s
    out, i, inq = [], 0, False
    while i < len(s):
        c = s[i]
        if c == '"':
            inq = not inq
        elif inq and c == "\\" and i + 1 < len(s):
            if len(s[i + 1:i + 4]) == 3 and s[i + 1:i + 4].isdigit():
                out.append(chr(int(s[i + 1:i + 4]))); i += 3
            else:
                out.append(s[i + 1]); i += 1
        elif inq:
            out.append(c)
        i += 1
    return "".join(out)


class Resolver:
    """query(name, rtype) -> (values, status); status ok | void | error:<why>.
    void = NXDOMAIN or no answer of that type."""

    def __init__(self, nameserver=None, timeout=5.0, doh=None):
        self.doh, self.timeout, self.r = doh, timeout, None
        if not doh:
            import dns.resolver
            self.r = dns.resolver.Resolver()
            if nameserver:
                self.r.nameservers = [nameserver]
            self.r.lifetime = timeout

    @property
    def servers(self):
        return [self.doh] if self.doh else list(self.r.nameservers)

    def query(self, name, rtype):
        return self._doh(name, rtype) if self.doh else self._dns(name, rtype)

    def _dns(self, name, rtype):
        import dns.exception, dns.resolver
        try:
            ans = self.r.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], "void"
        except dns.exception.DNSException as e:
            return [], "error:" + type(e).__name__
        if rtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in ans], "ok"
        return [r.to_text() for r in ans], "ok"

    def _doh(self, name, rtype):
        url = self.doh + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as f:
                j = json.load(f)
        except Exception as e:
            return [], "error:" + type(e).__name__
        if j.get("Status") == 3:
            return [], "void"
        if j.get("Status") != 0:
            return [], f"error:rcode{j.get('Status')}"
        data = [a["data"] for a in j.get("Answer", []) or [] if a.get("type") == DOH_TYPES[rtype]]
        if rtype == "TXT":
            data = [parse_txt_presentation(d) for d in data]
        return (data, "ok") if data else ([], "void")


# ------------------------------------------------------------------ helpers
def issue(sev, code, msg):
    return {"severity": sev, "code": code, "message": msg}


def verdict(issues):
    sev = {i["severity"] for i in issues}
    return "fail" if "error" in sev else "warn" if "warning" in sev else "ok"


def mx_match(pattern, host):
    """RFC 8461 4.1: RFC 6125 matching; '*' only as the whole left-most label
    and matches exactly one label. Case-insensitive, trailing dots ignored."""
    p, h = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if p.startswith("*."):
        suf = p[2:]
        if not h.endswith("." + suf):
            return False
        left = h[: -len(suf) - 1]
        return bool(left) and "." not in left
    return "*" not in p and p == h


def valid_mx_pattern(p):
    """sts-policy-mx-value = ["*."] Domain (RFC 8461 3.2; Domain per RFC 5321)."""
    d = p[2:] if p.startswith("*.") else p
    return bool(re.fullmatch(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                             r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", d))


# --------------------------------------------------------------- TXT record
def parse_sts_txt(rec):
    """RFC 8461 3.1 ABNF. -> (fields dict or None, issues)."""
    iss = []
    if not re.match(r"^v=STSv1\s*(;|$)", rec):
        return None, [issue("error", "txt_version", "record must begin with 'v=STSv1' (case-sensitive) (RFC 8461 3.1)")]
    fields = {}
    for part in [x.strip(" \t") for x in rec.split(";")][1:]:
        if not part:
            continue
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]{0,31})=([\x21-\x3a\x3c\x3e-\x7e]+)", part)
        if not m:
            return None, [issue("error", "txt_syntax", f"invalid field {part!r} (RFC 8461 3.1)")]
        fields.setdefault(m.group(1), m.group(2))
    if "id" not in fields:
        return None, [issue("error", "txt_no_id", "required field id is missing (RFC 8461 3.1)")]
    if not re.fullmatch(r"[A-Za-z0-9]{1,32}", fields["id"]):
        return None, [issue("error", "txt_bad_id", f"id={fields['id']!r} must be 1-32 letters/digits (RFC 8461 3.1)")]
    return fields, iss


def check_txt(domain, res):
    name = "_mta-sts." + domain
    txts, st = res.query(name, "TXT")
    out = {"name": name, "record": None, "id": None, "issues": []}
    if st.startswith("error"):
        out["issues"].append(issue("error", "txt_dns_error", f"{name} TXT lookup failed: {st}"))
        return out
    recs = [t for t in txts if t.startswith("v=STSv1")]
    if not recs:
        out["issues"].append(issue("error", "txt_absent", f"no v=STSv1 TXT at {name}: senders treat the domain as having no MTA-STS (RFC 8461 3.1)"))
        out["absent"] = True
        return out
    if len(recs) > 1:
        out["issues"].append(issue("error", "txt_multiple", f"{len(recs)} v=STSv1 records at {name}: senders MUST treat this as no policy (RFC 8461 3.1)"))
        out["record"] = recs
        return out
    out["record"] = recs[0]
    fields, iss = parse_sts_txt(recs[0])
    out["issues"] += iss
    if fields:
        out["id"] = fields["id"]
    return out


# ------------------------------------------------------------- policy fetch
def fetch_policy(domain, timeout=10.0, context=None, connect=None):
    """HTTPS GET https://mta-sts.<domain>/.well-known/mta-sts.txt with PKIX
    validation for that host and no redirects (RFC 8461 3.3).
    connect=(ip, port) overrides the TCP target (tests). -> dict."""
    host = "mta-sts." + domain
    ctx = context or ssl.create_default_context()
    addr, port = connect or (host, 443)
    out = {"url": f"https://{host}{POLICY_PATH}", "status": None, "content_type": None,
           "body": None, "truncated": False, "location": None, "cert_not_after": None,
           "error": None}
    try:
        sock = socket.create_connection((addr, port), timeout=timeout)
    except socket.gaierror as e:
        out["error"] = f"dns: {host} does not resolve ({e.strerror or e})"; return out
    except OSError as e:
        out["error"] = f"connect: {type(e).__name__}: {e}"; return out
    try:
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError as e:
        sock.close(); out["error"] = f"certificate: {e.verify_message}"; return out
    except (ssl.SSLError, OSError) as e:
        sock.close(); out["error"] = f"tls: {type(e).__name__}: {e}"; return out
    try:
        cert = tls.getpeercert()
        if cert and cert.get("notAfter"):
            out["cert_not_after"] = dt.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc).isoformat(timespec="seconds")
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        conn.sock = tls
        conn.request("GET", POLICY_PATH, headers={"Host": host, "User-Agent": f"mta-sts-audit/{__version__}",
                                                   "Cache-Control": "no-cache"})
        r = conn.getresponse()
        out["status"], out["content_type"], out["location"] = r.status, r.getheader("Content-Type"), r.getheader("Location")
        body = r.read(BODY_LIMIT + 1)
        out["truncated"] = len(body) > BODY_LIMIT
        out["body"] = body[:BODY_LIMIT].decode("utf-8", "replace")
        conn.close()
    except Exception as e:
        out["error"] = f"http: {type(e).__name__}: {e}"
    finally:
        tls.close()
    return out


# ------------------------------------------------------------ policy parse
def parse_policy(body):
    """RFC 8461 3.2. Keys and values are case-sensitive (%s in the ABNF).
    -> (policy dict, issues)."""
    iss, pol, mx, seen = [], {}, [], set()
    if body.startswith("\ufeff"):
        iss.append(issue("warning", "policy_bom", "policy starts with a byte-order mark; strict parsers fail on line 1"))
        body = body[1:]
    if "\r" in body.replace("\r\n", ""):
        iss.append(issue("error", "policy_bare_cr", "bare CR line ending; lines end in LF or CRLF (RFC 8461 3.2 ABNF)"))
    crlf, lf = body.count("\r\n"), body.count("\n") - body.count("\r\n")
    pol["line_endings"] = "CRLF" if crlf and not lf else "LF" if lf and not crlf else "mixed" if crlf else "none"
    if pol["line_endings"] == "mixed":
        iss.append(issue("info", "policy_mixed_eol", "mixed CRLF and LF line endings (both are valid terminators, RFC 8461 3.2 ABNF)"))
    lines = body.replace("\r\n", "\n").split("\n")
    while lines and lines[-1].strip() == "":
        lines.pop()
    if any(l.strip() == "" for l in lines):
        iss.append(issue("warning", "policy_blank_line", "blank line inside the policy is outside the RFC 8461 3.2 ABNF; some parsers reject it"))
    for n, line in enumerate(lines, 1):
        if line.strip() == "":
            continue
        if line[:1] in (" ", "\t"):
            iss.append(issue("warning", "policy_leading_ws", f"line {n} starts with whitespace; strict parsers reject it"))
        m = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9_.-]{0,31}):[ \t]*(.*?)[ \t]*", line)
        if not m:
            iss.append(issue("error", "policy_syntax", f"line {n} is not 'key: value': {line!r} (RFC 8461 3.2)"))
            continue
        k, v = m.group(1), m.group(2)
        if k == "mx":
            mx.append(v); continue
        if k.lower() in ("version", "mode", "max_age", "mx") and k != k.lower():
            iss.append(issue("error", "policy_key_case", f"line {n}: key {k!r} must be lower-case {k.lower()!r}; field names are case-sensitive, so this field is ignored (RFC 8461 3.2)"))
            continue
        if k in seen:
            iss.append(issue("warning", "policy_duplicate", f"duplicate {k!r}; only the first is used (RFC 8461 3.2)"))
            continue
        seen.add(k)
        if k in ("version", "mode", "max_age"):
            pol[k] = v
        else:
            iss.append(issue("info", "policy_unknown_field", f"unknown field {k!r} is ignored (RFC 8461 3.2)"))
    pol["mx"] = mx
    if pol.get("version") != "STSv1":
        iss.append(issue("error", "policy_version", f"version must be 'STSv1', got {pol.get('version')!r} (RFC 8461 3.2)"))
    mode = pol.get("mode")
    if mode not in ("enforce", "testing", "none"):
        iss.append(issue("error", "policy_mode", f"mode must be enforce, testing or none (case-sensitive), got {mode!r} (RFC 8461 3.2)"))
    ma = pol.get("max_age")
    if ma is None:
        iss.append(issue("error", "policy_no_max_age", "max_age is required (RFC 8461 3.2)"))
    elif not re.fullmatch(r"\d{1,10}", ma):
        iss.append(issue("error", "policy_bad_max_age", f"max_age {ma!r} must be 1-10 digits (RFC 8461 3.2)"))
    else:
        v = int(ma); pol["max_age_seconds"] = v
        if v > MAX_AGE_MAX:
            iss.append(issue("error", "policy_max_age_high", f"max_age {v} exceeds the maximum {MAX_AGE_MAX} (RFC 8461 3.2)"))
        elif v < MAX_AGE_WEEK and mode in ("enforce", "testing"):
            iss.append(issue("warning" if mode == "enforce" else "info", "policy_max_age_short",
                             f"max_age {v}s ({v/86400:g} days) is under one week; RFC 8461 3.2 expects weeks or greater to limit attacks at refresh time"))
    if mode in ("enforce", "testing") and not mx:
        iss.append(issue("error", "policy_no_mx", "at least one mx is required unless mode is none (RFC 8461 3.2)"))
    for p in mx:
        if not valid_mx_pattern(p):
            iss.append(issue("error", "policy_bad_mx", f"mx {p!r} is not a domain or '*.'-prefixed domain; trailing dots and other wildcards are invalid (RFC 8461 3.2)"))
    return pol, iss


def check_policy(fetched, txt_id=None):
    """Turn a fetch_policy() result into findings. -> (policy or None, issues)."""
    iss = []
    if fetched["error"]:
        return None, [issue("error", "policy_fetch", f"{fetched['url']}: {fetched['error']}; senders without a cached policy deliver as if no MTA-STS (RFC 8461 3.3)")]
    s = fetched["status"]
    if s and 300 <= s < 400:
        return None, [issue("error", "policy_redirect", f"HTTP {s} redirect to {fetched['location']!r}; redirects MUST NOT be followed (RFC 8461 3.3)")]
    if s != 200:
        return None, [issue("error", "policy_status", f"HTTP {s}; only 200 is valid (RFC 8461 3.3)")]
    ct = (fetched["content_type"] or "").split(";")[0].strip().lower()
    if ct != "text/plain":
        iss.append(issue("warning", "policy_content_type", f"Content-Type {fetched['content_type']!r}; senders SHOULD require text/plain and some reject others (RFC 8461 3.2)"))
    if fetched["truncated"]:
        iss.append(issue("warning", "policy_size", f"policy over {BODY_LIMIT} bytes, the suggested maximum (RFC 8461 3.3)"))
    if fetched.get("cert_not_after"):
        left = (dt.datetime.fromisoformat(fetched["cert_not_after"]) - dt.datetime.now(dt.timezone.utc)).days
        if left < CERT_WARN_DAYS:
            iss.append(issue("warning", "policy_cert_expiring", f"policy host certificate expires in {left} days"))
    pol, p_iss = parse_policy(fetched["body"] or "")
    return pol, iss + p_iss


# --------------------------------------------------------------- MX checks
def get_mx(domain, res):
    vals, st = res.query(domain, "MX")
    if st.startswith("error"):
        return None, st
    hosts = []
    for v in vals:
        parts = v.split()
        if len(parts) == 2:
            hosts.append((int(parts[0]), parts[1].lower().rstrip(".")))
    return sorted(hosts), st


def check_mx(domain, policy, res):
    """Match every live MX against policy mx patterns (RFC 8461 4.1)."""
    mx, st = get_mx(domain, res)
    rows, iss = [], []
    if mx is None:
        return rows, [issue("error", "mx_dns_error", f"MX lookup for {domain} failed: {st}")]
    if not mx:
        return rows, [issue("warning", "mx_none", f"{domain} has no MX records; nothing for the policy to match")]
    if len(mx) == 1 and mx[0][1] in ("", "."):
        return rows, [issue("info", "mx_null", "null MX (RFC 7505): domain accepts no mail")]
    pats = (policy or {}).get("mx", [])
    mode = (policy or {}).get("mode")
    for pref, host in mx:
        hit = [p for p in pats if mx_match(p, host)]
        rows.append({"preference": pref, "host": host, "matched_by": hit})
        if pats and not hit:
            sev = "error" if mode == "enforce" else "warning" if mode == "testing" else "info"
            iss.append(issue(sev, "mx_unmatched",
                             f"MX {host} (pref {pref}) matches no policy mx pattern"
                             + ("; enforcing senders MUST NOT deliver to it (RFC 8461 4.1, 5)" if mode == "enforce" else " (RFC 8461 4.1)")))
    for p in pats:
        if not any(mx_match(p, h) for _, h in mx):
            iss.append(issue("info", "mx_pattern_unused", f"policy mx {p!r} matches no current MX"))
    return rows, iss


def smtp_cert(host, timeout=15.0, context=None, port=25):
    """STARTTLS to host and validate the certificate (RFC 8461 4.2): chain to
    a trusted root, not expired, a DNS-ID SAN matching host (4.1 wildcard rules)."""
    out = {"host": host, "starttls": None, "cert_valid": None, "names": [], "not_after": None, "error": None}
    ctx = context or ssl.create_default_context()
    ctx.check_hostname = False   # name matched below with RFC 8461 rules
    try:
        s = smtplib.SMTP(host, port, timeout=timeout)
    except (OSError, smtplib.SMTPException) as e:
        out["error"] = f"unreachable: {type(e).__name__}"; return out
    try:
        s.ehlo()
        out["starttls"] = s.has_extn("starttls")
        if not out["starttls"]:
            return out
        try:
            s.starttls(context=ctx)
        except ssl.SSLCertVerificationError as e:
            out["cert_valid"] = False; out["error"] = f"certificate: {e.verify_message}"; return out
        cert = s.sock.getpeercert()
        out["names"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        out["not_after"] = cert.get("notAfter")
        out["cert_valid"] = any(mx_match(n, host) for n in out["names"])
        if not out["cert_valid"]:
            out["error"] = "certificate has no DNS-ID SAN matching the MX host"
    except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            s.quit()
        except Exception:
            pass
    return out


def check_smtp(rows, mode, probe=smtp_cert, timeout=15.0):
    iss, results = [], []
    sev = "error" if mode == "enforce" else "warning"
    for r in rows:
        c = probe(r["host"], timeout)
        results.append(c)
        if c["error"] and c["error"].startswith("unreachable"):
            iss.append(issue("info", "smtp_unreachable", f"{r['host']}: port 25 not reachable from here ({c['error']}); certificate not tested"))
        elif c["starttls"] is False:
            iss.append(issue(sev, "smtp_no_starttls", f"{r['host']} does not offer STARTTLS (RFC 8461 4, 5)"))
        elif c["cert_valid"] is False:
            iss.append(issue(sev, "smtp_cert", f"{r['host']}: {c['error']} (RFC 8461 4.2)"))
        elif c["error"]:
            iss.append(issue("warning", "smtp_error", f"{r['host']}: {c['error']}"))
    return results, iss


# ------------------------------------------------------------------ TLS-RPT
def check_tlsrpt(domain, res):
    """RFC 8460 3: _smtp._tls TXT 'v=TLSRPTv1; rua=<mailto|https URIs>'."""
    name = "_smtp._tls." + domain
    txts, st = res.query(name, "TXT")
    out = {"name": name, "record": None, "rua": [], "issues": []}
    if st.startswith("error"):
        out["issues"].append(issue("error", "tlsrpt_dns_error", f"{name} TXT lookup failed: {st}")); return out
    recs = [t for t in txts if re.match(r"^v=TLSRPTv1\s*(;|$)", t)]
    if not recs:
        out["issues"].append(issue("warning", "tlsrpt_absent", f"no v=TLSRPTv1 TXT at {name}: you get no reports of TLS delivery failures (RFC 8460 3)")); return out
    if len(recs) > 1:
        out["issues"].append(issue("error", "tlsrpt_multiple", f"{len(recs)} TLSRPT records: senders MUST assume no TLSRPT (RFC 8460 3)")); return out
    out["record"] = rec = recs[0]
    rua = None
    for part in [x.strip(" \t") for x in rec.split(";")][1:]:
        if not part:
            continue
        if "=" not in part:
            out["issues"].append(issue("error", "tlsrpt_syntax", f"invalid field {part!r} (RFC 8460 3)")); return out
        k, v = part.split("=", 1)
        if k == "rua" and rua is None:
            rua = v
    if not rua:
        out["issues"].append(issue("error", "tlsrpt_no_rua", "rua is required (RFC 8460 3)")); return out
    for u in [x.strip() for x in rua.split(",") if x.strip()]:
        out["rua"].append(u)
        sch = u.split(":", 1)[0].lower() if ":" in u else ""
        if sch == "mailto":
            if "@" not in u:
                out["issues"].append(issue("error", "tlsrpt_bad_uri", f"mailto URI {u!r} has no address (RFC 8460 3)"))
        elif sch == "https":
            if not urllib.parse.urlsplit(u).hostname:
                out["issues"].append(issue("error", "tlsrpt_bad_uri", f"https URI {u!r} has no host (RFC 8460 3)"))
        else:
            out["issues"].append(issue("error", "tlsrpt_scheme", f"rua URI {u!r}: only mailto and https are defined (RFC 8460 3)"))
    return out


# -------------------------------------------------------------------- audit
ROLLOUT_NOTE = ("Common rollout order: publish TLS-RPT, then MTA-STS in mode testing with a "
                "short max_age; once reports show clean delivery to every MX, switch to "
                "enforce and raise max_age to weeks or more. Update the policy file before "
                "the TXT id (RFC 8461 8.1).")


def audit(domain, res, fetcher=None, smtp=False, smtp_probe=None, timeout=10.0):
    """Full audit of one domain. Pure: returns a dict, prints nothing."""
    issues = []
    txt = check_txt(domain, res); issues += txt["issues"]
    tlsrpt = check_tlsrpt(domain, res)
    out = {"domain": domain, "txt": {k: v for k, v in txt.items() if k != "issues"},
           "policy": None, "fetch": None, "mx": [], "smtp": [],
           "tlsrpt": {k: v for k, v in tlsrpt.items() if k != "issues"}}
    if txt.get("absent"):
        issues += tlsrpt["issues"]
        out.update(issues=issues, result="absent", note=ROLLOUT_NOTE)
        return out
    f = (fetcher or fetch_policy)(domain, timeout=timeout)
    out["fetch"] = {k: v for k, v in f.items() if k != "body"}
    pol, p_iss = check_policy(f, txt.get("id")); issues += p_iss
    out["policy"] = pol
    rows, m_iss = check_mx(domain, pol, res); issues += m_iss
    out["mx"] = rows
    mode = (pol or {}).get("mode")
    if smtp and rows:
        out["smtp"], s_iss = check_smtp(rows, mode, smtp_probe or smtp_cert, timeout); issues += s_iss
    issues += tlsrpt["issues"]
    if mode == "enforce" and not tlsrpt["record"]:
        issues.append(issue("warning", "enforce_without_tlsrpt", "mode enforce with no TLS-RPT: delivery failures caused by the policy are invisible to you"))
    if mode == "testing":
        issues.append(issue("info", "mode_testing", "mode testing: failures are reported (if TLS-RPT is set) but mail is still delivered (RFC 8461 5)"))
    if mode == "none":
        issues.append(issue("info", "mode_none", "mode none: policy opt-out (RFC 8461 8.3)"))
    if mode in ("testing", None):
        out["note"] = ROLLOUT_NOTE
    out.update(issues=issues, result=verdict(issues))
    return out


# -------------------------------------------------------------------- input
def extract_domain(raw):
    """URL, email, host:port or bare name -> lowercase ASCII domain. ValueError."""
    s = raw.strip()
    if not s:
        raise ValueError("empty")
    if "://" in s:
        s = urllib.parse.urlsplit(s).netloc
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        raise ValueError("IP literal, not a domain")
    s = s.split(":")[0].rstrip(".").strip().lower()
    if not s:
        raise ValueError("no host")
    try:
        ipaddress.ip_address(s)
    except ValueError:
        pass
    else:
        raise ValueError("IP address, not a domain")
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid IDN")
    labels = s.split(".")
    if len(s) > 253 or len(labels) < 2 or not all(
            re.fullmatch(r"(?!-)[a-z0-9_-]{1,63}(?<!-)", l) for l in labels):
        raise ValueError("not a valid domain name")
    return s


def read_lines(lines):
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.extend(line.replace(",", " ").split())
    return out


def collect(args, files, stdin, auto_stdin=False):
    """-> (deduped domains in first-seen order, [{input, error}]).
    A positional argument naming an existing file is read as a list (v1.0 usage)."""
    raw = []
    def read(f):
        if f == "-":
            return read_lines(stdin)
        with open(f, encoding="utf-8") as fh:
            return read_lines(fh)
    for a in args:
        raw += read(a) if os.path.isfile(a) else [a]
    for f in files or []:
        raw += read(f)
    if auto_stdin and stdin is not None and not stdin.isatty():
        raw += read_lines(stdin)
    seen, domains, bad = set(), [], []
    for r in raw:
        try:
            d = extract_domain(r)
        except ValueError as e:
            bad.append({"input": r, "error": str(e)}); continue
        if d not in seen:
            seen.add(d); domains.append(d)
    return domains, bad


# --------------------------------------------------------------------- main
def run_one(domain, res, **kw):
    checked = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        r = audit(domain, res, **kw)
    except Exception as e:  # per-domain isolation
        r = {"domain": domain, "result": "error", "policy": None, "mx": [], "tlsrpt": {},
             "issues": [issue("error", "internal", f"{type(e).__name__}: {e}")]}
    return {"tool": "mta-sts-audit", "version": __version__, "checked_at_utc": checked,
            "resolvers": res.servers, **r}


def summary_row(r):
    pol = r.get("policy") or {}
    mx = r.get("mx") or []
    return {"checked_at_utc": r["checked_at_utc"], "domain": r["domain"], "result": r["result"],
            "txt_id": (r.get("txt") or {}).get("id") or "",
            "mode": pol.get("mode") or "", "max_age": pol.get("max_age") or "",
            "mx_total": len(mx), "mx_unmatched": sum(1 for m in mx if pol.get("mx") and not m["matched_by"]),
            "tlsrpt": "yes" if (r.get("tlsrpt") or {}).get("record") else "no",
            "issues": " | ".join(f"{i['severity']}:{i['code']}" for i in r["issues"]),
            "resolver": ",".join(r["resolvers"])}


def main(argv=None, stdin=None):
    stdin = sys.stdin if stdin is None else stdin
    p = argparse.ArgumentParser(prog="mta_sts_audit.py",
        description="Audit MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) for one or many domains.")
    p.add_argument("domains", nargs="*", help="domains, URLs or email addresses")
    p.add_argument("-f", "--file", action="append", help="file with one input per line ('-' = stdin); repeatable")
    p.add_argument("--json", help="write JSON array to file, '-' for stdout")
    p.add_argument("--csv", help="write one summary row per domain to this CSV file")
    p.add_argument("--smtp", action="store_true", help="also STARTTLS to each MX on port 25 and validate its certificate")
    p.add_argument("--resolver", help="nameserver IP (port 53)")
    p.add_argument("--doh", action="store_true", help="use DNS-over-HTTPS JSON API instead of port 53")
    p.add_argument("--doh-url", default="https://dns.google/resolve", help="DoH JSON endpoint (default %(default)s)")
    p.add_argument("--timeout", type=float, default=10.0, help="per-operation timeout, seconds (default 10)")
    p.add_argument("-c", "--concurrency", type=int, default=8, help="domains in parallel (default 8, max 64)")
    p.add_argument("-q", "--quiet", action="store_true", help="summary table only")
    p.add_argument("--version", action="version", version=f"mta-sts-audit {__version__}")
    a = p.parse_args(argv)
    if not 1 <= a.concurrency <= 64:
        p.error("--concurrency must be 1..64")
    try:
        domains, bad = collect(a.domains, a.file, stdin, auto_stdin=not a.domains and not a.file)
    except OSError as e:
        p.error(str(e))
    for b in bad:
        print(f"skipped input {b['input']!r}: {b['error']}", file=sys.stderr)
    if not domains:
        p.error("no valid domains given")
    res = Resolver(a.resolver, a.timeout, a.doh_url if a.doh else None)
    with ThreadPoolExecutor(max_workers=min(a.concurrency, len(domains))) as ex:
        results = list(ex.map(lambda d: run_one(d, res, smtp=a.smtp, timeout=a.timeout), domains))
    out = sys.stderr if a.json == "-" else sys.stdout
    if not a.quiet:
        for r in results:
            pol = r.get("policy") or {}
            print(f"{r['domain']}: {r['result'].upper()}", file=out)
            if pol:
                print(f"  policy: mode={pol.get('mode')} max_age={pol.get('max_age')} mx={','.join(pol.get('mx', []))} eol={pol.get('line_endings')}", file=out)
            for m in r.get("mx") or []:
                print(f"  MX {m['preference']} {m['host']}: " + (f"matched by {', '.join(m['matched_by'])}" if m["matched_by"] else "NO MATCH"), file=out)
            for i in r["issues"]:
                print(f"  [{i['severity']}] {i['message']}", file=out)
            if r.get("note"):
                print(f"  note: {r['note']}", file=out)
            print(file=out)
    rows = [summary_row(r) for r in results]
    w = max([6] + [len(r["domain"]) for r in rows])
    print(f"{'domain':<{w}}  result  mode     max_age   mx  unmatched  tlsrpt", file=out)
    for r in rows:
        print(f"{r['domain']:<{w}}  {r['result']:<6}  {r['mode'] or '-':<7}  {str(r['max_age'] or '-'):>8}  {r['mx_total']:>3}  {r['mx_unmatched']:>9}  {r['tlsrpt']}", file=out)
    print(f"checked {results[0]['checked_at_utc']} via {','.join(res.servers)}", file=out)
    if a.json:
        s = json.dumps(results, indent=2) + "\n"
        if a.json == "-":
            sys.stdout.write(s)
        else:
            with open(a.json, "w") as f:
                f.write(s)
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            cw = csv.DictWriter(f, fieldnames=list(rows[0].keys())); cw.writeheader(); cw.writerows(rows)
    return 1 if (bad or any(r["result"] != "ok" and r["result"] != "warn" for r in results)) else 0


if __name__ == "__main__":
    sys.exit(main())
