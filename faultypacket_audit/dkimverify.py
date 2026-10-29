"""DKIM signature re-verification (RFC 6376 3.4-3.7, 6.1; RFC 8301; RFC 8463).

verify(raw_bytes, resolver, now=None) -> one result per DKIM-Signature, in
header order:
  {"d", "s", "i", "a", "c", "result": pass|fail|neutral|permerror|temperror|policy,
   "reason", "problems": [(rule_id, section, message)], "body_hash_ok"}

Works on the raw octets: header fields are kept exactly as received (RFC 6376
3.4.1), so a message that was re-encoded or re-wrapped on disk will fail just
as it would at a receiver. RSA and Ed25519 need the optional ``cryptography``
package; without it every signature is "neutral (not verified)"."""
import base64
import hashlib
import re
import time

WSP = re.compile(rb"[ \t]+")


class _Perm(Exception):
    pass


def split_message(raw):
    """-> ([(name_bytes, full_field_bytes_with_crlf)], body_bytes). Line ends normalised to CRLF."""
    raw = re.sub(rb"\r?\n", b"\r\n", raw)
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, body = raw, b""
    fields, cur = [], None
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and cur is not None:
            cur += b"\r\n" + line
        else:
            if cur is not None:
                fields.append(cur)
            cur = line
    if cur:
        fields.append(cur)
    out = []
    for f in fields:
        name = f.split(b":", 1)[0]
        out.append((name, f + b"\r\n"))
    return out, body


def canon_header(field, alg):
    if alg == "simple":
        return field
    name, _, val = field.partition(b":")
    val = re.sub(rb"\r\n(?=[ \t])", b"", val)       # unfold
    val = WSP.sub(b" ", val).strip(b" \t\r\n")
    return name.strip().lower() + b":" + val + b"\r\n"


def canon_body(body, alg, length=None):
    if alg == "relaxed":
        lines = body.split(b"\r\n")
        lines = [WSP.sub(b" ", ln).rstrip(b" ") for ln in lines]
        body = b"\r\n".join(lines)
    body = body.rstrip(b"\r\n") if alg == "relaxed" else re.sub(rb"(\r\n)*$", b"", body)
    body = body + b"\r\n" if body or alg == "simple" else b""
    if length is not None:
        body = body[:length]
    return body


def parse_tags(value):
    """Tag-list (RFC 6376 3.2) -> dict; raises _Perm on duplicates or bad syntax."""
    tags = {}
    for part in value.split(";"):
        if not part.strip():
            continue
        if "=" not in part:
            raise _Perm(("dkim.sig_syntax", "3.2", f"tag without '=': {part.strip()[:30]!r}"))
        k, v = part.split("=", 1)
        k = k.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", k):
            raise _Perm(("dkim.sig_syntax", "3.2", f"bad tag name {k!r}"))
        if k in tags:
            raise _Perm(("dkim.sig_syntax", "3.2", f"duplicate tag {k}="))
        tags[k] = re.sub(r"\s+", "", v) if k in ("b", "bh", "p", "h") else v.strip()
    return tags


def _b64(s):
    try:
        return base64.b64decode(re.sub(r"\s+", "", s), validate=True)
    except ValueError:
        raise _Perm(("dkim.sig_syntax", "3.5", "b=/bh= is not valid base64")) from None


def strip_b(field):
    """The signature header with the b= value emptied (RFC 6376 3.7), keeping all other octets."""
    name, _, val = field.partition(b":")
    m = re.search(rb"(^|;)([ \t\r\n]*b[ \t\r\n]*=)([^;]*)", val)
    if not m:
        return field
    return name + b":" + val[:m.start(3)] + val[m.end(3):]


def select_headers(fields, hlist, sig_index):
    """RFC 6376 5.4.2: for each name, take the last unused instance, bottom-up; missing -> null."""
    used, out = set(), []
    for name in hlist:
        n = name.strip().lower().encode()
        for idx in range(len(fields) - 1, -1, -1):
            if idx in used or idx == sig_index:
                continue
            if fields[idx][0].strip().lower() == n:
                used.add(idx)
                out.append(fields[idx][1])
                break
    return out


def fetch_key(res, s, d):
    vals, st = res.query(f"{s}._domainkey.{d}", "TXT")
    if st.startswith("error"):
        return None, "temperror", f"key lookup failed ({st})"
    recs = [v for v in vals if not v.strip().lower().startswith("v=") or v.replace(" ", "").startswith("v=DKIM1")]
    if not recs:
        return None, "permerror", f"no key at {s}._domainkey.{d}"
    if len(recs) > 1:
        return None, "permerror", f"{len(recs)} TXT records at {s}._domainkey.{d}; results are undefined (RFC 6376 3.6.2.2)"
    try:
        t = parse_tags(recs[0])
    except _Perm as e:
        return None, "permerror", e.args[0][2]
    return t, "ok", ""


def _verify_sig(alg, pub, data, sig):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None
    try:
        if alg.startswith("ed25519"):
            key = ed25519.Ed25519PublicKey.from_public_bytes(pub)
            key.verify(sig, hashlib.sha256(data).digest())
        else:
            key = serialization.load_der_public_key(pub)
            if not isinstance(key, rsa.RSAPublicKey):
                return False
            if key.key_size < 1024:
                raise _Perm(("dkim.sig_weak_key", "RFC 8301 3.2", f"RSA key is {key.key_size} bits; verifiers MUST NOT accept keys under 1024"))
            key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256() if alg.endswith("sha256") else hashes.SHA1())
        return True
    except InvalidSignature:
        return False
    except ValueError:
        raise _Perm(("dkim.key_syntax", "3.6.1", "public key p= does not decode")) from None


def verify_one(fields, body, idx, res, now):
    raw = fields[idx][1]
    value = raw.split(b":", 1)[1].decode("utf-8", "replace")
    out = {"d": "", "s": "", "i": "", "a": "", "c": "", "result": "permerror", "reason": "", "problems": [], "body_hash_ok": None}
    P = lambda rid, sec, msg: out["problems"].append((rid, sec, msg))
    try:
        t = parse_tags(value)
        for k in ("v", "a", "b", "bh", "d", "h", "s"):
            if k not in t:
                raise _Perm(("dkim.sig_missing_tag", "3.5", f"required tag {k}= is missing"))
        out.update(d=t["d"].lower().rstrip("."), s=t["s"], a=t["a"].lower(), c=t.get("c", "simple/simple"))
        if t["v"] != "1":
            raise _Perm(("dkim.sig_syntax", "3.5", f"v={t['v']} (must be 1)"))
        if out["a"] not in ("rsa-sha256", "rsa-sha1", "ed25519-sha256"):
            raise _Perm(("dkim.sig_algorithm", "3.5", f"unknown algorithm a={out['a']}"))
        if out["a"] == "rsa-sha1":
            raise _Perm(("dkim.sig_algorithm", "RFC 8301 3.1", "rsa-sha1 MUST NOT be used; treated as a failed signature"))
        c = out["c"].lower().split("/")
        hc, bc = c[0], (c[1] if len(c) > 1 else "simple")
        if hc not in ("simple", "relaxed") or bc not in ("simple", "relaxed"):
            raise _Perm(("dkim.sig_syntax", "3.5", f"unknown canonicalisation c={out['c']}"))
        hlist = [h for h in t["h"].split(":") if h]
        if not any(h.lower() == "from" for h in hlist):
            raise _Perm(("dkim.sig_from_unsigned", "5.4", "h= does not include From; it MUST"))
        if any(h.lower() == "dkim-signature" for h in hlist):
            P("dkim.sig_h_self", "3.5", "h= lists DKIM-Signature; it MUST NOT include the signature being verified (other signatures may be signed)")
        i = t.get("i", "@" + out["d"])
        out["i"] = i
        idom = i.rpartition("@")[2].lower().rstrip(".")
        if idom != out["d"] and not idom.endswith("." + out["d"]):
            raise _Perm(("dkim.sig_i_outside_d", "3.5", f"i={i}: the domain MUST be d={out['d']} or a subdomain of it"))
        if "x" in t:
            if not t["x"].isdigit():
                raise _Perm(("dkim.sig_syntax", "3.5", "x= is not a number"))
            if "t" in t and t["t"].isdigit() and int(t["x"]) < int(t["t"]):
                raise _Perm(("dkim.sig_expired", "3.5", f"x={t['x']} is before t={t['t']}"))
            if int(t["x"]) < now:
                out["result"], out["reason"] = "fail", f"signature expired (x={t['x']})"
                P("dkim.sig_expired", "3.5", out["reason"])
                return out
        if "t" in t and t["t"].isdigit() and int(t["t"]) > now + 3600:
            P("dkim.sig_future", "3.5", f"t={t['t']} is in the future")
        if "q" in t and "dns/txt" not in t["q"].split(":"):
            raise _Perm(("dkim.sig_syntax", "3.5", f"q={t['q']}: only dns/txt is defined"))
        length = None
        if "l" in t:
            if not t["l"].isdigit():
                raise _Perm(("dkim.sig_syntax", "3.5", "l= is not a number"))
            length = int(t["l"])
            P("dkim.sig_body_length", "8.2", f"l={length}: content can be appended after the signed part")
        cb = canon_body(body, bc)
        if length is not None and length > len(cb):
            raise _Perm(("dkim.sig_body_length", "3.5", f"l={length} is longer than the canonicalised body ({len(cb)})"))
        bh = hashlib.sha256(cb[:length] if length is not None else cb).digest()
        out["body_hash_ok"] = bh == _b64(t["bh"])
        key, st, why = fetch_key(res, out["s"], out["d"]) if res is not None else (None, "neutral", "no resolver: key not fetched")
        if key is None:
            out["result"], out["reason"] = st, why
            if st == "permerror":
                P("dkim.sig_key", "6.1.2", why)
            return out
        if key.get("v", "DKIM1") != "DKIM1":
            raise _Perm(("dkim.sig_key", "3.6.1", "key record v= is not DKIM1"))
        if not key.get("p"):
            raise _Perm(("dkim.sig_key", "3.6.1", "key revoked (empty p=)"))
        kk = key.get("k", "rsa").lower()
        if (kk == "ed25519") != out["a"].startswith("ed25519") or kk not in ("rsa", "ed25519"):
            raise _Perm(("dkim.sig_key", "3.6.1", f"key type k={kk} does not match a={out['a']}"))
        if "h" in key and out["a"].split("-")[1] not in key["h"].split(":"):
            raise _Perm(("dkim.sig_key", "3.6.1", f"key h={key['h']} does not allow {out['a']}"))
        if "s" in key and not ({"*", "email"} & {x.strip() for x in key["s"].split(":")}):
            raise _Perm(("dkim.sig_key", "3.6.1", f"key s={key['s']} is not for email"))
        if "s" in [x.strip() for x in key.get("t", "").split(":")] and idom != out["d"]:
            raise _Perm(("dkim.sig_i_outside_d", "3.6.1", f"key has t=s but i= domain {idom} is a subdomain of d={out['d']}"))
        if not out["body_hash_ok"]:
            out["result"], out["reason"] = "fail", "body hash mismatch: the body changed after signing (or l=/c= mismatch)"
            P("dkim.sig_body_hash", "3.7", out["reason"])
            return out
        hdrs = select_headers(fields, hlist, idx)
        data = b"".join(canon_header(h, hc) for h in hdrs)
        data += canon_header(strip_b(raw), hc).rstrip(b"\r\n")
        ok = _verify_sig(out["a"], _b64(key["p"]), data, _b64(t["b"]))
        if ok is None:
            out["result"], out["reason"] = "neutral", "not verified: pip install faultypacket-audit[crypto]"
        elif ok:
            out["result"], out["reason"] = "pass", f"verified with {out['s']}._domainkey.{out['d']}"
            if "y" in [x.strip() for x in key.get("t", "").split(":")]:
                out["reason"] += " (key has t=y: testing, treat as unsigned)"
        else:
            out["result"], out["reason"] = "fail", "signature does not verify: a signed header changed, or the wrong key"
            P("dkim.sig_bad", "3.7", out["reason"])
    except _Perm as e:
        rid, sec, msg = e.args[0]
        out["result"], out["reason"] = "permerror", msg
        P(rid, sec, msg)
    return out


def verify(raw, res, now=None):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    now = int(now if now is not None else time.time())
    fields, body = split_message(raw)
    return [verify_one(fields, body, i, res, now) for i, (n, _f) in enumerate(fields) if n.strip().lower() == b"dkim-signature"]
