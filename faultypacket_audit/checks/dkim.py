"""DKIM key discovery and strength (RFC 6376 3.6.1, RFC 8301 3.1/3.2, RFC 8463 4.2).

Selectors cannot be enumerated from DNS (RFC 6376 3.1), so the check probes a
list of common selectors (rules.json dkim.common_selectors) plus any the user
gives with --dkim-selector. "No key found" is therefore info, not an error,
unless the user named the selector.
"""
import base64

from ._common import tags, result

NAME = "dkim"


def rsa_bits(p_b64):
    """Modulus size of a base64 SubjectPublicKeyInfo (or bare RSAPublicKey)."""
    der = base64.b64decode(p_b64 + "=" * (-len(p_b64) % 4), validate=False)
    return _der_rsa_bits(der)


def _der_rsa_bits(der):
    """Minimal DER walk: find the first INTEGER large enough to be a modulus."""
    def read(i):
        tag, ln = der[i], der[i + 1]
        i += 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(der[i:i + n], "big"); i += n
        return tag, i, ln
    i, stack = 0, []
    while i < len(der):
        tag, j, ln = read(i)
        if tag in (0x30,):            # SEQUENCE: descend
            i = j; continue
        if tag == 0x03:               # BIT STRING: skip unused-bits byte, descend
            i = j + 1; continue
        if tag == 0x02:
            v = der[j:j + ln].lstrip(b"\x00")
            if len(v) >= 64:
                return int.from_bytes(v, "big").bit_length()
        i = j + ln
    raise ValueError("no RSA modulus found")


def analyse_key(name, rec, R):
    """One TXT at <sel>._domainkey.<domain> -> (info dict, findings)."""
    F = lambda sev, rid, msg, **e: R.finding(NAME, sev, rid, msg, selector=name, **e)
    t, fs = tags(rec), []
    info = {"name": name, "record": rec, "k": t.get("k", "rsa"), "bits": None,
            "testing": False, "revoked": False}
    if "v" in t and t["v"] != "DKIM1":
        fs.append(F("error", "dkim.bad_version", f"{name}: v={t['v']!r}; if present v MUST be DKIM1"))
    if t.get("__dup__"):
        fs.append(F("error", "dkim.syntax", f"{name}: duplicate tag(s) {', '.join(t['__dup__'])}; the record is invalid"))
    if "p" not in t:
        fs.append(F("error", "dkim.no_p", f"{name}: no p= tag; the key record is unusable"))
        return info, fs
    flags = [f.strip() for f in t.get("t", "").split(":") if f.strip()]
    if "y" in flags:
        info["testing"] = True
        fs.append(F("warning", "dkim.testing", f"{name}: t=y testing flag; verifiers MUST treat mail as unsigned, so it gives you no DKIM pass for DMARC-dependent policies"))
    for fl in flags:
        if fl == "s":
            fs.append(F("info", "dkim.strict_subdomain", f"{name}: t=s; signatures whose i= is a subdomain of d= will fail with this key"))
        elif fl != "y":
            fs.append(F("warning", "dkim.unknown_flag", f"{name}: unknown t= flag {fl!r}; verifiers ignore it"))
    if "s" in t:
        svc = [x.strip() for x in t["s"].split(":") if x.strip()]
        if not ({"*", "email"} & set(svc)):
            fs.append(F("error", "dkim.service_type", f"{name}: s={t['s']}; the key is not usable for email (needs s=email or s=*)"))
    if "g" in t:
        fs.append(F("info" if t["g"] in ("*", "") else "warning", "dkim.granularity",
                    f"{name}: g={t['g']!r} is from RFC 4871 and was dropped by RFC 6376"
                    + ("" if t["g"] in ("*", "") else "; some older verifiers still restrict the key to that local-part")))
    if "h" in t and "sha256" not in t["h"].split(":"):
        fs.append(F("error", "dkim.sha1_only", f"{name}: h={t['h']} excludes sha256; rsa-sha1 MUST NOT be used"))
    if t["p"] == "":
        info["revoked"] = True
        fs.append(F("info", "dkim.revoked_empty_p", f"{name}: empty p= (key revoked). Fine if deliberate; remove the selector from signing"))
        return info, fs
    k = info["k"].lower()
    if k == "ed25519":
        try:
            raw = base64.b64decode(t["p"] + "=" * (-len(t["p"]) % 4))
        except Exception:
            raw = b""
        info["bits"] = 256
        if len(raw) != 32:
            fs.append(F("error", "dkim.ed25519_key", f"{name}: ed25519 p= must be a 32-byte raw key, got {len(raw)} bytes"))
        else:
            fs.append(F("info", "dkim.ed25519_key", f"{name}: ed25519 key; also publish an RSA key, many receivers do not verify ed25519"))
        return info, fs
    if k != "rsa":
        fs.append(F("error", "dkim.unknown_k", f"{name}: unknown key type k={k}"))
        return info, fs
    try:
        bits = info["bits"] = rsa_bits(t["p"])
    except Exception as e:
        fs.append(F("error", "dkim.bad_key", f"{name}: p= is not a decodable RSA public key ({type(e).__name__})"))
        return info, fs
    if bits < R.value("dkim.min_rsa_bits"):
        fs.append(F("error", "dkim.min_rsa_bits", f"{name}: RSA {bits}-bit key; signers MUST use at least 1024 bits and verifiers may reject it", bits=bits))
    elif bits < R.value("dkim.recommended_rsa_bits"):
        fs.append(F("warning", "dkim.recommended_rsa_bits", f"{name}: RSA {bits}-bit key; 2048 bits SHOULD be used", bits=bits))
    return info, fs


def check(domain, res, R, options=None):
    options = options or {}
    user = [s.strip() for s in options.get("dkim_selectors") or [] if s.strip()]
    common = list(R.value("dkim.common_selectors")) if options.get("probe_common", True) else []
    sels = list(dict.fromkeys(user + common))
    keys, fs, errors = [], [], []
    for sel in sels:
        name = f"{sel}._domainkey.{domain}"
        txts, st = res.query(name, "TXT")
        if st.startswith("error"):
            errors.append(name)
            if sel in user:
                fs.append(R.finding(NAME, "warning", "dkim.dns_error", f"{name}: DNS error {st}", selector=name))
            continue
        recs = [x for x in txts if "p=" in x.replace(" ", "") or x.startswith("v=DKIM1")]
        if sel not in user:
            # probed names often hit wildcard TXT (e.g. a DMARC or SPF record); only
            # judge records that look like DKIM keys (v=DKIM… or no v= tag at all)
            recs = [x for x in recs if x.replace(" ", "").startswith("v=DKIM") or not x.lstrip().startswith("v=")]
        if not recs:
            if sel in user:
                fs.append(R.finding(NAME, "error", "dkim.no_key", f"{name}: selector you sign with has no key record", selector=name))
            continue
        if len(recs) > 1:
            fs.append(R.finding(NAME, "error", "dkim.syntax", f"{name}: {len(recs)} key records; verifiers may pick either", selector=name))
        info, f2 = analyse_key(name, recs[0], R)
        info["selector"] = sel
        keys.append(info); fs += f2
    if not keys:
        fs.append(R.finding(NAME, "info", "dkim.not_found",
                            f"no DKIM key at {len(sels)} common selectors; selectors can't be listed from DNS, give yours with --dkim-selector"))
    usable = [k["selector"] for k in keys if not k["revoked"] and not k["testing"] and k["bits"]
              and (k["k"] == "ed25519" or k["bits"] >= R.value("dkim.min_rsa_bits"))]
    return result(NAME, domain, fs, {"probed": len(sels), "keys": keys, "usable_selectors": usable,
                                     "min_rsa_bits": min([k["bits"] for k in keys if k["k"] == "rsa" and k["bits"]] or [0]) or None,
                                     "dns_errors": errors})
