"""DNS access shared by every check.

query(name, rtype) -> (values, status)
  status: "ok" | "void" | "error:<why>"
  void  = NXDOMAIN or NOERROR with no answer of the asked type
          (the RFC 7208 4.6.4 meaning; other checks treat it as "absent").
TXT values come back with their character-strings concatenated.
"""
import json, threading, urllib.parse, urllib.request

import dns.exception, dns.flags, dns.resolver

DOH_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
             "AAAA": 28, "DS": 43, "DNSKEY": 48, "TLSA": 52, "CAA": 257}
DEFAULT_DOH = "https://cloudflare-dns.com/dns-query"


def parse_txt_presentation(s):
    """Concatenate the character-strings of one TXT RR in presentation form
    ('"v=spf1 a" " -all"'), handling backslash escapes. Unquoted -> as is."""
    s = s.strip()
    if not s.startswith('"'):
        return s
    out, i, inq = [], 0, False
    while i < len(s):
        c = s[i]
        if c == '"':
            inq = not inq
        elif inq and c == "\\" and i + 1 < len(s):
            if s[i + 1:i + 4].isdigit() and len(s[i + 1:i + 4]) == 3:
                out.append(chr(int(s[i + 1:i + 4]))); i += 3
            else:
                out.append(s[i + 1]); i += 1
        elif inq:
            out.append(c)
        i += 1
    return "".join(out)


def _ad_of(exc):
    try:
        resp = exc.response() if callable(getattr(exc, "response", None)) else exc.kwargs.get("response")
        if resp is None and exc.kwargs.get("responses"):
            resp = next(iter(exc.kwargs["responses"].values()))
        return bool(resp.flags & dns.flags.AD)
    except Exception:
        return False


class Resolver:
    """System/explicit nameserver on port 53, or a DNS-over-HTTPS JSON API."""

    def __init__(self, nameserver=None, timeout=5.0, doh=None):
        self.doh, self.timeout = doh, timeout
        self.r = dns.resolver.Resolver()
        if nameserver:
            self.r.nameservers = [nameserver]
        self.r.lifetime = timeout

    @property
    def servers(self):
        return [self.doh] if self.doh else list(self.r.nameservers)

    def query(self, name, rtype):
        return self._doh(name, rtype) if self.doh else self._dns(name, rtype)[:2]

    def query_ad(self, name, rtype):
        """-> (values, status, ad). ad is True only when the resolver set the
        Authenticated Data bit (RFC 4035 3.2.3), i.e. it validated the answer.
        Only meaningful when the resolver itself validates (e.g. the default
        DoH endpoint); a non-validating port-53 resolver always gives False."""
        return self._doh(name, rtype, want_ad=True) if self.doh else self._dns(name, rtype, want_ad=True)

    def _dns(self, name, rtype, want_ad=False):
        r = self.r
        if want_ad:     # separate resolver object: DO bit + AD request (RFC 6840 5.7)
            r = dns.resolver.Resolver()
            r.nameservers, r.lifetime = self.r.nameservers, self.r.lifetime
            r.use_edns(0, dns.flags.DO, 1232)
            r.flags = dns.flags.RD | dns.flags.AD
        try:
            ans = r.resolve(name, rtype)
        except dns.resolver.NXDOMAIN as e:
            return [], "void", _ad_of(e) if want_ad else False
        except dns.resolver.NoAnswer as e:
            return [], "void", _ad_of(e) if want_ad else False
        except dns.exception.DNSException as e:
            return [], "error:" + type(e).__name__, False
        ad = bool(ans.response.flags & dns.flags.AD) if want_ad else False
        if rtype == "TXT":
            return [b"".join(x.strings).decode("utf-8", "replace") for x in ans], "ok", ad
        return [x.to_text() for x in ans], "ok", ad

    def _doh(self, name, rtype, want_ad=False):
        q = {"name": name, "type": rtype}
        if want_ad:
            q["do"] = "1"
        url = self.doh + "?" + urllib.parse.urlencode(q)
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as f:
                j = json.load(f)
        except Exception as e:
            r = [], "error:" + type(e).__name__
            return r + (False,) if want_ad else r
        ad = bool(j.get("AD"))
        if j.get("Status") == 3:
            r = [], "void"
        elif j.get("Status") != 0:
            r = [], f"error:rcode{j.get('Status')}"
        else:
            data = [a["data"] for a in j.get("Answer", []) or [] if a.get("type") == DOH_TYPES[rtype]]
            if rtype == "TXT":
                data = [parse_txt_presentation(d) for d in data]
            r = (data, "ok") if data else ([], "void")
        return r + (ad,) if want_ad else r


class Cached:
    """Per-run cache in front of any resolver (Tree Walks and the bulk-sender
    verdict repeat queries). Thread-safe; errors are cached too, so one run
    sees one consistent answer per name."""

    def __init__(self, res):
        self.res, self.c, self.lock = res, {}, threading.Lock()

    @property
    def servers(self):
        return self.res.servers

    def query(self, name, rtype):
        k = (name.lower().rstrip("."), rtype)
        with self.lock:
            if k in self.c:
                return self.c[k]
        v = self.res.query(name, rtype)
        with self.lock:
            self.c.setdefault(k, v)
        return v

    def query_ad(self, name, rtype):
        """Validated-answer query; resolvers without query_ad report ad=False."""
        k = (name.lower().rstrip("."), rtype, "ad")
        with self.lock:
            if k in self.c:
                return self.c[k]
        f = getattr(self.res, "query_ad", None)
        v = f(name, rtype) if f else self.res.query(name, rtype) + (False,)
        with self.lock:
            self.c.setdefault(k, v)
        return v
