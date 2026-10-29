"""Fake resolver used by the audit-level tests."""
from tests.keys import RSA2048


class Zone:
    """records: {(name, rtype): list | 'err'}; missing -> void."""
    servers = ["fake"]

    def __init__(self, records):
        self.z, self.asked = {(k[0].lower(), k[1]): v for k, v in records.items()}, []

    def query_ad(self, name, rtype):
        """AD bit: True for names listed in self.secure (zone 'validates')."""
        v, st = self.query(name, rtype)
        n = name.lower().rstrip(".")
        return v, st, any(n == s or n.endswith("." + s) for s in getattr(self, "secure", ()))

    def query(self, name, rtype):
        self.asked.append((name, rtype))
        v = self.z.get((name.lower().rstrip("."), rtype))
        if v == "err":
            return [], "error:Timeout"
        return (list(v), "ok") if v else ([], "void")


GOOD = {
    ("good.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
    ("_dmarc.good.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@good.test"],
    ("s1._domainkey.good.test", "TXT"): ["v=DKIM1; k=rsa; p=" + RSA2048],
    ("10.2.0.192.in-addr.arpa", "PTR"): ["mail.good.test."],
    ("mail.good.test", "A"): ["192.0.2.10"],
}
