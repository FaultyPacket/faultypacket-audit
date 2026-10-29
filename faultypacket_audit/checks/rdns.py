"""Reverse DNS / forward-confirmed reverse DNS for supplied IPs (--sending-ip)
and the domain's MX hosts. Receivers widely require it; RFC 1912 2.1 asks
for matching PTR and A records."""
import ipaddress

from ._common import mx_hosts, result
from .bulk_sender import fcrdns

NAME = "rdns"


def check(domain, res, R, options=None):
    options = options or {}
    fs, rows = [], []
    targets = [("sending-ip", ip) for ip in options.get("sending_ips") or []]
    mx, _ = mx_hosts(domain, res)
    for _, host in (mx or [])[:5]:
        if host in ("", "."):
            continue
        for ip in (res.query(host, "A")[0] + res.query(host, "AAAA")[0])[:2]:
            targets.append((f"mx {host}", ip))
    for src, ip in targets:
        st, detail = fcrdns(ip, res)
        rows.append({"source": src, "ip": ip, "status": st, "detail": detail})
        if st == "fail":
            sev = "error" if src == "sending-ip" else "warning"
            fs.append(R.finding(NAME, sev, "rdns.fcrdns", f"{src}: {detail}", ip=ip))
        elif st == "unknown":
            fs.append(R.finding(NAME, "info", "rdns.dns_error", f"{src}: {detail}", ip=ip))
    if not targets:
        fs.append(R.finding(NAME, "info", "rdns.no_targets", "no sending IPs given and no MX addresses; pass --sending-ip to test your outbound IPs"))
    return result(NAME, domain, fs, {"targets": rows})
