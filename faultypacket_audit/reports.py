"""Offline DMARC aggregate (RFC 7489 7.2, Appendix C) and TLS-RPT (RFC 8460 4)
report reader (RFC 9990 is the current aggregate-report spec): ``faultypacket-audit reports FILE...``.

Everything is parsed locally. Nothing is uploaded or fetched. Accepts .xml,
.xml.gz/.gz, .zip (each member read) and .json/.json.gz TLS-RPT reports.
"""
import gzip, io, ipaddress, json, sys, zipfile
import xml.etree.ElementTree as ET

MAX_BYTES = 64 * 1024 * 1024  # decompressed cap per report (zip/gzip bomb guard)


class ReportError(ValueError):
    pass


def _cap(data):
    if len(data) > MAX_BYTES:
        raise ReportError("report larger than %d bytes after decompression" % MAX_BYTES)
    return data


def _gunzip(data):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
        out = g.read(MAX_BYTES + 1)
    return _cap(out)


def blobs(name, data):
    """-> [(name, bytes)] after unwrapping gzip/zip containers."""
    if data[:2] == b"\x1f\x8b":
        return blobs(name[:-3] if name.endswith(".gz") else name, _gunzip(data))
    if data[:4] == b"PK\x03\x04":
        out = []
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_BYTES:
                    raise ReportError(f"{info.filename}: member too large")
                with z.open(info) as f:
                    out += blobs(info.filename, _cap(f.read(MAX_BYTES + 1)))
        return out
    return [(name, _cap(data))]


def _t(el, path, default=""):
    v = el.find(path) if el is not None else None
    return (v.text or "").strip() if v is not None and v.text else default


def parse_dmarc(data):
    if b"<!DOCTYPE" in data[:4096].upper() or b"<!ENTITY" in data.upper():
        raise ReportError("DTDs/entities are not allowed in DMARC reports")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ReportError(f"XML: {e}") from None
    if root.tag.split("}")[-1] != "feedback":
        raise ReportError("not a DMARC aggregate report (root is not <feedback>)")
    for el in root.iter():  # drop namespaces (RFC 9990 aggregate reports declare one)
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    md, pp = root.find("report_metadata"), root.find("policy_published")
    rows = []
    for rec in root.findall("record"):
        row = rec.find("row")
        ip = _t(row, "source_ip")
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ReportError(f"bad source_ip {ip!r}") from None
        try:
            count = int(_t(row, "count", "0"))
        except ValueError:
            raise ReportError("bad count") from None
        if count < 0:
            raise ReportError("negative count")
        pe = row.find("policy_evaluated") if row is not None else None
        ar = rec.find("auth_results")
        dkim = [{"domain": _t(d, "domain").lower(), "selector": _t(d, "selector"), "result": _t(d, "result").lower()}
                for d in (ar.findall("dkim") if ar is not None else [])]
        spf = [{"domain": _t(s, "domain").lower(), "result": _t(s, "result").lower()}
               for s in (ar.findall("spf") if ar is not None else [])]
        rows.append({"source_ip": ip, "count": count,
                     "disposition": _t(pe, "disposition", "none").lower(),
                     "dkim_aligned": _t(pe, "dkim").lower() == "pass",
                     "spf_aligned": _t(pe, "spf").lower() == "pass",
                     "header_from": _t(rec, "identifiers/header_from").lower() or _t(pp, "domain").lower(),
                     "dkim": dkim, "spf": spf})
    return {"type": "dmarc", "org_name": _t(md, "org_name"), "report_id": _t(md, "report_id"),
            "begin": _t(md, "date_range/begin"), "end": _t(md, "date_range/end"),
            "policy_domain": _t(pp, "domain").lower(), "policy": _t(pp, "p"), "records": rows}


def parse_tlsrpt(data):
    try:
        return _parse_tlsrpt(data)
    except (TypeError, AttributeError, ValueError) as e:
        if isinstance(e, ReportError):
            raise
        raise ReportError(f"TLS-RPT: malformed field ({e})") from None


def _parse_tlsrpt(data):
    try:
        j = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ReportError(f"JSON: {e}") from None
    if not isinstance(j, dict) or not isinstance(j.get("policies"), list):
        raise ReportError("not a TLS-RPT report (no policies list)")
    pols = []
    for p in j["policies"]:
        if not isinstance(p, dict):
            raise ReportError("policy entry is not an object")
        pol, s = p.get("policy") or {}, p.get("summary") or {}
        fails = []
        for f in p.get("failure-details") or []:
            if isinstance(f, dict):
                fails.append({"result_type": str(f.get("result-type", "")),
                              "sending_mta_ip": str(f.get("sending-mta-ip", "")),
                              "receiving_mx": str(f.get("receiving-mx-hostname", "")),
                              "count": int(f.get("failed-session-count", 0) or 0)})
        pols.append({"policy_type": str(pol.get("policy-type", "")), "policy_domain": str(pol.get("policy-domain", "")).lower(),
                     "success": int(s.get("total-successful-session-count", 0) or 0),
                     "failure": int(s.get("total-failure-session-count", 0) or 0), "failures": fails})
    dr = j.get("date-range") or {}
    return {"type": "tlsrpt", "org_name": str(j.get("organization-name", "")), "report_id": str(j.get("report-id", "")),
            "begin": str(dr.get("start-datetime", "")), "end": str(dr.get("end-datetime", "")), "policies": pols}


def parse_bytes(name, data):
    out = []
    for n, b in blobs(name, data):
        s = b.lstrip()
        if s.startswith(b"\xef\xbb\xbf"):
            s = s[3:].lstrip()
        if s[:1] == b"{":
            out.append(parse_tlsrpt(s))
        elif s[:1] == b"<":
            out.append(parse_dmarc(s))
        else:
            raise ReportError(f"{n}: neither XML nor JSON")
    return out


def _bucket():
    return {"messages": 0, "spf_pass": 0, "spf_fail": 0, "dkim_pass": 0, "dkim_fail": 0,
            "dmarc_pass": 0, "dmarc_fail": 0, "spf_aligned": 0, "dkim_aligned": 0, "quarantined": 0, "rejected": 0}


def summarise(reports):
    by_ip, by_dom, tls = {}, {}, {}
    n_dmarc = n_tls = 0
    for r in reports:
        if r["type"] == "tlsrpt":
            n_tls += 1
            for p in r["policies"]:
                t = tls.setdefault(p["policy_domain"], {"success": 0, "failure": 0, "result_types": {}})
                t["success"] += p["success"]
                t["failure"] += p["failure"]
                for f in p["failures"]:
                    t["result_types"][f["result_type"]] = t["result_types"].get(f["result_type"], 0) + f["count"]
            continue
        n_dmarc += 1
        for row in r["records"]:
            c = row["count"]
            spf_ok = any(s["result"] == "pass" for s in row["spf"])
            dkim_ok = any(d["result"] == "pass" for d in row["dkim"])
            aligned = row["dkim_aligned"] or row["spf_aligned"]
            for b in (by_ip.setdefault(row["source_ip"], dict(_bucket(), domains=set())),
                      by_dom.setdefault(row["header_from"], _bucket())):
                b["messages"] += c
                b["spf_pass" if spf_ok else "spf_fail"] += c
                b["dkim_pass" if dkim_ok else "dkim_fail"] += c
                b["dmarc_pass" if aligned else "dmarc_fail"] += c
                b["spf_aligned"] += c if row["spf_aligned"] else 0
                b["dkim_aligned"] += c if row["dkim_aligned"] else 0
                b["quarantined"] += c if row["disposition"] == "quarantine" else 0
                b["rejected"] += c if row["disposition"] == "reject" else 0
            by_ip[row["source_ip"]]["domains"].add(row["header_from"])
    for b in by_ip.values():
        b["domains"] = sorted(b["domains"])
    failing = [{"source_ip": ip, **b} for ip, b in sorted(by_ip.items()) if b["dmarc_fail"]]
    unauth = [f["source_ip"] for f in failing if f["dmarc_pass"] == 0]
    total = sum(b["messages"] for b in by_dom.values())
    return {"dmarc_reports": n_dmarc, "tlsrpt_reports": n_tls, "messages": total,
            "dmarc_pass": sum(b["dmarc_pass"] for b in by_dom.values()),
            "by_source_ip": dict(sorted(by_ip.items())), "by_domain": dict(sorted(by_dom.items())),
            "failing_senders": failing, "unauthorised_senders": unauth, "tls": dict(sorted(tls.items()))}


def _pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "n/a"


def markdown(s):
    L = ["# DMARC and TLS-RPT report summary", "",
         f"{s['dmarc_reports']} DMARC aggregate report(s), {s['tlsrpt_reports']} TLS-RPT report(s), "
         f"{s['messages']} message(s); DMARC pass {_pct(s['dmarc_pass'], s['messages'])}.", "",
         "Parsed locally; nothing was uploaded.", ""]
    hdr = "| {} | Messages | SPF pass | DKIM pass | Aligned (DMARC pass) | Fail |"
    for title, key, col in (("By sending domain", "by_domain", "Domain"), ("By source IP", "by_source_ip", "Source IP")):
        if s[key]:
            L += [f"## {title}", "", hdr.format(col), "|---|---:|---:|---:|---:|---:|"]
            for k, b in s[key].items():
                L.append(f"| {k} | {b['messages']} | {_pct(b['spf_pass'], b['messages'])} | {_pct(b['dkim_pass'], b['messages'])} "
                         f"| {_pct(b['dmarc_pass'], b['messages'])} | {b['dmarc_fail']} |")
            L.append("")
    if s["failing_senders"]:
        L += ["## Failing senders", "", "Sources with messages that failed DMARC (no aligned SPF or DKIM pass). "
              "Those marked unauthorised never passed; check whether they are yours before authorising them.", ""]
        for f in s["failing_senders"]:
            tag = " **unauthorised**" if f["source_ip"] in s["unauthorised_senders"] else ""
            L.append(f"- {f['source_ip']}{tag}: {f['dmarc_fail']} of {f['messages']} failed ({', '.join(f['domains'])})")
        L.append("")
    if s["tls"]:
        L += ["## TLS-RPT", "", "| Policy domain | Successful sessions | Failed sessions | Failure types |", "|---|---:|---:|---|"]
        for d, t in s["tls"].items():
            ft = ", ".join(f"{k} ({v})" for k, v in sorted(t["result_types"].items())) or "none"
            L.append(f"| {d} | {t['success']} | {t['failure']} | {ft} |")
        L.append("")
    return "\n".join(L)


def main(argv, stdin=None, stdout=None, stderr=None):
    import argparse
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    p = argparse.ArgumentParser(prog="faultypacket-audit reports",
                                description="Summarise DMARC aggregate (RFC 7489) and TLS-RPT (RFC 8460) reports locally. "
                                            "Accepts .xml, .gz, .zip and .json; nothing is uploaded.")
    p.add_argument("files", nargs="+", help="report files")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("-o", "--output", metavar="FILE", help="write here instead of stdout")
    p.add_argument("--fail-on-unauthorised", action="store_true", help="exit 1 if any source never passed DMARC")
    a = p.parse_args(argv)
    reports, bad = [], 0
    for path in a.files:
        try:
            with open(path, "rb") as f:
                reports += parse_bytes(path, f.read(MAX_BYTES + 1))
        except (OSError, ReportError, zipfile.BadZipFile, EOFError, gzip.BadGzipFile) as e:
            print(f"{path}: {e}", file=stderr)
            bad += 1
    s = summarise(reports)
    text = json.dumps(s, indent=2) if a.format == "json" else markdown(s)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text, file=stdout)
    if bad and not reports:
        return 2
    return 1 if (a.fail_on_unauthorised and s["unauthorised_senders"]) or bad else 0
