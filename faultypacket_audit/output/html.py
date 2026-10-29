"""Self-contained HTML report (no external CSS, fonts, scripts or images).
Prints cleanly to PDF from any browser (File > Print > Save as PDF).
Input: the JSON-able reports (output.jsonout.to_jsonable)."""
from html import escape as E

SEV = {"error": 0, "warning": 1, "unverified": 2, "info": 3}
CSS = """
body{font:14px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#111;max-width:980px;margin:24px auto;padding:0 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;border-bottom:2px solid #111;padding-bottom:3px;margin-top:28px}
h3{font-size:15px;margin:18px 0 6px}table{border-collapse:collapse;width:100%;margin:6px 0 12px}
th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eee}
.error{color:#a40000;font-weight:600}.warning{color:#8a5a00;font-weight:600}.unverified{color:#555}.info{color:#245}
.ok,.pass{color:#0a6b20;font-weight:600}.fail{color:#a40000;font-weight:600}
code,pre{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;background:#f4f4f4}pre{padding:6px;white-space:pre-wrap;word-break:break-all}
.meta{color:#555;font-size:12px}.cite{font-size:12px;color:#333}a{color:#0645ad}
@media print{body{margin:0;max-width:none}h2{page-break-after:avoid}tr,pre{page-break-inside:avoid}a{color:#000}
.domain{page-break-before:always}.domain:first-of-type{page-break-before:auto}}
"""


def _href(u):
    u = str(u or "")
    return E(u) if u.startswith(("https://", "http://")) else ""


def _summary(reports):
    rows = []
    for r in reports:
        counts = {}
        for c in r["checks"]:
            for f in c["findings"]:
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        rows.append((r["domain"], r["status"], counts.get("error", 0), counts.get("warning", 0), len(r.get("fixes", []))))
    return rows


def render(reports, version, title="Email and DNS security audit"):
    when = reports[0]["checked_at_utc"] if reports else ""
    rv = reports[0]["rules_version"] if reports else ""
    out = ["<!doctype html><html lang=en><meta charset=utf-8>",
           "<meta name=viewport content='width=device-width,initial-scale=1'>",
           f"<title>{E(title)}</title><style>{CSS}</style><body>",
           f"<h1>{E(title)}</h1><p class=meta>faultypacket-audit {E(version)} &middot; rules {E(rv)} &middot; "
           f"checked {E(when)} (UTC) &middot; every finding cites its source</p>",
           "<h2>Executive summary</h2><table><tr><th>Domain</th><th>Status</th><th>Errors</th><th>Warnings</th><th>Suggested fixes</th></tr>"]
    for d, st, e, w, fx in _summary(reports):
        out.append(f"<tr><td><a href='#d-{E(d)}'>{E(d)}</a></td><td class={E(st)}>{E(st)}</td><td>{e}</td><td>{w}</td><td>{fx}</td></tr>")
    out.append("</table>")
    tot_e = sum(x[2] for x in _summary(reports))
    tot_w = sum(x[3] for x in _summary(reports))
    out.append(f"<p>{len(reports)} domain(s) checked: {tot_e} error(s), {tot_w} warning(s). Errors break a standard "
               "(MUST) or a mailbox-provider requirement; warnings are SHOULD-level. Info findings are listed per domain.</p>")
    for r in reports:
        out.append(f"<section class=domain id='d-{E(r['domain'])}'><h2>{E(r['domain'])} &mdash; <span class={E(r['status'])}>{E(r['status'])}</span></h2>")
        bulk = next((c for c in r["checks"] if c["check"] == "bulk-sender"), None)
        if bulk and bulk["data"].get("providers"):
            out.append("<h3>Mailbox-provider verdicts</h3><table><tr><th>Provider</th><th>Verdict</th><th>Requirement</th><th>Status</th><th>Detail</th></tr>")
            for p in bulk["data"]["providers"]:
                reqs = p.get("requirements", [])
                for i, q in enumerate(reqs):
                    head = (f"<td rowspan={len(reqs)}><a href='{_href(p.get('url'))}'>{E(p['provider'])}</a><br>"
                            f"<span class=meta>effective {E(str(p.get('effective', '')))}</span></td>"
                            f"<td rowspan={len(reqs)} class={E(str(p.get('verdict', '')).split()[0] if p.get('verdict') else '')}>{E(str(p.get('verdict', '')))}</td>") if i == 0 else ""
                    out.append(f"<tr>{head}<td>{E(q['requirement'])} ({E(q['audience'])})</td><td>{E(q['status'])}</td><td>{E(q.get('detail', ''))}</td></tr>")
            out.append("</table>")
        fs = sorted(((c["check"], f) for c in r["checks"] for f in c["findings"]), key=lambda x: (SEV.get(x[1]["severity"], 9), x[0]))
        out.append("<h3>Findings</h3>")
        if not fs:
            out.append("<p>No findings.</p>")
        else:
            out.append("<table><tr><th>Severity</th><th>Check</th><th>Finding</th><th>Source</th></tr>")
            for chk, f in fs:
                src = E(f.get("citation", ""))
                if _href(f.get("url")):
                    src = f"<a href='{E(f['url'])}'>{src}</a>"
                out.append(f"<tr><td class={E(f['severity'])}>{E(f['severity'])}</td><td>{E(chk)}</td><td>{E(f['message'])}"
                           f"<br><code>{E(f['rule_id'])}</code></td><td class=cite>{src}<br>{E(f.get('level', ''))}</td></tr>")
            out.append("</table>")
        fixes = r.get("fixes") or []
        out.append("<h3>Suggested fixes</h3>")
        if not fixes:
            out.append("<p>None.</p>")
        for x in fixes:
            out.append(f"<p><b>{E(x['type'])}</b> <code>{E(x['name'])}</code> <span class=meta>(answers {E(x['rule_id'])})</span></p>"
                       f"<pre>{E(x['value'])}</pre><p class=cite>{E(x['note'])}</p>")
        out.append("<p class=meta>Values starting REPLACE- are yours to fill in. Check every change before publishing it.</p></section>")
    out.append("<p class=meta>Generated by faultypacket-audit (AGPL-3.0-or-later), https://github.com/FaultyPacket/faultypacket-audit</p></body></html>")
    return "\n".join(out)


def to_pdf(reports, version, path):
    """Optional: needs the pure-Python fpdf2 package (pip install 'faultypacket-audit[pdf]').
    Plain-text layout; for a styled PDF print the HTML report instead."""
    try:
        from fpdf import FPDF
    except ImportError as e:
        raise RuntimeError("PDF output needs fpdf2: pip install fpdf2 (or print the --html report to PDF)") from e

    def t(s):
        return str(s).replace("\u2014", "-").replace("\u2013", "-").replace("\u2019", "'").replace("\u2018", "'") \
            .replace("\u201c", '"').replace("\u201d", '"').replace("\u00a3", "GBP ").encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 8, t("Email and DNS security audit"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    if reports:
        pdf.multi_cell(0, 5, t(f"faultypacket-audit {version} - rules {reports[0]['rules_version']} - checked {reports[0]['checked_at_utc']} UTC"),
                       new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 12)
    pdf.multi_cell(0, 7, "Executive summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for d, st, e, w, fx in _summary(reports):
        pdf.multi_cell(0, 5, t(f"{d}: {st} - {e} error(s), {w} warning(s), {fx} suggested fix(es)"), new_x="LMARGIN", new_y="NEXT")
    for r in reports:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.multi_cell(0, 7, t(f"{r['domain']} - {r['status']}"), new_x="LMARGIN", new_y="NEXT")
        bulk = next((c for c in r["checks"] if c["check"] == "bulk-sender"), None)
        if bulk and bulk["data"].get("providers"):
            pdf.set_font("Helvetica", "B", 11)
            pdf.multi_cell(0, 6, "Mailbox-provider verdicts", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for p in bulk["data"]["providers"]:
                pdf.multi_cell(0, 5, t(f"{p['provider']}: {p.get('verdict', '')}  ({p.get('url', '')})"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(0, 6, "Findings", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for c in r["checks"]:
            for f in sorted(c["findings"], key=lambda f: SEV.get(f["severity"], 9)):
                pdf.multi_cell(0, 4.5, t(f"[{f['severity']}] {c['check']}: {f['message']}  -- {f.get('citation', '')} {f.get('url', '')} ({f['rule_id']})"),
                               new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(0, 6, "Suggested fixes", new_x="LMARGIN", new_y="NEXT")
        for x in r.get("fixes") or []:
            pdf.set_font("Helvetica", "B", 9)
            pdf.multi_cell(0, 4.5, t(f"{x['type']} {x['name']} ({x['rule_id']})"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4, t(x["value"]), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 4, t(x["note"]), new_x="LMARGIN", new_y="NEXT")
    pdf.output(path)
