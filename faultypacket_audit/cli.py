"""faultypacket-audit command line."""
import argparse, sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .audit import audit, ORDER, ALL, now_utc
from .core.finding import rank
from .core.inputs import collect
from .core.resolver import Cached, Resolver, DEFAULT_DOH
from .core.rules import load_rules, RulesError
from .output import csvout, diff as diffout, jsonout, sarif, text


def _write(path, data, stdout):
    if path == "-":
        stdout.write(data)
    else:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(data)


def _line_numbers(files):
    """domain -> first line number in the first input file (for SARIF)."""
    from .core.inputs import extract_domain
    out = {}
    for f in files or []:
        if f == "-":
            continue
        with open(f, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                s = line.split("#", 1)[0].strip()
                try:
                    out.setdefault(extract_domain(s), n)
                except ValueError:
                    pass
        break
    return out


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    p = argparse.ArgumentParser(prog="faultypacket-audit",
        description="Cited mail/DNS security audit: SPF, DMARC (RFC 9989), DKIM, MX, MTA-STS/TLS-RPT, "
                    "DNSSEC, DANE, CAA, reverse DNS, BIMI, and Google/Yahoo/Outlook sender requirements that DNS can show.")
    p.add_argument("domains", nargs="*", help="domains, URLs or email addresses")
    p.add_argument("-f", "--file", action="append", help="file with one input per line ('-' = stdin); repeatable")
    p.add_argument("--checks", default=",".join(ORDER), help="comma list from: " + ", ".join(ALL) + " (default: all except the opt-in blocklist, lookalike, security-txt)")
    p.add_argument("--json", metavar="FILE", help="write JSON ('-' = stdout)")
    p.add_argument("--csv", metavar="FILE", help="write CSV, one row per finding ('-' = stdout)")
    p.add_argument("--html", metavar="FILE", help="write a self-contained HTML report (prints to PDF from a browser)")
    p.add_argument("--pdf", metavar="FILE", help="write a PDF report (needs the optional fpdf2 package: pip install 'faultypacket-audit[pdf]')")
    p.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 ('-' = stdout)")
    p.add_argument("--sarif-artifact", default=None, help="file path SARIF results point at (default: first -f file, else domains.txt)")
    p.add_argument("--sarif-info", action="store_true", help="include info findings in SARIF")
    p.add_argument("--rules", help="use this rules.json instead of the bundled one")
    p.add_argument("--resolver", help="nameserver IP (port 53)")
    p.add_argument("--doh", action="store_true", help="use DNS-over-HTTPS JSON API instead of port 53")
    p.add_argument("--doh-url", default=DEFAULT_DOH, help="DoH JSON endpoint (default %(default)s)")
    p.add_argument("--timeout", type=float, default=5.0, help="per-query timeout, seconds (default 5)")
    p.add_argument("-c", "--concurrency", type=int, default=4, help="domains in parallel (default 4, max 32)")
    p.add_argument("--sending-ip", action="append", default=[], help="rdns/bulk-sender: an IP you send from (FCrDNS check); repeatable")
    p.add_argument("--dkim-selector", action="append", default=[], help="dkim/bulk-sender: a DKIM selector you sign with (added to the common-selector probe); repeatable")
    p.add_argument("--bulk", action="store_true", help="you send 5,000+ a day: bulk-only requirement failures are errors, not warnings")
    p.add_argument("--smtp", action="store_true", help="mta-sts: probe each MX on port 25 (STARTTLS + certificate); reported as 'not tested' where port 25 is blocked")
    p.add_argument("--validating-resolver", action="store_true", help="dnssec: treat --resolver as DNSSEC-validating (a missing AD bit is then an error); implied by --doh")
    p.add_argument("--baseline", metavar="FILE", help="previous --json output; report what changed since then")
    p.add_argument("--diff", metavar="FILE", help="write the change report (Markdown) here ('-' = stdout); needs --baseline")
    p.add_argument("--fail-on-new", action="store_true", help="with --baseline: exit 1 only for new or worsened warnings/errors")
    p.add_argument("--fail-on", choices=["error", "warning"], default="error", help="exit 1 at this severity or worse (default error)")
    p.add_argument("-v", "--verbose", action="store_true", help="show info findings in the text report")
    p.add_argument("-q", "--quiet", action="store_true", help="summary table only")
    p.add_argument("--version", action="version", version=f"faultypacket-audit {__version__}")
    a = p.parse_args(argv)
    checks = [c.strip() for c in a.checks.split(",") if c.strip()]
    unknown = [c for c in checks if c not in ALL]
    if unknown or not checks:
        p.error(f"unknown check(s): {', '.join(unknown) or '(none)'}; choose from {', '.join(ALL)}")
    if not 1 <= a.concurrency <= 32:
        p.error("--concurrency must be 1..32")
    try:
        rules = load_rules(a.rules)
    except (OSError, ValueError, RulesError) as e:
        p.error(f"rules: {e}")
    try:
        domains, bad = collect(a.domains, a.file, stdin, auto_stdin=not a.domains and not a.file)
    except OSError as e:
        p.error(str(e))
    for b in bad:
        print(f"skipped input {b['input']!r}: {b['error']}", file=stderr)
    if not domains:
        p.error("no valid domains given")
    res = Cached(Resolver(a.resolver, a.timeout, a.doh_url if a.doh else None))
    opts = {"sending_ips": a.sending_ip, "dkim_selectors": a.dkim_selector, "bulk": a.bulk,
            "smtp": a.smtp, "validating_resolver": a.validating_resolver, "timeout": max(a.timeout, 5.0)}
    if a.diff and not a.baseline:
        p.error("--diff needs --baseline")

    def one(d):
        try:
            return audit(d, res, rules, checks, opts)
        except Exception as e:     # per-domain isolation (audit already isolates checks)
            f = rules.finding("core", "error", "core.internal", f"{type(e).__name__}: {e}")
            return {"domain": d, "checked_at_utc": now_utc(), "rules_version": rules.version,
                    "resolvers": res.servers, "status": "error",
                    "checks": [{"check": "core", "domain": d, "data": {}, "findings": [f], "status": "error"}]}

    with ThreadPoolExecutor(max_workers=min(a.concurrency, len(domains))) as ex:
        reports = list(ex.map(one, domains))
    to_stdout = "-" in (a.json, a.csv, a.sarif, a.html)
    human = stderr if to_stdout else stdout
    if not a.quiet:
        print(text.render(reports, a.verbose), file=human)
    print(text.summary(reports), file=human)
    print(f"checked {reports[0]['checked_at_utc']} via {','.join(res.servers)}; rules {rules.version}", file=human)
    if a.json:
        _write(a.json, jsonout.dumps(reports, __version__), stdout)
    if a.csv:
        _write(a.csv, csvout.dumps(reports), stdout)
    if a.html:
        from .output import html as htmlout
        _write(a.html, htmlout.render(jsonout.to_jsonable(reports, __version__), __version__), stdout)
    if a.pdf:
        from .output import html as htmlout
        try:
            htmlout.to_pdf(jsonout.to_jsonable(reports, __version__), __version__, a.pdf)
        except RuntimeError as e:
            print(f"--pdf: {e}", file=stderr)
            return 2
    if a.sarif:
        art = a.sarif_artifact or next((f for f in (a.file or []) if f != "-"), "domains.txt")
        _write(a.sarif, sarif.dumps(reports, rules, __version__, artifact=art,
                                    lines=_line_numbers(a.file), include_info=a.sarif_info), stdout)
    change = None
    if a.baseline:
        try:
            base = diffout.load(a.baseline)
        except (OSError, ValueError) as e:
            print(f"baseline {a.baseline!r} unreadable ({e}); treating every finding as new", file=stderr)
            base = []
        change = diffout.compare(base, jsonout.to_jsonable(reports, __version__), a.fail_on)
        md = diffout.markdown(change)
        if a.diff:
            _write(a.diff, md, stdout)
        else:
            print(md, file=human)
    if a.fail_on_new and change is not None:
        return 1 if (diffout.has_regression(change) or bad) else 0
    threshold = rank(a.fail_on)
    failed = any(rank(r["status"]) >= threshold for r in reports)
    return 1 if (failed or bad) else 0


def entry():
    if sys.argv[1:2] == ["mcp"]:
        from .mcp import serve
        sys.exit(serve(sys.argv[2:]))
    if sys.argv[1:2] == ["headers"]:
        from .headers import main as hmain
        sys.exit(hmain(sys.argv[2:], sys.stdin, sys.stdout, sys.stderr))
    if sys.argv[1:2] == ["analyse"]:  # headers + DKIM re-verification
        from .headers import main as hmain
        sys.exit(hmain(sys.argv[2:], sys.stdin, sys.stdout, sys.stderr, prog="analyse", verify_default=True))
    for name, mod in (("reports", "reports"), ("alert", "alerts"), ("spf-drift", "spfdrift")):
        if sys.argv[1:2] == [name]:
            import importlib
            m = importlib.import_module(f".{mod}", __package__)
            sys.exit(m.main(sys.argv[2:], sys.stdin, sys.stdout, sys.stderr))
    sys.exit(main())


if __name__ == "__main__":
    entry()
