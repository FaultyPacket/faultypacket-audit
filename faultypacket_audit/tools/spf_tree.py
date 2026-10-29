"""spf-tree compatible CLI on top of faultypacket_audit.checks.spf.
Kept so spf-tree users (and its 73-test suite) keep working:
    python -m faultypacket_audit.tools.spf_tree example.com
"""
import argparse, csv, datetime as dt, json, sys
from concurrent.futures import ThreadPoolExecutor

from ..core.resolver import Resolver, parse_txt_presentation   # noqa: F401 (re-exported)
from ..core.inputs import extract_domain, read_lines, collect   # noqa: F401
from ..checks.spf import (analyse, get_spf, parse_term, LOOKUP_LIMIT, VOID_LIMIT)  # noqa: F401

__version__ = "1.0.0"   # spf-tree output compatibility; package version is faultypacket_audit.__version__


# ------------------------------------------------------------------- output
def render(node, indent=0, out=None):
    out = [] if out is None else out
    pad = "  " * indent
    q = "" if node["qualifier"] == "+" else " " + node["qualifier"]
    bits = [f"lookups: {node['lookups_subtree']}"]
    if node.get("duplicate"):
        bits.append("DUPLICATE")
    if node.get("error"):
        bits.append("ERROR: " + node["error"])
    out.append(f"{pad}{node['domain']} [{node['via']}{q}] ({', '.join(bits)})")
    if node.get("record"):
        out.append(f"{pad}  \u2514 {node['record']}")
    for c in node["children"]:
        render(c, indent + 1, out)
    return out


def run_one(domain, res):
    checked = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        r = analyse(domain, res)
    except Exception as e:  # isolate per-domain failures in a batch
        r = {"domain": domain, "lookups": None, "lookup_limit": LOOKUP_LIMIT,
             "void_lookups": None, "void_limit": VOID_LIMIT, "result": "error",
             "issues": [{"severity": "error", "code": "internal",
                         "message": f"{type(e).__name__}: {e}"}],
             "lookup_log": [], "tree": None}
    return {"tool": "spf-tree", "version": __version__, "checked_at_utc": checked,
            "resolvers": res.servers, **r}


def summary_table(results):
    w = max([6] + [len(r["domain"]) for r in results])
    lines = [f"{'domain':<{w}}  lookups  void  result     issues"]
    for r in results:
        lk = "-" if r["lookups"] is None else f"{r['lookups']}/{LOOKUP_LIMIT}"
        vd = "-" if r["void_lookups"] is None else f"{r['void_lookups']}/{VOID_LIMIT}"
        n = sum(i["severity"] != "info" for i in r["issues"])
        lines.append(f"{r['domain']:<{w}}  {lk:>7}  {vd:>4}  {r['result']:<9}  {n}")
    return lines


def main(argv=None, stdin=None):
    stdin = sys.stdin if stdin is None else stdin
    p = argparse.ArgumentParser(prog="spf_tree.py",
        description="Expand SPF records and count DNS lookups (RFC 7208 4.6.4).")
    p.add_argument("domains", nargs="*", help="domains, URLs or email addresses")
    p.add_argument("-f", "--file", action="append", help="file with one input per line ('-' = stdin); repeatable")
    p.add_argument("--json", help="write JSON array (one object per domain) to file, '-' for stdout")
    p.add_argument("--csv", help="write one summary row per domain to this CSV file")
    p.add_argument("--lookups-csv", help="write one row per counted lookup to this CSV file")
    p.add_argument("--resolver", help="nameserver IP to use (port 53)")
    p.add_argument("--doh", action="store_true", help="use a DNS-over-HTTPS JSON API instead of port 53")
    p.add_argument("--doh-url", default="https://dns.google/resolve", help="DoH JSON endpoint (default %(default)s)")
    p.add_argument("--timeout", type=float, default=5.0, help="per-query timeout, seconds (default 5)")
    p.add_argument("-c", "--concurrency", type=int, default=8, help="domains checked in parallel (default 8, max 64)")
    p.add_argument("-q", "--quiet", action="store_true", help="summary table only, no trees")
    p.add_argument("--version", action="version", version=f"spf-tree {__version__}")
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
        results = list(ex.map(lambda d: run_one(d, res), domains))
    out = sys.stderr if a.json == "-" else sys.stdout
    if not a.quiet:
        for r in results:
            if r["tree"]:
                print("\n".join(render(r["tree"])), file=out)
            for i in r["issues"]:
                print(f"   [{i['severity']}] {i['message']}", file=out)
            print(file=out)
    print("\n".join(summary_table(results)), file=out)
    print(f"checked {results[0]['checked_at_utc']} via {','.join(res.servers)}", file=out)
    if a.json:
        data = json.dumps(results, indent=2)
        if a.json == "-":
            sys.stdout.write(data + "\n")
        else:
            with open(a.json, "w") as f:
                f.write(data + "\n")
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["checked_at_utc", "domain", "result", "lookups", "void_lookups",
                        "issues", "resolver"])
            for r in results:
                w.writerow([r["checked_at_utc"], r["domain"], r["result"], r["lookups"],
                            r["void_lookups"],
                            " | ".join(f"{i['severity']}:{i['code']}" for i in r["issues"]),
                            ",".join(r["resolvers"])])
    if a.lookups_csv:
        with open(a.lookups_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["checked_at_utc", "domain", "lookup_no", "path", "term", "void", "status"])
            for r in results:
                for row in r["lookup_log"]:
                    w.writerow([r["checked_at_utc"], r["domain"], row["lookup_no"], row["path"],
                                row["term"], row["void"], row["status"]])
    return 1 if (bad or any(r["result"] != "ok" for r in results)) else 0


if __name__ == "__main__":
    sys.exit(main())
