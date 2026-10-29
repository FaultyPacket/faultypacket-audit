"""Minimal Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0).

Run: ``faultypacket-audit mcp`` (add ``--doh`` where port 53 is blocked).
Tools: ``audit_domain`` and ``list_rules``. No third-party MCP SDK needed.
"""
import argparse, json, sys

from . import __version__
from .audit import audit, ORDER
from .core.resolver import Cached, Resolver, DEFAULT_DOH
from .core.rules import load_rules
from .core.inputs import extract_domain
from .output import jsonout

PROTOCOL = "2025-06-18"

TOOLS = [
    {"name": "audit_domain",
     "description": ("Audit a domain's public mail/DNS security (SPF, DMARC RFC 9989, DKIM, MX, MTA-STS, "
                     "TLS-RPT, DNSSEC, DANE, CAA, reverse DNS, BIMI, Google/Yahoo/Outlook bulk-sender rows). "
                     "Returns the audit.json object: every finding has rule_id, severity, citation and url. "
                     "Read-only DNS/HTTPS lookups; nothing is sent to FaultyPacket."),
     "inputSchema": {"type": "object", "required": ["domain"], "additionalProperties": False, "properties": {
         "domain": {"type": "string", "description": "domain, URL or email address"},
         "checks": {"type": "array", "items": {"type": "string", "enum": ORDER},
                    "description": "subset of checks (default all)"},
         "dkim_selectors": {"type": "array", "items": {"type": "string"}},
         "sending_ips": {"type": "array", "items": {"type": "string"}},
         "bulk": {"type": "boolean", "description": "sender of 5,000+ messages/day"}}}},
    {"name": "list_rules",
     "description": "Return the bundled rules.json (rules_version, and each rule's id, level, source, url, verified date).",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
]


class Server:
    def __init__(self, resolver, rules):
        self.res, self.rules = resolver, rules

    def call(self, name, args):
        if name == "list_rules":
            return {"rules_version": self.rules.version, "rules": list(self.rules.by_id.values())}
        if name != "audit_domain":
            raise KeyError(name)
        domain = extract_domain(str(args.get("domain", "")).strip())
        checks = args.get("checks") or ORDER
        bad = [c for c in checks if c not in ORDER]
        if bad:
            raise ValueError(f"unknown check(s): {', '.join(bad)}")
        opts = {"sending_ips": list(args.get("sending_ips") or []),
                "dkim_selectors": list(args.get("dkim_selectors") or []),
                "bulk": bool(args.get("bulk")), "smtp": False, "validating_resolver": False, "timeout": 5.0}
        return jsonout.to_jsonable([audit(domain, self.res, self.rules, checks, opts)], __version__)[0]

    def handle(self, msg):
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if mid is None:                       # notification
            return None
        try:
            if method == "initialize":
                result = {"protocolVersion": params.get("protocolVersion") or PROTOCOL,
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": "faultypacket-audit", "version": __version__}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                try:
                    data = self.call(params.get("name"), params.get("arguments") or {})
                    result = {"content": [{"type": "text", "text": json.dumps(data)}],
                              "structuredContent": data, "isError": False}
                except KeyError:
                    return _err(mid, -32602, f"unknown tool {params.get('name')!r}")
                except ValueError as e:
                    result = {"content": [{"type": "text", "text": str(e)}], "isError": True}
            else:
                return _err(mid, -32601, f"method not found: {method}")
        except Exception as e:                 # never crash the server
            return _err(mid, -32603, f"{type(e).__name__}: {e}")
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(argv=None, stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    p = argparse.ArgumentParser(prog="faultypacket-audit mcp", description="MCP server over stdio")
    p.add_argument("--doh", action="store_true", help="use DNS-over-HTTPS")
    p.add_argument("--doh-url", default=DEFAULT_DOH)
    p.add_argument("--resolver")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--rules")
    a = p.parse_args(argv)
    srv = Server(Cached(Resolver(a.resolver, a.timeout, a.doh_url if a.doh else None)), load_rules(a.rules))
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            out = _err(None, -32700, "parse error")
        else:
            out = srv.handle(msg) if isinstance(msg, dict) else _err(None, -32600, "invalid request")
        if out is not None:
            stdout.write(json.dumps(out) + "\n")
            stdout.flush()
    return 0
