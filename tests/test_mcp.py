import io, json
from faultypacket_audit import mcp
from faultypacket_audit.core.rules import load_rules


class FakeRes:
    servers = ["fake"]


def run(lines, monkeypatch=None):
    out = io.StringIO()
    srv = mcp.Server(FakeRes(), load_rules())
    for l in lines:
        r = srv.handle(l)
        if r is not None:
            out.write(json.dumps(r) + "\n")
    return [json.loads(x) for x in out.getvalue().splitlines()]


def test_initialize_and_list():
    r = run([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
             {"jsonrpc": "2.0", "method": "notifications/initialized"},
             {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    assert len(r) == 2
    assert r[0]["result"]["serverInfo"]["name"] == "faultypacket-audit"
    assert r[0]["result"]["capabilities"] == {"tools": {}}
    assert {t["name"] for t in r[1]["result"]["tools"]} == {"audit_domain", "list_rules"}


def test_list_rules():
    r = run([{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_rules", "arguments": {}}}])
    sc = r[0]["result"]["structuredContent"]
    assert sc["rules_version"] == load_rules().version and len(sc["rules"]) > 100


def test_audit_domain_uses_audit(monkeypatch):
    seen = {}

    def fake(domain, res, rules, checks, opts):
        seen.update(domain=domain, checks=checks)
        return {"domain": domain, "checked_at_utc": "t", "rules_version": rules.version,
                "resolvers": ["fake"], "status": "ok", "checks": []}
    monkeypatch.setattr(mcp, "audit", fake)
    r = run([{"jsonrpc": "2.0", "id": 4, "method": "tools/call",
              "params": {"name": "audit_domain", "arguments": {"domain": "https://Example.COM/x", "checks": ["spf"]}}}])
    res = r[0]["result"]
    assert not res["isError"] and res["structuredContent"]["tool"] == "faultypacket-audit"
    assert seen == {"domain": "example.com", "checks": ["spf"]}


def test_errors():
    r = run([{"jsonrpc": "2.0", "id": 5, "method": "nope"},
             {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "zzz"}},
             {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
              "params": {"name": "audit_domain", "arguments": {"domain": "example.com", "checks": ["bad"]}}}])
    assert r[0]["error"]["code"] == -32601
    assert r[1]["error"]["code"] == -32602
    assert r[2]["result"]["isError"] is True


def test_serve_stdio():
    inp = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\nnot json\n')
    out = io.StringIO()
    assert mcp.serve([], stdin=inp, stdout=out) == 0
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0] == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert lines[1]["error"]["code"] == -32700


def test_mcp_schema_lists_opt_in_checks():
    from faultypacket_audit.mcp import TOOLS
    enum = next(t for t in TOOLS if t["name"] == "audit_domain")["inputSchema"]["properties"]["checks"]["items"]["enum"]
    assert "blocklist" in enum and "lookalike" in enum
