"""JSON: one object per domain; findings as plain dicts."""
import json


def to_jsonable(reports, tool_version):
    out = []
    for r in reports:
        o = {k: v for k, v in r.items() if k != "checks"}
        o["tool"] = "faultypacket-audit"
        o["version"] = tool_version
        o["checks"] = [{**{k: v for k, v in c.items() if k != "findings"},
                        "findings": [f.to_dict() for f in c["findings"]]} for c in r["checks"]]
        out.append(o)
    return out


def dumps(reports, tool_version):
    return json.dumps(to_jsonable(reports, tool_version), indent=2) + "\n"
