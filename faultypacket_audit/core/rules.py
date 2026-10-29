"""rules.json loader. Every Finding is created through Rules.finding(), so a
finding without a known rule (and therefore without a citation) cannot exist.

Schema faultypacket-rules/1:
  {schema, rules_version (CalVer), rules: [{id, check, value, level, source,
   url, verified, ...}]}
level TOOL marks tool-side conditions (DNS failure, internal error); those
need a source but no url. Everything else needs a url and a verified date.
"""
import json, re
from importlib import resources

from .finding import Finding

SCHEMA = "faultypacket-rules/1"
LEVELS = {"MUST", "SHOULD", "MAY", "PROVIDER", "TOOL"}
REQUIRED = ("id", "check", "value", "level", "source", "verified")


class RulesError(ValueError):
    pass


class Rules:
    def __init__(self, data, origin="<memory>"):
        self.origin = origin
        problems = validate(data)
        if problems:
            raise RulesError(f"{origin}: " + "; ".join(problems))
        self.version = data["rules_version"]
        self.by_id = {r["id"]: r for r in data["rules"]}

    def __contains__(self, rule_id):
        return rule_id in self.by_id

    def get(self, rule_id):
        try:
            return self.by_id[rule_id]
        except KeyError:
            raise RulesError(f"unknown rule {rule_id!r} (not in {self.origin})") from None

    def value(self, rule_id):
        return self.get(rule_id)["value"]

    def for_check(self, check):
        return [r for r in self.by_id.values() if r["check"] == check]

    def finding(self, check, severity, rule_id, message, **evidence):
        r = self.get(rule_id)
        return Finding(check=check, severity=severity, rule_id=rule_id, message=message,
                       citation=r["source"], url=r.get("url", ""), level=r["level"],
                       evidence=evidence, rules_version=self.version)


def validate(data):
    out = []
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return [f"schema must be {SCHEMA}"]
    if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}\.\d+", str(data.get("rules_version", ""))):
        out.append("rules_version must be CalVer YYYY.MM.DD.N")
    seen = set()
    for r in data.get("rules", []):
        rid = r.get("id", "?")
        for k in REQUIRED:
            if k not in r or r[k] in ("", None):
                out.append(f"{rid}: missing {k}")
        if r.get("level") not in LEVELS:
            out.append(f"{rid}: bad level {r.get('level')!r}")
        if r.get("level") != "TOOL" and not str(r.get("url", "")).startswith("https://"):
            out.append(f"{rid}: missing https url")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r.get("verified", ""))):
            out.append(f"{rid}: verified must be YYYY-MM-DD")
        if rid in seen:
            out.append(f"{rid}: duplicate id")
        seen.add(rid)
    return out


def load_rules(path=None):
    """Bundled rules.json, or a local override (--rules)."""
    if path:
        with open(path, encoding="utf-8") as f:
            return Rules(json.load(f), origin=path)
    text = resources.files("faultypacket_audit.data").joinpath("rules.json").read_text(encoding="utf-8")
    return Rules(json.loads(text), origin="bundled rules.json")
