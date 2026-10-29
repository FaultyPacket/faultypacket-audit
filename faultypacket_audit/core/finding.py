"""Finding: one observation, always tied to a rule (and so to a citation)."""
from dataclasses import dataclass, field, asdict

SEVERITIES = ("ok", "info", "warning", "error")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str           # info | warning | error
    rule_id: str
    message: str
    citation: str           # human-readable source, e.g. "RFC 9989 4.7"
    url: str
    level: str              # MUST | SHOULD | MAY | PROVIDER | TOOL
    evidence: dict = field(default_factory=dict)
    rules_version: str = ""  # rules.json version that produced this finding

    def __post_init__(self):
        if self.severity not in _RANK or self.severity == "ok":
            raise ValueError(f"bad severity {self.severity!r}")
        if not self.citation:
            raise ValueError(f"finding {self.rule_id} has no citation")

    def to_dict(self):
        return asdict(self)


def worst(severities):
    """Worst of an iterable of severities; 'ok' when empty."""
    best = "ok"
    for s in severities:
        if _RANK[s] > _RANK[best]:
            best = s
    return best


def rank(sev):
    return _RANK[sev]
