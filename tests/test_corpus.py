"""Differential corpus: one test per unique real-world or mutated TXT record.

Records come from a dated public DNS scan (anonymised: pseudonymous .example
hosts, reports@example.org, documentation/benchmark IP ranges) plus
deterministic mutations.  Each expected result was frozen only where
faultypacket-audit and the independent reference oracle checkdmarc agreed on
the comparable verdicts, or where a disagreement was reviewed against the RFC
text (see docs/differential-findings.md).  Rebuild with maint/corpus/*.py."""
import json, pathlib, sys
import pytest

HERE = pathlib.Path(__file__).parent / "corpus"
sys.path.insert(0, str(HERE.parent.parent / "maint" / "corpus"))
from oracle import ours  # noqa: E402

ZONE = json.loads((HERE / "zone.json").read_text())
CASES = [json.loads(l) for l in (HERE / "cases.jsonl").read_text().splitlines() if l.strip()]


def _id(c):
    import hashlib
    return f"{c['kind']}-{c['origin']}-{hashlib.sha256(c['record'].encode()).hexdigest()[:10]}"


@pytest.mark.parametrize("case", CASES, ids=[_id(c) for c in CASES])
def test_corpus_record(case):
    assert ours(case["kind"], case["record"], ZONE, case["domain"]) == case["expected"]


def test_corpus_is_deduplicated():
    import re
    keys = [(c["kind"], re.sub(r"\s+", " ", c["record"].strip()), json.dumps(c["expected"], sort_keys=True)) for c in CASES]
    assert len(keys) == len(set(keys))


def test_corpus_is_anonymised():
    import re
    blob = (HERE / "cases.jsonl").read_text() + (HERE / "zone.json").read_text()
    for m in re.finditer(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)", blob):
        assert m.group(1).lower().rstrip(".") in ("example.org", "example.com"), m.group(0)
    hosts = set(re.findall(r"\b(?:[a-z0-9_-]+\.)+([a-z]{2,})\b", blob.lower()))
    assert hosts <= {"example", "org", "com"}, sorted(hosts)[:20]
