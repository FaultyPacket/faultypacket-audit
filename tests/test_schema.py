import json, pathlib
import pytest
from faultypacket_audit import __version__
from faultypacket_audit.output import jsonout
from tests.test_audit_outputs_cli import reports

jsonschema = pytest.importorskip("jsonschema")
SCHEMA = json.loads((pathlib.Path(__file__).resolve().parents[1] / "schema/audit.schema.json").read_text())


def test_schema_is_valid_and_matches_output():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    data = json.loads(jsonout.dumps(reports("good.test", "bad.test"), __version__))
    jsonschema.validate(data, SCHEMA)
    assert any(c["findings"] for r in data for c in r["checks"])
