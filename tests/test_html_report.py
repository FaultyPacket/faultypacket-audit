import io, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from html.parser import HTMLParser
import pytest
from faultypacket_audit import __version__
from faultypacket_audit.output import html, jsonout
from tests.test_audit_outputs_cli import reports, _cli


def doc(*doms):
    return html.render(jsonout.to_jsonable(reports(*doms), __version__), __version__)


class P(HTMLParser):
    def __init__(self):
        super().__init__(); self.tags, self.ext, self.text = [], [], []
    def handle_starttag(self, t, a):
        self.tags.append(t)
        for k, v in a:
            if k in ("src",) or (t == "link" and k == "href"):
                self.ext.append(v)
    def handle_data(self, d):
        self.text.append(d)


def parsed(h):
    p = P(); p.feed(h); return p


def test_self_contained_no_external_resources():
    h = doc("good.test", "bad.test")
    p = parsed(h)
    assert "script" not in p.tags and "img" not in p.tags and not p.ext and "<style>" in h
    assert not re.search(r"@import|url\(", h)


def test_has_required_sections():
    h = doc("bad.test")
    for s in ("Executive summary", "Mailbox-provider verdicts", "Findings", "Suggested fixes"):
        assert s in h


def test_every_finding_cited_with_link():
    r = jsonout.to_jsonable(reports("bad.test"), __version__)
    h = html.render(r, __version__)
    for c in r[0]["checks"]:
        for f in c["findings"]:
            assert html.E(f["rule_id"]) in h
            if f.get("url"):
                assert html.E(f["url"]) in h


def test_fixes_rendered_with_placeholders_warning():
    h = doc("bad.test")
    assert "REPLACE-" in h and "Values starting REPLACE- are yours" in h


def test_html_escapes_hostile_content():
    r = jsonout.to_jsonable(reports("good.test"), __version__)
    r[0]["domain"] = "<script>alert(1)</script>"
    r[0]["checks"][0]["findings"].append({"severity": "error", "rule_id": "x\"><b>", "message": "<img src=x onerror=1>",
                                          "citation": "c", "url": "javascript:'x'", "level": "MUST"})
    h = html.render(r, __version__)
    assert "<script>alert" not in h and "<img src=x" not in h and "javascript:" not in h.split("href=")[-1][:20]
    assert "&lt;script&gt;" in h and "&lt;img src=x" in h
    assert "href='javascript" not in h


def test_print_css_present():
    assert "@media print" in doc("good.test")


def test_summary_counts_match():
    r = jsonout.to_jsonable(reports("good.test", "bad.test"), __version__)
    rows = html._summary(r)
    for (d, st, e, w, fx), rep in zip(rows, r):
        assert e == sum(f["severity"] == "error" for c in rep["checks"] for f in c["findings"])
        assert fx == len(rep["fixes"])


def test_cli_html_to_file(tmp_path):
    p = tmp_path / "r.html"
    rc, out, err = _cli(["bad.test", "-q", "--html", str(p)])
    assert p.read_text().startswith("<!doctype html>") and "bad.test" in p.read_text()


def test_cli_html_stdout_keeps_human_text_on_stderr():
    rc, out, err = _cli(["good.test", "--html", "-"])
    assert out.startswith("<!doctype html>") and "good.test" in err


def test_pdf_optional(tmp_path):
    pytest.importorskip("fpdf")
    p = tmp_path / "r.pdf"
    rc, out, err = _cli(["bad.test", "-q", "--pdf", str(p)])
    assert p.read_bytes().startswith(b"%PDF")


def test_pdf_missing_dependency_message(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__
    def fake(name, *a, **k):
        if name == "fpdf":
            raise ImportError("no fpdf")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    rc, out, err = _cli(["good.test", "-q", "--pdf", str(tmp_path / "x.pdf")])
    assert rc == 2 and "fpdf2" in err


def test_cli_opt_in_checks_accepted_and_unknown_rejected():
    rc, out, err = _cli(["good.test", "-q", "--checks", "spf,lookalike"])
    assert "lookalike" in out
    with pytest.raises(SystemExit):
        _cli(["good.test", "--checks", "nope"])
