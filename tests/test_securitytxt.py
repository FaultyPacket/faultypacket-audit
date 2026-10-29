"""security.txt (RFC 9116) - synthetic files only."""
import datetime as dt
from hypothesis import given, strategies as st
from faultypacket_audit import load_rules
from faultypacket_audit.checks import securitytxt as S

NOW = dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc)
URL = "https://example.com/.well-known/security.txt"
GOOD = (b"Contact: mailto:security@example.com\nContact: https://example.com/report\n"
        b"Encryption: https://example.com/pgp.asc\nExpires: 2027-06-01T00:00:00Z\n"
        b"Preferred-Languages: en, fr\nCanonical: https://example.com/.well-known/security.txt\n# comment\n\n")
ids = lambda out: {r for _, r, _ in out}


def test_good_file_only_unsigned_info():
    assert ids(S.lint(GOOD, URL, now=NOW)) == {"sectxt.unsigned"}


def test_signed_file_dash_escaped():
    signed = (b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + GOOD + b"- # dash-escaped comment\n"
              b"-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n")
    assert ids(S.lint(signed, URL, now=NOW)) == set()


def test_faults():
    bad = (b"Contact: http://example.com/x\nEncryption: -----BEGIN PGP PUBLIC KEY BLOCK-----\nExpires: 2025-01-01T00:00:00Z\n"
           b"Expires: 2025-01-02T00:00:00Z\nPreferred-Languages: \nnot a field\nPolicy: https://example.com/a, https://example.com/b\n"
           b"Canonical: https://example.org/.well-known/security.txt\n")
    got = ids(S.lint(bad, URL, "text/html", now=NOW))
    assert {"sectxt.https_uri", "sectxt.encryption_key", "sectxt.duplicate", "sectxt.expired", "sectxt.syntax",
            "sectxt.chained", "sectxt.canonical", "sectxt.content_type"} <= got


def test_missing_required_and_far_expiry():
    got = ids(S.lint(b"Expires: 2029-01-01T00:00:00Z\n", URL, now=NOW))
    assert {"sectxt.no_contact", "sectxt.expires_far"} <= got
    assert "sectxt.expires" in ids(S.lint(b"Contact: mailto:a@example.com\n", URL, now=NOW))
    assert "sectxt.contact_unencrypted" in ids(S.lint(b"Contact: mailto:a@example.com\n", URL, now=NOW))
    assert "sectxt.encoding" in ids(S.lint(b"Contact: mailto:\xff@example.com\n", URL, now=NOW))
    assert "sectxt.content_type" in ids(S.lint(GOOD, URL, "text/plain; charset=latin1", now=NOW))


def fetcher(table):
    return lambda url, timeout=10.0: table.get(url, (404, "", b"", url))


def run(table):
    r = S.check("example.com", None, load_rules(), {"sectxt_fetch": fetcher(table), "now": NOW})
    return {f.rule_id for f in r["findings"]}, r


def test_check_locations_and_redirects():
    assert run({})[0] == {"sectxt.absent"}
    assert run({URL: (200, "text/plain; charset=utf-8", GOOD, URL)})[0] == {"sectxt.unsigned", "sectxt.ok"}
    legacy = "https://example.com/security.txt"
    g = GOOD.replace(b".well-known/security.txt", b"security.txt")
    assert "sectxt.location" in run({legacy: (200, "text/plain; charset=utf-8", g, legacy)})[0]
    got = run({URL: (200, "text/plain; charset=utf-8", GOOD, "http://www.example.org/security.txt")})[0]
    assert {"sectxt.https", "sectxt.scope"} <= got


def test_rules_cited():
    R = load_rules()
    for rid in ["sectxt.encoding", "sectxt.unsigned", "sectxt.chained", "sectxt.encryption_key", "sectxt.contact_unencrypted",
                "sectxt.languages", "sectxt.https", "sectxt.scope"]:
        assert "rfc9116#section-" in R.get(rid)["url"]


@given(st.binary(max_size=400), st.sampled_from(["text/plain", "", "application/octet-stream"]))
def test_prop_lint_never_crashes(body, ct):
    for sev, rid, _ in S.lint(body, URL, ct, now=NOW):
        assert sev in ("info", "warning", "error") and rid.startswith("sectxt.")
