"""DKIM re-verification: RFC 8463 A.3 vectors, cross-checks against an independent signer (dkimpy), and faults."""
import base64, os, time
import pytest
from hypothesis import given, settings, strategies as st, HealthCheck
from faultypacket_audit import dkimverify as V, headers as H, load_rules
from tests.zone import Zone

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = os.path.dirname(__file__)
RFC8463 = open(os.path.join(HERE, "fixtures/dkim/rfc8463-a3.eml"), "rb").read()
FOOTBALL = Zone({
    ("brisbane._domainkey.football.example.com", "TXT"): ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
    ("test._domainkey.football.example.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"]})
T0 = 1528637909


def test_rfc8463_vectors_pass():
    assert [(r["a"], r["result"]) for r in V.verify(RFC8463, FOOTBALL, T0)] == [("ed25519-sha256", "pass"), ("rsa-sha256", "pass")]


def test_rfc8463_lf_line_endings_still_pass():
    assert {r["result"] for r in V.verify(RFC8463.replace(b"\r\n", b"\n"), FOOTBALL, T0)} == {"pass"}


@pytest.mark.parametrize("old,new,res", [(b"Is dinner ready?", b"Is dinner ready!", "fail"),     # signed header changed
                                         (b"We lost the game.", b"We won the game.", "fail"),   # body changed
                                         (b"Subject: Is", b"subject:   Is", "pass")])          # relaxed header canon
def test_rfc8463_tampering(old, new, res):
    assert {r["result"] for r in V.verify(RFC8463.replace(old, new), FOOTBALL, T0)} == {res}


def test_relaxed_body_whitespace_tolerated():
    raw = RFC8463.replace(b"Are you hungry yet?", b"Are you   hungry yet?  ") + b"\r\n\r\n"
    assert {r["result"] for r in V.verify(raw, FOOTBALL, T0)} == {"pass"}


def test_key_problems():
    z = Zone({("test._domainkey.football.example.com", "TXT"): ["v=DKIM1; p="],
              ("brisbane._domainkey.football.example.com", "TXT"): ["v=DKIM1; k=ed25519; p=AAAA", "v=DKIM1; k=ed25519; p=BBBB"]})
    got = {r["s"]: r for r in V.verify(RFC8463, z, T0)}
    assert got["test"]["result"] == "permerror" and "revoked" in got["test"]["reason"]
    assert got["brisbane"]["result"] == "permerror" and "3.6.2.2" in got["brisbane"]["reason"]
    assert {r["result"] for r in V.verify(RFC8463, Zone({}), T0)} == {"permerror"}
    err = Zone({("test._domainkey.football.example.com", "TXT"): "err", ("brisbane._domainkey.football.example.com", "TXT"): "err"})
    assert {r["result"] for r in V.verify(RFC8463, err, T0)} == {"temperror"}
    assert {r["result"] for r in V.verify(RFC8463, None, T0)} == {"neutral"}


# ---------------------------------------------------------------- independent signer
dkim = pytest.importorskip("dkim")
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
PUB = base64.b64encode(KEY.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
MSG = (b"From: Alice <alice@example.com>\r\nTo: bob@example.org\r\nSubject: Quarterly  figures\r\n"
       b"Date: Thu, 29 Oct 2026 10:00:00 +0000\r\nReceived: from a\r\nReceived: from b\r\nMessage-ID: <1@example.com>\r\n\r\n"
       b"Hello Bob,\r\n\r\n  figures   attached.  \r\n\r\n\r\n")
NOW = int(time.time()) + 60


def zone(key=None, extra=""):
    return Zone({("s1._domainkey.example.com", "TXT"): [f"v=DKIM1; k=rsa;{extra} p={key or PUB}"]})


def sign(msg=MSG, **kw):
    kw.setdefault("include_headers", [b"from", b"to", b"subject", b"date", b"message-id"])
    sig = dkim.sign(msg, b"s1", b"example.com", PEM, **kw)
    return sig + msg


@pytest.mark.parametrize("canon", [(b"simple", b"simple"), (b"relaxed", b"relaxed"), (b"relaxed", b"simple"), (b"simple", b"relaxed")])
def test_independent_signer_all_canonicalisations(canon):
    assert V.verify(sign(canonicalize=canon), zone(), NOW)[0]["result"] == "pass"


def test_multiple_instances_and_nonexistent_headers():
    raw = sign(include_headers=[b"from", b"x-tag", b"x-tag", b"x-tag", b"subject", b"reply-to"])
    assert V.verify(raw, zone(), NOW)[0]["result"] == "pass"
    # adding another Received on top changes which instances are taken bottom-up -> still pass (bottom-up selection),
    # but adding a Reply-To that was signed as absent breaks it (RFC 6376 5.4)
    assert V.verify(b"X-Tag: c\r\n" + raw, zone(), NOW)[0]["result"] == "fail"
    assert V.verify(raw.replace(b"Subject:", b"Reply-To: x@example.net\r\nSubject:"), zone(), NOW)[0]["result"] == "fail"


def test_body_length_and_appended_content():
    raw = sign(length=True)
    r = V.verify(raw + b"P.S. appended\r\n", zone(), NOW)[0]
    assert r["result"] == "pass" and "dkim.sig_body_length" in {p[0] for p in r["problems"]}


@pytest.mark.parametrize("kw,mut,rid", [
    ({"identity": b"@other.example.org"}, None, "dkim.sig_i_outside_d"),
    ({"identity": b"@mail.example.com"}, ("key", " t=s;"), "dkim.sig_i_outside_d"),
    ({}, ("key", " s=tlsrpt;"), "dkim.sig_key"),
    ({}, ("key", " h=sha1;"), "dkim.sig_key"),
    ({}, ("msg", (b"Subject: Quarterly", b"Subject: Quarterlz")), "dkim.sig_bad"),
    ({}, ("msg", (b"attached.", b"attachez.")), "dkim.sig_body_hash"),
])
def test_faults(kw, mut, rid):
    try:
        raw = sign(**kw)
    except dkim.ParameterError:
        # dkimpy refuses i= outside d=; forge it into a valid signature's header
        raw = sign().replace(b"i=@example.com;", b"i=@other.example.org;", 1)
    z = zone(extra=mut[1]) if mut and mut[0] == "key" else zone()
    if mut and mut[0] == "msg":
        raw = raw.replace(*mut[1])
    r = V.verify(raw, z, NOW)[0]
    assert r["result"] in ("fail", "permerror") and rid in {p[0] for p in r["problems"]}, r


def test_from_not_signed_and_expired():
    raw = sign().replace(b"h=from : to", b"h=to", 1)
    assert "dkim.sig_from_unsigned" in {p[0] for p in V.verify(raw, zone(), NOW)[0]["problems"]}
    raw = dkim.sign(MSG, b"s1", b"example.com", PEM, signature_algorithm=b"rsa-sha256",
                    include_headers=[b"from"]) + MSG
    raw = raw.replace(b"t=", b"x=1; t=", 1)
    r = V.verify(raw, zone(), NOW)[0]
    assert r["result"] in ("fail", "permerror") and "dkim.sig_expired" in {p[0] for p in r["problems"]}


def test_ed25519_independent():
    pytest.importorskip("nacl")
    from cryptography.hazmat.primitives.asymmetric import ed25519
    k = ed25519.Ed25519PrivateKey.generate()
    sk = base64.b64encode(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    pk = base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    raw = dkim.sign(MSG, b"s1", b"example.com", sk, signature_algorithm=b"ed25519-sha256", include_headers=[b"from", b"subject"]) + MSG
    z = Zone({("s1._domainkey.example.com", "TXT"): [f"v=DKIM1; k=ed25519; p={pk}"]})
    assert V.verify(raw, z, NOW)[0]["result"] == "pass"
    assert V.verify(raw, zone(), NOW)[0]["result"] == "permerror"   # k=rsa key for an ed25519 signature


def test_analyse_integration_alignment_and_rendering():
    raw = sign()
    r = H.analyse(raw, verify=True, keys=zone(), now=NOW)
    assert r["verdict"] == "pass" and r["dkim_verification"][0]["aligned"]
    assert "DKIM re-verification" in H.render(r)
    other = raw.replace(b"From: Alice <alice@example.com>", b"From: Alice <alice@example.net>")
    r = H.analyse(other, verify=True, keys=zone(), now=NOW)
    assert r["verdict"] != "pass"


def test_rule_ids_exist():
    R = load_rules()
    import inspect, re
    for rid in set(re.findall(r'"(dkim\.(?:sig|key)_[a-z_]+)"', inspect.getsource(V))):
        assert rid in R and "#section-" in R.get(rid)["url"], rid


TXT = st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=60)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(TXT, max_size=6), TXT, st.sampled_from([(b"simple", b"simple"), (b"relaxed", b"relaxed"), (b"relaxed", b"simple")]))
def test_prop_independent_sign_then_verify(lines, subj, canon):
    msg = (b"From: a@example.com\r\nSubject: " + subj.encode() + b"\r\n\r\n" + b"\r\n".join(l.encode() for l in lines) + b"\r\n")
    raw = dkim.sign(msg, b"s1", b"example.com", PEM, canonicalize=canon, include_headers=[b"from", b"subject"]) + msg
    assert V.verify(raw, zone(), NOW)[0]["result"] == "pass"
    tampered = raw.replace(b"From: a@example.com", b"From: b@example.com")
    assert V.verify(tampered, zone(), NOW)[0]["result"] == "fail"
