"""Build synthetic BIMI mark-certificate chains for tests (never real CAs)."""
import base64, datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

NOW = dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def chain(domain="d.test", svg=b"<svg/>", days=365, eku=True, with_root=True, wrong_issuer=False, logo=True):
    rk, lk, ok = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = (x509.CertificateBuilder().subject_name(_name("Example Test Root")).issuer_name(_name("Example Test Root"))
            .public_key(rk.public_key()).serial_number(1).not_valid_before(NOW - dt.timedelta(days=10))
            .not_valid_after(NOW + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(rk, hashes.SHA256()))
    b = (x509.CertificateBuilder().subject_name(_name(domain)).issuer_name(root.subject).public_key(lk.public_key())
         .serial_number(2).not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.5.5.7.3.31")]), critical=False)
    if logo:
        uri = b"data:image/svg+xml;base64," + base64.b64encode(svg)
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.5.5.7.1.12"), b"\x30\x00" + uri), critical=False)
    leaf = b.sign(ok if wrong_issuer else rk, hashes.SHA256())
    pem = leaf.public_bytes(serialization.Encoding.PEM)
    return pem + (root.public_bytes(serialization.Encoding.PEM) if with_root else b"")
