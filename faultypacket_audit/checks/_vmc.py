"""BIMI mark certificate (VMC/CMC) checks, draft-brand-indicators-for-message-
identification-14 7.4: PEM chain order and signatures (RFC 5280 6.1), leaf
expiry, the BIMI EKU, the domain in subjectAltName, and the RFC 3709 logotype
image compared with the l= SVG. Needs the optional ``cryptography`` package;
without it the checks report 'not tested'. Trust in the issuing root is not
judged (no root store is bundled)."""
import base64, datetime as dt, gzip, hashlib, re

EKU_BIMI = "1.3.6.1.5.5.7.3.31"
LOGOTYPE = "1.3.6.1.5.5.7.1.12"


def _svg(b):
    if b and b[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(b)
        except OSError:
            return b
    return b


def logotype_images(der_ext):
    """data: URIs inside the logotype extension -> decoded image bytes."""
    out = []
    for m in re.finditer(rb"data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)", der_ext):
        try:
            out.append(_svg(base64.b64decode(m.group(1))))
        except ValueError:
            pass
    return out


def check_pem(pem, domain, logo=None, now=None):
    """-> [(severity, rule_id, message)]."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
    except ImportError:
        return [("info", "bimi.vmc_parse", "chain, expiry and logo binding not tested: pip install cryptography")]
    try:
        certs = x509.load_pem_x509_certificates(pem)
    except ValueError as e:
        return [("error", "bimi.vmc_parse", f"PEM does not parse as X.509 ({e})")]
    out, leaf = [], certs[0]
    now = now or dt.datetime.now(dt.timezone.utc)
    na = leaf.not_valid_after_utc
    if na < now or leaf.not_valid_before_utc > now:
        out.append(("error", "bimi.vmc_expired", f"leaf certificate is outside its validity period ({leaf.not_valid_before_utc:%Y-%m-%d} to {na:%Y-%m-%d})"))
    elif (na - now).days < 30:
        out.append(("warning", "bimi.vmc_expiring", f"leaf certificate expires {na:%Y-%m-%d} ({(na - now).days} days)"))
    if len(certs) == 1:
        out.append(("error", "bimi.vmc_chain", "only the leaf is published; the issuing chain MUST follow it in the same file"))
    for child, parent in zip(certs, certs[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except Exception as e:  # ValueError, TypeError, InvalidSignature
            out.append(("error", "bimi.vmc_chain", f"'{child.subject.rfc4514_string()}' is not signed by the next certificate in the file ({type(e).__name__})"))
            break
    try:
        ekus = [o.dotted_string for o in leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value]
    except x509.ExtensionNotFound:
        ekus = []
    if EKU_BIMI not in ekus:
        out.append(("error", "bimi.vmc_eku", "leaf lacks the BIMI extended key usage (1.3.6.1.5.5.7.3.31)"))
    try:
        names = [n.lower().rstrip(".") for n in leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    if domain.lower() not in names:
        out.append(("error", "bimi.vmc_san", f"{domain} is not in the certificate's subjectAltName ({', '.join(names) or 'none'})"))
    imgs = []
    for ext in leaf.extensions:
        if ext.oid.dotted_string == LOGOTYPE:
            raw = getattr(ext.value, "value", None) or ext.value.public_bytes()
            imgs = logotype_images(raw)
    if not imgs:
        out.append(("error", "bimi.vmc_logo_hash", "no embedded SVG logotype (RFC 3709) in the certificate"))
    elif logo is not None:
        want = hashlib.sha256(_svg(logo)).hexdigest()
        if want not in {hashlib.sha256(i).hexdigest() for i in imgs}:
            out.append(("error", "bimi.vmc_logo_hash", f"l= logo (sha256 {want[:16]}...) differs from the logo in the certificate"))
    if not [o for o in out if o[0] == "error"]:
        out.append(("info", "bimi.vmc_ok", f"chain order/signatures, EKU, SAN, expiry ({na:%Y-%m-%d}) and logo binding OK; root trust not judged"))
    return out
