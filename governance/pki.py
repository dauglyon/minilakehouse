"""
pki.py — one-shot: the certificates that let governance know its internal callers.

Governance serves /internal/* on a TLS listener that accepts only client certificates from this
CA: `opa` for the grant lookups, `gate` for its table create/drop reports, `gate` and
`broker` for the access log (PROVENANCE.md 4.1), `broker` for transfers, and `trino` for the
statement events its HTTP event listener sends (docs/HANDOFF-2026-10-22-groups.md section 4).
Each caller presents
its certificate from files it mounts; a file, unlike OPA's environment, cannot be read back
through OPA's query API.

Each party gets its own volume: /pki/ca (the CA, this job only), /pki/governance (the server
certificate, and the Ed25519 key governance signs declarations with, PROVENANCE.md 5.3),
/pki/opa, /pki/gate, /pki/broker and /pki/trino (client certificates; Trino's also as one PEM
file holding key and certificate, the key store its HTTP client reads). Existing files are kept and a
missing certificate is added under the existing CA, so the job is safe to rerun.
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DIR, GOV_DIR = "/pki/ca", "/pki/governance"
OPA_DIR, GATE_DIR, BROKER_DIR, TRINO_DIR = "/pki/opa", "/pki/gate", "/pki/broker", "/pki/trino"
DAYS = 3650
# Each private key is readable only by the user its container runs as: governance, the gate and
# the broker run as root, the OPA image as OPA_UID, the Trino image as TRINO_UID.
OPA_UID = int(os.environ.get("OPA_UID", "1000"))
TRINO_UID = int(os.environ.get("TRINO_UID", "1000"))
# directory: (file stem, certificate name, key usage, DNS names, key owner)
PARTIES = {
    GOV_DIR: ("server", "governance", ExtendedKeyUsageOID.SERVER_AUTH, ["governance"], 0),
    OPA_DIR: ("client", "opa", ExtendedKeyUsageOID.CLIENT_AUTH, None, OPA_UID),
    GATE_DIR: ("client", "gate", ExtendedKeyUsageOID.CLIENT_AUTH, None, 0),
    BROKER_DIR: ("client", "broker", ExtendedKeyUsageOID.CLIENT_AUTH, None, 0),
    TRINO_DIR: ("client", "trino", ExtendedKeyUsageOID.CLIENT_AUTH, None, TRINO_UID),
}


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _write(path, data, mode=0o644, owner=None):
    # Created with its final mode, so a key is never briefly readable by others.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
        os.fchmod(fd, mode)
        if owner is not None:
            os.fchown(fd, owner, owner)
    finally:
        os.close(fd)


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _cert(subject_cn, key, issuer_name, issuer_key, *, ca=False, eku=None, dns=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .issuer_name(issuer_name or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(days=DAYS))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if dns:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _ca():
    """The CA's certificate and key, created on the first run."""
    key_path, crt_path = f"{CA_DIR}/ca.key", f"{CA_DIR}/ca.crt"
    if not os.path.exists(crt_path) and os.path.exists(f"{GOV_DIR}/ca.crt"):
        _write(crt_path, open(f"{GOV_DIR}/ca.crt", "rb").read())   # kept only beside the parties before
    if os.path.exists(key_path) and os.path.exists(crt_path):
        os.chmod(key_path, 0o600)
        key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
        return x509.load_pem_x509_certificate(open(crt_path, "rb").read()), key, False
    key = _key()
    ca = _cert("minilakehouse internal CA", key, None, key, ca=True)
    _write(key_path, _pem_key(key), 0o600, 0)
    _write(crt_path, ca.public_bytes(serialization.Encoding.PEM))
    return ca, key, True


def main():
    for d in (CA_DIR, *PARTIES):
        os.makedirs(d, exist_ok=True)
    ca, ca_key, created = _ca()
    made = ["CA"] if created else []
    for d, (stem, name, eku, dns, owner) in PARTIES.items():
        if os.path.exists(f"{d}/{stem}.crt") and not created:
            os.chmod(f"{d}/{stem}.key", 0o600)   # keys written by an earlier version were 0644
            os.chown(f"{d}/{stem}.key", owner, owner)
            continue
        key = _key()
        cert = _cert(name, key, ca.subject, ca_key, eku=eku, dns=dns)
        _write(f"{d}/ca.crt", ca.public_bytes(serialization.Encoding.PEM))
        _write(f"{d}/{stem}.crt", cert.public_bytes(serialization.Encoding.PEM))
        _write(f"{d}/{stem}.key", _pem_key(key), 0o600, owner)
        if d == TRINO_DIR:
            _write(f"{d}/{stem}.pem", _pem_key(key) + cert.public_bytes(serialization.Encoding.PEM), 0o600, owner)
        made.append(name)
    if not os.path.exists(f"{GOV_DIR}/signing.key"):
        key = ed25519.Ed25519PrivateKey.generate()
        _write(f"{GOV_DIR}/signing.key", _pem_key(key), 0o600, 0)
        _write(f"{GOV_DIR}/signing.pub", key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        made.append("signing key")
    print(f"pki: created {', '.join(made)}" if made else "pki: certificates exist")


if __name__ == "__main__":
    main()
