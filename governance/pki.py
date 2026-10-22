"""
pki.py — one-shot: the certificates that let governance know OPA by its TLS certificate.

Governance serves the grant lookups (/internal/*) on a TLS listener that accepts only a client
certificate from this CA with the name `opa`. OPA presents that certificate from files it
mounts; a file, unlike its environment, cannot be read back through OPA's query API.

Each party gets its own volume: /pki/ca (the CA key, this job only), /pki/governance (the
server certificate), /pki/opa (the client certificate). Existing files are kept, so the job is
safe to rerun.
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DIR, GOV_DIR, OPA_DIR = "/pki/ca", "/pki/governance", "/pki/opa"
DAYS = 3650


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _write(path, data, mode=0o644):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


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


def main():
    for d in (CA_DIR, GOV_DIR, OPA_DIR):
        os.makedirs(d, exist_ok=True)
    if all(os.path.exists(p) for p in (f"{CA_DIR}/ca.key", f"{GOV_DIR}/server.crt", f"{OPA_DIR}/client.crt")):
        print("pki: certificates exist")
        return
    ca_key = _key()
    ca = _cert("minilakehouse internal CA", ca_key, None, ca_key, ca=True)
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    _write(f"{CA_DIR}/ca.key", _pem_key(ca_key), 0o600)
    server_key, client_key = _key(), _key()
    server = _cert("governance", server_key, ca.subject, ca_key,
                   eku=ExtendedKeyUsageOID.SERVER_AUTH, dns=["governance"])
    client = _cert("opa", client_key, ca.subject, ca_key, eku=ExtendedKeyUsageOID.CLIENT_AUTH)
    for d, name, cert, key in ((GOV_DIR, "server", server, server_key),
                               (OPA_DIR, "client", client, client_key)):
        _write(f"{d}/ca.crt", ca_pem)
        _write(f"{d}/{name}.crt", cert.public_bytes(serialization.Encoding.PEM))
        # World-readable inside its own volume: the container mounting it may run as another user.
        _write(f"{d}/{name}.key", _pem_key(key), 0o644)
    print("pki: created CA, governance server certificate, opa client certificate")


if __name__ == "__main__":
    main()
