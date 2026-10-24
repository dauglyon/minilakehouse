"""
broker — the blob vending broker (Flow C: blob datasets). The true end-to-end plane.

A client presents its OWN Keycloak token and names a dataset. The broker
**cryptographically verifies it** (signature against Keycloak's JWKS, issuer, expiry) —
no engine in the byte path, safe even against a compromised engine.

Flow:
  1. verify the user's token            -> subject
  2. ask OPA about the dataset id -> {allow, prefix}: `vend` to read (the dataset's `read`
     grant), `vend_write` to write (its `write` grant), `vend_delete` to delete (its `delete`
     grant). OPA fetches the names the person holds grants through and the folder's grants and prefix
     from governance
  3. on allow: AssumeRole on `blob-vendor` (read: get and list), `blob-writer` (write: put
     and delete, no get, WHITEPAPER 4.2) or `blob-deleter` (delete: list and delete, no get
     or put) with an inline session policy scoped to that prefix
     (the role permits datasets/*; the session policy narrows; the client cannot widen it)
     -> per-dataset temp credentials
  4. have governance log the credential against the person's current session (PROVENANCE.md
     4.1); when the log refuses or cannot be reached, refuse the request
  5. return the scoped credentials; the client reads or writes those objects directly in RGW.

OPA denies an unknown dataset exactly as a denied one, so the broker reveals nothing about
which datasets exist.
"""
import json
import os
import re

import boto3
import jwt
import requests
from botocore.config import Config
from flask import Flask, jsonify, request

KEYCLOAK_JWKS = os.environ["KEYCLOAK_JWKS"]
KEYCLOAK_ISS = os.environ["KEYCLOAK_ISS"]
EXPECTED_AZP = os.environ.get("EXPECTED_AZP", "trino")
# The broker accepts only tokens issued for it (keycloak/setup.py): `scope=openid aud-broker`.
AUDIENCE = os.environ.get("TOKEN_AUDIENCE", "broker")
OPA_BLOB = os.environ["OPA_BLOB_URL"]  # .../v1/data/lakehouse/blob
RGW_ENDPOINT = os.environ["RGW_ENDPOINT"]
BLOB_ROLE_ARN = os.environ["BLOB_ROLE_ARN"]
BLOB_WRITE_ROLE_ARN = os.environ["BLOB_WRITE_ROLE_ARN"]
BLOB_DELETE_ROLE_ARN = os.environ["BLOB_DELETE_ROLE_ARN"]
BUCKET = os.environ["BUCKET"]
BROKER_KEY = os.environ["BLOB_BROKER_KEY"]
BROKER_SECRET = os.environ["BLOB_BROKER_SECRET"]
TTL = int(os.environ.get("CRED_TTL_SECONDS", "900"))
# The access log, on governance's internal listener, which knows the broker by its client
# certificate (governance/pki.py).
GOVERNANCE_INTERNAL = os.environ["GOVERNANCE_INTERNAL_URL"]
PKI = os.environ.get("PKI_DIR", "/pki")
# A dataset id is a tenant-qualified name (e.g. projx/public).
ID_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")

_jwks = jwt.PyJWKClient(KEYCLOAK_JWKS)
_http = requests.Session()
_sts = boto3.client(
    "sts", endpoint_url=RGW_ENDPOINT, aws_access_key_id=BROKER_KEY,
    aws_secret_access_key=BROKER_SECRET, region_name="us-east-1",
    config=Config(signature_version="s3v4"),
)

app = Flask(__name__)


# NOTE: verify_user + authed_user are duplicated in the other service (governance/broker) —
# separate container images, no shared module. Keep the two copies in sync.
def verify_user(token):
    """Cryptographically verify the caller's own Keycloak token -> its claims. PyJWT enforces
    signature, exp, issuer and audience; we add azp (the token must have been issued through our
    login client, not some other realm client). Groups are not read from the token: OPA gets
    them from governance."""
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=KEYCLOAK_ISS, audience=AUDIENCE)
    if claims.get("azp") != EXPECTED_AZP:
        raise jwt.InvalidTokenError(f"unexpected azp {claims.get('azp')!r}")
    return claims


def subject_of(claims):
    return claims.get("principal_name") or claims.get("preferred_username") or claims.get("sub")


def authed_user():
    """Verify the request's bearer token. Returns (claims, None) on success, or
    (None, error_response) for the caller to return as-is."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "missing bearer token"}), 401)
    try:
        return verify_user(auth[7:]), None
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return None, (jsonify({"error": "invalid token"}), 401)


def opa_vend(subject, dataset, mode):
    """OPA's {allow, prefix} for this subject reading or writing this dataset."""
    rule = {"write": "vend_write", "delete": "vend_delete"}.get(mode, "vend")
    r = _http.post(f"{OPA_BLOB}/{rule}", json={"input": {"subject": subject, "dataset": dataset}},
                   timeout=5)
    r.raise_for_status()
    return r.json().get("result") or {"allow": False}


def log_access(claims, dataset, mode, expiration):
    """Have governance log this credential for the caller. Raises when the log refuses or cannot
    be reached: a credential that is not logged would be missing from what the person's
    outputs may derive from."""
    _http.post(f"{GOVERNANCE_INTERNAL}/internal/accesses", timeout=5,
               cert=(f"{PKI}/client.crt", f"{PKI}/client.key"), verify=f"{PKI}/ca.crt",
               json={"person": subject_of(claims), "sub": claims.get("sub") or "",
                     "sid": claims.get("sid") or "",
                     "entries": [{"dataset": dataset, "kind": "files", "mode": mode,
                                  "expires": int(expiration.timestamp() * 1000)}]}
               ).raise_for_status()


def session_policy(prefix, mode):
    if mode == "delete":
        return json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:DeleteObject"],
             "Resource": [f"arn:aws:s3:::{BUCKET}/{prefix}*"]},
            {"Effect": "Allow", "Action": ["s3:ListBucket"],
             "Resource": [f"arn:aws:s3:::{BUCKET}"],
             "Condition": {"StringLike": {"s3:prefix": [f"{prefix}*"]}}},
        ]})
    if mode == "write":
        return json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Resource": [f"arn:aws:s3:::{BUCKET}/{prefix}*"],
             "Action": ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload",
                        "s3:ListMultipartUploadParts"]},
        ]})
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": [f"arn:aws:s3:::{BUCKET}/{prefix}*"]},
        {"Effect": "Allow", "Action": ["s3:ListBucket"],
         "Resource": [f"arn:aws:s3:::{BUCKET}"],
         "Condition": {"StringLike": {"s3:prefix": [f"{prefix}*"]}}},
    ]})


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/vend")
def vend():
    claims, err = authed_user()
    if err:
        return err
    subject = subject_of(claims)

    body = request.get_json(silent=True) or {}
    dataset, mode = body.get("dataset"), body.get("mode", "read")
    if not isinstance(dataset, str) or len(dataset) > 200 or not ID_RE.match(dataset):
        return jsonify({"error": "invalid dataset id"}), 400
    if mode not in ("read", "write", "delete"):
        return jsonify({"error": "mode must be read, write or delete"}), 400
    decision = opa_vend(subject, dataset, mode)
    if decision.get("allow") is not True:
        app.logger.info("DENY %s subject=%s dataset=%s", mode, subject, dataset)
        return jsonify({"error": "forbidden"}), 403

    # Governance confined the prefix at registration; it becomes an STS ARN below, so
    # re-check rather than trust it.
    prefix = decision.get("prefix", "")
    if not (prefix.startswith("datasets/") and prefix.endswith("/") and ".." not in prefix):
        app.logger.error("refusing unconfined prefix for %s: %r", dataset, prefix)
        return jsonify({"error": "internal error"}), 500

    cr = _sts.assume_role(
        # STS caps the session-name length; truncate so a long username can't fail AssumeRole.
        RoleArn={"write": BLOB_WRITE_ROLE_ARN, "delete": BLOB_DELETE_ROLE_ARN}.get(mode, BLOB_ROLE_ARN),
        RoleSessionName=f"blob-{subject}"[:32],
        Policy=session_policy(prefix, mode), DurationSeconds=TTL,
    )["Credentials"]
    try:
        log_access(claims, dataset, mode, cr["Expiration"])
    except requests.RequestException as e:
        app.logger.warning("not logged, refusing %s subject=%s dataset=%s: %s", mode, subject, dataset, e)
        return jsonify({"error": "service unavailable"}), 503
    app.logger.info("VEND %s subject=%s dataset=%s prefix=%s", mode, subject, dataset, prefix)
    return jsonify({
        "access_key_id": cr["AccessKeyId"],
        "secret_access_key": cr["SecretAccessKey"],
        "session_token": cr["SessionToken"],
        "expiration": cr["Expiration"].isoformat(),
        "endpoint": RGW_ENDPOINT,
        "bucket": BUCKET,
        "prefix": prefix,
        "mode": mode,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9100)
