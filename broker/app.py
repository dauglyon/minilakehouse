"""
broker — the blob vending broker (Flow C: blob datasets). The true end-to-end plane.

A client presents its OWN Keycloak token and names a dataset. The broker
**cryptographically verifies it** (signature against Keycloak's JWKS, issuer, expiry) —
no engine in the byte path, safe even against a compromised engine.

Flow:
  1. verify the user's token            -> subject
  2. ask OPA's `vend` rule about the dataset id -> {allow, prefix}; OPA fetches the
     person's groups and the dataset's grants and registered prefix from governance
  3. on allow: AssumeRole on `blob-vendor` with an inline session policy scoped to that
     prefix (the role permits datasets/*; the session policy narrows; the client cannot
     widen it) -> per-dataset temp credentials
  4. return the scoped credentials; the client reads those objects directly from RGW.

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
OPA_URL = os.environ["OPA_URL"]
RGW_ENDPOINT = os.environ["RGW_ENDPOINT"]
BLOB_ROLE_ARN = os.environ["BLOB_ROLE_ARN"]
BUCKET = os.environ["BUCKET"]
BROKER_KEY = os.environ["BLOB_BROKER_KEY"]
BROKER_SECRET = os.environ["BLOB_BROKER_SECRET"]
TTL = int(os.environ.get("CRED_TTL_SECONDS", "900"))
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
    """Cryptographically verify the caller's own Keycloak token -> subject. PyJWT enforces
    signature + exp; we add issuer and azp (the token must have been issued through our login
    client, not some other realm client). Groups are not read from the token: OPA gets them
    from governance."""
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=KEYCLOAK_ISS,
                        options={"verify_aud": False})
    if claims.get("azp") != EXPECTED_AZP:
        raise jwt.InvalidTokenError(f"unexpected azp {claims.get('azp')!r}")
    return claims.get("principal_name") or claims.get("preferred_username") or claims.get("sub")


def authed_user():
    """Verify the request's bearer token. Returns (subject, None) on success, or
    (None, error_response) for the caller to return as-is."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "missing bearer token"}), 401)
    try:
        return verify_user(auth[7:]), None
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return None, (jsonify({"error": "invalid token"}), 401)


def opa_vend(subject, dataset):
    """OPA's {allow, prefix} for this subject reading this dataset."""
    r = _http.post(OPA_URL, json={"input": {"subject": subject, "dataset": dataset}}, timeout=5)
    r.raise_for_status()
    return r.json().get("result") or {"allow": False}


def session_policy(prefix):
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
    subject, err = authed_user()
    if err:
        return err

    dataset = (request.get_json(silent=True) or {}).get("dataset")
    if not isinstance(dataset, str) or len(dataset) > 200 or not ID_RE.match(dataset):
        return jsonify({"error": "invalid dataset id"}), 400
    decision = opa_vend(subject, dataset)
    if decision.get("allow") is not True:
        app.logger.info("DENY subject=%s dataset=%s", subject, dataset)
        return jsonify({"error": "forbidden"}), 403

    # Governance confined the prefix at registration; it becomes an STS ARN below, so
    # re-check rather than trust it.
    prefix = decision.get("prefix", "")
    if not (prefix.startswith("datasets/") and prefix.endswith("/") and ".." not in prefix):
        app.logger.error("refusing unconfined prefix for %s: %r", dataset, prefix)
        return jsonify({"error": "internal error"}), 500

    cr = _sts.assume_role(
        # STS caps the session-name length; truncate so a long username can't fail AssumeRole.
        RoleArn=BLOB_ROLE_ARN, RoleSessionName=f"blob-{subject}"[:32],
        Policy=session_policy(prefix), DurationSeconds=TTL,
    )["Credentials"]
    app.logger.info("VEND subject=%s dataset=%s prefix=%s", subject, dataset, prefix)
    return jsonify({
        "access_key_id": cr["AccessKeyId"],
        "secret_access_key": cr["SecretAccessKey"],
        "session_token": cr["SessionToken"],
        "expiration": cr["Expiration"].isoformat(),
        "endpoint": RGW_ENDPOINT,
        "bucket": BUCKET,
        "prefix": prefix,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9100)
