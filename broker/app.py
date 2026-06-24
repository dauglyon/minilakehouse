"""
broker — the blob vending broker (Phase 1, Flow C). The TRUE end-to-end plane.

A client presents its OWN Keycloak token and names a dataset. Unlike the idp-shim (which
trusts the engine's *assertion* of a user), the broker has the user's real token, so it
**cryptographically verifies it** (signature against Keycloak's JWKS, issuer, expiry) —
no engine in the byte path, safe even against a compromised engine.

Flow:
  1. verify the user's token            -> subject + groups
  2. resolve dataset -> prefix          (the broker's static registry; NOT OPA)
  3. ask OPA the predicate "may S read dataset X?"  -> yes/no   (OPA never enumerates)
  4. on allow: AssumeRole on `blob-vendor` with an inline session policy scoped to the
     dataset's prefix (the role permits datasets/*; the session policy narrows; the
     client cannot widen it) -> per-dataset temp credentials
  5. return the scoped credentials; the client reads those objects directly from RGW.
"""
import json
import os
import re
from urllib.parse import quote

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
GOVERNANCE_URL = os.environ["GOVERNANCE_URL"]
TTL = int(os.environ.get("CRED_TTL_SECONDS", "900"))
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

_jwks = jwt.PyJWKClient(KEYCLOAK_JWKS)
_http = requests.Session()
_sts = boto3.client(
    "sts", endpoint_url=RGW_ENDPOINT, aws_access_key_id=BROKER_KEY,
    aws_secret_access_key=BROKER_SECRET, region_name="us-east-1",
    config=Config(signature_version="s3v4"),
)

app = Flask(__name__)


def verify_user(token):
    """Cryptographically verify the caller's own Keycloak token -> (subject, groups). PyJWT
    enforces signature + exp; we add issuer and azp (the token must have been issued through
    our login client, not some other realm client)."""
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=KEYCLOAK_ISS,
                        options={"verify_aud": False})
    if claims.get("azp") != EXPECTED_AZP:
        raise jwt.InvalidTokenError(f"unexpected azp {claims.get('azp')!r}")
    subject = claims.get("principal_name") or claims.get("preferred_username") or claims.get("sub")
    groups = claims.get("principal_roles") or claims.get("groups") or []
    return subject, groups


def authed_user():
    """Verify the request's bearer token. Returns (subject, groups, None) on success, or
    (None, None, error_response) for the caller to return as-is."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None, (jsonify({"error": "missing bearer token"}), 401)
    try:
        return (*verify_user(auth[7:]), None)
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return None, None, (jsonify({"error": "invalid token"}), 401)


def opa_allows(subject, groups, dataset):
    r = _http.post(OPA_URL, json={"input": {
        "subject": subject, "groups": groups, "action": "read", "dataset": dataset,
    }}, timeout=5)
    r.raise_for_status()
    return r.json().get("result") is True


def resolve_prefix(dataset):
    """Resolve dataset -> prefix from the governance registry (single source of truth).
    The name is URL-encoded so it can't traverse to other governance routes (it's caller
    input)."""
    r = _http.get(f"{GOVERNANCE_URL}/datasets/{quote(dataset, safe='')}", timeout=5)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()["prefix"]


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
    subject, groups, err = authed_user()
    if err:
        return err

    dataset = (request.get_json(silent=True) or {}).get("dataset")
    if not isinstance(dataset, str) or not NAME_RE.match(dataset):
        return jsonify({"error": "invalid dataset name"}), 400
    prefix = resolve_prefix(dataset)
    if prefix is None:
        return jsonify({"error": f"unknown dataset {dataset!r}"}), 404

    if not opa_allows(subject, groups, dataset):
        app.logger.info("DENY subject=%s groups=%s dataset=%s", subject, groups, dataset)
        return jsonify({"error": "forbidden"}), 403

    cr = _sts.assume_role(
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
