"""
broker — the blob vending broker (Flow C: blob datasets). The true end-to-end plane.

A client presents its OWN Keycloak token and names a folder. The broker
**cryptographically verifies it** (signature against Keycloak's JWKS, issuer, expiry) —
no engine in the byte path, safe even against a compromised engine.

Flow:
  1. verify the user's token            -> subject
  2. ask OPA about the folder -> {allow, prefix}: `vend` to read (the folder's `read` grant),
     `vend_write` to write (its `write` grant), `vend_delete` to delete (its `delete` grant).
     OPA fetches the names the person holds grants through and the folder's grants and prefix
     from governance. A credential covers everything under the folder unless the request says
     `"recursive": false`, when it covers only the files directly in it; no recursive one is
     issued for a folder with a published dataset under it
     (docs/HANDOFF-2026-10-22-groups.md section 3)
  3. on allow: AssumeRole on `blob-vendor` (read: get and list), `blob-writer` (write: put
     and delete, no get, WHITEPAPER 4.2) or `blob-deleter` (delete: list and delete, no get
     or put) with an inline session policy scoped to that prefix
     (the role permits datasets/*; the session policy narrows; the client cannot widen it)
     -> per-dataset temp credentials
  4. have governance log the credential against the person's current session (PROVENANCE.md
     4.1); when the log refuses or cannot be reached, refuse the request
  5. return the scoped credentials; the client reads or writes those objects directly in RGW.

OPA denies an unknown folder exactly as a denied one, so the broker reveals nothing about
which folders exist.

It also moves folders (POST /transfers, docs/HANDOFF-2026-10-22-groups.md section 1): from a
personal space or a plain group's space into another group's space, by server-side copy and
then deleting the originals, under a credential naming only the two folders.
"""
import json
import os
import re

import boto3
import jwt
import requests
from botocore.config import Config
from botocore.exceptions import ClientError
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
BLOB_MOVE_ROLE_ARN = os.environ["BLOB_MOVE_ROLE_ARN"]
BUCKET = os.environ["BUCKET"]
BROKER_KEY = os.environ["BLOB_BROKER_KEY"]
BROKER_SECRET = os.environ["BLOB_BROKER_SECRET"]
TTL = int(os.environ.get("CRED_TTL_SECONDS", "900"))
# The access log, on governance's internal listener, which knows the broker by its client
# certificate (governance/pki.py).
GOVERNANCE_INTERNAL = os.environ["GOVERNANCE_INTERNAL_URL"]
PKI = os.environ.get("PKI_DIR", "/pki")
# A folder is named as a dataset id is: its path under datasets/, beginning with the group whose
# space holds it (e.g. jgi/public).
ID_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
# The refusal for a recursive request over a folder with a published dataset under it. It names
# nothing inside the folder, and goes only to someone the folder is otherwise open to.
RECURSIVE_REFUSED = ("{prefix} contains published datasets, so it can't be opened recursively. "
                     'Open it with "recursive": false for the files directly in it, or open its '
                     "subfolders and datasets separately.")

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


def opa_vend(subject, folder, mode, recursive):
    """OPA's {allow, prefix} for this subject reading, writing or deleting in this folder."""
    rule = {"write": "vend_write", "delete": "vend_delete"}.get(mode, "vend")
    r = _http.post(f"{OPA_BLOB}/{rule}", json={"input": {"subject": subject, "dataset": folder,
                                                         "recursive": recursive}}, timeout=5)
    r.raise_for_status()
    return r.json().get("result") or {"allow": False}


def log_access(claims, folder, mode, recursive, expiration):
    """Have governance log this credential for the caller, against the folder it covers.
    Raises when the log refuses or cannot be reached: a credential that is not logged would be
    missing from what the person's outputs may derive from."""
    _http.post(f"{GOVERNANCE_INTERNAL}/internal/accesses", timeout=5,
               cert=(f"{PKI}/client.crt", f"{PKI}/client.key"), verify=f"{PKI}/ca.crt",
               json={"person": subject_of(claims), "sub": claims.get("sub") or "",
                     "sid": claims.get("sid") or "",
                     "entries": [{"dataset": folder, "kind": "files", "mode": mode, "recursive": recursive,
                                  "expires": int(expiration.timestamp() * 1000)}]}
               ).raise_for_status()


def session_policy(prefix, mode, recursive=True):
    if not recursive:
        return direct_policy(prefix, mode)
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


def direct_policy(prefix, mode):
    """A credential for the files directly in a folder: objects matching <prefix>* but not
    <prefix>*/*, and listing only the folder itself one level at a time (prefix exactly the
    folder, delimiter `/`), which shows its files and its subfolders' names. Its size is the
    same for every folder. Tried on Ceph on 2026-10-24 (docs/HANDOFF-2026-10-22-groups.md
    section 3)."""
    actions = {"read": ["s3:GetObject"], "delete": ["s3:DeleteObject"],
               "write": ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload",
                         "s3:ListMultipartUploadParts"]}[mode]
    statements = [
        {"Effect": "Allow", "Action": actions, "Resource": [f"arn:aws:s3:::{BUCKET}/{prefix}*"]},
        {"Effect": "Deny", "Action": actions, "Resource": [f"arn:aws:s3:::{BUCKET}/{prefix}*/*"]},
    ]
    if mode != "write":   # a write credential never lists (WHITEPAPER 4.2)
        statements.append({"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [f"arn:aws:s3:::{BUCKET}"],
                           "Condition": {"StringEquals": {"s3:prefix": [prefix], "s3:delimiter": ["/"]}}})
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


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
    folder, mode, recursive = body.get("folder"), body.get("mode", "read"), body.get("recursive", True)
    if not isinstance(folder, str) or len(folder) > 200 or not ID_RE.match(folder):
        return jsonify({"error": "invalid folder"}), 400
    if mode not in ("read", "write", "delete") or not isinstance(recursive, bool):
        return jsonify({"error": "mode must be read, write or delete, and recursive a boolean"}), 400
    decision = opa_vend(subject, folder, mode, recursive)
    if decision.get("allow") is not True:
        app.logger.info("DENY %s subject=%s folder=%s recursive=%s", mode, subject, folder, recursive)
        if decision.get("recursive_refused") is True:
            return jsonify({"error": RECURSIVE_REFUSED.format(prefix=f"datasets/{folder}/")}), 403
        if isinstance(decision.get("moved_to"), str):
            return jsonify({"error": f"{folder} has moved to {decision['moved_to']}"}), 403
        return jsonify({"error": "forbidden"}), 403

    # Governance confines every folder; the prefix becomes an STS ARN below, so re-check rather
    # than trust it.
    prefix = decision.get("prefix", "")
    if not (prefix.startswith("datasets/") and prefix.endswith("/") and ".." not in prefix):
        app.logger.error("refusing unconfined prefix for %s: %r", folder, prefix)
        return jsonify({"error": "internal error"}), 500

    cr = _sts.assume_role(
        # STS caps the session-name length; truncate so a long username can't fail AssumeRole.
        RoleArn={"write": BLOB_WRITE_ROLE_ARN, "delete": BLOB_DELETE_ROLE_ARN}.get(mode, BLOB_ROLE_ARN),
        RoleSessionName=f"blob-{subject}"[:32],
        Policy=session_policy(prefix, mode, recursive), DurationSeconds=TTL,
    )["Credentials"]
    try:
        log_access(claims, folder, mode, recursive, cr["Expiration"])
    except requests.RequestException as e:
        app.logger.warning("not logged, refusing %s subject=%s folder=%s: %s", mode, subject, folder, e)
        return jsonify({"error": "service unavailable"}), 503
    app.logger.info("VEND %s subject=%s folder=%s prefix=%s recursive=%s", mode, subject, folder, prefix, recursive)
    return jsonify({
        "access_key_id": cr["AccessKeyId"],
        "secret_access_key": cr["SecretAccessKey"],
        "session_token": cr["SessionToken"],
        "expiration": cr["Expiration"].isoformat(),
        "endpoint": RGW_ENDPOINT,
        "bucket": BUCKET,
        "prefix": prefix,
        "mode": mode,
        "recursive": recursive,
    })


def _internal(path, body):
    r = _http.post(f"{GOVERNANCE_INTERNAL}{path}", timeout=30, json=body,
                   cert=(f"{PKI}/client.crt", f"{PKI}/client.key"), verify=f"{PKI}/ca.crt")
    return r.status_code, (r.json() if r.content else {})


@app.post("/transfers")
def transfer():
    # Move a folder, {"from", "to"}: OPA's allow_transfer decides (the person whose personal space
    # it is, or an owner or admin of the plain group whose space holds it; a member or above of
    # the receiving group). Governance then checks the destination is empty, lists the old
    # folder, and logs the move as a read of the old folder and a write of the new one in a
    # session of its own, so the copies carry what the old folder carried (PROVENANCE.md 6, rule
    # 2). The broker copies exactly the files governance listed, server-side and each only while
    # its ETag matches, so a file written into the old folder since is left behind rather than
    # copied without its sources; it deletes the originals once all are copied, and has governance
    # record the old entry as moved to the new one before deleting the originals. A failure before
    # that leaves the old folder whole: a changed file, or governance refusing to record the move,
    # removes the copies made so far, and governance is told the move stopped.
    claims, err = authed_user()
    if err:
        return err
    subject = subject_of(claims)
    body = request.get_json(silent=True) or {}
    src, dst = body.get("from"), body.get("to")
    if not all(isinstance(f, str) and len(f) <= 200 and ID_RE.match(f) for f in (src, dst)) or src == dst:
        return jsonify({"error": "from and to must be two folders"}), 400
    r = _http.post(f"{OPA_BLOB}/allow_transfer", json={"input": {"subject": subject, "from": src, "to": dst}},
                   timeout=5)
    r.raise_for_status()
    if r.json().get("result") is not True:
        app.logger.info("DENY transfer subject=%s from=%s to=%s", subject, src, dst)
        return jsonify({"error": "forbidden"}), 403
    old, new = f"datasets/{src}/", f"datasets/{dst}/"
    cr = _sts.assume_role(RoleArn=BLOB_MOVE_ROLE_ARN, RoleSessionName=f"move-{subject}"[:32], DurationSeconds=TTL,
                          Policy=json.dumps({"Version": "2012-10-17", "Statement": [
                              {"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteObject"],
                               "Resource": [f"arn:aws:s3:::{BUCKET}/{old}*"]},
                              {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [f"arn:aws:s3:::{BUCKET}"],
                               "Condition": {"StringLike": {"s3:prefix": [f"{old}*"]}}},
                              {"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"],
                               "Resource": [f"arn:aws:s3:::{BUCKET}/{new}*"]}]}))["Credentials"]
    begun = {}
    try:
        status, begun = _internal("/internal/transfers", {
            "phase": "begin", "person": subject, "sub": claims.get("sub") or "", "sid": claims.get("sid") or "",
            "from": src, "to": dst, "expires": int(cr["Expiration"].timestamp() * 1000)})
        if status != 200:
            return jsonify({"error": begun.get("error", "transfer refused")}), status
        s3 = boto3.client("s3", endpoint_url=RGW_ENDPOINT, aws_access_key_id=cr["AccessKeyId"],
                          aws_secret_access_key=cr["SecretAccessKey"], aws_session_token=cr["SessionToken"],
                          region_name="us-east-1", config=Config(signature_version="s3v4"))
        keys, copied = [f["key"] for f in begun["files"]], []
        try:
            for f in begun["files"]:
                s3.copy_object(Bucket=BUCKET, Key=new + f["key"][len(old):], CopySourceIfMatch=f["etag"],
                               CopySource={"Bucket": BUCKET, "Key": f["key"]})
                copied.append(new + f["key"][len(old):])
        except ClientError as e:
            for k in copied:
                s3.delete_object(Bucket=BUCKET, Key=k)
            _internal("/internal/transfers", {"phase": "abort", "transfer": begun["transfer"]})
            app.logger.info("transfer %s -> %s stopped, a file changed: %s", src, dst, e)
            return jsonify({"error": f"{src} changed during the move; nothing was moved"}), 409
        status, done = _internal("/internal/transfers", {"phase": "done", "transfer": begun["transfer"]})
        if status != 200:
            for k in copied:
                s3.delete_object(Bucket=BUCKET, Key=k)
            _internal("/internal/transfers", {"phase": "abort", "transfer": begun["transfer"]})
            app.logger.info("transfer %s -> %s not recorded, copies removed: %s", src, dst, done)
            return jsonify({"error": done.get("error", "the move was not recorded; nothing was moved")}), 409
        for k in keys:
            s3.delete_object(Bucket=BUCKET, Key=k)
    except (requests.RequestException, boto3.exceptions.Boto3Error, ClientError) as e:
        # Copies may be left at the destination; ending the transfer keeps governance from
        # counting anything written there later as one.
        if "transfer" in begun:
            try:
                _internal("/internal/transfers", {"phase": "abort", "transfer": begun["transfer"]})
            except requests.RequestException:
                pass
        app.logger.warning("transfer %s -> %s failed: %s", src, dst, e)
        return jsonify({"error": "transfer failed"}), 503
    app.logger.info("TRANSFER subject=%s from=%s to=%s objects=%d", subject, src, dst, len(keys))
    return jsonify({"ok": True, "from": src, "to": dst, "objects": len(keys), "transfer": begun["transfer"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9100)
