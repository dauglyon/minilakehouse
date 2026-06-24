"""
seed/ingest-demo.py — a governed ingest (Phase 3: register-at-ingest).

Shows how a NEW dataset is born: a steward uploads its objects, then registers it WITH ITS
MEANING (name, prefix, description, grants — the part only a human can supply). Run it
in-network (service hostnames, so the token issuer matches what governance validates):

    docker compose exec governance python /seed/ingest-demo.py

It authenticates as `alice` (a member of the `stewards` group), uploads two blobs under
datasets/projz/, then POSTs the registration to governance. Governance authorizes via OPA
(the `stewards` capability in the published bundle), inserts the dataset as `pending`, and
reconciles it to `live`. After OPA's next bundle poll, alice can discover and read projz
through the broker — born WITH meaning, not guessed from storage.
"""
import os

import boto3
import requests
from botocore.config import Config

KC = os.environ.get("KC_TOKEN_URL",
                    "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token")
GOV = os.environ.get("GOVERNANCE_URL", "http://governance:8000")
RGW = os.environ.get("RGW_ENDPOINT", "http://ceph:8080")
BUCKET = os.environ.get("S3_BUCKET", "lakehouse")
AK = os.environ.get("RGW_ACCESS_KEY", "test_access_key")
SK = os.environ.get("RGW_SECRET_KEY", "test_access_secret")
PREFIX = "datasets/projz/"


def token(user):
    r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                                "client_secret": "trino-secret",
                                "username": user, "password": user})
    r.raise_for_status()
    return r.json()["access_token"]


def main():
    # 1. the steward writes the dataset's objects (the ingest write path)
    s3 = boto3.client("s3", endpoint_url=RGW, aws_access_key_id=AK, aws_secret_access_key=SK,
                      region_name="us-east-1", config=Config(signature_version="s3v4"))
    for i in (1, 2):
        s3.put_object(Bucket=BUCKET, Key=f"{PREFIX}part-{i}.txt",
                      Body=f"projz row {i}\n".encode())
    print(f"uploaded 2 objects under {PREFIX}")

    # 2. register the dataset WITH ITS MEANING, as a steward
    tok = token("alice")
    r = requests.post(f"{GOV}/datasets", headers={"Authorization": f"Bearer {tok}"}, json={
        "name": "projz",
        "prefix": PREFIX,
        "description": "projz ingested dataset",
        "visibility": ["jgi-writers"],
        "access": ["jgi-writers"],
    })
    print("register:", r.status_code, r.json())
    r.raise_for_status()


if __name__ == "__main__":
    main()
