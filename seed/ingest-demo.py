"""
seed/ingest-demo.py — a governed ingest (register-at-ingest).

As steward `alice`, upload a dataset's objects then register it WITH ITS MEANING (name,
prefix, description, grants — the part only a human supplies). Run in-network so the token
issuer matches what governance validates:

    docker compose exec governance python /seed/ingest-demo.py
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
# The steward's WRITE step uses the dev admin key — deliberately its OWN env var, not
# RGW_ACCESS_KEY, so running this inside the governance container does NOT inherit
# governance's read-only reader creds. (A real steward would write with a scoped credential.)
AK = os.environ.get("INGEST_S3_KEY", "test_access_key")
SK = os.environ.get("INGEST_S3_SECRET", "test_access_secret")
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
