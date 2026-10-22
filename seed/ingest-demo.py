"""
seed/ingest-demo.py — a governed ingest (register-at-ingest), with no storage admin key.

As steward `alice`: register the dataset WITH ITS MEANING (prefix, description, grants — the
part only a human supplies; the id derives from the prefix), then ask the broker for a write
credential, which the dataset's `write` grant allows, and upload with it. The dataset stays
`pending` until its first object lands; the bucket notification then makes it `live`. Run
in-network so the token issuer matches what governance and the broker validate:

    docker compose exec governance python /seed/ingest-demo.py
"""
import os

import boto3
import requests
from botocore.config import Config

KC = os.environ.get("KC_TOKEN_URL",
                    "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token")
GOV = os.environ.get("GOVERNANCE_URL", "http://governance:8000")
BROKER = os.environ.get("BROKER_URL", "http://broker:9100")
PREFIX = "datasets/projz/"


def token(user):
    r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                                "client_secret": "trino-secret",
                                "username": user, "password": user})
    r.raise_for_status()
    return r.json()["access_token"]


def main():
    h = {"Authorization": f"Bearer {token('alice')}"}
    # 1. register the dataset WITH ITS MEANING, as a steward whose group owns datasets/projz/
    r = requests.post(f"{GOV}/datasets", headers=h, json={
        "prefix": PREFIX,
        "description": "projz ingested dataset",
        "visibility": ["jgi-writers"],
        "access": ["jgi-writers"],
        "write": ["jgi-writers"],
    })
    print("register:", r.status_code, r.json())   # -> id "projz" (derived from the prefix)
    if r.status_code != 409:
        r.raise_for_status()

    # 2. a write credential for that folder only (put and delete, no get), then the upload
    c = requests.post(f"{BROKER}/vend", headers=h, json={"dataset": "projz", "mode": "write"})
    c.raise_for_status()
    c = c.json()
    s3 = boto3.client("s3", endpoint_url=c["endpoint"], aws_access_key_id=c["access_key_id"],
                      aws_secret_access_key=c["secret_access_key"],
                      aws_session_token=c["session_token"], region_name="us-east-1",
                      config=Config(signature_version="s3v4"))
    for i in (1, 2):
        s3.put_object(Bucket=c["bucket"], Key=f"{c['prefix']}part-{i}.txt",
                      Body=f"projz row {i}\n".encode())
    print(f"uploaded 2 objects under {c['prefix']} with a write credential")


if __name__ == "__main__":
    main()
