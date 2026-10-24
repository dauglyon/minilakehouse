"""
seed/ingest-demo.py — a governed ingest: write first, publish after, with no storage admin key.

As alice, a member and the steward of `jgi`: ask the broker for a write credential for a folder
in jgi's space that nothing has written yet. The credential makes the folder an entry, not
yet published, which jgi's members read through the space's grants; the upload goes straight
to storage, and the bucket notification makes the entry `live`. Then publish it: give it a
description and grants of its own (docs/HANDOFF-2026-10-22-groups.md section 3), which only a
steward of the space's group may do. Run in-network so the token issuer matches what
governance and the broker validate:

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
FOLDER = "jgi/projz"


def token(user, audience):
    r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                                "client_secret": "trino-secret",
                                "username": user, "password": user,
                                "scope": f"openid aud-{audience}"})
    r.raise_for_status()
    return r.json()["access_token"]


def main():
    # 1. a write credential for the folder only (put and delete, no get), then the upload
    c = requests.post(f"{BROKER}/vend", headers={"Authorization": f"Bearer {token('alice', 'broker')}"},
                      json={"dataset": FOLDER, "mode": "write"})
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

    # 2. publish it, as a steward of jgi: a description, and projw may see that it exists
    r = requests.patch(f"{GOV}/datasets/{FOLDER}", headers={"Authorization": f"Bearer {token('alice', 'governance')}"},
                       json={"description": "projz ingested dataset", "describe": ["projw"]})
    print("publish:", r.status_code, r.json())
    r.raise_for_status()


if __name__ == "__main__":
    main()
