"""
rgw_setup.py — a one-shot, admin-credentialed RGW configuration step so the long-lived
governance service never holds the RGW admin key.

It does the two things that need bucket-owner/admin rights:
  1. (required) grant `governance-reader` ListBucket on datasets/* via a bucket policy, so
     reconcile can list dataset prefixes with a least-privilege static credential;
  2. (best-effort) wire bucket notifications -> governance /events.

Idempotent. Run as a compose one-shot before governance starts.
"""
import json
import os
import time

import boto3
from botocore.config import Config

RGW = os.environ.get("RGW_ENDPOINT", "http://ceph:8080")
AK, SK = os.environ["RGW_ACCESS_KEY"], os.environ["RGW_SECRET_KEY"]  # admin
BUCKET = os.environ.get("S3_BUCKET", "lakehouse")
READER = os.environ.get("GOVERNANCE_READER_UID", "governance-reader")
READER_KEY = os.environ.get("GOVERNANCE_READER_KEY", "")
READER_SECRET = os.environ.get("GOVERNANCE_READER_SECRET", "")
EVENTS = os.environ.get("EVENTS_ENDPOINT", "http://governance:8000/events")
TOPIC = os.environ.get("EVENTS_TOPIC", "dataset-events")
_cfg = Config(signature_version="s3v4", connect_timeout=5, read_timeout=5,
              retries={"max_attempts": 3})


def main():
    s3 = boto3.client("s3", endpoint_url=RGW, aws_access_key_id=AK,
                      aws_secret_access_key=SK, region_name="us-east-1", config=_cfg)
    # Required: the reader needs only ListBucket on datasets/* (stats come from the listing).
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": [f"arn:aws:iam:::user/{READER}"]},
        "Action": ["s3:ListBucket"], "Resource": [f"arn:aws:s3:::{BUCKET}"],
        "Condition": {"StringLike": {"s3:prefix": ["datasets/*"]}},
    }]}))
    print(f"bucket policy set: {READER} may ListBucket datasets/*")

    # Best-effort: push object create/remove under datasets/ to governance /events. If RGW
    # lacks the notifications API, the reconcile timer still keeps freshness honest.
    try:
        sns = boto3.client("sns", endpoint_url=RGW, aws_access_key_id=AK,
                           aws_secret_access_key=SK, region_name="us-east-1", config=_cfg)
        arn = sns.create_topic(Name=TOPIC, Attributes={"push-endpoint": EVENTS})["TopicArn"]
        s3.put_bucket_notification_configuration(Bucket=BUCKET, NotificationConfiguration={
            "TopicConfigurations": [{
                "Id": "dataset-freshness", "TopicArn": arn,
                "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "datasets/"}]}},
            }]})
        print(f"notifications wired: {arn} -> {EVENTS}")
    except Exception as e:  # noqa: BLE001
        print(f"WARN: notification wiring failed (timer reconcile still works): {e}")

    # Post-condition: don't exit 0 until governance-reader can ACTUALLY list datasets/. The
    # reader user is created asynchronously by sts-bootstrap, and a UID/key mismatch would
    # otherwise wedge governance silently (empty discovery). This makes `depends_on:
    # rgw-setup completed` a real guarantee, not a timing accident.
    reader = boto3.client("s3", endpoint_url=RGW, aws_access_key_id=READER_KEY,
                          aws_secret_access_key=READER_SECRET, region_name="us-east-1", config=_cfg)
    for _ in range(30):
        try:
            reader.list_objects_v2(Bucket=BUCKET, Prefix="datasets/", MaxKeys=1)
            print("verified: governance-reader can list datasets/")
            return
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1)
    raise SystemExit(f"governance-reader cannot list datasets/ (user or policy not ready): {last}")


if __name__ == "__main__":
    main()
