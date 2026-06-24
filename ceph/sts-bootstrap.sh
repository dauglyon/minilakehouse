#!/bin/sh
# Ceph RGW STS bootstrap — creates the role Polaris assumes to vend per-table creds.
# Runs INSIDE the ceph container (radosgw-admin). The Polaris server, using its
# ambient RGW admin key (root/test_access_key), calls sts:AssumeRole on this role at
# loadTable; RGW returns a temporary credential that Polaris further subscopes (via a
# session policy) to the one table's prefix.
set -e

ROLE="${ROLE:-polaris-vendor}"
BUCKET="${BUCKET:-lakehouse}"
# The warehouse lives under this sub-prefix (must match the catalog's
# default-base-location in polaris/bootstrap.sh). Scoping the role here means a
# vended credential whose session policy is somehow missing/buggy can still only
# reach the warehouse — not the whole bucket, and not future blob datasets.
WHPREFIX="${WAREHOUSE_PREFIX:-warehouse}"
# The principal Polaris authenticates as when calling AssumeRole. RGW admin user
# `root` has no tenant, so its ARN has an empty account field.
ASSUMING_ARN="${ASSUMING_ARN:-arn:aws:iam:::user/root}"

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["'"$ASSUMING_ARN"'"]},"Action":["sts:AssumeRole"]}]}'
# Least-privilege: only the object/bucket actions the catalog needs (no s3:* — which
# would include bucket-policy/ACL/delete-bucket), and object actions confined to the
# warehouse prefix. Polaris's per-table session policy narrows further at vend time.
PERM='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::'"$BUCKET"'/'"$WHPREFIX"'/*"]},{"Effect":"Allow","Action":["s3:ListBucket","s3:GetBucketLocation"],"Resource":["arn:aws:s3:::'"$BUCKET"'"],"Condition":{"StringLike":{"s3:prefix":["'"$WHPREFIX"'/*"]}}}]}'

echo ">>> creating role $ROLE (trust: $ASSUMING_ARN)"
radosgw-admin role create --role-name="$ROLE" --assume-role-policy-doc="$TRUST" 2>/dev/null \
  || echo "    role already exists (OK)"

echo ">>> attaching s3 permission policy"
radosgw-admin role-policy put --role-name="$ROLE" --policy-name=s3access --policy-doc="$PERM"

echo ">>> granting the assuming user (root) the ability to call AssumeRole"
radosgw-admin caps add --uid=root --caps="roles=*" >/dev/null 2>&1 || true

echo ">>> role $ROLE:"
radosgw-admin role get --role-name="$ROLE"

# ---------------------------------------------------------------------------
# Blob plane (Phase 1, Flow C): the role the vending BROKER assumes to mint
# per-dataset credentials. The broker authenticates as the dedicated `blob-broker`
# user (holding no S3 rights of its own — only the ability to assume this role), and
# narrows to one dataset prefix per request via an inline session policy. The role is
# read-only and confined to the blob area `datasets/*` — it cannot reach the warehouse.
# ---------------------------------------------------------------------------
BLOB_ROLE="${BLOB_ROLE:-blob-vendor}"
BLOB_PREFIX="${BLOB_PREFIX:-datasets}"
BLOB_BROKER_UID="${BLOB_BROKER_UID:-blob-broker}"
BLOB_BROKER_KEY="${BLOB_BROKER_KEY:-blob-broker}"
BLOB_BROKER_SECRET="${BLOB_BROKER_SECRET:-blob-broker-secret}"
BLOB_ASSUMING_ARN="arn:aws:iam:::user/${BLOB_BROKER_UID}"

echo ">>> creating broker user ${BLOB_BROKER_UID}"
radosgw-admin user create --uid="${BLOB_BROKER_UID}" --display-name="Blob Broker" \
  --access-key="${BLOB_BROKER_KEY}" --secret-key="${BLOB_BROKER_SECRET}" 2>/dev/null \
  || echo "    broker user exists (OK)"
radosgw-admin caps add --uid="${BLOB_BROKER_UID}" --caps="roles=*" >/dev/null 2>&1 || true

BLOB_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["'"$BLOB_ASSUMING_ARN"'"]},"Action":["sts:AssumeRole"]}]}'
BLOB_PERM='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::'"$BUCKET"'/'"$BLOB_PREFIX"'/*"]},{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::'"$BUCKET"'"],"Condition":{"StringLike":{"s3:prefix":["'"$BLOB_PREFIX"'/*"]}}}]}'

echo ">>> creating blob role ${BLOB_ROLE} (trust: ${BLOB_ASSUMING_ARN})"
radosgw-admin role create --role-name="${BLOB_ROLE}" --assume-role-policy-doc="$BLOB_TRUST" 2>/dev/null \
  || echo "    blob role exists (OK)"
radosgw-admin role-policy put --role-name="${BLOB_ROLE}" --policy-name=blobread --policy-doc="$BLOB_PERM"
echo ">>> blob role ${BLOB_ROLE}:"
radosgw-admin role get --role-name="${BLOB_ROLE}"
