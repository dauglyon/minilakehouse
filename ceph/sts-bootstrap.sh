#!/bin/sh
# Ceph RGW STS bootstrap — creates the roles the catalog (Polaris) and the blob broker
# assume to vend scoped, short-lived credentials. Runs INSIDE the ceph container
# (radosgw-admin). radosgw-admin mints roles with a stable empty-account ARN
# (arn:aws:iam:::role/<name>) — unlike the IAM API, which uses a per-instance account id.
set -e

BUCKET="${BUCKET:-lakehouse}"
# The warehouse lives under this sub-prefix (must match the catalog's default-base-location
# in polaris/bootstrap.sh). Confining the role here means a vended credential whose session
# policy is somehow missing still can't reach beyond the warehouse.
WHPREFIX="${WAREHOUSE_PREFIX:-warehouse}"
BLOB_PREFIX="${BLOB_PREFIX:-datasets}"

# Create a role only if absent, then (always, idempotently) attach its policy. A genuine
# create failure is NOT swallowed — it aborts via `set -e` and surfaces in the logs, rather
# than masquerading as "already exists".
ensure_role() {  # name  trust_doc  policy_name  policy_doc
  radosgw-admin role get --role-name="$1" >/dev/null 2>&1 \
    || radosgw-admin role create --role-name="$1" --assume-role-policy-doc="$2"
  radosgw-admin role-policy put --role-name="$1" --policy-name="$3" --policy-doc="$4"
  radosgw-admin role get --role-name="$1"
}

# --- Table plane: the role Polaris assumes to vend per-table creds (warehouse/ only). ---
# RGW admin user `root` has no tenant, so its ARN has an empty account field. Polaris
# narrows further with a per-table session policy at vend time. Least-privilege: only the
# object/bucket actions the catalog needs (no s3:*), objects confined to warehouse/.
POLARIS_ROLE="${ROLE:-polaris-vendor}"
POLARIS_TRUST=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Principal":{"AWS":["arn:aws:iam:::user/root"]},"Action":["sts:AssumeRole"]}]}
JSON
)
POLARIS_PERM=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow",
   "Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],
   "Resource":["arn:aws:s3:::${BUCKET}/${WHPREFIX}/*"]},
  {"Effect":"Allow","Action":["s3:ListBucket","s3:GetBucketLocation"],
   "Resource":["arn:aws:s3:::${BUCKET}"],
   "Condition":{"StringLike":{"s3:prefix":["${WHPREFIX}/*"]}}}]}
JSON
)
echo ">>> ensuring role ${POLARIS_ROLE}"
radosgw-admin caps add --uid=root --caps="roles=*" >/dev/null 2>&1 || true  # grant AssumeRole (no-op if present)
ensure_role "$POLARIS_ROLE" "$POLARIS_TRUST" s3access "$POLARIS_PERM"

# --- Blob plane (Flow C): the role the broker assumes to vend per-dataset creds. The broker
# authenticates as `blob-broker` (no S3 rights of its own — only AssumeRole) and narrows to
# one dataset prefix per request via a session policy. The role is read-only, datasets/ only. ---
BLOB_ROLE="${BLOB_ROLE:-blob-vendor}"
BLOB_UID="${BLOB_BROKER_UID:-blob-broker}"
BLOB_KEY="${BLOB_BROKER_KEY:-blob-broker}"
BLOB_SECRET="${BLOB_BROKER_SECRET:-blob-broker-secret}"
echo ">>> ensuring broker user ${BLOB_UID}"
radosgw-admin user info --uid="$BLOB_UID" >/dev/null 2>&1 \
  || radosgw-admin user create --uid="$BLOB_UID" --display-name="Blob Broker" \
       --access-key="$BLOB_KEY" --secret-key="$BLOB_SECRET"
radosgw-admin caps add --uid="$BLOB_UID" --caps="roles=*" >/dev/null 2>&1 || true

BLOB_TRUST=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Principal":{"AWS":["arn:aws:iam:::user/${BLOB_UID}"]},"Action":["sts:AssumeRole"]}]}
JSON
)
BLOB_PERM=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::${BUCKET}/${BLOB_PREFIX}/*"]},
  {"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::${BUCKET}"],
   "Condition":{"StringLike":{"s3:prefix":["${BLOB_PREFIX}/*"]}}}]}
JSON
)
echo ">>> ensuring role ${BLOB_ROLE}"
ensure_role "$BLOB_ROLE" "$BLOB_TRUST" blobread "$BLOB_PERM"
