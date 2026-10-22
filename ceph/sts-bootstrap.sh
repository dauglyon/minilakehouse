#!/bin/sh
# Ceph RGW STS bootstrap — creates the roles the catalog (Polaris) and the blob broker
# assume to vend scoped, short-lived credentials. Runs INSIDE the ceph container
# (radosgw-admin). radosgw-admin mints roles with a stable empty-account ARN
# (arn:aws:iam:::role/<name>) — unlike the IAM API, which uses a per-instance account id.
set -e

BUCKET="${BUCKET:-lakehouse}"

# The cluster persists (ceph/start.sh), so a user's first key would otherwise outlive a change in
# .env. On every run each user's only S3 key becomes the configured one: `key create` on an
# existing access key replaces its secret, and every other key is removed.
ensure_key() {  # uid access_key secret
  radosgw-admin key create --uid="$1" --key-type=s3 --access-key="$2" --secret="$3" >/dev/null
  for k in $(radosgw-admin user info --uid="$1" | jq -r '.keys[].access_key'); do
    [ "$k" = "$2" ] || radosgw-admin key rm --uid="$1" --key-type=s3 --access-key="$k" >/dev/null
  done
}
echo ">>> ensuring the admin user's key"
ensure_key root "${RGW_ACCESS_KEY:?}" "${RGW_SECRET_KEY:?}"
# The warehouse lives under this sub-prefix (must match the catalog's default-base-location
# in polaris/bootstrap.sh). Confining the role here means a vended credential whose session
# policy is somehow missing still can't reach beyond the warehouse.
WHPREFIX="${WAREHOUSE_PREFIX:-warehouse}"
BLOB_PREFIX="${BLOB_PREFIX:-datasets}"

# Create a role only if absent, then (always, idempotently) set its trust and attach its
# policy, so a rerun moves an existing role to the current trust. A genuine create failure is
# NOT swallowed — it aborts via `set -e` and surfaces in the logs, rather than masquerading as
# "already exists".
ensure_role() {  # name  trust_doc  policy_name  policy_doc
  radosgw-admin role get --role-name="$1" >/dev/null 2>&1 \
    || radosgw-admin role create --role-name="$1" --assume-role-policy-doc="$2"
  radosgw-admin role-trust-policy modify --role-name="$1" --assume-role-policy-doc="$2"
  radosgw-admin role-policy put --role-name="$1" --policy-name="$3" --policy-doc="$4"
  radosgw-admin role get --role-name="$1"
}

# --- Table plane: the role Polaris assumes to vend per-table creds (warehouse/ only). ---
# Polaris authenticates as `polaris-catalog`, which holds no S3 rights of its own — only the
# ability to assume this role — and narrows further with a per-table session policy at vend
# time; it reads and writes table metadata with such credentials too. The user has no tenant,
# so its ARN has an empty account field. Least-privilege: only the object/bucket actions the
# catalog needs (no s3:*), objects confined to warehouse/.
POLARIS_ROLE="${ROLE:-polaris-vendor}"
POLARIS_UID="${POLARIS_S3_UID:-polaris-catalog}"
POLARIS_KEY="${POLARIS_S3_KEY:?}"
POLARIS_SECRET="${POLARIS_S3_SECRET:?}"
echo ">>> ensuring catalog user ${POLARIS_UID}"
radosgw-admin user info --uid="$POLARIS_UID" >/dev/null 2>&1 \
  || radosgw-admin user create --uid="$POLARIS_UID" --display-name="Polaris Catalog" \
       --access-key="$POLARIS_KEY" --secret-key="$POLARIS_SECRET"
ensure_key "$POLARIS_UID" "$POLARIS_KEY" "$POLARIS_SECRET"
POLARIS_TRUST=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Principal":{"AWS":["arn:aws:iam:::user/${POLARIS_UID}"]},"Action":["sts:AssumeRole"]}]}
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
ensure_role "$POLARIS_ROLE" "$POLARIS_TRUST" s3access "$POLARIS_PERM"

# --- Blob plane (Flow C): the role the broker assumes to vend per-dataset creds. The broker
# authenticates as `blob-broker` (no S3 rights of its own — only AssumeRole) and narrows to
# one dataset prefix per request via a session policy. The role is read-only, datasets/ only. ---
BLOB_ROLE="${BLOB_ROLE:-blob-vendor}"
BLOB_UID="${BLOB_BROKER_UID:-blob-broker}"
BLOB_KEY="${BLOB_BROKER_KEY:?}"
BLOB_SECRET="${BLOB_BROKER_SECRET:?}"
echo ">>> ensuring broker user ${BLOB_UID}"
radosgw-admin user info --uid="$BLOB_UID" >/dev/null 2>&1 \
  || radosgw-admin user create --uid="$BLOB_UID" --display-name="Blob Broker" \
       --access-key="$BLOB_KEY" --secret-key="$BLOB_SECRET"
ensure_key "$BLOB_UID" "$BLOB_KEY" "$BLOB_SECRET"
# No RGW capabilities: AssumeRole needs none (the role's trust policy decides), and `roles=*`
# would let the broker read and rewrite role policies. Removed from a user that has it.
radosgw-admin caps rm --uid="$BLOB_UID" --caps="roles=*" >/dev/null 2>&1 || true

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

# The role the broker assumes for a dataset's `write` grant: put and delete under datasets/,
# never get or list (WHITEPAPER 4.2), narrowed per request to one dataset's folder.
BLOB_WRITE_ROLE="${BLOB_WRITE_ROLE:-blob-writer}"
BLOB_WRITE_PERM=$(cat <<JSON
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow",
   "Action":["s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],
   "Resource":["arn:aws:s3:::${BUCKET}/${BLOB_PREFIX}/*"]}]}
JSON
)
echo ">>> ensuring role ${BLOB_WRITE_ROLE}"
ensure_role "$BLOB_WRITE_ROLE" "$BLOB_TRUST" blobwrite "$BLOB_WRITE_PERM"

# --- Governance reader: a least-privilege S3 user the governance service uses to LIST
# dataset prefixes (reconcile). It holds no rights of its own; the rgw-setup one-shot grants
# it ListBucket on datasets/* via a bucket policy. So governance never holds the admin key. ---
GR_UID="${GOVERNANCE_READER_UID:-governance-reader}"
GR_KEY="${GOVERNANCE_READER_KEY:?}"
GR_SECRET="${GOVERNANCE_READER_SECRET:?}"
echo ">>> ensuring reader user ${GR_UID}"
radosgw-admin user info --uid="$GR_UID" >/dev/null 2>&1 \
  || radosgw-admin user create --uid="$GR_UID" --display-name="Governance Reader" \
       --access-key="$GR_KEY" --secret-key="$GR_SECRET"
ensure_key "$GR_UID" "$GR_KEY" "$GR_SECRET"
