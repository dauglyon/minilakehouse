#!/bin/sh
# Ceph RGW bootstrap — Stage A (static-cred portion).
#
# Creates the warehouse bucket using the `mc` (MinIO) client, which talks to RGW
# reliably (the aws-cli v2.34 high-level/s3api commands hit an internal parse bug
# against this RGW image). The bucket is created by the RGW admin user whose key
# Polaris holds via AWS_ACCESS_KEY_ID/SECRET while storage is in static-cred mode.
#
# The STS portion (radosgw-admin roles + policies, rgw_s3_auth_use_sts) runs *inside* the
# ceph container — radosgw-admin is not in this client image. See ceph/sts-bootstrap.sh.
set -e

mc alias set rgw "${MC_ENDPOINT}" "${MC_ACCESS_KEY}" "${MC_SECRET_KEY}"
mc mb --ignore-existing "rgw/${S3_BUCKET}"

# Phase 1 (Flow C): seed demo blob datasets under datasets/projx/{public,private}/.
if [ -d /blobs ]; then
  echo "Seeding demo blobs into ${S3_BUCKET}/datasets/ ..."
  mc cp --recursive /blobs/ "rgw/${S3_BUCKET}/datasets/"
fi

echo "Buckets:"
mc ls rgw
echo "Ceph bucket ${S3_BUCKET} ready."
