#!/bin/sh
# Entrypoint wrapper for the RGW test image. Two jobs:
#
#  1. Inject rgw_sts_key + rgw_s3_auth_use_sts into ceph.conf BEFORE radosgw starts
#     (radosgw reads rgw_sts_key only at startup). rgw_sts_key is the server-side key
#     RGW uses to sign STS session tokens (must be 16 alphanumeric chars).
#
#  2. Once the cluster + admin user are up, create the `polaris-vendor` STS role that
#     Polaris assumes to vend per-table credentials. Done in the background so we can
#     hand the foreground to the image's own entrypoint (which must stay PID 1 for
#     signal handling and `wait`). radosgw-admin creates the role with an empty-account
#     ARN (arn:aws:iam:::role/polaris-vendor) — stable, unlike the IAM API which mints a
#     per-instance account id.
set -e

if ! grep -q 'rgw_sts_key' /etc/ceph/ceph.conf; then
  sed -i "s|\[client.rgw.test\]|[client.rgw.test]\n    rgw_sts_key = ${RGW_STS_KEY}\n    rgw_s3_auth_use_sts = true|" /etc/ceph/ceph.conf
fi

# Bucket notifications (registry freshness): this image's ceph.conf explicitly narrows the enabled APIs to
# `rgw enable apis = s3, admin, iam, sts` — which DROPS `notifications` (present in the
# compiled default). Bucket notifications + the SNS topic API need it, so append it.
# (Ceph treats `rgw enable apis` and `rgw_enable_apis` as the same key.)
if ! grep -qE 'rgw[ _]enable[ _]apis.*notifications' /etc/ceph/ceph.conf; then
  sed -i -E 's|^([[:space:]]*rgw[ _]enable[ _]apis[[:space:]]*=.*)$|\1, notifications|' /etc/ceph/ceph.conf
fi

(
  # Wait for RGW to answer (cluster up) and for the admin user the image provisions.
  until curl -sf "http://127.0.0.1:${RGW_PORT:-8080}" >/dev/null 2>&1; do sleep 1; done
  until radosgw-admin user info --uid=root >/dev/null 2>&1; do sleep 1; done
  sh /sts-bootstrap.sh || echo "WARN: STS role bootstrap failed (see logs)"
) &

exec /entrypoint.sh
