#!/bin/bash
# Single-node Ceph whose data survives restarts and recreation. The image's own /entrypoint.sh
# runs the OSD on memstore (RAM) and deletes the cluster at every start; this keeps the cluster
# on the ceph_data volume (/var/lib/ceph): the first start creates it with a BlueStore OSD on a
# sparse file, and every later start runs the existing one. The fsid file is written last, so a
# first start that dies partway is redone from scratch at the next start.
set -e

RGW_PORT="${RGW_PORT:-8080}"
# No fallback to well-known keys. sts-bootstrap.sh resets the admin key from these at every
# start, so a changed key in .env replaces the stored one.
: "${RGW_ACCESS_KEY:?RGW_ACCESS_KEY must be set}" "${RGW_SECRET_KEY:?RGW_SECRET_KEY must be set}"
DATA=/var/lib/ceph
CONF=/etc/ceph/ceph.conf

# Forward SIGTERM/SIGINT to the daemons so they shut down cleanly on docker stop.
trap 'kill $(jobs -p) 2>/dev/null' TERM INT

if [ -f "$DATA/fsid" ]; then
  FSID=$(cat "$DATA/fsid"); FRESH=0
else
  FSID=$(uuidgen); FRESH=1
fi
if grep -q 'fsid' "$CONF"; then
  sed -i "s/fsid = .*/fsid = $FSID/" "$CONF"
else
  sed -i "s/\[global\]/[global]\n    fsid = $FSID/" "$CONF"
fi
# The OSD's disk is a sparse file beside, not inside, the OSD directory: BlueStore links
# <osd dir>/block to it.
mkdir -p "$DATA/osd-block"
sed -i '/osd objectstore\|bluestore block\|osd memory target/d' "$CONF"
sed -i "s|\[osd\]|[osd]\n    osd objectstore = bluestore\n    bluestore block path = $DATA/osd-block/ceph-0\n    bluestore block create = true\n    bluestore block size = 21474836480\n    osd memory target = 1073741824|" "$CONF"

if [ "$FRESH" = 1 ]; then
  rm -rf "$DATA/mon/ceph-a" "$DATA/mgr/ceph-a" "$DATA/osd/ceph-0" "$DATA/osd-block/ceph-0" /tmp/monmap
  mkdir -p "$DATA/mon/ceph-a" "$DATA/mgr/ceph-a" "$DATA/osd/ceph-0" /var/log/ceph
  monmaptool --create --add a 127.0.0.1 --fsid "$FSID" /tmp/monmap >/dev/null
  ceph-mon --id a --mkfs --monmap /tmp/monmap
fi
ceph-mon --id a &
echo "Waiting for MON..."
timeout 60 bash -c "until ceph -s &>/dev/null; do sleep 1; done"

ceph-mgr --id a &
if [ "$FRESH" = 1 ]; then
  ceph-osd --id 0 --mkfs
  ceph osd create
fi
ceph-osd --id 0 &
echo "Waiting for OSD..."
timeout 120 bash -c "until ceph osd stat 2>/dev/null | grep -q '1 up'; do sleep 1; done"

radosgw -f --name client.rgw.test --rgw-frontends="beast port=${RGW_PORT}" &
RGW_PID=$!
echo "Waiting for RGW..."
timeout 120 bash -c "until curl -sf http://127.0.0.1:${RGW_PORT} &>/dev/null; do sleep 1; done"

if [ "$FRESH" = 1 ]; then
  ACCOUNT_ID=$(radosgw-admin account create --account-name="testaccount" | jq -r '.id')
  radosgw-admin user create --uid="root" --display-name="AccountRoot" --account-id="${ACCOUNT_ID}" \
    --account-root --access-key="${RGW_ACCESS_KEY}" --secret="${RGW_SECRET_KEY}" >/dev/null
  echo "$FSID" > "$DATA/fsid"
fi
echo "RGW ready on port ${RGW_PORT} (cluster ${FSID}, $([ "$FRESH" = 1 ] && echo created || echo existing))"

wait $RGW_PID
