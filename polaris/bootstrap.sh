#!/bin/sh
# Polaris catalog bootstrap.
#
# The Polaris *metastore* is bootstrapped separately by the polaris-admin-tool
# container (creates the POLARIS realm + root principal). This script creates the
# `lakehouse` catalog over Ceph RGW in STS mode: it sets a roleArn + stsEndpoint, so
# at loadTable Polaris assumes the `polaris-vendor` RGW role (using its ambient admin
# key) and mints a per-table scoped credential. Authenticates with Polaris's INTERNAL
# OAuth as root; with OPA in allow-all mode the root CREATE_CATALOG passes. Runs in an
# alpine/curl container.
#
# Re-runnable: if the catalog already exists (e.g. from a prior static-cred run) it is
# deleted (namespaces first) and recreated, so the storage config is always current.
set -e

apk add --no-cache jq >/dev/null 2>&1 || true

POLARIS="http://polaris:8181"
CAT_API="${POLARIS}/api/catalog/v1/${CATALOG_NAME}"
MGMT="${POLARIS}/api/management/v1"

echo "Obtaining root token from Polaris internal OAuth ..."
TOKEN=$(curl -sf "${POLARIS}/api/catalog/v1/oauth/tokens" \
  --user "${POLARIS_ROOT_CLIENT_ID}:${POLARIS_ROOT_CLIENT_SECRET}" \
  -H "Polaris-Realm: ${POLARIS_REALM}" \
  -d grant_type=client_credentials \
  -d scope=PRINCIPAL_ROLE:ALL | jq -r .access_token)

if [ -z "${TOKEN}" ] || [ "${TOKEN}" = "null" ]; then
  echo "ERROR: failed to obtain root token" >&2
  exit 1
fi
AUTH="Authorization: Bearer ${TOKEN}"
RH="Polaris-Realm: ${POLARIS_REALM}"

# --- drop an existing catalog so we can (re)apply the STS storage config ---
if curl -sf -o /dev/null -H "${AUTH}" -H "${RH}" "${MGMT}/catalogs/${CATALOG_NAME}"; then
  echo "Existing catalog found; dropping it (tables, then namespaces, then catalog) ..."
  for ns in $(curl -sf -H "${AUTH}" -H "${RH}" "${CAT_API}/namespaces" | jq -r '.namespaces[]?|join(".")'); do
    for tbl in $(curl -sf -H "${AUTH}" -H "${RH}" "${CAT_API}/namespaces/${ns}/tables" | jq -r '.identifiers[]?.name'); do
      echo "  dropping table ${ns}.${tbl}"
      # purgeRequested=false: drop only the catalog metadata. Purge would need vended
      # S3 creds (an STS AssumeRole), which is exactly the path we may be reconfiguring.
      curl -s -o /dev/null -X DELETE -H "${AUTH}" -H "${RH}" "${CAT_API}/namespaces/${ns}/tables/${tbl}?purgeRequested=false" || true
    done
    echo "  dropping namespace ${ns}"
    curl -s -o /dev/null -X DELETE -H "${AUTH}" -H "${RH}" "${CAT_API}/namespaces/${ns}" || true
  done
  curl -s -o /dev/null -X DELETE -H "${AUTH}" -H "${RH}" "${MGMT}/catalogs/${CATALOG_NAME}" || true
fi

echo "Creating catalog '${CATALOG_NAME}' over s3://${S3_BUCKET}/ (STS via ${STS_ROLE_ARN}) ..."
PAYLOAD=$(cat <<JSON
{
  "catalog": {
    "name": "${CATALOG_NAME}",
    "type": "INTERNAL",
    "properties": { "default-base-location": "s3://${S3_BUCKET}/warehouse/" },
    "storageConfigInfo": {
      "storageType": "S3",
      "allowedLocations": ["s3://${S3_BUCKET}/warehouse/"],
      "endpoint": "${S3_ENDPOINT}",
      "endpointInternal": "${S3_ENDPOINT}",
      "stsEndpoint": "${S3_ENDPOINT}",
      "pathStyleAccess": true,
      "roleArn": "${STS_ROLE_ARN}",
      "kmsUnavailable": true
    }
  }
}
JSON
)

HTTP=$(curl -s -o /tmp/cat-resp.json -w '%{http_code}' -X POST \
  "${MGMT}/catalogs" \
  -H "${AUTH}" \
  -H "Content-Type: application/json" \
  -H "${RH}" \
  -d "${PAYLOAD}")

case "${HTTP}" in
  200|201) echo "  -> catalog created" ;;
  409)     echo "  -> catalog already exists (OK)" ;;
  *)       echo "ERROR: catalog create returned ${HTTP}" >&2; cat /tmp/cat-resp.json >&2; exit 1 ;;
esac

# Register the bare external principals (names only — no roles, no grants). Polaris
# requires every external identity to exist as a managed principal; OPA holds all the
# rules, so these are pure identity records. trino_svc is the engine's service identity
# (granted nothing in OPA); alice/bob are the end users.
for p in trino_svc alice bob; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${MGMT}/principals" \
    -H "${AUTH}" -H "Content-Type: application/json" -H "${RH}" \
    -d "{\"principal\":{\"name\":\"${p}\",\"type\":\"USER\"}}")
  case "${code}" in
    200|201) echo "  principal ${p} created" ;;
    409)     echo "  principal ${p} exists (OK)" ;;
    *)       echo "  WARN: principal ${p} create returned ${code}" ;;
  esac
done

echo "Polaris catalog + principal setup complete."
