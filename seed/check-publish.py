"""
seed/check-publish.py — spaces, writing first and publishing after
(docs/HANDOFF-2026-10-22-groups.md sections 1 to 3, docs/PLAN-2026-10-24.md item 3a), through
the broker, the gate and governance. A new group has alice as its owner, appointed its steward
by carol, a platform admin who is not in it; bob is a member. carol's group projw is the
outside audience. Exits 1 at the first check that fails. Run in the governance container:

    docker compose exec governance python /seed/check-publish.py

Group and session names are new on each run. Waits up to 10 s for the storage notification
that makes a written folder live.
"""
import sys
import time

import boto3
import requests
from botocore.config import Config
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.schema import Schema
from pyiceberg.types import LongType, NestedField

KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
GOV, BROKER = "http://governance:8000", "http://broker:9100"
_tokens = {}


def token(user):
    if user not in _tokens:
        r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                                    "client_secret": "trino-secret", "username": user, "password": user,
                                    "scope": "openid aud-polaris aud-governance aud-broker"})
        r.raise_for_status()
        _tokens[user] = r.json()["access_token"]
    return _tokens[user]


def gov(method, path, user, body=None):
    return requests.request(method, GOV + path, json=body, headers={"Authorization": f"Bearer {token(user)}"})


def vend(user, folder, mode="read"):
    return requests.post(f"{BROKER}/vend", json={"folder": folder, "mode": mode},
                         headers={"Authorization": f"Bearer {token(user)}"})


def catalog(user):
    return RestCatalog("gate", uri="http://gate:8182/api/catalog", warehouse="lakehouse", token=token(user))


def index(user):
    """{id: row} of the user's governance.datasets."""
    return {r["id"]: r for r in catalog(user).load_table("governance.datasets").scan().to_arrow().to_pylist()}


def reads_table(user, ident):
    """Whether loading the table hands the user a read credential."""
    try:
        return "s3.access-key-id" in catalog(user).load_table(ident).io.properties
    except Exception:  # noqa: BLE001 — pyiceberg raises its own error for not-found
        return False


def creates(user, ident):
    try:
        catalog(user).create_table(ident, schema=Schema(NestedField(1, "x", LongType(), required=False)))
        return True
    except Exception:  # noqa: BLE001 — pyiceberg raises its own error for the gate's 403
        return False


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


ts = str(int(time.time()))
g = f"pc{ts}"
folder = f"{g}/scratch"
for user in ("alice", "bob", "carol"):
    gov("POST", "/sessions", user, {"name": f"publish-{ts}"})
check("alice creates a group", gov("POST", "/groups", "alice", {"name": g}).status_code == 201)
check("bob joins it as a member",
      gov("PATCH", f"/groups/{g}", "alice", {"members": {"add": ["bob"]}}).status_code == 200)
check("carol appoints alice its steward", gov("PUT", f"/groups/{g}/stewards/alice", "carol").status_code == 200)

# Writing first
c = vend("bob", folder, "write")
check(f"a member gets a write credential for a folder nothing has written ({c.status_code})", c.status_code == 200)
c = c.json()
boto3.client("s3", endpoint_url=c["endpoint"], aws_access_key_id=c["access_key_id"],
             aws_secret_access_key=c["secret_access_key"], aws_session_token=c["session_token"],
             region_name="us-east-1", config=Config(signature_version="s3v4")
             ).put_object(Bucket=c["bucket"], Key=f"{c['prefix']}a.txt", Body=b"scratch\n")
for _ in range(20):
    row = index("bob").get(folder)
    if row:
        break
    time.sleep(0.5)
check("the folder is listed to its group's member, unpublished",
      row is not None and row["published"] is False and row["can_read"])
check("and to its owner", folder in index("alice"))
check("and to no one outside the group", folder not in index("carol"))
check("someone outside is refused a read credential", vend("carol", folder).status_code == 403)

# Publishing after
check("a member's publish is refused",
      gov("PATCH", f"/datasets/{folder}", "bob", {"description": "x"}).status_code == 403)
r = gov("PATCH", f"/datasets/{folder}", "alice", {"description": "scratch, published", "read": ["projw"]})
check(f"the steward publishes it with read for projw ({r.status_code})", r.status_code == 200)
row = index("carol").get(folder)
check("projw's carol now finds it, published, and may read it",
      row is not None and row["published"] and row["can_read"] and vend("carol", folder).status_code == 200)
check("no credential reaches inside the published dataset", vend("bob", f"{folder}/sub", "write").status_code == 403)
check("nor one for a folder containing it", vend("bob", g).status_code == 403)
r = gov("GET", f"/datasets/{folder}", "carol")
check("GET /datasets shows where each grant comes from",
      r.status_code == 200 and [l["from"] for l in r.json()["layers"]] == ["own", "space"])

r = gov("PATCH", f"/permissions/dataset/{folder}", "alice", {"changes": [{"group": "noaccess", "add": ["describe"]}]})
check(f"the steward changes the published dataset's grants ({r.status_code})",
      r.status_code == 200 and r.json()["grants"]["describe"] == ["noaccess"])
check("a member, holding no manage, may not", gov("PATCH", f"/permissions/dataset/{folder}", "bob",
      {"changes": [{"group": "noaccess", "add": ["read"]}]}).status_code == 403)

# A folder's grants reach the entries under it
r = gov("PATCH", f"/permissions/folder/{g}/team", "alice", {"changes": [{"group": "projw", "add": ["read"]}]})
check(f"the steward grants projw read on a folder ({r.status_code})", r.status_code == 200)
check("a member writes a folder inside it", vend("bob", f"{g}/team/notes", "write").status_code == 200)
check("projw reads that folder through the grant above it", vend("carol", f"{g}/team/notes").status_code == 200)
check("but not the folder itself, which the grant is on", vend("carol", f"{g}/team").status_code == 403)

# Tables take their namespaces' grants
r = gov("PATCH", f"/permissions/namespace/lakehouse.{g}.shared", "alice",
        {"changes": [{"group": "projw", "add": ["read"]}]})
check(f"the steward grants projw read on a namespace not created yet ({r.status_code})", r.status_code == 200)
check("a member's grant change is refused", gov("PATCH", f"/permissions/namespace/lakehouse.{g}.shared", "bob",
      {"changes": [{"group": "noaccess", "add": ["read"]}]}).status_code == 403)
bob = catalog("bob")
bob.create_namespace((g,))
bob.create_namespace((g, "shared"))
schema = Schema(NestedField(1, "x", LongType(), required=False))
bob.create_table((g, "shared", "t"), schema=schema)
bob.create_table((g, "other"), schema=schema)
check("the namespace's grant reaches a table created after it", reads_table("carol", (g, "shared", "t")))
check("and not a table beside it", not reads_table("carol", (g, "other")))
check("which is listed to the group only, unpublished",
      index("bob").get(f"lakehouse.{g}.other", {}).get("published") is False
      and f"lakehouse.{g}.other" not in index("carol"))
check("a reader outside the group may not create a table there", not creates("carol", (g, "shared", "c")))
check("a group whose space holds data is not deleted", gov("DELETE", f"/groups/{g}", "alice").status_code == 409)
