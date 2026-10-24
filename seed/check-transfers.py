"""
seed/check-transfers.py — moving a folder or a table into another group's space
(docs/HANDOFF-2026-10-22-groups.md section 1, docs/PLAN-2026-10-24.md item 3d). alice owns a new
group G with carol a member, and a second group with bob a viewer. alice builds a personal
folder from a folder of G's, and a report in G from the personal folder; the report stays closed
to carol until the personal folder moves into G. The same for a table. Exits 1 at the first check
that fails. Run in the governance container:

    docker compose exec governance python /seed/check-transfers.py

Names are new on each run. Waits 3 s once, and up to 10 s for listings.
"""
import sys
import time

import boto3
import pyarrow as pa
import requests
from botocore.config import Config
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.schema import Schema
from pyiceberg.types import LongType, NestedField

sys.path.insert(0, "/app")
import app  # noqa: E402  (governance's own module: what OPA's lookups return)

KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
GOV, BROKER = "http://governance:8000", "http://broker:9100"
_tokens = {}
app.connect_pool()


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


def broker(path, user, body):
    return requests.post(f"{BROKER}{path}", json=body, headers={"Authorization": f"Bearer {token(user)}"})


def vend(user, folder, mode="read"):
    return broker("/vend", user, {"folder": folder, "mode": mode})


def put(user, folder, name):
    c = vend(user, folder, "write").json()
    boto3.client("s3", endpoint_url=c["endpoint"], aws_access_key_id=c["access_key_id"],
                 aws_secret_access_key=c["secret_access_key"], aws_session_token=c["session_token"],
                 region_name="us-east-1", config=Config(signature_version="s3v4")
                 ).put_object(Bucket=c["bucket"], Key=c["prefix"] + name, Body=name.encode())


def catalog(user):
    return RestCatalog("gate", uri="http://gate:8182/api/catalog", warehouse="lakehouse", token=token(user))


def reads_table(user, ident):
    try:
        return "s3.access-key-id" in catalog(user).load_table(ident).io.properties
    except Exception:  # noqa: BLE001 — pyiceberg raises its own error for not-found
        return False


def carries(entry, source):
    for _ in range(20):
        if source in [c["id"] for c in app.carried(entry)]:
            return True
        time.sleep(0.5)
    return False


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


ts = str(int(time.time()))
g, g2 = f"gt{ts}", f"gu{ts}"
src, work, report, moved = f"{g}/src", f"u_alice/work{ts}", f"{g}/report", f"{g}/work"
for user in ("alice", "bob", "carol"):
    gov("POST", "/sessions", user, {"name": f"transfers-{ts}"})
gov("POST", "/groups", "alice", {"name": g})
gov("PATCH", f"/groups/{g}", "alice", {"members": {"add": ["carol"]}})
gov("POST", "/groups", "alice", {"name": g2})
gov("PATCH", f"/groups/{g2}", "alice", {"viewers": {"add": ["bob"]}})

# Files
put("alice", src, "s.txt")
check("alice reads a folder of G's", vend("alice", src).status_code == 200)
put("alice", work, "a.txt")
check("her personal folder carries it", carries(work, src))
check("she reads her personal folder", vend("alice", work).status_code == 200)
put("alice", report, "r.txt")
check("a report in G built from it carries the personal folder", carries(report, work))
check("so carol, in G, may not read the report", vend("carol", report).status_code == 403)

check("a tenant's folder is not moved", broker("/transfers", "alice", {"from": "jgi/public", "to": f"{g}/x"}).status_code == 403)
check("nor into a folder that exists", broker("/transfers", "alice", {"from": work, "to": report}).status_code == 409)
gov("PUT", f"/groups/{g}/stewards/alice", "carol")
vend("alice", f"{g}/pubdest", "write")
vend("alice", f"{g}/outer/pub/deep", "write")   # tracked before the dataset around it is published
vend("alice", f"{g}/outer/pub", "write")
for d in (f"{g}/pubdest", f"{g}/outer/pub"):
    gov("PATCH", f"/datasets/{d}", "alice", {"description": "published, empty"})
gov("DELETE", f"/groups/{g}/stewards/alice", "carol")
check("nor into a published dataset, though it is empty",
      broker("/transfers", "alice", {"from": work, "to": f"{g}/pubdest"}).status_code == 403)
check("nor into a folder holding one", broker("/transfers", "alice", {"from": work, "to": f"{g}/outer"}).status_code == 403)
check("a published dataset is not moved out of a group that has since lost its steward",
      broker("/transfers", "alice", {"from": f"{g}/pubdest", "to": f"{g2}/a"}).status_code == 403)
check("nor a folder inside one", broker("/transfers", "alice", {"from": f"{g}/outer/pub/deep", "to": f"{g2}/b"}).status_code == 403)
r = broker("/transfers", "alice", {"from": work, "to": moved})
check(f"alice moves her personal folder into G ({r.status_code})", r.status_code == 200 and r.json()["objects"] == 1)
check("the moved folder keeps its sources", carries(moved, src))
check("data built from the old folder opens to the group", vend("carol", report).status_code == 200)
check("the new folder is G's", vend("carol", moved).status_code == 200)
r = vend("alice", work)
check(f"the old path names the new one to its mover ({r.json()['error']})",
      r.status_code == 403 and r.json()["error"] == f"{work} has moved to {moved}")
r = vend("carol", work)
check("and to carol, who may describe the new one", r.status_code == 403 and r.json()["error"].endswith(moved))
r = vend("bob", work)
check("and is the ordinary refusal for bob, who may not", r.status_code == 403 and r.json()["error"] == "forbidden")
put("bob", f"u_bob/x{ts}", "x.txt")
check("a viewer may not move a folder into the group",
      broker("/transfers", "bob", {"from": f"u_bob/x{ts}", "to": f"{g2}/x"}).status_code == 403)

# Tables
gov("POST", "/sessions", "alice", {"name": f"transfers-{ts}-tables"})
cat = catalog("alice")
schema = Schema(NestedField(1, "x", LongType(), required=False))
cat.create_namespace_if_not_exists(("u_alice",))
cat.create_namespace_if_not_exists((g,))
cat.create_table(("u_alice", f"tt{ts}"), schema=schema).append(pa.table({"x": pa.array([7], pa.int64())}))
cat.create_table((g, "other"), schema=schema)
time.sleep(3)   # a read up to 2 s after a write counts toward it (PROVENANCE.md 8); this one must not
rows = cat.load_table(("u_alice", f"tt{ts}")).scan().to_arrow()
cat.create_table((g, "tt"), schema=schema).append(rows)
old, new = f"lakehouse.u_alice.tt{ts}", f"lakehouse.{g}.tt"
check("alice's copy of her personal table in G carries it", carries(new, old))
check("so carol may not read the copy", not reads_table("carol", (g, "tt")))
check("a move the copy does not carry is refused",
      gov("POST", "/transfers", "alice", {"from": old, "to": f"lakehouse.{g}.other"}).status_code == 409)
check("someone else's move of it is refused",
      gov("POST", "/transfers", "carol", {"from": old, "to": new}).status_code == 403)
gov("PUT", f"/groups/{g}/stewards/alice", "carol")
gov("PATCH", f"/namespaces/lakehouse.{g}.pubns", "alice", {"description": "published"})
gov("DELETE", f"/groups/{g}/stewards/alice", "carol")
cat.create_namespace_if_not_exists((g, "pubns"))
cat.create_table((g, "pubns", "p"), schema=schema)
cat.create_namespace_if_not_exists((g2,))
cat.create_table((g2, "pcopy"), schema=schema)
check("a table in a published namespace is not moved",
      gov("POST", "/transfers", "alice", {"from": f"lakehouse.{g}.pubns.p", "to": f"lakehouse.{g2}.pcopy"}).status_code == 403)
r = gov("POST", "/transfers", "alice", {"from": old, "to": new})
check(f"alice records the move ({r.status_code})", r.status_code == 200)
check("carol now reads the copy", reads_table("carol", (g, "tt")))
cat.drop_table(("u_alice", f"tt{ts}"))
time.sleep(1)
with app.db() as cur:
    cur.execute("SELECT status, moved_to FROM table_entries WHERE id = %s", (old,))
    row = cur.fetchone()
check("the dropped original keeps the record of its move", row["status"] == "moved" and row["moved_to"] == new)
