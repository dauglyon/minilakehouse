"""
seed/check-collections.py — collections (docs/HANDOFF-2026-10-22-groups.md section 5,
docs/PLAN-2026-10-24.md item 4). alice, steward of jgi, publishes two folders and a namespace in
jgi's space, one folder built from jgi/public, and puts them in a collection whose `read` she
gives projw; carol is in projw, bob in nothing that reaches them. Exits 1 at the first check
that fails. Run in the governance container:

    docker compose exec governance python /seed/check-collections.py

Names are new on each run.
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


def put(user, folder, name):
    c = vend(user, folder, "write").json()
    boto3.client("s3", endpoint_url=c["endpoint"], aws_access_key_id=c["access_key_id"],
                 aws_secret_access_key=c["secret_access_key"], aws_session_token=c["session_token"],
                 region_name="us-east-1", config=Config(signature_version="s3v4")
                 ).put_object(Bucket=c["bucket"], Key=c["prefix"] + name, Body=name.encode())


def catalog(user):
    return RestCatalog("gate", uri="http://gate:8182/api/catalog", warehouse="lakehouse", token=token(user))


def index(user, table="datasets"):
    return catalog(user).load_table(f"governance.{table}").scan().to_arrow().to_pylist()


def reads_table(user, ident):
    try:
        return "s3.access-key-id" in catalog(user).load_table(ident).io.properties
    except Exception:  # noqa: BLE001 — pyiceberg raises its own error for not-found
        return False


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


ts = str(int(time.time()))
plain, built, ns = f"jgi/c{ts}", f"jgi/d{ts}", f"lakehouse.jgi.c{ts}"
share, outer = f"jgi:share{ts}", f"jgi:outer{ts}"
for user in ("alice", "bob", "carol"):
    gov("POST", "/sessions", user, {"name": f"collections-{ts}"})
put("alice", plain, "p.txt")
cat = catalog("alice")
cat.create_namespace((f"jgi", f"c{ts}"))
cat.create_table(("jgi", f"c{ts}", "t"), schema=Schema(NestedField(1, "x", LongType(), required=False))
                 ).append(pa.table({"x": pa.array([1], pa.int64())}))
time.sleep(3)   # a read up to 2 s after a write counts toward it (PROVENANCE.md 8)
check("alice reads jgi/public", vend("alice", "jgi/public").status_code == 200)
put("alice", built, "d.txt")
for d in (plain, built):
    check(f"alice publishes {d}", gov("PATCH", f"/datasets/{d}", "alice", {"description": d}).status_code == 200)
check("and the namespace", gov("PATCH", f"/namespaces/{ns}", "alice", {"description": "tables"}).status_code == 200)
check("carol, outside jgi, may not read them", vend("carol", plain).status_code == 403
      and not reads_table("carol", ("jgi", f"c{ts}", "t")))

r = gov("POST", "/collections", "alice", {"group": "jgi", "name": f"share{ts}", "description": "for projw"})
check(f"alice creates a collection in jgi ({r.status_code})", r.status_code == 201)
check("bob may not create one in jgi", gov("POST", "/collections", "bob",
                                           {"group": "jgi", "name": f"x{ts}"}).status_code == 403)
check("she gives projw read on it", gov("PATCH", f"/collections/{share}", "alice",
      {"changes": [{"group": "projw", "add": ["read"]}]}).status_code == 200)
check("carol may not change who reads it", gov("PATCH", f"/collections/{share}", "carol",
      {"changes": [{"group": "projw", "add": ["describe"]}]}).status_code == 403)
for m in (plain, built, ns):
    check(f"she adds {m}", gov("POST", f"/collections/{share}/members/{m}", "alice").status_code == 200)
check("an unpublished folder is no member", gov("POST", f"/collections/{share}/members/jgi/unpub{ts}",
                                                "alice").status_code == 403)

check("carol reads a member through the collection", vend("carol", plain).status_code == 200)
check("and a table in the namespace member", reads_table("carol", ("jgi", f"c{ts}", "t")))
check("a member built from what carol may not read stays closed to her", vend("carol", built).status_code == 403)
rows = {r["id"]: r for r in index("carol")}
check("carol's index lists the collection", rows.get(share, {}).get("kind") == "collection" and rows[share]["can_read"])
check("and its members she may describe", {(m["collection"], m["member"]) for m in index("carol", "collection_members")}
      >= {(share, plain), (share, ns)})
check("bob's does not", share not in {r["id"] for r in index("bob")})
r = gov("GET", f"/datasets/{plain}", "alice")
check("the member's manage holders see the collection reaching it", share in r.json().get("collections", []))

# Membership
gov("POST", "/collections", "carol", {"group": "projw", "name": f"mine{ts}"})
check("carol, without manage on a jgi folder, may not add it to her collection",
      gov("POST", f"/collections/projw:mine{ts}/members/{plain}", "carol").status_code == 403)
check("nor add her own dataset to alice's, without write on it",
      gov("POST", f"/collections/{share}/members/projw/private", "carol").status_code == 403)
gov("POST", "/collections", "alice", {"group": "jgi", "name": f"outer{ts}"})
check("alice nests her collection in another", gov("POST", f"/collections/{outer}/members/{share}", "alice").status_code == 200)
check("a cycle is refused", gov("POST", f"/collections/{share}/members/{outer}", "alice").status_code == 409)
check("read on the outer collection reaches the inner one's members",
      gov("PATCH", f"/collections/{outer}", "alice", {"changes": [{"group": "noaccess", "add": ["read"]}]}).status_code == 200
      and vend("bob", plain).status_code == 200)
check("taking the inner one out takes that away",
      gov("DELETE", f"/collections/{outer}/members/{share}", "alice").status_code == 200
      and vend("bob", plain).status_code == 403)
check("removing a member takes away what the collection gave",
      gov("DELETE", f"/collections/{share}/members/{plain}", "alice").status_code == 200
      and vend("carol", plain).status_code == 403)
check("its admins delete a collection, its members untouched",
      gov("DELETE", f"/collections/{share}", "alice").status_code == 200 and vend("alice", built).status_code == 200)
