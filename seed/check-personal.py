"""
seed/check-personal.py — personal spaces (PROVENANCE.md 9, docs/HANDOFF-2026-10-22-groups.md
section 1, docs/PLAN-2026-10-24.md item 3c). carol, steward of projw, publishes a folder whose
`read` names jgi; alice reads it and copies it into her personal space, u_alice, and into jgi's
space, as files and as tables. When jgi loses `read` on the source, the jgi copies close and her
own stay open, until carol adds u_alice to the source's `revoked`. Then nothing in u_alice can
be granted or published, and a declaration marking a group-space folder unused reaches that
group's admins. Exits 1 at the first check that fails. Run in the governance container:

    docker compose exec governance python /seed/check-personal.py

Names are new on each run. Waits up to 10 s for listings.
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
src, mine, theirs = f"projw/src{ts}", f"u_alice/copy{ts}", f"jgi/copy{ts}"
for user in ("alice", "bob", "carol"):
    gov("POST", "/sessions", user, {"name": f"personal-{ts}"})
check("alice has a personal group, as its only owner",
      {"group": "u_alice", "role": "owner", "steward": False, "tenant": False} in gov("GET", "/me", "alice").json()["groups"])

put("carol", src, "data.txt")
check("carol publishes a folder readable by jgi",
      gov("PATCH", f"/datasets/{src}", "carol", {"description": "source", "read": ["jgi"]}).status_code == 200)
check("alice reads it", vend("alice", src).status_code == 200)
put("alice", mine, "copy.txt")
put("alice", theirs, "copy.txt")
schema = Schema(NestedField(1, "x", LongType(), required=False))
cat = catalog("alice")
cat.create_namespace_if_not_exists(("u_alice",))
for ident in (("u_alice", f"t{ts}"), ("jgi", f"t{ts}")):
    cat.create_table(ident, schema=schema).append(pa.table({"x": pa.array([1], pa.int64())}))
check("her copies carry the source", all(carries(e, src) for e in (mine, theirs, f"lakehouse.u_alice.t{ts}",
                                                                 f"lakehouse.jgi.t{ts}")))

r = gov("PATCH", f"/permissions/dataset/{src}", "carol", {"changes": [{"group": "jgi", "remove": ["read"]}]})
check(f"jgi loses read on the source ({r.status_code})", r.status_code == 200 and vend("alice", src).status_code == 403)
check("the copies in jgi's space close to her",
      vend("alice", theirs).status_code == 403 and not reads_table("alice", ("jgi", f"t{ts}")))
check("her own copies stay open to her",
      vend("alice", mine).status_code == 200 and reads_table("alice", ("u_alice", f"t{ts}")))
check("and she may still write her own space", vend("alice", mine, "write").status_code == 200)
check("someone who is not projw's steward may not add her to the source's revoked",
      gov("PATCH", f"/permissions/dataset/{src}", "alice",
          {"changes": [{"group": "u_alice", "add": ["revoked"]}]}).status_code == 403)
r = gov("PATCH", f"/permissions/dataset/{src}", "carol", {"changes": [{"group": "u_alice", "add": ["revoked"]}]})
check(f"projw's steward adds her ({r.status_code})", r.status_code == 200)
check("her own copies close", vend("alice", mine).status_code == 403 and not reads_table("alice", ("u_alice", f"t{ts}")))
r = gov("GET", f"/datasets/{src}", "carol")
check("the revocation is recorded, with who added it, for the source's manage holders",
      r.status_code == 200 and "u_alice" in r.json()["grants"]["revoked"]
      and {"group": "u_alice", "added_by": "carol"}.items() <= r.json()["revocations"][-1].items())

# A personal space is granted to no one else
for user in ("alice", "carol"):
    check(f"{user} may not grant a folder in u_alice", gov("PATCH", f"/permissions/folder/{mine}", user,
          {"changes": [{"group": "projw", "add": ["read"]}]}).status_code == 403)
check("nor publish there", gov("PATCH", f"/datasets/{mine}", "carol", {"description": "x"}).status_code == 403)
check("nor add anyone to the group", gov("PATCH", "/groups/u_alice", "alice",
                                         {"members": {"add": ["bob"]}}).status_code == 403)
check("nor give it a steward", gov("PUT", "/groups/u_alice/stewards/alice", "carol").status_code == 403)

# A declaration marking a group-space folder unused reaches the group's admins
g = f"pd{ts}"
gov("POST", "/groups", "alice", {"name": g})
gov("PATCH", f"/groups/{g}", "alice", {"members": {"add": ["bob"]}, "viewers": {"add": ["carol"]}})
gov("POST", "/sessions", "alice", {"name": f"personal-{ts}-group"})   # nothing she read above
put("alice", f"{g}/data", "d.txt")
check("bob, a member, reads the group's folder", vend("bob", f"{g}/data").status_code == 200)
put("bob", f"u_bob/out{ts}", "out.txt")
r = gov("POST", "/declarations", "bob", {"rows": [{"source": f"{g}/data", "source_type": "files",
                                                    "target": f"u_bob/out{ts}", "used": False}]})
check(f"and declares it unused in his own output ({r.status_code})", r.status_code == 201)


def shown(user):
    rows = catalog(user).load_table("governance.derivations").scan().to_arrow().to_pylist()
    return any(r["source"] == f"{g}/data" and r["target"] == f"u_bob/out{ts}" and r["used"] is False
               and r["declared_by"] == "bob" for r in rows)


check("the group's owner sees the declaration", shown("alice"))
check("its viewer does not", not shown("carol"))
