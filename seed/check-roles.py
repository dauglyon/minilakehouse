"""
seed/check-roles.py — groups, roles and stewards (docs/HANDOFF-2026-10-22-groups.md section 1,
docs/PLAN-2026-10-24.md item 2) through governance's API, the broker and the gate. alice owns
and stewards `jgi`, which owns datasets/projx/ and lakehouse.db; carol is a platform admin; bob
holds nothing. Exits 1 at the first check that fails. Run in the governance container:

    docker compose exec governance python /seed/check-roles.py

Group, dataset, table and session names are new on each run; `dave` and `erin` are subjects
with no login, added to groups only.
"""
import sys
import time

import requests
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
    return requests.request(method, GOV + path, json=body,
                            headers={"Authorization": f"Bearer {token(user)}"})


def vend(user, dataset, mode):
    return requests.post(f"{BROKER}/vend", json={"dataset": dataset, "mode": mode},
                         headers={"Authorization": f"Bearer {token(user)}"}).status_code


def create_table(user, name):
    """Whether the gate let the user create lakehouse.<name>, with pyiceberg."""
    cat = RestCatalog("gate", uri="http://gate:8182/api/catalog", warehouse="lakehouse", token=token(user))
    try:
        cat.create_table(name, schema=Schema(NestedField(1, "x", LongType(), required=False)))
        return True
    except Exception:  # noqa: BLE001 — pyiceberg raises its own error for the gate's 403
        return False


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


ts = str(int(time.time()))
g, mine, ds, tbl = f"rc{ts}", f"bc{ts}", f"projx/rc{ts}", f"db.rc{ts}"


def patch(user, body):
    return gov("PATCH", f"/groups/{g}", user, body).status_code


# bob's reads from earlier runs would be sources of the table he creates below.
gov("POST", "/sessions", "bob", {"name": f"roles-{ts}"})

# Creating a group
r = gov("POST", "/groups", "bob", {"name": mine})
check("bob creates a group and is its owner", r.status_code == 201 and r.json()["owners"] == ["bob"])
check("GET /me shows it", {"group": mine, "role": "owner", "steward": False, "tenant": False}
      in gov("GET", "/me", "bob").json()["groups"])
bad = ["a", "Ab1", "has-hyphen", "1abc", "u_bob", "admin", "governance", "x" * 65]
codes = [gov("POST", "/groups", "bob", {"name": n}).status_code for n in bad]
check(f"names outside the rule or reserved are refused {codes}", set(codes) == {400})
check("a name in use is refused", gov("POST", "/groups", "alice", {"name": mine}).status_code == 409)

# Roles
check("alice creates another", gov("POST", "/groups", "alice", {"name": g}).status_code == 201)
check("its owner adds an admin", patch("alice", {"admins": {"add": ["bob"]}}) == 200)
check("an admin adds a member and a viewer",
      patch("bob", {"members": {"add": ["dave"]}, "viewers": {"add": ["erin"]}}) == 200)
check("an admin may not add an owner", patch("bob", {"owners": {"add": ["dave"]}}) == 403)
check("an admin may not remove an admin", patch("bob", {"admins": {"remove": ["bob"]}}) == 403)
check("the owner moves the admin down to member", patch("alice", {"members": {"add": ["bob"]}}) == 200)
check("a member changes nobody", patch("bob", {"viewers": {"add": ["frank"]}}) == 403)
check("a change leaving no owner is refused", patch("alice", {"owners": {"remove": ["alice"]}}) == 409)

# Stewards
check("an owner may not appoint a steward",
      gov("PUT", f"/groups/{g}/stewards/bob", "alice").status_code == 403)
r = gov("PUT", f"/groups/{g}/stewards/bob", "carol")
check("a platform admin appoints a member steward, making a tenant",
      r.status_code == 200 and r.json()["stewards"] == ["bob"] and r.json()["tenant"])
check("a viewer cannot be a steward", gov("PUT", f"/groups/{g}/stewards/erin", "carol").status_code == 409)
check("removing a steward from the group is refused", patch("alice", {"members": {"remove": ["bob"]}}) == 409)
r = gov("DELETE", f"/groups/{g}/stewards/bob", "carol")
check("a platform admin removes the steward", r.status_code == 200 and r.json()["stewards"] == [])

# Registration: a steward of a group owning the root
check("alice adds bob to jgi as a member", gov("PATCH", "/groups/jgi", "alice",
                                               {"members": {"add": ["bob"]}}).status_code == 200)
grants = {"describe": [g], "access": [g], "write": [g]}
check("a member's registration is refused",
      gov("POST", "/datasets", "bob", {"prefix": f"datasets/{ds}/", **grants}).status_code == 403)
check("a steward's registration is accepted",
      gov("POST", "/datasets", "alice", {"prefix": f"datasets/{ds}/", **grants}).status_code == 201)
table_grants = {"id": f"lakehouse.{tbl}", "read": [g], "write": [g], "delete": [g]}
check("a member's table registration is refused", gov("POST", "/tables", "bob", table_grants).status_code == 403)
check("a steward's table registration is accepted",
      gov("POST", "/tables", "alice", table_grants).status_code == 201)
check("bob leaves jgi", gov("PATCH", "/groups/jgi", "alice", {"members": {"remove": ["bob"]}}).status_code == 200)

# A viewer holds describe and read, never write
check("bob becomes a viewer", patch("alice", {"viewers": {"add": ["bob"]}}) == 200)
check("the viewer reads the dataset", vend("bob", ds, "read") == 200)
check("the viewer is refused a write credential", vend("bob", ds, "write") == 403)
check("the viewer is refused creating the table", not create_table("bob", tbl))
check("GET /groups answers a viewer", gov("GET", f"/groups/{g}", "bob").status_code == 200)
check("GET /groups refuses someone outside", gov("GET", "/groups/projw", "bob").status_code == 404)
r = gov("GET", f"/datasets/{ds}", "bob")
check("GET /datasets shows the viewer the entry", r.status_code == 200 and r.json()["can_read"]
      and r.json()["effective_read"] == [g])
check("bob becomes a member again", patch("alice", {"members": {"add": ["bob"]}}) == 200)
check("the member gets a write credential", vend("bob", ds, "write") == 200)
check("the member creates the table", create_table("bob", tbl))
r = gov("GET", f"/tables/lakehouse.{tbl}", "bob")
check("GET /tables shows a reader the entry", r.status_code == 200 and r.json()["grants"]["read"] == [g])
check("GET /tables refuses someone who may not describe it",
      gov("GET", f"/tables/lakehouse.{tbl}", "carol").status_code == 404)
RestCatalog("gate", uri="http://gate:8182/api/catalog", warehouse="lakehouse", token=token("bob")).drop_table(tbl)

# Deleting
check("an owner deletes a group", gov("DELETE", f"/groups/{mine}", "bob").status_code == 200)
check("a group owning a root is not deleted", gov("DELETE", "/groups/jgi", "alice").status_code == 409)
check("a non-owner may not delete", gov("DELETE", f"/groups/{g}", "bob").status_code == 403)
check("alice deletes hers", gov("DELETE", f"/groups/{g}", "alice").status_code == 200)
check("its name stays taken while grants name it",
      gov("POST", "/groups", "bob", {"name": g}).status_code == 409)
