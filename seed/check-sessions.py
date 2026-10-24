"""
seed/check-sessions.py — switching sessions (PROVENANCE.md 3): a name inserted into
governance.sessions, through the gate as any Iceberg client inserts, and POST /sessions.
Exits 1 at the first check that fails. Run in the governance container:

    docker compose exec governance python /seed/check-sessions.py

Every call for a person uses one token, so all of them come from one login (one `sid`), whose
pointer the inserts move. Session names are new on each run.
"""
import sys
import time
from datetime import datetime, timezone

import pyarrow as pa
import requests
from pyiceberg.catalog.rest import RestCatalog

KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
GOV = "http://governance:8000"


def login(user):
    r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                                "client_secret": "trino-secret", "username": user, "password": user,
                                "scope": "openid aud-polaris aud-governance"})
    r.raise_for_status()
    token = r.json()["access_token"]
    return token, RestCatalog("gate", uri="http://gate:8182/api/catalog", warehouse="lakehouse", token=token)


def rows(cat, table):
    return cat.load_table(f"governance.{table}").scan().to_arrow().to_pylist()


def insert(cat, *names):
    t = cat.load_table("governance.sessions")
    t.append(pa.Table.from_pylist([{"name": n} for n in names], schema=t.schema().as_arrow()))


def current(cat):
    return [r["name"] for r in rows(cat, "sessions") if r["current"]]


def read_stamped(cat):
    """The session governance stamped a fresh read of lakehouse.jgi.t1 with, as lineage shows it."""
    since = datetime.now(timezone.utc)
    cat.load_table("jgi.t1")   # a credentialed load: the gate logs a read
    return [r["session"] for r in rows(cat, "lineage")
            if r["source"] == "lakehouse.jgi.t1" and r["target"] is None and r["event_time"] >= since]


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


exp1, exp2 = f"exp-{int(time.time())}", f"exp-{int(time.time())}-api"
token, alice = login("alice")

insert(alice, exp1)
check(f"alice inserts {exp1}: it is her current session", current(alice) == [exp1])
check(f"her next read is stamped {exp1}", read_stamped(alice) == [exp1])
insert(alice, "default")
check("inserting default points her back", current(alice) == ["default"])
check("her next read is stamped default", read_stamped(alice) == ["default"])

try:
    insert(alice, "a", "b")
    refused = ""
except Exception as e:  # noqa: BLE001 — pyiceberg raises its own error for the 400
    refused = str(e)
check(f"two rows in one insert are refused ({refused.splitlines()[0] if refused else 'accepted'})",
      "insert one session name" in refused and current(alice) == ["default"])

h = {"Authorization": f"Bearer {token}"}
r = requests.post(f"{GOV}/sessions", headers=h, json={"name": exp2})
check(f"POST /sessions starts {exp2} ({r.status_code})", r.status_code == 201 and current(alice) == [exp2])
r = requests.post(f"{GOV}/sessions", headers=h, json={"name": exp1})
check(f"POST /sessions resumes {exp1} ({r.status_code})", r.status_code == 200 and current(alice) == [exp1])
insert(alice, "default")

_, bob = login("bob")
check("bob's governance.sessions shows none of alice's",
      not {r["name"] for r in rows(bob, "sessions")} & {exp1, exp2})
