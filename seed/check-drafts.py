"""
seed/check-drafts.py — engine-drafted declarations (docs/HANDOFF-2026-10-22-groups.md section 4,
docs/PLAN-2026-10-24.md item 5), through Trino's HTTP statement API as alice, on one login. In a
new session she copies t2 into a table, reads that table back to the client, then creates a
table from t1. Trino's event listener reports each statement; the draft of the last marks t1
used, t2 unused (its rows only ever went into a table) and leaves out the table whose rows went
to the client. Exits 1 at the first check that fails. Run in the governance container:

    docker compose exec governance python /seed/check-drafts.py

Names are new on each run. Waits up to 10 s for Trino's events, and 3 s once.
"""
import ssl
import sys
import tempfile
import time

import requests

sys.path.insert(0, "/app")
import app  # noqa: E402  (governance's own module: the sources OPA's lookups return)

app.connect_pool()
# Trino makes a self-signed certificate at each start; pinned here, as the login proxy pins it.
PIN = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
PIN.write(ssl.get_server_certificate(("trino", 8443)))
PIN.close()
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
TOKEN = requests.post(KC, data={"grant_type": "password", "client_id": "trino", "client_secret": "trino-secret",
                                "username": "alice", "password": "alice", "scope": "openid aud-polaris"}
                      ).json()["access_token"]
H = {"Authorization": f"Bearer {TOKEN}", "X-Trino-User": "alice", "X-Trino-Catalog": "iceberg",
     "X-Trino-Extra-Credential": f"token={TOKEN}"}


def trino(sql):
    """The statement's rows, or its error message as a RuntimeError."""
    r = requests.post("https://trino:8443/v1/statement", data=sql.encode(), headers=H, verify=PIN.name).json()
    rows = []
    while True:
        rows += r.get("data", [])
        if "error" in r:
            raise RuntimeError(r["error"]["message"])
        if "nextUri" not in r:
            return rows
        r = requests.get(r["nextUri"], headers=H, verify=PIN.name).json()


def refused(sql):
    try:
        trino(sql)
        return ""
    except RuntimeError as e:
        return str(e)


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


ts = str(int(time.time()))
a, b = f"lakehouse.jgi.da{ts}", f"lakehouse.jgi.db{ts}"
trino(f"INSERT INTO governance.sessions (name) VALUES ('drafts-{ts}')")
trino(f"CREATE TABLE jgi.da{ts} AS SELECT * FROM jgi.t2")
check("alice reads her copy back to the client", trino(f"SELECT * FROM jgi.da{ts}") == [[2]])
trino(f"CREATE TABLE jgi.db{ts} AS SELECT * FROM jgi.t1")

draft = []
for _ in range(20):
    draft = trino(f"SELECT source, source_type, used, engine FROM governance.drafts WHERE target = '{b}' ORDER BY source")
    if draft:
        break
    time.sleep(0.5)
check(f"the draft for {b} marks t1 used and t2 unused, and leaves out the table read to the client {draft}",
      draft == [["lakehouse.jgi.t1", "table", True, "trino"], ["lakehouse.jgi.t2", "table", False, "trino"]])
check("the draft for the copy marks t2 used",
      trino(f"SELECT source, used FROM governance.drafts WHERE target = '{a}'") == [["lakehouse.jgi.t2", True]])

carried = {c["id"]: c["declared"] for c in app.carried(b)}
check("the draft alone changes nothing: every source is still carried, undeclared",
      carried == {"lakehouse.jgi.t1": False, "lakehouse.jgi.t2": False, a: False})

time.sleep(3)   # a declaration covers a file from 2 s after it was written (PROVENANCE.md 8)
confirm = (f"INSERT INTO governance.derivations (source, source_type, target, used) "
           f"SELECT source, source_type, target, used FROM governance.drafts WHERE target = '{b}'")
message = refused(confirm)
check(f"confirming the draft as it is runs the insert's checks ({message.split(': ', 1)[-1]})",
      f"not declared: {a}" in message)
check("confirming it with the left-out candidate accounted for is accepted",
      refused(confirm + f" UNION ALL VALUES ('{a}', 'table', '{b}', true)") == "")
carried = {c["id"]: c["declared"] for c in app.carried(b)}
check("after which t2 is no longer carried and the rest are declared",
      carried == {"lakehouse.jgi.t1": True, a: True})
