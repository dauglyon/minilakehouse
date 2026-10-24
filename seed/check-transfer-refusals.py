"""
seed/check-transfer-refusals.py — a folder's move that fails partway leaves the folder whole
(docs/HANDOFF-2026-10-22-groups.md section 1, Transfers). alice moves a personal folder of N
files into a new group of hers through the broker, three times. While the broker copies, after
governance has recorded the move's start, one thing changes: a file in the folder is
overwritten; the move's time runs out; a dataset at the destination is published. Each move
must end refused, with no copy left at the destination, every file still in the folder, and the
folder not marked moved, and the move ended in governance, so the folders may be published
again. The last two changes are made in governance's database, since no API call can make them
while a move is under way. Exits 1 at the first check that fails. Run in the
governance container:

    docker compose exec governance python /seed/check-transfer-refusals.py

Names are new on each run. Takes about 8 s.
"""
import sys
import threading
import time

import boto3
import requests
from botocore.config import Config

sys.path.insert(0, "/app")
import app  # noqa: E402  (governance's own module and storage key)

KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
GOV, BROKER = "http://governance:8000", "http://broker:9100"
N = 30
TOKEN = requests.post(KC, data={"grant_type": "password", "client_id": "trino", "client_secret": "trino-secret",
                                "username": "alice", "password": "alice",
                                "scope": "openid aud-governance aud-broker"}).json()["access_token"]
H = {"Authorization": f"Bearer {TOKEN}"}
app.connect_pool()


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


def keys(prefix):
    out, token = [], {}
    while True:
        r = app._s3.list_objects_v2(Bucket=app.S3_BUCKET, Prefix=prefix, **token)
        out += [o["Key"] for o in r.get("Contents", [])]
        if not r.get("IsTruncated"):
            return out
        token = {"ContinuationToken": r["NextContinuationToken"]}


def sql(query, args=()):
    with app.db(commit=True) as cur:
        cur.execute(query, args)
        return cur.fetchall() if cur.description else None


ts = str(int(time.time()))
g, src = f"tr{ts}", f"u_alice/tr{ts}"
requests.post(f"{GOV}/sessions", json={"name": f"transfer-refusals-{ts}"}, headers=H)
check("alice creates a group", requests.post(f"{GOV}/groups", json={"name": g}, headers=H).status_code == 201)
c = requests.post(f"{BROKER}/vend", json={"folder": src, "mode": "write"}, headers=H).json()
s3 = boto3.client("s3", endpoint_url=c["endpoint"], aws_access_key_id=c["access_key_id"],
                  aws_secret_access_key=c["secret_access_key"], aws_session_token=c["session_token"],
                  region_name="us-east-1", config=Config(signature_version="s3v4"))
for i in range(N):
    s3.put_object(Bucket=c["bucket"], Key=f"{c['prefix']}f{i:04d}", Body=b"x")
last = f"{c['prefix']}f{N - 1:04d}"   # the broker copies in listing order, so this one last


def move(dst, perturb):
    """Start the move, and once governance has recorded its start, perturb(transfer id) while
    the broker copies. The broker's answer and the transfer id."""
    out, tid = {}, None
    t = threading.Thread(target=lambda: out.update(r=requests.post(
        f"{BROKER}/transfers", json={"from": src, "to": dst}, headers=H, timeout=120)))
    t.start()
    for _ in range(2000):
        rows = sql("SELECT id FROM transfers WHERE from_id = %s AND to_id = %s", (src, dst))
        if rows:
            tid = rows[0]["id"]
            perturb(tid)
            break
        time.sleep(0.005)
    t.join()
    return out["r"], tid


def left_whole(dst, r, tid, error):
    check(f"  the broker refuses it ({r.status_code}: {r.json().get('error')})",
          r.status_code == 409 and error in r.json().get("error", ""))
    check("  no copy is left at the destination", keys(f"datasets/{dst}/") == [])
    check(f"  every file is still in the folder", len(keys(f"datasets/{src}/")) == N)
    check("  the folder is not marked moved",
          sql("SELECT status FROM datasets WHERE id = %s", (src,))[0]["status"] != "moved")
    check("  and the move is no longer under way, nor its session's read and write",
          not sql("SELECT 1 FROM transfers WHERE id = %s AND expires > now()", (tid,))
          and not sql("SELECT 1 FROM accesses a JOIN transfers t ON t.session = a.session "
                      "WHERE t.id = %s AND a.expires > now()", (tid,)))


print("A file is overwritten during the copy")
r, tid = move(f"{g}/a", lambda _: s3.put_object(Bucket=c["bucket"], Key=last, Body=b"changed"))
left_whole(f"{g}/a", r, tid, "changed during the move")
check("  the overwritten file keeps its new content",   # governance's key lists, never reads
      app._s3.list_objects_v2(Bucket=app.S3_BUCKET, Prefix=last)["Contents"][0]["Size"] == len(b"changed"))

print("The move's time runs out during the copy")
r, tid = move(f"{g}/b", lambda t: sql("UPDATE transfers SET expires = now() - interval '1 second' WHERE id = %s", (t,)))
left_whole(f"{g}/b", r, tid, "no such transfer under way")

print("A dataset at the destination is published during the copy")
r, tid = move(f"{g}/c", lambda _: sql("UPDATE datasets SET published = true WHERE id = %s", (f"{g}/c",)))
sql("UPDATE datasets SET published = false WHERE id = %s", (f"{g}/c",))
left_whole(f"{g}/c", r, tid, "was published")
