"""
seed/check-credentials.py — what a file credential covers (docs/HANDOFF-2026-10-22-groups.md
section 3, docs/PLAN-2026-10-24.md item 3b), against Ceph itself. A new group has alice as its
owner and steward and bob as a member. bob writes `top/loose.txt` and `top/sub/inner.txt`, and
alice publishes `top/pub`, so `top` holds a published dataset. Exits 1 at the first check that
fails. Run in the governance container:

    docker compose exec governance python /seed/check-credentials.py

Group and session names are new on each run. Waits 3 s once, and up to 10 s for a listing.
"""
import sys
import time

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
GOV, BROKER = "http://governance:8000", "http://broker:9100"
_tokens = {}


def token(user):
    if user not in _tokens:
        r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                                    "client_secret": "trino-secret", "username": user, "password": user,
                                    "scope": "openid aud-governance aud-broker"})
        r.raise_for_status()
        _tokens[user] = r.json()["access_token"]
    return _tokens[user]


def gov(method, path, user, body=None):
    return requests.request(method, GOV + path, json=body, headers={"Authorization": f"Bearer {token(user)}"})


def vend(user, folder, mode="read", recursive=True):
    return requests.post(f"{BROKER}/vend", json={"folder": folder, "mode": mode, "recursive": recursive},
                         headers={"Authorization": f"Bearer {token(user)}"})


def s3(cred):
    c = cred.json()
    return boto3.client("s3", endpoint_url=c["endpoint"], aws_access_key_id=c["access_key_id"],
                        aws_secret_access_key=c["secret_access_key"], aws_session_token=c["session_token"],
                        region_name="us-east-1", config=Config(signature_version="s3v4")), c["bucket"]


def works(call):
    try:
        call()
        return True
    except ClientError:
        return False


def check(what, ok):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        sys.exit(1)


ts = str(int(time.time()))
g = f"cc{ts}"
top, base = f"{g}/top", f"datasets/{g}/top/"
for user in ("alice", "bob"):
    gov("POST", "/sessions", user, {"name": f"credentials-{ts}"})
gov("POST", "/groups", "alice", {"name": g})
gov("PATCH", f"/groups/{g}", "alice", {"members": {"add": ["bob"]}})
gov("PUT", f"/groups/{g}/stewards/alice", "carol")

w, bucket = s3(vend("bob", top, "write"))
for key in ("loose.txt", "sub/inner.txt", "pub/data.txt"):
    w.put_object(Bucket=bucket, Key=base + key, Body=key.encode())
check("a recursive write credential wrote the folder and its subfolders", True)
# Listed times are whole seconds, and a read up to 2 s after a file's listed time counts toward
# it (PROVENANCE.md 8), so the reads below wait for the writes above to be older than that.
time.sleep(3)
check("bob tracks the subfolder to publish", vend("bob", f"{top}/pub", "write").status_code == 200)
check("alice publishes it", gov("PATCH", f"/datasets/{top}/pub", "alice", {"description": "pub"}).status_code == 200)

r = vend("bob", top)
message = r.json().get("error", "")
check(f"a recursive read of the folder around it is refused with the message ({r.status_code})",
      r.status_code == 403 and message.startswith(f"{base} contains published datasets")
      and '"recursive": false' in message)
r = vend("carol", top)
check("someone it is not open to gets the plain refusal", r.status_code == 403 and r.json()["error"] == "forbidden")

direct, _ = s3(vend("bob", top, recursive=False))
check("a direct read credential reads a file directly in the folder",
      works(lambda: direct.get_object(Bucket=bucket, Key=base + "loose.txt")))
check("and is refused a file in a subfolder",
      not works(lambda: direct.get_object(Bucket=bucket, Key=base + "sub/inner.txt")))
check("and inside the published dataset",
      not works(lambda: direct.get_object(Bucket=bucket, Key=base + "pub/data.txt")))
listing = direct.list_objects_v2(Bucket=bucket, Prefix=base, Delimiter="/")
check("it lists the folder's files and its subfolders' names",
      [o["Key"] for o in listing.get("Contents", [])] == [base + "loose.txt"]
      and sorted(p["Prefix"] for p in listing.get("CommonPrefixes", [])) == [base + "pub/", base + "sub/"])
check("and is refused listing below the folder",
      not works(lambda: direct.list_objects_v2(Bucket=bucket, Prefix=base + "sub/", Delimiter="/")))
check("and listing the folder recursively", not works(lambda: direct.list_objects_v2(Bucket=bucket, Prefix=base)))

wdirect, _ = s3(vend("bob", top, "write", recursive=False))
check("a direct write credential writes directly in the folder",
      works(lambda: wdirect.put_object(Bucket=bucket, Key=base + "new.txt", Body=b"n")))
check("and is refused writing in a subfolder",
      not works(lambda: wdirect.put_object(Bucket=bucket, Key=base + "sub/new.txt", Body=b"n")))

sub, _ = s3(vend("bob", f"{top}/sub"))
check("a subfolder with no published dataset under it opens recursively",
      works(lambda: sub.get_object(Bucket=bucket, Key=base + "sub/inner.txt")))
check("and its credential reaches nothing beside it",
      not works(lambda: sub.get_object(Bucket=bucket, Key=base + "loose.txt")))
check("the published dataset opens on its own credential", vend("bob", f"{top}/pub").status_code == 200)
check("no credential, direct or not, opens a folder inside it",
      vend("bob", f"{top}/pub/x", recursive=False).status_code == 403)

# Attribution follows what a credential covers. bob has read top/sub in this session; a file he
# writes directly in top with a direct credential carries it, and top/sub gains nothing.
sys.path.insert(0, "/app")
import app  # noqa: E402  (governance's own module: the lookup OPA's rules get)

app.connect_pool()
wdirect, _ = s3(vend("bob", top, "write", recursive=False))
wdirect.put_object(Bucket=bucket, Key=base + "after-reading-sub.txt", Body=b"n")
for _ in range(20):
    if f"{top}/sub" in [c["id"] for c in app.carried(top)]:
        break
    time.sleep(0.5)
check("a file written directly in the folder carries what its writer read",
      f"{top}/sub" in [c["id"] for c in app.carried(top)])
check("and the subfolder, which that credential does not cover, carries nothing", app.carried(f"{top}/sub") == [])
