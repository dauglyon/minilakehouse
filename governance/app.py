"""
governance — the PAP + dataset registry, and the single source of truth (Postgres-backed).

It owns group membership, the dataset and table registries, and all grants; OPA holds none,
and Keycloak only proves who a person is. Every caller, governance included,
sends OPA only who is asking and what they name; OPA's rules fetch the grants they need from
the /internal/* lookups here, at decision time. Durable state lives in a dedicated
`governance` Postgres DB.

Two truths, reconciled not merged: storage is truth for existence/stats; the registry is
truth for meaning/grants. The `datasets` row carries both, written by disjoint paths —
meaning/grants by ingest+seed, existence/stats by reconcile. Entries served to OPA carry
meaning/grants only, so storage churn never changes a decision.

Two permission planes per dataset, as separate grant sets: visibility (may you SEE it
exists) vs access (may you READ the bytes) — so a dataset can be see-but-not-read.

Governance builds every list; OPA only says which of the candidates it was given pass.
"""
import hmac
import json
import logging
import os
import re
import threading
import time
from contextlib import contextmanager

import boto3
import jwt
import psycopg2
import requests
from botocore.config import Config
from flask import Flask, jsonify, request
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

REGISTRY_PATH = os.environ.get("REGISTRY", "/app/registry.json")
OPA_BASE = os.environ.get("OPA_BASE", "http://opa:8181")
DB_DSN = os.environ["GOVERNANCE_DB_DSN"]
KEYCLOAK_JWKS = os.environ["KEYCLOAK_JWKS"]
KEYCLOAK_ISS = os.environ["KEYCLOAK_ISS"]
# Bearer OPA presents to /internal/*. Those return any entry's grants, including datasets the
# person can't see, so they are closed to everyone else.
ENTRY_TOKEN = os.environ["ENTRY_TOKEN"]
# Bearer the gate presents when it reports a table created or dropped through Polaris.
LIFECYCLE_TOKEN = os.environ["LIFECYCLE_TOKEN"]
# Polaris refuses a token whose name has no stored principal (released Polaris has no other
# mode), so governance creates each person's, name only, the first time the gate sees them.
# It logs in as `provisioner`, which OPA allows to create principals and nothing else.
POLARIS_URL = os.environ["POLARIS_URL"]
POLARIS_REALM = os.environ["POLARIS_REALM"]
PROVISIONER = (os.environ["PROVISIONER_CLIENT_ID"], os.environ["PROVISIONER_CLIENT_SECRET"])
# Polaris's own principals; a person with one of these names would act as it.
RESERVED_PRINCIPALS = {"root", "provisioner"}
# A table id: catalog, namespace levels and name joined by "." (opa/tables.rego).
TABLE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){2,}$")
# Only tokens issued THROUGH our login client are accepted (azp), so a token minted for some
# other realm client can't be replayed here as a user credential.
EXPECTED_AZP = os.environ.get("EXPECTED_AZP", "trino")
# A prefix becomes an STS resource ARN; it's from an authenticated steward but still
# untrusted. Confine it: datasets/<bounded, safe-charset>/ — capped so it can't blow the STS
# policy-size limit and restricted so no control/space/unicode reaches the ARN.
PREFIX_RE = re.compile(r"^datasets/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}/$")


def derive_id(prefix):
    """A dataset's id is its prefix without the `datasets/` root and trailing slash:
    `datasets/projx/public/` -> `projx/public`."""
    return prefix[len("datasets/"):-1]

# --- Storage / freshness ---
# Least-privilege reader creds (ListBucket on datasets/* via a bucket policy set by the
# rgw-setup one-shot). Governance does NOT hold the RGW admin key; reconcile only lists.
RGW_ENDPOINT = os.environ.get("RGW_ENDPOINT", "http://ceph:8080")
RGW_KEY = os.environ.get("RGW_ACCESS_KEY", "")
RGW_SECRET = os.environ.get("RGW_SECRET_KEY", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "lakehouse")
RECONCILE_INTERVAL = int(os.environ.get("RECONCILE_INTERVAL", "30"))
MAX_EVENT_RECORDS = 1000  # cap the per-request reconcile fan-out (the endpoint is unauthenticated)
SEED_LOCK_KEY = 0x6D6C68      # arbitrary fixed key: serialize the one-time registry seed
REGISTER_LOCK_KEY = 0x6D6C72  # arbitrary fixed key: serialize register-at-ingest
# Short timeouts: storage calls are best-effort; the periodic reconcile timer is the
# authority and self-heals, so governance must never hang/crash on RGW being slow/absent.
_boto_cfg = Config(signature_version="s3v4", connect_timeout=5, read_timeout=5,
                   retries={"max_attempts": 2})
# One reusable client/session each (thread-safe), instead of rebuilding per reconcile/poll.
_s3 = boto3.client("s3", endpoint_url=RGW_ENDPOINT, aws_access_key_id=RGW_KEY,
                   aws_secret_access_key=RGW_SECRET, region_name="us-east-1", config=_boto_cfg)
_http = requests.Session()

# Full schema up front (incl. the existence/stats columns reconcile fills in) so
# CREATE TABLE IF NOT EXISTS never has to ALTER a table on an already-persisted volume.
SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets (
    id              TEXT PRIMARY KEY,        -- derive_id(prefix): the tenant-qualified identity
    prefix          TEXT UNIQUE NOT NULL,    -- storage location; one dataset per prefix
    description     TEXT,
    steward         TEXT,
    visibility      TEXT[] NOT NULL DEFAULT '{}',
    access          TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending | live | gone
    object_count    BIGINT NOT NULL DEFAULT 0,
    total_bytes     BIGINT NOT NULL DEFAULT 0,
    last_modified   TIMESTAMPTZ,
    last_reconciled TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS group_members (
    grp    TEXT NOT NULL,
    member TEXT NOT NULL,                    -- a person's subject (the token's principal_name)
    PRIMARY KEY (grp, member)
);
CREATE TABLE IF NOT EXISTS table_entries (
    id          TEXT PRIMARY KEY,            -- <catalog>.<namespace...>.<table>
    description TEXT,
    steward     TEXT,
    see         TEXT[] NOT NULL DEFAULT '{}',
    read        TEXT[] NOT NULL DEFAULT '{}',
    write       TEXT[] NOT NULL DEFAULT '{}',
    "delete"    TEXT[] NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending | live | gone
    location    TEXT                         -- learned from Polaris when the table is created
);
CREATE TABLE IF NOT EXISTS namespace_owners (
    grp       TEXT NOT NULL,
    namespace TEXT NOT NULL,                 -- <catalog>.<namespace...>; covers every namespace under it
    PRIMARY KEY (grp, namespace)
);
CREATE TABLE IF NOT EXISTS register_grants (
    grp      TEXT PRIMARY KEY,
    prefixes TEXT[] NOT NULL DEFAULT '{}'   -- prefix roots this group may register under
);
"""

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
_jwks = jwt.PyJWKClient(KEYCLOAK_JWKS)
app = Flask(__name__)
app.logger.setLevel(logging.INFO)  # Flask defaults app.logger to WARNING when debug=off
POOL_MAX = 16
_pool = None
# ThreadedConnectionPool.getconn() RAISES when exhausted rather than waiting; the dev server
# spawns unbounded request threads. This semaphore bounds concurrent borrowers to POOL_MAX so
# an event/request burst degrades to latency, not 500s.
_db_gate = threading.BoundedSemaphore(POOL_MAX)


def connect_pool(retries=30, delay=1):
    """The governance DB exists by now (bootstrap one-shot), but tolerate a slow start."""
    global _pool
    last = None
    for _ in range(retries):
        try:
            _pool = ThreadedConnectionPool(1, POOL_MAX, dsn=DB_DSN)
            return
        except psycopg2.OperationalError as e:  # noqa: PERF203
            last = e
            app.logger.warning("waiting for governance DB: %s", e)
            time.sleep(delay)
    raise last


@contextmanager
def db(commit=False):
    """A pooled connection + RealDict cursor. Per-operation, thread-safe (request threads and
    the reconcile timer all borrow from the pool); the gate bounds concurrency to the pool."""
    with _db_gate:
        conn = _pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                yield cur
            conn.commit() if commit else conn.rollback()
        except Exception:
            conn.rollback()
            raise
        finally:
            _pool.putconn(conn)


def init_db():
    """Create the schema, and seed from registry.json once (when datasets is empty).
    registry.json is now a one-time fixture; Postgres is the source of truth thereafter."""
    with db(commit=True) as cur:
        cur.execute(SCHEMA)
    with db(commit=True) as cur:
        # Serialize the check-then-seed so two instances starting together can't both seed.
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (SEED_LOCK_KEY,))
        cur.execute("SELECT count(*) AS n FROM datasets")
        if cur.fetchone()["n"]:
            return
        with open(REGISTRY_PATH) as f:
            reg = json.load(f)
        for d in reg.get("datasets", []):
            if not _confined_prefix(d["prefix"]):  # the fixture is untrusted-into-ARN too
                raise ValueError(f"registry.json: bad prefix {d['prefix']!r}")
            cur.execute(
                "INSERT INTO datasets (id, prefix, description, steward, visibility, access) "
                "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (derive_id(d["prefix"]), d["prefix"], d.get("description"), d.get("steward"),
                 d.get("visibility", []), d.get("access", [])),
            )
        for grp, members in reg.get("groups", {}).items():
            for m in members:
                cur.execute("INSERT INTO group_members (grp, member) VALUES (%s, %s) "
                            "ON CONFLICT DO NOTHING", (grp, m))
        for t in reg.get("tables", []):
            if not TABLE_ID_RE.match(t["id"]):
                raise ValueError(f"registry.json: bad table id {t['id']!r}")
            cur.execute(
                'INSERT INTO table_entries (id, description, steward, see, read, write, "delete") '
                "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (t["id"], t.get("description"), t.get("steward"), t.get("see", []),
                 t.get("read", []), t.get("write", []), t.get("delete", [])),
            )
        for grp, namespaces in reg.get("namespace_owners", {}).items():
            for ns in namespaces:
                cur.execute("INSERT INTO namespace_owners (grp, namespace) VALUES (%s, %s) "
                            "ON CONFLICT DO NOTHING", (grp, ns))
        for grp, prefixes in reg.get("register_grants", {}).items():
            # Roots MUST end in / — the ownership boundary is startswith(prefix, root), so a
            # missing slash would let `datasets/projx` own `datasets/projxEVIL/`.
            roots = [p if p.endswith("/") else p + "/" for p in prefixes]
            cur.execute("INSERT INTO register_grants (grp, prefixes) VALUES (%s, %s) "
                        "ON CONFLICT (grp) DO NOTHING", (grp, roots))
        app.logger.info("seeded governance registry from %s", REGISTRY_PATH)


def _entry(row):
    """The meaning/grants half of a datasets row — what OPA decides over."""
    return {"id": row["id"], "prefix": row["prefix"],
            "visibility": row["visibility"], "access": row["access"]}


# NOTE: verify_user + authed_user are duplicated in the other service (governance/broker) —
# separate container images, no shared module. Keep the two copies in sync.
def verify_user(token):
    """Cryptographically verify the caller's own Keycloak token -> subject. PyJWT enforces
    signature + exp; we add issuer and azp (the token must have been issued through our login
    client, not some other realm client). Groups are not read from the token: OPA gets them
    from governance."""
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=KEYCLOAK_ISS,
                        options={"verify_aud": False})
    if claims.get("azp") != EXPECTED_AZP:
        raise jwt.InvalidTokenError(f"unexpected azp {claims.get('azp')!r}")
    return claims.get("principal_name") or claims.get("preferred_username") or claims.get("sub")


def authed_user():
    """Verify the request's bearer token. Returns (subject, None) on success, or
    (None, error_response) for the caller to return as-is."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "missing bearer token"}), 401)
    try:
        return verify_user(auth[7:]), None
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return None, (jsonify({"error": "invalid token"}), 401)


def opa(rule, inp, package="blob"):
    """Evaluate one lakehouse.<package> rule; returns its result."""
    r = _http.post(f"{OPA_BASE}/v1/data/lakehouse/{package}/{rule}", json={"input": inp},
                   timeout=5)
    r.raise_for_status()
    return r.json().get("result")


def internal_caller():
    """None if the request carries ENTRY_TOKEN, else the 401 to return."""
    if hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {ENTRY_TOKEN}"):
        return None
    return jsonify({"error": "unauthorized"}), 401


def _confined_prefix(prefix):
    """A registrable prefix: datasets/<segment>/, bounded safe charset, no traversal/escape."""
    return (isinstance(prefix, str) and PREFIX_RE.match(prefix) is not None
            and ".." not in prefix and "//" not in prefix)


# Lifecycle, expressed in SQL so the status transition reads `status` at write time under
# the row lock — no read-modify-write window where a concurrent reconcile (timer vs event)
# loses the update or resurrects a gone dataset. Non-empty => live; empty => gone ONLY if it
# was live (was-populated-now-empty), else unchanged (pending stays pending, gone stays gone).
_RECONCILE_SQL = """
WITH prev AS (SELECT status AS old FROM datasets WHERE id = %(n)s FOR UPDATE)
UPDATE datasets d SET
    status = CASE WHEN %(c)s > 0 THEN 'live'
                  WHEN d.status = 'live' THEN 'gone'
                  ELSE d.status END,
    object_count = %(c)s, total_bytes = %(t)s,
    last_modified = %(m)s, last_reconciled = now()
FROM prev WHERE d.id = %(n)s
RETURNING prev.old AS old, d.status AS new
"""


def _stat_prefix(prefix):
    """List a dataset's prefix; stats come straight from the listing (no GetObject)."""
    count, total, last = 0, 0, None
    for page in _s3.get_paginator("list_objects_v2").paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for o in page.get("Contents", []):
            count += 1
            total += o["Size"]
            if last is None or o["LastModified"] > last:
                last = o["LastModified"]
    return count, total, last


def reconcile(ds_id=None):
    """The ONLY writer of the existence/stats columns. With `ds_id`: just that dataset (the
    event path). Without: a full sweep (the timer). Storage is the truth here; the registry
    grants are untouched, so reconcile never moves OPA."""
    with db() as cur:
        # ds_id=None => full sweep (NULL IS NULL matches every row); else just that dataset.
        cur.execute("SELECT id, prefix FROM datasets WHERE (%s IS NULL OR id = %s)",
                    (ds_id, ds_id))
        rows = cur.fetchall()
    for row in rows:
        try:
            count, total, last = _stat_prefix(row["prefix"])
        except Exception as e:  # noqa: BLE001
            app.logger.warning("reconcile %s: list failed: %s", row["id"], e)
            continue
        with db(commit=True) as cur:
            cur.execute(_RECONCILE_SQL, {"n": row["id"], "c": count, "t": total, "m": last})
            r = cur.fetchone()
        if r and r["old"] != r["new"]:
            app.logger.info("reconcile %s: %s -> %s (count=%s)",
                            row["id"], r["old"], r["new"], count)


def reconcile_loop():
    """Periodic full sweep — convergence. Catches anything events missed (events are a
    latency optimization, not the authority)."""
    while True:
        time.sleep(RECONCILE_INTERVAL)
        try:
            reconcile()
        except Exception as e:  # noqa: BLE001
            app.logger.warning("reconcile sweep failed: %s", e)


@app.get("/health")
def health():
    with db() as cur:
        cur.execute("SELECT 1")
    return jsonify({"ok": True})


# Grant lookups for OPA's rules (opa/governance.rego), behind ENTRY_TOKEN.


@app.post("/internal/datasets")
def internal_datasets():
    # {id: entry} for the named ids that exist; an unknown id is simply absent.
    if err := internal_caller():
        return err
    ids = (request.get_json(silent=True) or {}).get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        return jsonify({"error": "ids must be a list of strings"}), 400
    with db() as cur:
        cur.execute("SELECT id, prefix, visibility, access FROM datasets WHERE id = ANY(%s)",
                    (ids,))
        rows = cur.fetchall()
    return jsonify({"entries": {r["id"]: _entry(r) for r in rows}})


@app.get("/internal/register-grants")
def internal_register_grants():
    if err := internal_caller():
        return err
    with db() as cur:
        cur.execute("SELECT grp, prefixes FROM register_grants")
        rows = cur.fetchall()
    return jsonify({r["grp"]: r["prefixes"] for r in rows})


@app.get("/internal/groups/<subject>")
def internal_groups(subject):
    if err := internal_caller():
        return err
    with db() as cur:
        cur.execute("SELECT grp FROM group_members WHERE member = %s ORDER BY grp", (subject,))
        return jsonify({"groups": [r["grp"] for r in cur.fetchall()]})


_TABLE_COLS = 'id, see, read, write, "delete", status'


def _ids_from_body():
    ids = (request.get_json(silent=True) or {}).get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        return None
    return ids


@app.get("/internal/tables/<table_id>")
def internal_table(table_id):
    # A table's grants, as sets of groups; an unregistered table is 404, so its rules deny.
    if err := internal_caller():
        return err
    with db() as cur:
        cur.execute(f"SELECT {_TABLE_COLS} FROM table_entries WHERE id = %s", (table_id,))
        row = cur.fetchone()
    return (jsonify(row), 200) if row else (jsonify({"error": "not found"}), 404)


@app.post("/internal/tables")
def internal_tables():
    if err := internal_caller():
        return err
    if (ids := _ids_from_body()) is None:
        return jsonify({"error": "ids must be a list of strings"}), 400
    with db() as cur:
        cur.execute(f"SELECT {_TABLE_COLS} FROM table_entries WHERE id = ANY(%s)", (ids,))
        return jsonify({"entries": {r["id"]: r for r in cur.fetchall()}})


@app.post("/internal/namespaces")
def internal_namespaces():
    # {id: {id, owners: [group], viewers: [group]}}. Owners own the namespace or one above it;
    # viewers hold see, read or write on some table at any depth under it (`lakehouse.db`
    # covers `lakehouse.db.t1` and `lakehouse.db.x.t2`). Ids are compared with starts_with,
    # not LIKE, so "_" and "%" in a name are plain characters.
    if err := internal_caller():
        return err
    if (ids := _ids_from_body()) is None:
        return jsonify({"error": "ids must be a list of strings"}), 400
    entries = {}
    with db() as cur:
        for i in ids:
            cur.execute("SELECT DISTINCT grp FROM namespace_owners "
                        "WHERE namespace = %s OR starts_with(%s, namespace || '.')", (i, i))
            owners = sorted(r["grp"] for r in cur.fetchall())
            cur.execute("SELECT DISTINCT unnest(see || read || write) AS grp FROM table_entries "
                        "WHERE starts_with(id, %s || '.')", (i,))
            viewers = sorted(r["grp"] for r in cur.fetchall())
            entries[i] = {"id": i, "owners": owners, "viewers": viewers}
    return jsonify({"entries": entries})


@app.post("/internal/table-events")
def table_events():
    # The gate's report that Polaris created or dropped a table: created sets a pending entry
    # live and records its location, dropped sets a live entry gone. Any other transition is
    # logged and ignored.
    if not hmac.compare_digest(request.headers.get("Authorization", ""),
                               f"Bearer {LIFECYCLE_TOKEN}"):
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    table_id, event = body.get("id"), body.get("event")
    old, new = {"created": ("pending", "live"), "dropped": ("live", "gone")}.get(event, (None, None))
    if not isinstance(table_id, str) or old is None:
        return jsonify({"error": "id and event (created|dropped) required"}), 400
    with db(commit=True) as cur:
        cur.execute("UPDATE table_entries SET status = %s, location = COALESCE(%s, location) "
                    "WHERE id = %s AND status = %s RETURNING id",
                    (new, body.get("location"), table_id, old))
        changed = cur.fetchone() is not None
    app.logger.info("TABLE %s %s%s", event, table_id, "" if changed else " (no matching entry; ignored)")
    return jsonify({"ok": True, "changed": changed})


@app.post("/events")
def events():
    # RGW bucket-notification sink. Events carry NO authority — they only TRIGGER a
    # reconcile, which reads storage truth itself; a missed/forged event is harmless and
    # self-heals on the next timer sweep. Unauthenticated by design (trusted-network dev).
    body = request.get_json(silent=True) or {}
    records = body.get("Records", [])
    if len(records) > MAX_EVENT_RECORDS:  # bound the fan-out; the timer reconcile covers the rest
        app.logger.warning("/events: truncating %d records to %d", len(records), MAX_EVENT_RECORDS)
        records = records[:MAX_EVENT_RECORDS]
    with db() as cur:  # the registry once, not once per record
        cur.execute("SELECT id, prefix FROM datasets")
        registry = [(r["id"], r["prefix"]) for r in cur.fetchall()]
    touched = set()
    for rec in records:
        key = rec.get("s3", {}).get("object", {}).get("key", "")
        app.logger.info("EVENT %s key=%s", rec.get("eventName", "?"), key)
        # longest registered prefix the key falls under (disambiguates nested prefixes)
        match = max((p for p in registry if key.startswith(p[1])), key=lambda p: len(p[1]), default=None)
        if match:
            touched.add(match[0])
        else:
            app.logger.info("EVENT key=%s is ungoverned (no registered dataset)", key)
    for ds in touched:
        reconcile(ds)
    return jsonify({"ok": True, "received": len(records), "reconciled": sorted(touched)})


@app.post("/datasets")
def register_dataset():
    # Register a new dataset. The steward supplies the PREFIX (which they own); the id is
    # derived from it. authN = the caller's token; authZ = OPA's allow_register.
    subject, err = authed_user()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    prefix = body.get("prefix")
    if not _confined_prefix(prefix):
        return jsonify({"error": "prefix must be datasets/<...>/ with no '..' or escape"}), 400
    ds_id = derive_id(prefix)

    if opa("allow_register", {"subject": subject, "prefix": prefix}) is not True:
        app.logger.info("DENY register subject=%s prefix=%s", subject, prefix)
        return jsonify({"error": "forbidden"}), 403

    try:
        with db(commit=True) as cur:
            # Serialize: the overlap check + insert must be atomic, else two concurrent
            # overlapping prefixes both pass. The lock is held to commit.
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (REGISTER_LOCK_KEY,))
            cur.execute("SELECT prefix FROM datasets")
            existing = [r["prefix"] for r in cur.fetchall()]
            if any(prefix.startswith(p) or p.startswith(prefix) for p in existing):
                return jsonify({"error": "dataset unavailable"}), 409
            cur.execute(
                "INSERT INTO datasets (id, prefix, description, steward, visibility, access, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, 'pending')",
                (ds_id, prefix, body.get("description"), subject,
                 body.get("visibility", []), body.get("access", [])),
            )
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "dataset unavailable"}), 409

    # The dataset is registered; classify it now (pending->live if its bytes already exist) so
    # callers see it immediately. Best-effort: a slow/absent RGW must not fail a committed
    # registration — the periodic timer will classify it regardless.
    try:
        reconcile(ds_id)
    except Exception as e:  # noqa: BLE001
        app.logger.warning("post-register reconcile failed (timer will classify %s): %s", ds_id, e)
    app.logger.info("REGISTER subject=%s id=%s prefix=%s", subject, ds_id, prefix)
    return jsonify({"ok": True, "id": ds_id, "registered_by": subject}), 201


@app.post("/principals/me")
def provision_principal():
    # Create the caller's Polaris principal if it doesn't exist. Authenticated by the person's
    # own token, so it creates only that person's; the gate calls it before a person's first
    # request reaches Polaris, which would otherwise refuse it (and log the token).
    subject, err = authed_user()
    if err:
        return err
    if subject in RESERVED_PRINCIPALS:
        return jsonify({"error": "reserved name"}), 403
    headers = {"Polaris-Realm": POLARIS_REALM}
    tok = _http.post(f"{POLARIS_URL}/api/catalog/v1/oauth/tokens", auth=PROVISIONER, headers=headers,
                     data={"grant_type": "client_credentials", "scope": "PRINCIPAL_ROLE:ALL"},
                     timeout=5)
    tok.raise_for_status()
    headers["Authorization"] = f"Bearer {tok.json()['access_token']}"
    r = _http.post(f"{POLARIS_URL}/api/management/v1/principals", headers=headers, timeout=5,
                   json={"principal": {"name": subject, "type": "USER"}})
    if r.status_code not in (201, 409):
        app.logger.warning("provision %s: Polaris returned %s %s", subject, r.status_code, r.text[:200])
        return jsonify({"error": "could not create principal"}), 502
    if r.status_code == 201:
        app.logger.info("PROVISION principal=%s", subject)
    return jsonify({"ok": True, "principal": subject, "created": r.status_code == 201})


@app.post("/tables")
def register_table():
    # Register a table before it is created: Polaris (through the gate) creates only a
    # registered, pending table, for someone in its write grant. authZ = OPA's
    # lakehouse.tables.allow_register (a steward whose group owns the namespace).
    subject, err = authed_user()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    table_id = body.get("id")
    grants = {g: body.get(g, []) for g in ("see", "read", "write", "delete")}
    if not isinstance(table_id, str) or not TABLE_ID_RE.match(table_id):
        return jsonify({"error": "id must be <catalog>.<namespace...>.<table>"}), 400
    if not all(isinstance(v, list) and all(isinstance(x, str) for x in v) for v in grants.values()):
        return jsonify({"error": "see, read, write and delete must be lists of groups"}), 400
    if opa("allow_register", {"subject": subject, "id": table_id}, package="tables") is not True:
        app.logger.info("DENY register-table subject=%s id=%s", subject, table_id)
        return jsonify({"error": "forbidden"}), 403
    try:
        with db(commit=True) as cur:
            cur.execute(
                'INSERT INTO table_entries (id, description, steward, see, read, write, "delete") '
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (table_id, body.get("description"), subject, grants["see"], grants["read"],
                 grants["write"], grants["delete"]))
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "table unavailable"}), 409
    app.logger.info("REGISTER-TABLE subject=%s id=%s", subject, table_id)
    return jsonify({"ok": True, "id": table_id, "status": "pending"}), 201


@app.get("/discover")
def discover():
    subject, err = authed_user()
    if err:
        return err

    # Only LIVE datasets are advertised — discovery never shows a dead (gone) or not-yet-
    # populated (pending) dataset. Existence is storage truth (reconcile); visibility is
    # the OPA predicate below. Discovery = OPA-visible ∩ live.
    with db() as cur:
        cur.execute("SELECT id, description, steward FROM datasets WHERE status = 'live' ORDER BY id")
        rows = cur.fetchall()

    # One decision over every candidate id; OPA returns which pass, governance builds the list.
    res = opa("discover", {"subject": subject, "datasets": [r["id"] for r in rows]})
    seen, reads = set(res["visible"]), set(res["readable"])
    visible = [{"id": r["id"], "description": r["description"], "steward": r["steward"],
                "can_read": r["id"] in reads} for r in rows if r["id"] in seen]
    return jsonify({"subject": subject, "visible": visible})


if __name__ == "__main__":
    connect_pool()
    init_db()
    try:
        reconcile()           # startup sweep: classify seeded datasets (pending -> live/gone)
    except Exception as e:    # noqa: BLE001 — RGW trouble must not abort boot; the timer retries
        app.logger.warning("startup reconcile failed: %s", e)
    threading.Thread(target=reconcile_loop, daemon=True).start()
    # use_reloader=False: a reloader spawns a second process — wrong for a service that
    # owns a connection pool and a single reconcile timer thread.
    app.run(host="0.0.0.0", port=8000, use_reloader=False)
