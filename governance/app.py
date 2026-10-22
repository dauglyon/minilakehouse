"""
governance — the PAP + dataset registry, and the single source of truth (Postgres-backed).

It owns groups (their members and owners), the dataset and table registries, and all
grants; OPA holds none, and Keycloak only proves who a person is. Every caller, governance
included, sends OPA only who is asking and what they name; OPA's rules fetch the grants they
need from the /internal/* lookups here, at decision time. Durable state lives in a dedicated
`governance` Postgres DB.

Two truths, reconciled not merged: storage is truth for existence; the registry is truth for
meaning/grants. The `datasets` row carries both, written by disjoint paths — meaning/grants by
ingest+seed, existence (status) by reconcile. Entries served to OPA carry
meaning/grants only, so storage churn never changes a decision.

Two permission planes per dataset, as separate grant sets: visibility (may you SEE it
exists) vs access (may you READ the bytes) — so a dataset can be see-but-not-read.

Governance builds every list; OPA only says which of the candidates it was given pass.
"""
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import threading
import time
from contextlib import contextmanager

import boto3
import index_table
import jwt
import psycopg2
import requests
from botocore.config import Config
from flask import Flask, Response, jsonify, request
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool
from werkzeug.serving import make_server

REGISTRY_PATH = os.environ.get("REGISTRY", "/app/registry.json")
OPA_BASE = os.environ.get("OPA_BASE", "http://opa:8181")
DB_DSN = os.environ["GOVERNANCE_DB_DSN"]
KEYCLOAK_JWKS = os.environ["KEYCLOAK_JWKS"]
KEYCLOAK_ISS = os.environ["KEYCLOAK_ISS"]
# The grant lookups OPA's rules make (/internal/*) return any entry's grants, including
# datasets the person can't see, the gate's table create/drop reports set a table's status, and
# access log entries decide what a person's outputs may be derived from, so all three are served
# only on INTERNAL_PORT, a TLS listener that requires a client certificate from the internal CA
# (pki.py): `opa` for the lookups, `gate` for the reports, `gate` and `broker` for the log.
INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", "8443"))
PKI_DIR = os.environ.get("PKI_DIR", "/pki")
# RGW adds this to every bucket notification it sends (the topic's opaque data, rgw_setup.py);
# /events ignores a delivery whose events lack it.
EVENTS_SECRET = os.environ["EVENTS_SECRET"]
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
# Each service accepts only tokens issued for it (keycloak/setup.py). Governance's own API takes
# `governance`; the two calls the gate makes for the catalog, a load of the dataset index and
# creating a person's Polaris principal, carry the person's catalog token, audience `polaris`.
AUDIENCE = os.environ.get("TOKEN_AUDIENCE", "governance")
CATALOG_AUDIENCE = os.environ.get("CATALOG_AUDIENCE", "polaris")
# A prefix becomes an STS resource ARN; it's from an authenticated steward but still
# untrusted. Confine it: datasets/<bounded, safe-charset>/ — capped so it can't blow the STS
# policy-size limit and restricted so no control/space/unicode reaches the ARN.
PREFIX_RE = re.compile(r"^datasets/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}/$")
GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$")  # <catalog>.<namespace...>
SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,254}$")


def derive_id(prefix):
    """A dataset's id is its prefix without the `datasets/` root and trailing slash:
    `datasets/projx/public/` -> `projx/public`."""
    return prefix[len("datasets/"):-1]

# --- Storage / freshness ---
# Least-privilege reader creds (ListBucket on datasets/* via a bucket policy set by the
# rgw-setup one-shot). Governance does NOT hold the RGW admin key; reconcile only lists.
RGW_ENDPOINT = os.environ.get("RGW_ENDPOINT", "http://ceph:8080")
# Where engines fetch the dataset index's files (index_table.py): the storage address every
# engine already uses, by bucket-in-hostname addressing. Docker DNS points
# governance-index.storage.internal at this service's INDEX_PORT and <bucket>.storage.internal
# at Ceph.
INDEX_ENDPOINT = os.environ.get("INDEX_ENDPOINT", "http://storage.internal:8080")
INDEX_PORT = int(os.environ.get("INDEX_PORT", "8080"))
RGW_KEY = os.environ.get("RGW_ACCESS_KEY", "")
RGW_SECRET = os.environ.get("RGW_SECRET_KEY", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "lakehouse")
MAX_EVENT_RECORDS = 1000  # refuse larger deliveries: the endpoint is unauthenticated
SEED_LOCK_KEY = 0x6D6C68      # arbitrary fixed key: serialize the one-time registry seed
REGISTER_LOCK_KEY = 0x6D6C72  # arbitrary fixed key: serialize register-at-ingest
ROOTS_LOCK_KEY = 0x6D6C6F     # arbitrary fixed key: serialize changes to root ownership
# Short timeouts: a slow or absent RGW fails the check quickly, and the event that triggered it
# is delivered again (persistent topic), so governance never hangs on storage.
_boto_cfg = Config(signature_version="s3v4", connect_timeout=5, read_timeout=5,
                   retries={"max_attempts": 2})
# One reusable client/session each (thread-safe), instead of rebuilding per reconcile/poll.
_s3 = boto3.client("s3", endpoint_url=RGW_ENDPOINT, aws_access_key_id=RGW_KEY,
                   aws_secret_access_key=RGW_SECRET, region_name="us-east-1", config=_boto_cfg)
_http = requests.Session()

# Full schema up front (incl. the existence/stats columns reconcile fills in). CREATE TABLE IF
# NOT EXISTS leaves a table on an already-persisted volume as it was, so a column added later
# is also added by an idempotent ALTER at the end.
SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets (
    id              TEXT PRIMARY KEY,        -- derive_id(prefix): the tenant-qualified identity
    prefix          TEXT UNIQUE NOT NULL,    -- storage location; one dataset per prefix
    description     TEXT,
    steward         TEXT,
    visibility      TEXT[] NOT NULL DEFAULT '{}',
    access          TEXT[] NOT NULL DEFAULT '{}',
    share           TEXT[] NOT NULL DEFAULT '{}',
    write           TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending | live | gone
    last_reconciled TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS group_members (
    grp    TEXT NOT NULL,
    member TEXT NOT NULL,                    -- a person's subject (the token's principal_name)
    PRIMARY KEY (grp, member)
);
CREATE TABLE IF NOT EXISTS group_owners (
    grp   TEXT NOT NULL,
    owner TEXT NOT NULL,                     -- a group whose members may change grp's members/owners
    PRIMARY KEY (grp, owner)
);
CREATE TABLE IF NOT EXISTS table_entries (
    id          TEXT PRIMARY KEY,            -- <catalog>.<namespace...>.<table>
    description TEXT,
    steward     TEXT,
    see         TEXT[] NOT NULL DEFAULT '{}',
    read        TEXT[] NOT NULL DEFAULT '{}',
    share       TEXT[] NOT NULL DEFAULT '{}',
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
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS share TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS write TEXT[] NOT NULL DEFAULT '{}';
-- The dataset index narrows its candidates to entries whose viewing grants name one of the
-- person's groups (_index_rows); these keep that query proportional to the matches.
-- Object count, bytes and last-modified were recorded by a periodic full listing and read by
-- nothing; status needs only whether a folder is empty.
ALTER TABLE datasets DROP COLUMN IF EXISTS object_count, DROP COLUMN IF EXISTS total_bytes,
    DROP COLUMN IF EXISTS last_modified;
CREATE INDEX IF NOT EXISTS datasets_viewers ON datasets USING gin ((visibility || access));
CREATE INDEX IF NOT EXISTS table_entries_viewers ON table_entries USING gin ((see || read || write));
ALTER TABLE table_entries ADD COLUMN IF NOT EXISTS share TEXT[] NOT NULL DEFAULT '{}';
-- Provenance (PROVENANCE.md 3, 4.1). A session is a unit of work a person names; each login
-- points at one of the person's sessions, and every access is stamped with the session its
-- login pointed at when the access was logged.
CREATE TABLE IF NOT EXISTS sessions (
    id        BIGSERIAL PRIMARY KEY,
    person    TEXT NOT NULL,
    name      TEXT NOT NULL,
    started   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (person, name)
);
CREATE TABLE IF NOT EXISTS logins (
    person  TEXT NOT NULL,
    sid     TEXT NOT NULL,                   -- the token's Keycloak login session; '' when it has none
    session BIGINT NOT NULL REFERENCES sessions (id),
    PRIMARY KEY (person, sid)
);
CREATE TABLE IF NOT EXISTS accesses (
    id      BIGSERIAL PRIMARY KEY,
    person  TEXT NOT NULL,
    sub     TEXT NOT NULL,                   -- Keycloak subject, which storage events name
    sid     TEXT NOT NULL,
    session BIGINT NOT NULL REFERENCES sessions (id),
    dataset TEXT NOT NULL,                   -- a file dataset's id or a table's id
    kind    TEXT NOT NULL,                   -- files | table
    mode    TEXT NOT NULL,                   -- read: a credential issued | write: a credential or table commit
    at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires TIMESTAMPTZ                      -- the credential's expiry; none for a table commit
);
CREATE INDEX IF NOT EXISTS accesses_session ON accesses (session, mode, dataset);
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
    """A pooled connection + RealDict cursor. Per-operation, thread-safe (every request thread
    borrows from the pool); the gate bounds concurrency to the pool."""
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
    """Create the schema, and seed from registry.json once (when datasets is empty); returns
    the ids of datasets seeded now. registry.json is a one-time fixture; Postgres is the
    source of truth thereafter."""
    with db(commit=True) as cur:
        cur.execute(SCHEMA)
    with db(commit=True) as cur:
        # Serialize the check-then-seed so two instances starting together can't both seed.
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (SEED_LOCK_KEY,))
        cur.execute("SELECT count(*) AS n FROM datasets")
        if cur.fetchone()["n"]:
            return []
        with open(REGISTRY_PATH) as f:
            reg = json.load(f)
        for d in reg.get("datasets", []):
            if not _confined_prefix(d["prefix"]):  # the fixture is untrusted-into-ARN too
                raise ValueError(f"registry.json: bad prefix {d['prefix']!r}")
            cur.execute(
                "INSERT INTO datasets (id, prefix, description, steward, visibility, access, share, write) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (derive_id(d["prefix"]), d["prefix"], d.get("description"), d.get("steward"),
                 d.get("visibility", []), d.get("access", []), d.get("share", []), d.get("write", [])),
            )
        for grp, members in reg.get("groups", {}).items():
            for m in members:
                cur.execute("INSERT INTO group_members (grp, member) VALUES (%s, %s) "
                            "ON CONFLICT DO NOTHING", (grp, m))
        for grp, owners in reg.get("group_owners", {}).items():
            for o in owners:
                cur.execute("INSERT INTO group_owners (grp, owner) VALUES (%s, %s) "
                            "ON CONFLICT DO NOTHING", (grp, o))
        for t in reg.get("tables", []):
            if not TABLE_ID_RE.match(t["id"]):
                raise ValueError(f"registry.json: bad table id {t['id']!r}")
            cur.execute(
                'INSERT INTO table_entries (id, description, steward, see, read, share, write, "delete") '
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (t["id"], t.get("description"), t.get("steward"), t.get("see", []),
                 t.get("read", []), t.get("share", []), t.get("write", []), t.get("delete", [])),
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
        return [derive_id(d["prefix"]) for d in reg.get("datasets", [])]


def _entry(row):
    """The meaning/grants half of a datasets row — what OPA decides over."""
    return {"id": row["id"], "prefix": row["prefix"],
            "visibility": row["visibility"], "access": row["access"], "share": row["share"],
            "write": row["write"]}


# NOTE: verify_user + authed_user are duplicated in the other service (governance/broker) —
# separate container images, no shared module. Keep the two copies in sync.
def verify_user(token, audience):
    """Cryptographically verify the caller's own Keycloak token -> its claims. PyJWT enforces
    signature, exp, issuer and audience; we add azp (the token must have been issued through our
    login client, not some other realm client). Groups are not read from the token: OPA gets
    them from governance."""
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=KEYCLOAK_ISS, audience=audience)
    if claims.get("azp") != EXPECTED_AZP:
        raise jwt.InvalidTokenError(f"unexpected azp {claims.get('azp')!r}")
    return claims


def subject_of(claims):
    return claims.get("principal_name") or claims.get("preferred_username") or claims.get("sub")


def authed_claims(audience=AUDIENCE):
    """Verify the request's bearer token. Returns (claims, None) on success, or
    (None, error_response) for the caller to return as-is."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "missing bearer token"}), 401)
    try:
        return verify_user(auth[7:], audience), None
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return None, (jsonify({"error": "invalid token"}), 401)


def authed_user(audience=AUDIENCE):
    """(subject, None) for the request's verified bearer token, or (None, error_response)."""
    claims, err = authed_claims(audience)
    return (subject_of(claims), None) if claims else (None, err)


def opa(rule, inp, package="blob"):
    """Evaluate one lakehouse.<package> rule; returns its result."""
    r = _http.post(f"{OPA_BASE}/v1/data/lakehouse/{package}/{rule}", json={"input": inp},
                   timeout=5)
    r.raise_for_status()
    return r.json().get("result")


internal_app = Flask("internal")
# The certificate names that may call each internal route; every other route is a grant lookup,
# OPA's alone.
INTERNAL_CALLERS = {"/internal/table-events": {"gate"}, "/internal/accesses": {"gate", "broker"}}


@internal_app.before_request
def known_caller():
    # The listener already requires a certificate from the internal CA, which signs every
    # internal caller's and governance's own, so the name decides the route.
    sock = request.environ.get("werkzeug.socket")
    cert = sock.getpeercert() if sock is not None and hasattr(sock, "getpeercert") else None
    names = [v for rdn in (cert or {}).get("subject", ()) for k, v in rdn if k == "commonName"]
    if len(names) != 1 or names[0] not in INTERNAL_CALLERS.get(request.path, {"opa"}):
        return jsonify({"error": "unauthorized"}), 401
    return None


def internal_server():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{PKI_DIR}/ca.crt")
    ctx.load_cert_chain(f"{PKI_DIR}/server.crt", f"{PKI_DIR}/server.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    return make_server("0.0.0.0", INTERNAL_PORT, internal_app, threaded=True, ssl_context=ctx)


def _confined_prefix(prefix):
    """A registrable prefix: datasets/<segment>/, bounded safe charset, no traversal/escape."""
    return (isinstance(prefix, str) and PREFIX_RE.match(prefix) is not None
            and ".." not in prefix and "//" not in prefix)


# Lifecycle, expressed in SQL so the status transition reads `status` at write time under
# the row lock — no read-modify-write window where two concurrent checks of one dataset (two
# events) lose the update or resurrect a gone dataset. Non-empty => live; empty => gone ONLY if
# it was live (was-populated-now-empty), else unchanged (pending stays pending, gone stays gone).
_RECONCILE_SQL = """
WITH prev AS (SELECT status AS old FROM datasets WHERE id = %(n)s FOR UPDATE)
UPDATE datasets d SET
    status = CASE WHEN %(nonempty)s THEN 'live'
                  WHEN d.status = 'live' THEN 'gone'
                  ELSE d.status END,
    last_reconciled = now()
FROM prev WHERE d.id = %(n)s
RETURNING prev.old AS old, d.status AS new
"""


def _nonempty(prefix):
    """Whether any object exists under the prefix: a listing capped at one object."""
    return _s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix, MaxKeys=1).get("KeyCount", 0) > 0


def reconcile(ds_id):
    """The ONLY writer of `status`: set one dataset live or gone from whether its folder holds
    anything. Storage is the truth here; grants are untouched, so reconcile never moves OPA.
    There is no periodic sweep: each bucket notification triggers this for the dataset it
    names, and the notification topic is persistent (rgw_setup.py), so a check that fails here
    raises and the event is delivered again."""
    with db() as cur:
        cur.execute("SELECT prefix FROM datasets WHERE id = %s", (ds_id,))
        row = cur.fetchone()
    if row is None:
        return
    nonempty = _nonempty(row["prefix"])
    with db(commit=True) as cur:
        cur.execute(_RECONCILE_SQL, {"n": ds_id, "nonempty": nonempty})
        r = cur.fetchone()
    if r and r["old"] != r["new"]:
        app.logger.info("reconcile %s: %s -> %s", ds_id, r["old"], r["new"])


@app.get("/health")
def health():
    with db() as cur:
        cur.execute("SELECT 1")
    return jsonify({"ok": True})


# Grant lookups for OPA's rules (opa/governance.rego), on the internal listener only.


@internal_app.post("/internal/datasets")
def internal_datasets():
    # {id: entry} for the named ids that exist; an unknown id is simply absent.
    ids = (request.get_json(silent=True) or {}).get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        return jsonify({"error": "ids must be a list of strings"}), 400
    with db() as cur:
        cur.execute("SELECT id, prefix, visibility, access, share, write FROM datasets WHERE id = ANY(%s)",
                    (ids,))
        rows = cur.fetchall()
    return jsonify({"entries": {r["id"]: _entry(r) for r in rows}})


@internal_app.get("/internal/register-grants")
def internal_register_grants():
    with db() as cur:
        cur.execute("SELECT grp, prefixes FROM register_grants")
        rows = cur.fetchall()
    return jsonify({r["grp"]: r["prefixes"] for r in rows})


@internal_app.get("/internal/groups/<subject>")
def internal_groups(subject):
    with db() as cur:
        cur.execute("SELECT grp FROM group_members WHERE member = %s ORDER BY grp", (subject,))
        return jsonify({"groups": [r["grp"] for r in cur.fetchall()]})


@internal_app.get("/internal/group-owners/<grp>")
def internal_group_owners(grp):
    with db() as cur:
        cur.execute("SELECT owner FROM group_owners WHERE grp = %s ORDER BY owner", (grp,))
        return jsonify({"owners": [r["owner"] for r in cur.fetchall()]})


_TABLE_COLS = 'id, see, read, share, write, "delete", status'


def _ids_from_body():
    ids = (request.get_json(silent=True) or {}).get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        return None
    return ids


@internal_app.get("/internal/tables/<table_id>")
def internal_table(table_id):
    # A table's grants, as sets of groups; an unregistered table is 404, so its rules deny.
    with db() as cur:
        cur.execute(f"SELECT {_TABLE_COLS} FROM table_entries WHERE id = %s", (table_id,))
        row = cur.fetchone()
    return (jsonify(row), 200) if row else (jsonify({"error": "not found"}), 404)


@internal_app.post("/internal/tables")
def internal_tables():
    if (ids := _ids_from_body()) is None:
        return jsonify({"error": "ids must be a list of strings"}), 400
    with db() as cur:
        cur.execute(f"SELECT {_TABLE_COLS} FROM table_entries WHERE id = ANY(%s)", (ids,))
        return jsonify({"entries": {r["id"]: r for r in cur.fetchall()}})


@internal_app.post("/internal/namespaces")
def internal_namespaces():
    # {id: {id, owners: [group], viewers: [group]}}. Owners own the namespace or one above it;
    # viewers hold see, read or write on some table at any depth under it (`lakehouse.db`
    # covers `lakehouse.db.t1` and `lakehouse.db.x.t2`). Ids are compared with starts_with,
    # not LIKE, so "_" and "%" in a name are plain characters.
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


@internal_app.post("/internal/table-events")
def table_events():
    # The gate's report that Polaris created or dropped a table: created sets a pending entry
    # live and records its location, dropped sets a live entry gone. Any other transition is
    # logged and ignored.
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


def _pointer(cur, person, sid, create=False):
    """The id of the session this login points at. A login with no pointer yet continues the
    person's most recently used session; with create, that becomes the login's pointer, and a
    person with no session gets one named `default`. None when there is nothing to point at
    and create is false."""
    cur.execute("SELECT session FROM logins WHERE person = %s AND sid = %s", (person, sid))
    if row := cur.fetchone():
        return row["session"]
    cur.execute("SELECT id FROM sessions WHERE person = %s ORDER BY last_used DESC LIMIT 1", (person,))
    row = cur.fetchone()
    if not create:
        return row and row["id"]
    if row is None:
        cur.execute("INSERT INTO sessions (person, name) VALUES (%s, 'default') "
                    "ON CONFLICT (person, name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
                    (person,))
        row = cur.fetchone()
    # A concurrent first access by the same login may have set the pointer since the SELECT;
    # theirs stands.
    cur.execute("INSERT INTO logins (person, sid, session) VALUES (%s, %s, %s) "
                "ON CONFLICT (person, sid) DO NOTHING", (person, sid, row["id"]))
    cur.execute("SELECT session FROM logins WHERE person = %s AND sid = %s", (person, sid))
    return cur.fetchone()["session"]


def _accesses_valid(body):
    entries = body.get("entries")
    return (all(isinstance(body.get(k), str) for k in ("person", "sub", "sid"))
            and body["person"] and body["sub"] and isinstance(entries, list) and entries
            and all(isinstance(e, dict) and isinstance(e.get("dataset"), str) and e["dataset"]
                    and e.get("kind") in ("files", "table") and e.get("mode") in ("read", "write")
                    and (e.get("expires") is None or isinstance(e["expires"], int))
                    for e in entries))


@internal_app.post("/internal/accesses")
def record_accesses():
    # The access log (PROVENANCE.md 4.1): the broker logs each file credential it issues, the
    # gate each table credential it passes on and each table write it forwards. Both log before
    # handing anything on and refuse the request when this fails, so the log holds every
    # access that reached a person. Body: {person, sub, sid, entries: [{dataset, kind, mode,
    # expires}]}, expires in epoch milliseconds or null. Answers the session they were
    # stamped with.
    body = request.get_json(silent=True) or {}
    if not _accesses_valid(body):
        return jsonify({"error": "person, sub, sid and entries [{dataset, kind, mode, expires}] required"}), 400
    with db(commit=True) as cur:
        session = _pointer(cur, body["person"], body["sid"], create=True)
        for e in body["entries"]:
            cur.execute("INSERT INTO accesses (person, sub, sid, session, dataset, kind, mode, expires) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, to_timestamp(%s / 1000.0))",
                        (body["person"], body["sub"], body["sid"], session, e["dataset"], e["kind"],
                         e["mode"], e.get("expires")))
        cur.execute("UPDATE sessions SET last_used = now() WHERE id = %s RETURNING name", (session,))
        name = cur.fetchone()["name"]
    app.logger.info("ACCESS person=%s session=%s %s", body["person"], name,
                    " ".join(f"{e['mode']}:{e['dataset']}" for e in body["entries"]))
    return jsonify({"ok": True, "session": name})


@app.post("/events")
def events():
    # RGW bucket-notification sink. Events carry NO authority — they only TRIGGER a check of
    # the dataset a key falls under, which reads storage truth itself, so a forged event can only
    # cause a check. Any answer but 2xx makes RGW deliver the event again (persistent topic).
    # RGW proves itself by the topic's secret, which it puts in every event as opaqueData; a
    # secret in the push URL would instead land in this server's request log.
    body = request.get_json(silent=True) or {}
    records = body.get("Records", [])
    if len(records) > MAX_EVENT_RECORDS:
        return jsonify({"error": f"at most {MAX_EVENT_RECORDS} records per delivery"}), 413
    if not records or not all(isinstance(r, dict) and isinstance(r.get("opaqueData"), str)
                              and hmac.compare_digest(r["opaqueData"], EVENTS_SECRET)
                              for r in records):
        app.logger.warning("/events: delivery without the topic's secret refused")
        return jsonify({"error": "unauthorized"}), 401
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
    try:
        for ds in touched:
            reconcile(ds)
    except Exception as e:  # noqa: BLE001 — RGW redelivers on a non-2xx answer
        app.logger.warning("/events: check failed, asking RGW to redeliver: %s", e)
        return jsonify({"error": "check failed"}), 503
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
    grants = {g: body.get(g, []) for g in ("visibility", "access", "share", "write")}
    if not all(isinstance(v, list) and all(isinstance(x, str) for x in v) for v in grants.values()):
        return jsonify({"error": "visibility, access, share and write must be lists of groups"}), 400

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
                "INSERT INTO datasets (id, prefix, description, steward, visibility, access, share, write, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')",
                (ds_id, prefix, body.get("description"), subject,
                 grants["visibility"], grants["access"], grants["share"], grants["write"]),
            )
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "dataset unavailable"}), 409

    # The dataset is registered; check its folder once (pending->live if its bytes already
    # exist) so callers see it immediately. Best-effort: a slow/absent RGW must not fail a
    # committed registration, and the next object written under it triggers the check again.
    try:
        reconcile(ds_id)
    except Exception as e:  # noqa: BLE001
        app.logger.warning("post-register check of %s failed: %s", ds_id, e)
    app.logger.info("REGISTER subject=%s id=%s prefix=%s", subject, ds_id, prefix)
    return jsonify({"ok": True, "id": ds_id, "registered_by": subject}), 201


@app.post("/principals/me")
def provision_principal():
    # Create the caller's Polaris principal if it doesn't exist. Authenticated by the person's
    # own token, so it creates only that person's; the gate calls it before a person's first
    # request reaches Polaris, which would otherwise refuse it (and log the token).
    subject, err = authed_user(CATALOG_AUDIENCE)
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
    grants = {g: body.get(g, []) for g in ("see", "read", "share", "write", "delete")}
    if not isinstance(table_id, str) or not TABLE_ID_RE.match(table_id):
        return jsonify({"error": "id must be <catalog>.<namespace...>.<table>"}), 400
    if not all(isinstance(v, list) and all(isinstance(x, str) for x in v) for v in grants.values()):
        return jsonify({"error": "see, read, share, write and delete must be lists of groups"}), 400
    if opa("allow_register", {"subject": subject, "id": table_id}, package="tables") is not True:
        app.logger.info("DENY register-table subject=%s id=%s", subject, table_id)
        return jsonify({"error": "forbidden"}), 403
    try:
        with db(commit=True) as cur:
            cur.execute(
                'INSERT INTO table_entries (id, description, steward, see, read, share, write, "delete") '
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (table_id, body.get("description"), subject, grants["see"], grants["read"],
                 grants["share"], grants["write"], grants["delete"]))
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "table unavailable"}), 409
    app.logger.info("REGISTER-TABLE subject=%s id=%s", subject, table_id)
    return jsonify({"ok": True, "id": table_id, "status": "pending"}), 201


# The grants a change may name, per kind, and the column each is stored in. A file dataset has
# no delete: its write credential deletes objects (WHITEPAPER 4.2).
_GRANT_COLS = {"dataset": {"see": "visibility", "read": "access", "share": "share", "write": "write"},
               "table": {g: g for g in ("see", "read", "share", "write", "delete")}}


@app.patch("/permissions/<kind>/<path:entry_id>")
def change_permissions(kind, entry_id):
    # Change which groups hold which grants on one dataset or table. The body follows Unity
    # Catalog's permissions API: {"changes": [{"group": g, "add": [grant], "remove": [grant]}]}.
    # authZ = OPA's allow_change over every grant the changes name (WHITEPAPER 4.4), asked while
    # this transaction holds the entry's row lock, so the entry OPA fetches is the one this
    # write replaces. An unknown id is refused exactly as a denied change. OPA's lookups into
    # /internal/* during that decision borrow pool connections too, so beyond POOL_MAX
    # concurrent changes a lookup times out and the change is refused rather than deadlocking.
    subject, err = authed_user()
    if err:
        return err
    cols = _GRANT_COLS.get(kind)
    if cols is None:
        return jsonify({"error": "not found"}), 404
    changes = (request.get_json(silent=True) or {}).get("changes")
    if not (isinstance(changes, list) and changes and all(
            isinstance(c, dict) and isinstance(c.get("group"), str) and c["group"]
            and all(isinstance(c.get(k, []), list) and set(c.get(k, [])) <= cols.keys()
                    for k in ("add", "remove"))
            for c in changes)):
        return jsonify({"error": "changes must be [{group, add: [grant], remove: [grant]}] "
                                 f"with grants from {sorted(cols)}"}), 400
    named = sorted({g for c in changes for k in ("add", "remove") for g in c.get(k, [])})
    if not named:
        return jsonify({"error": "changes name no grant"}), 400
    table, package, key = (("datasets", "blob", "dataset") if kind == "dataset"
                           else ("table_entries", "tables", "id"))
    col_sql = ", ".join(f'"{c}"' for c in cols.values())
    with db(commit=True) as cur:
        cur.execute(f"SELECT {col_sql} FROM {table} WHERE id = %s FOR UPDATE", (entry_id,))
        row = cur.fetchone()
        allowed = opa("allow_change", {"subject": subject, key: entry_id, "grants": named},
                      package=package) is True
        if row is None or not allowed:
            app.logger.info("DENY change subject=%s %s=%s grants=%s", subject, kind, entry_id, named)
            return jsonify({"error": "forbidden"}), 403
        sets = {g: set(row[c]) for g, c in cols.items()}
        for c in changes:
            for g in c.get("add", []):
                sets[g].add(c["group"])
            for g in c.get("remove", []):
                sets[g].discard(c["group"])
        cur.execute(f"UPDATE {table} SET " + ", ".join(f'"{c}" = %s' for c in cols.values())
                    + " WHERE id = %s", [sorted(sets[g]) for g in cols] + [entry_id])
    app.logger.info("CHANGE subject=%s %s=%s changes=%s", subject, kind, entry_id, changes)
    return jsonify({"ok": True, "id": entry_id, "grants": {g: sorted(s) for g, s in sets.items()}})


def _lock_group(cur, name):
    # Every writer of a group's members or owners takes this lock, so the owners OPA fetches
    # while it is held are the ones the write replaces.
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("group:" + name,))


def _names(v, pattern):
    return isinstance(v, list) and all(isinstance(x, str) and pattern.match(x) for x in v)


# A name some grant or ownership already names: creating it would hand whoever joins it those
# grants, so it is refused.
_NAME_IN_USE_SQL = """
SELECT EXISTS (SELECT 1 FROM group_members WHERE grp = %(g)s)
    OR EXISTS (SELECT 1 FROM group_owners WHERE grp = %(g)s OR owner = %(g)s)
    OR EXISTS (SELECT 1 FROM datasets WHERE %(g)s = ANY(visibility || access || share || write))
    OR EXISTS (SELECT 1 FROM table_entries WHERE %(g)s = ANY(see || read || share || write || "delete"))
    OR EXISTS (SELECT 1 FROM namespace_owners WHERE grp = %(g)s)
    OR EXISTS (SELECT 1 FROM register_grants WHERE grp = %(g)s) AS used
"""


@app.post("/groups")
def create_group():
    # Create a group with its first owners: {"name", "owners": [group], "members": [subject]}.
    # authZ = OPA's lakehouse.groups.allow_create.
    subject, err = authed_user()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    name, owners, members = body.get("name"), body.get("owners"), body.get("members", [])
    if not (isinstance(name, str) and GROUP_RE.match(name) and owners
            and _names(owners, GROUP_RE) and _names(members, SUBJECT_RE)):
        return jsonify({"error": "name and a non-empty owners list of groups required; "
                                 "members is a list of subjects"}), 400
    if opa("allow_create", {"subject": subject}, package="groups") is not True:
        app.logger.info("DENY create-group subject=%s group=%s", subject, name)
        return jsonify({"error": "forbidden"}), 403
    with db(commit=True) as cur:
        _lock_group(cur, name)
        cur.execute(_NAME_IN_USE_SQL, {"g": name})
        if cur.fetchone()["used"]:
            return jsonify({"error": "group name in use"}), 409
        for o in set(owners):
            cur.execute("INSERT INTO group_owners (grp, owner) VALUES (%s, %s)", (name, o))
        for m in set(members):
            cur.execute("INSERT INTO group_members (grp, member) VALUES (%s, %s)", (name, m))
    app.logger.info("CREATE-GROUP subject=%s group=%s owners=%s", subject, name, sorted(set(owners)))
    return jsonify({"ok": True, "group": name, "owners": sorted(set(owners)),
                    "members": sorted(set(members))}), 201


@app.patch("/groups/<name>")
def change_group(name):
    # Add or remove a group's members and owners:
    # {"members": {"add": [subject], "remove": [subject]}, "owners": {"add": [group], "remove": [group]}}.
    # authZ = OPA's lakehouse.groups.allow_change (the caller is in one of the group's owners),
    # asked while this transaction holds the group's lock. An unknown group has no owners, so
    # it is refused exactly as a denied change. A change leaving no owner is refused, since
    # only owners can change a group.
    subject, err = authed_user()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    patterns = {"members": SUBJECT_RE, "owners": GROUP_RE}
    if not (body and set(body) <= patterns.keys() and all(
            isinstance(body[f], dict) and body[f] and set(body[f]) <= {"add", "remove"}
            and all(_names(v, patterns[f]) for v in body[f].values())
            for f in body)):
        return jsonify({"error": "body is {members|owners: {add: [...], remove: [...]}}"}), 400
    with db(commit=True) as cur:
        _lock_group(cur, name)
        if opa("allow_change", {"subject": subject, "group": name}, package="groups") is not True:
            app.logger.info("DENY change-group subject=%s group=%s", subject, name)
            return jsonify({"error": "forbidden"}), 403
        cur.execute("SELECT member FROM group_members WHERE grp = %s", (name,))
        now = {"members": {r["member"] for r in cur.fetchall()}}
        cur.execute("SELECT owner FROM group_owners WHERE grp = %s", (name,))
        now["owners"] = {r["owner"] for r in cur.fetchall()}
        for f, ops in body.items():
            now[f] = (now[f] | set(ops.get("add", []))) - set(ops.get("remove", []))
        if not now["owners"]:
            return jsonify({"error": "a group keeps at least one owner"}), 409
        for f, (tbl, col) in {"members": ("group_members", "member"),
                              "owners": ("group_owners", "owner")}.items():
            cur.execute(f"DELETE FROM {tbl} WHERE grp = %s AND NOT ({col} = ANY(%s))",
                        (name, sorted(now[f])))
            for x in now[f]:
                cur.execute(f"INSERT INTO {tbl} (grp, {col}) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (name, x))
    app.logger.info("CHANGE-GROUP subject=%s group=%s change=%s", subject, name, body)
    return jsonify({"ok": True, "group": name, "members": sorted(now["members"]),
                    "owners": sorted(now["owners"])})


@app.patch("/roots/<kind>/<path:root_id>")
def change_root_owners(kind, root_id):
    # Add or remove the groups owning a prefix root or a namespace:
    # {"owners": {"add": [group], "remove": [group]}}. A dataset root is named as a dataset id is
    # (`projx/sub` is datasets/projx/sub/), a namespace by its id (`lakehouse.db`). Owning one
    # owns everything under it. authZ = OPA's allow_change_root, which reads the ownership of
    # this root and those above it; root changes are rare, so one lock serializes them all and
    # the decision and the write see the same ownership.
    subject, err = authed_user()
    if err:
        return err
    if kind == "dataset":
        root = f"datasets/{root_id}/"
        valid, package, inp = _confined_prefix(root), "blob", {"subject": subject, "prefix": root}
    elif kind == "namespace":
        root = root_id
        valid, package, inp = bool(NAMESPACE_RE.match(root)), "tables", {"subject": subject, "id": root}
    else:
        return jsonify({"error": "not found"}), 404
    owners = (request.get_json(silent=True) or {}).get("owners")
    if not (valid and isinstance(owners, dict) and owners and set(owners) <= {"add", "remove"}
            and all(_names(v, GROUP_RE) for v in owners.values())):
        return jsonify({"error": "a valid root and {owners: {add: [group], remove: [group]}} required"}), 400
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (ROOTS_LOCK_KEY,))
        if opa("allow_change_root", inp, package=package) is not True:
            app.logger.info("DENY change-root subject=%s %s=%s", subject, kind, root)
            return jsonify({"error": "forbidden"}), 403
        for g in owners.get("add", []):
            if kind == "dataset":
                cur.execute("INSERT INTO register_grants (grp, prefixes) VALUES (%(g)s, ARRAY[%(r)s]) "
                            "ON CONFLICT (grp) DO UPDATE SET prefixes = register_grants.prefixes || "
                            "%(r)s::text WHERE NOT %(r)s = ANY(register_grants.prefixes)", {"g": g, "r": root})
            else:
                cur.execute("INSERT INTO namespace_owners (grp, namespace) VALUES (%s, %s) "
                            "ON CONFLICT DO NOTHING", (g, root))
        for g in owners.get("remove", []):
            if kind == "dataset":
                cur.execute("UPDATE register_grants SET prefixes = array_remove(prefixes, %s) "
                            "WHERE grp = %s", (root, g))
                cur.execute("DELETE FROM register_grants WHERE grp = %s AND prefixes = '{}'", (g,))
            else:
                cur.execute("DELETE FROM namespace_owners WHERE grp = %s AND namespace = %s", (g, root))
        if kind == "dataset":
            cur.execute("SELECT grp FROM register_grants WHERE %s = ANY(prefixes) ORDER BY grp", (root,))
        else:
            cur.execute("SELECT grp FROM namespace_owners WHERE namespace = %s ORDER BY grp", (root,))
        now = [r["grp"] for r in cur.fetchall()]
    app.logger.info("CHANGE-ROOT subject=%s %s=%s owners=%s", subject, kind, root, owners)
    return jsonify({"ok": True, "root": root, "owners": now})


def _index_rows(subject):
    """Every live dataset and table the subject may see, with whether they may read it. Only
    live entries: existence is storage's truth (reconcile, the gate's reports), visibility
    OPA's; governance builds the list, OPA says which candidates pass.

    The candidates are only entries whose viewing grants name one of the subject's groups:
    see or read for a file dataset, see, read or write for a table. Those are exactly the
    grants OPA's visibility rules test (blob.rego `visible`, tables.rego `viewable`), so the
    narrowing drops only entries OPA would refuse, and OPA's cost follows what the person may
    see rather than the catalog's size. seed/check-index-narrowing.py checks the two agree."""
    with db() as cur:
        cur.execute("SELECT grp FROM group_members WHERE member = %s", (subject,))
        groups = [r["grp"] for r in cur.fetchall()]
        cur.execute("SELECT id, description, steward FROM datasets WHERE status = 'live' "
                    "AND (visibility || access) && %s::text[]", (groups,))
        files = cur.fetchall()
        cur.execute("SELECT id, description, steward FROM table_entries WHERE status = 'live' "
                    "AND (see || read || write) && %s::text[]", (groups,))
        tables = cur.fetchall()
    f = (opa("discover", {"subject": subject, "datasets": [r["id"] for r in files]})
         if files else {"visible": [], "readable": []})
    t = (opa("decide", {"subject": subject, "tables": [r["id"] for r in tables], "namespaces": []},
             package="tables") if tables else {"tables": [], "readable": []})
    rows = [{"id": r["id"], "kind": "files", "description": r["description"],
             "steward": r["steward"], "can_read": r["id"] in f["readable"]}
            for r in files if r["id"] in f["visible"]]
    rows += [{"id": r["id"], "kind": "table", "description": r["description"],
              "steward": r["steward"], "can_read": r["id"] in t["readable"]}
             for r in tables if r["id"] in t["tables"]]
    return sorted(rows, key=lambda r: (r["kind"], r["id"]))


def _session_rows(subject, sid):
    """The person's sessions; `current` marks the one this login's next access would be
    stamped with."""
    with db() as cur:
        current = _pointer(cur, subject, sid)
        cur.execute("SELECT id, name, started, last_used FROM sessions WHERE person = %s "
                    "ORDER BY started", (subject,))
        return [{"name": r["name"], "started": r["started"], "last_used": r["last_used"],
                 "current": r["id"] == current} for r in cur.fetchall()]


def _accessed_rows(subject, sid):
    """One row per dataset read in this login's current session: what an output made in it
    may derive from."""
    with db() as cur:
        current = _pointer(cur, subject, sid)
        cur.execute("SELECT a.dataset, a.kind, s.name AS session, min(a.at) AS first_access, "
                    "max(a.at) AS last_access FROM accesses a JOIN sessions s ON s.id = a.session "
                    "WHERE a.session = %s AND a.mode = 'read' "
                    "GROUP BY a.dataset, a.kind, s.name ORDER BY a.dataset", (current,))
        return cur.fetchall()


@app.post("/index/load")
def index_load():
    # The gate's answer to a catalog load of one of <catalog>.governance's tables
    # (index_table.TABLES), on the person's own token: an Iceberg LoadTableResult for that
    # person's table, whose files this service serves below with the storage credential in
    # `config`.
    claims, err = authed_claims(CATALOG_AUDIENCE)
    if err:
        return err
    subject, sid = subject_of(claims), claims.get("sid") or ""
    name = (request.get_json(silent=True) or {}).get("table", "datasets")
    if name == "datasets":
        rows = _index_rows(subject)
    elif name == "sessions":
        rows = _session_rows(subject, sid)
    elif name == "accessed":
        rows = _accessed_rows(subject, sid)
    else:
        return jsonify({"error": "no such table"}), 404
    table = index_table.build(subject, name, rows)
    config = {**index_table.mint(subject), "s3.endpoint": INDEX_ENDPOINT,
              "s3.force-virtual-addressing": "true", "s3.region": "us-east-1",
              "client.region": "us-east-1"}
    return jsonify({**table, "config": config})


def _s3_error(status, code):
    return Response(f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code></Error>",
                    status=status, content_type="application/xml")


# S3 GetObject/HeadObject for the index's files, served on INDEX_PORT to requests addressed to
# governance-index.storage. The signature names the person; they may read only their own prefix.
index_app = Flask("index")


@index_app.route("/<path:key>", methods=["GET", "HEAD"])
def index_object(key):
    raw_path, _, raw_query = (request.environ.get("RAW_URI") or request.path).partition("?")
    subject = index_table.verify(request.method, raw_path, raw_query, request.headers)
    if subject is None or not key.startswith(subject + "/"):
        return _s3_error(403, "AccessDenied")
    data = index_table.read(f"s3://{index_table.BUCKET}/{key}")
    if data is None:
        return _s3_error(404, "NoSuchKey")
    headers = {"Accept-Ranges": "bytes", "ETag": f'"{hashlib.md5(data).hexdigest()}"',
               "Last-Modified": "Thu, 01 Jan 2026 00:00:00 GMT"}
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", request.headers.get("Range", ""))
    if m and (m.group(1) or m.group(2)):
        if m.group(1):
            start = int(m.group(1))
            end = min(int(m.group(2)), len(data) - 1) if m.group(2) else len(data) - 1
        else:
            start, end = max(len(data) - int(m.group(2)), 0), len(data) - 1
        if start >= len(data) or start > end:
            return _s3_error(416, "InvalidRange")
        headers["Content-Range"] = f"bytes {start}-{end}/{len(data)}"
        body, status = data[start:end + 1], 206
    else:
        body, status = data, 200
    headers["Content-Length"] = str(len(body))
    # A HEAD answer has no body but must report the object's length; an iterable body keeps
    # Flask from replacing Content-Length with the empty body's 0.
    return Response([] if request.method == "HEAD" else [body], status=status, headers=headers,
                    content_type="application/octet-stream")


if __name__ == "__main__":
    connect_pool()
    for ds_id in init_db():   # datasets seeded just now are registered: check each folder once
        try:
            reconcile(ds_id)
        except Exception as e:  # noqa: BLE001 — RGW trouble must not abort boot
            app.logger.warning("check of seeded %s failed: %s", ds_id, e)
    threading.Thread(target=make_server("0.0.0.0", INDEX_PORT, index_app, threaded=True).serve_forever,
                     daemon=True).start()
    threading.Thread(target=internal_server().serve_forever, daemon=True).start()
    # use_reloader=False: a reloader spawns a second process — wrong for a service that
    # owns a connection pool and its own listener threads.
    app.run(host="0.0.0.0", port=8000, use_reloader=False)
