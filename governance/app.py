"""
governance — the PAP + dataset registry, and the single source of truth (Postgres-backed).

It owns the dataset registry + all grants and FEEDS OPA a bundle (OPA pulls it); it does
not mirror policy into backends. Durable state lives in a dedicated `governance` Postgres DB.

Two truths, reconciled not merged: storage is truth for existence/stats; the registry is
truth for meaning/grants. The `datasets` row carries both, written by disjoint paths —
meaning/grants by ingest+seed, existence/stats by reconcile. The bundle is built from
meaning/grants ONLY, so storage churn never moves OPA.

Two permission planes per dataset, as separate grant sets: visibility (may you SEE it
exists) vs access (may you READ the bytes) — so a dataset can be see-but-not-read.

OPA is only ever a PREDICATE: discovery enumerates the registry and asks OPA "may S see
dataset X?" per entry. OPA never returns a list.
"""
import gzip
import io
import json
import logging
import os
import re
import tarfile
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

POLICY_DIR = os.environ.get("POLICY_DIR", "/policies")
REGISTRY_PATH = os.environ.get("REGISTRY", "/app/registry.json")
OPA_BASE = os.environ.get("OPA_BASE", "http://opa:8181")
DB_DSN = os.environ["GOVERNANCE_DB_DSN"]
KEYCLOAK_JWKS = os.environ["KEYCLOAK_JWKS"]
KEYCLOAK_ISS = os.environ["KEYCLOAK_ISS"]
# Only tokens issued THROUGH our login client are accepted (azp), so a token minted for some
# other realm client can't be replayed here as a user credential.
EXPECTED_AZP = os.environ.get("EXPECTED_AZP", "trino")
REGO_FILES = ["policy.rego", "blob.rego"]
# A dataset name is a bundle/JSON key and a SQL pk; a prefix becomes an STS resource ARN.
# Both come from an authenticated steward but are still untrusted input — constrain them.
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# --- Storage / freshness ---
# Least-privilege reader creds (ListBucket on datasets/* via a bucket policy set by the
# rgw-setup one-shot). Governance does NOT hold the RGW admin key; reconcile only lists.
RGW_ENDPOINT = os.environ.get("RGW_ENDPOINT", "http://ceph:8080")
RGW_KEY = os.environ.get("RGW_ACCESS_KEY", "")
RGW_SECRET = os.environ.get("RGW_SECRET_KEY", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "lakehouse")
RECONCILE_INTERVAL = int(os.environ.get("RECONCILE_INTERVAL", "30"))
MAX_EVENT_RECORDS = 1000  # cap the per-request reconcile fan-out (the endpoint is unauthenticated)
SEED_LOCK_KEY = 0x6D6C68  # advisory-lock key for the one-time registry seed ("mlh")
# Short timeouts: notification wiring is best-effort; the reconcile timer (Stage 3) is the
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
    name            TEXT PRIMARY KEY,
    prefix          TEXT NOT NULL,
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
CREATE TABLE IF NOT EXISTS table_grants (
    id      INTEGER PRIMARY KEY DEFAULT 1,
    grants  JSONB  NOT NULL DEFAULT '{}'::jsonb,
    writers TEXT[] NOT NULL DEFAULT '{}',
    CONSTRAINT table_grants_singleton CHECK (id = 1)
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
        for name, d in reg.get("datasets", {}).items():
            cur.execute(
                "INSERT INTO datasets (name, prefix, description, steward, visibility, access) "
                "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (name) DO NOTHING",
                (name, d["prefix"], d.get("description"), d.get("steward"),
                 d.get("visibility", []), d.get("access", [])),
            )
        tg = reg.get("table_grants", {})
        cur.execute(
            "INSERT INTO table_grants (id, grants, writers) VALUES (1, %s, %s) "
            "ON CONFLICT (id) DO NOTHING",
            (json.dumps(tg.get("grants", {})), tg.get("writers", [])),
        )
        app.logger.info("seeded governance registry from %s", REGISTRY_PATH)


def derive_data():
    """Turn the registry into the OPA `data` document — meaning/grants ONLY (both planes,
    both flows). Deliberately status-agnostic: a pending/gone dataset keeps its grants, so
    reconcile (which only touches existence/stats) never moves OPA."""
    access_groups, vis_groups = {}, {}
    with db() as cur:
        cur.execute("SELECT name, visibility, access FROM datasets")
        for row in cur.fetchall():
            for g in row["access"]:
                access_groups.setdefault(g, []).append(row["name"])
            for g in row["visibility"]:
                vis_groups.setdefault(g, []).append(row["name"])
        cur.execute("SELECT grants, writers FROM table_grants WHERE id = 1")
        tg = cur.fetchone() or {"grants": {}, "writers": []}
    return {
        "grants": tg["grants"],
        "writers": tg["writers"],
        "dataset_grants": {"groups": access_groups},
        "visibility_grants": {"groups": vis_groups},
    }


def build_bundle():
    """An OPA bundle: the .rego policies + a data.json generated from the registry."""
    data = json.dumps(derive_data()).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for rego in REGO_FILES:
            tar.add(os.path.join(POLICY_DIR, rego), arcname=rego)
        ti = tarfile.TarInfo("data.json")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))
    return gzip.compress(raw.getvalue())


def verify_user(token):
    """Cryptographically verify the caller's own Keycloak token -> (subject, groups). PyJWT
    enforces signature + exp; we add issuer and azp (the token must have been issued through
    our login client, not some other realm client)."""
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=KEYCLOAK_ISS,
                        options={"verify_aud": False})
    if claims.get("azp") != EXPECTED_AZP:
        raise jwt.InvalidTokenError(f"unexpected azp {claims.get('azp')!r}")
    subject = claims.get("principal_name") or claims.get("preferred_username") or claims.get("sub")
    groups = claims.get("principal_roles") or claims.get("groups") or []
    return subject, groups


def authed_user():
    """Verify the request's bearer token. Returns (subject, groups, None) on success, or
    (None, None, error_response) for the caller to return as-is."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None, (jsonify({"error": "missing bearer token"}), 401)
    try:
        return (*verify_user(auth[7:]), None)
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return None, None, (jsonify({"error": "invalid token"}), 401)


def opa_pred(rule, subject, groups, dataset, action="read"):
    r = _http.post(f"{OPA_BASE}/v1/data/lakehouse/blob/{rule}", json={"input": {
        "subject": subject, "groups": groups, "action": action, "dataset": dataset,
    }}, timeout=5)
    r.raise_for_status()
    return r.json().get("result") is True


def _confined_prefix(prefix):
    """A registrable prefix: under datasets/<segment>/, ends in /, no traversal/escape."""
    return (isinstance(prefix, str) and prefix.startswith("datasets/")
            and prefix.endswith("/") and prefix != "datasets/"
            and ".." not in prefix and "//" not in prefix)


# Lifecycle, expressed in SQL so the status transition reads `status` at write time under
# the row lock — no read-modify-write window where a concurrent reconcile (timer vs event)
# loses the update or resurrects a gone dataset. Non-empty => live; empty => gone ONLY if it
# was live (was-populated-now-empty), else unchanged (pending stays pending, gone stays gone).
_RECONCILE_SQL = """
WITH prev AS (SELECT status AS old FROM datasets WHERE name = %(n)s FOR UPDATE)
UPDATE datasets d SET
    status = CASE WHEN %(c)s > 0 THEN 'live'
                  WHEN d.status = 'live' THEN 'gone'
                  ELSE d.status END,
    object_count = %(c)s, total_bytes = %(t)s,
    last_modified = %(m)s, last_reconciled = now()
FROM prev WHERE d.name = %(n)s
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


def reconcile(name=None):
    """The ONLY writer of the existence/stats columns. With `name`: just that dataset (the
    event path). Without: a full sweep (the timer). Storage is the truth here; the registry
    grants are untouched, so reconcile never moves OPA."""
    with db() as cur:
        # name=None => full sweep (NULL IS NULL matches every row); else just that dataset.
        cur.execute("SELECT name, prefix FROM datasets WHERE (%s IS NULL OR name = %s)",
                    (name, name))
        rows = cur.fetchall()
    for row in rows:
        try:
            count, total, last = _stat_prefix(row["prefix"])
        except Exception as e:  # noqa: BLE001
            app.logger.warning("reconcile %s: list failed: %s", row["name"], e)
            continue
        with db(commit=True) as cur:
            cur.execute(_RECONCILE_SQL, {"n": row["name"], "c": count, "t": total, "m": last})
            r = cur.fetchone()
        if r and r["old"] != r["new"]:
            app.logger.info("reconcile %s: %s -> %s (count=%s)",
                            row["name"], r["old"], r["new"], count)


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
        cur.execute("SELECT name FROM datasets ORDER BY name")
        names = [r["name"] for r in cur.fetchall()]
    return jsonify({"ok": True, "datasets": names})


@app.get("/bundle.tar.gz")
def bundle():
    return app.response_class(build_bundle(), mimetype="application/gzip")


@app.get("/datasets/<name>")
def dataset(name):
    # Prefix is stable meaning; the broker (a SEPARATE access plane) resolves it regardless
    # of status — a transiently-empty dataset must not 404 the broker.
    with db() as cur:
        cur.execute("SELECT prefix FROM datasets WHERE name = %s", (name,))
        row = cur.fetchone()
    if not row:
        return jsonify({"error": "unknown dataset"}), 404
    return jsonify({"prefix": row["prefix"]})


@app.post("/events")
def events():
    # RGW bucket-notification sink. Events carry NO authority — they only TRIGGER a
    # reconcile, which reads storage truth itself; a missed/forged event is harmless and
    # self-heals on the next timer sweep. Unauthenticated by design (trusted-network dev).
    body = request.get_json(silent=True) or {}
    records = body.get("Records", [])[:MAX_EVENT_RECORDS]  # bound the fan-out
    with db() as cur:  # the registry once, not once per record
        cur.execute("SELECT name, prefix FROM datasets")
        registry = [(r["name"], r["prefix"]) for r in cur.fetchall()]
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
    # Register-at-ingest: a NEW dataset enters the registry with its human-supplied meaning
    # (name, prefix, description, grants). authN = the caller's own token; authZ = OPA
    # (the `stewards` capability lives in the published bundle, not hardcoded here).
    subject, groups, err = authed_user()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    name, prefix = body.get("name"), body.get("prefix")
    # The credential the broker later vends is scoped by this PREFIX string, while OPA decides
    # by NAME — so an unconfined/overlapping prefix would let a steward read another dataset's
    # bytes. Confine it: under datasets/<segment>/, no escape, and no overlap with an existing
    # dataset's prefix (string-containment either way).
    if not name or not isinstance(name, str) or not NAME_RE.match(name):
        return jsonify({"error": "name must match [A-Za-z0-9._-]{1,128}"}), 400
    if not _confined_prefix(prefix):
        return jsonify({"error": "prefix must be datasets/<...>/ with no '..' or escape"}), 400

    if not opa_pred("allow_register", subject, groups, name, action="register"):
        app.logger.info("DENY register subject=%s groups=%s name=%s", subject, groups, name)
        return jsonify({"error": "forbidden"}), 403

    try:
        with db(commit=True) as cur:
            cur.execute("SELECT prefix FROM datasets")
            existing = [r["prefix"] for r in cur.fetchall()]
            if any(prefix.startswith(p) or p.startswith(prefix) for p in existing):
                return jsonify({"error": "prefix overlaps an existing dataset"}), 409
            cur.execute(
                "INSERT INTO datasets (name, prefix, description, steward, visibility, access, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, 'pending')",
                (name, prefix, body.get("description"), subject,
                 body.get("visibility", []), body.get("access", [])),
            )
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "dataset already exists"}), 409

    # Synchronous reconcile: if the bytes are already uploaded, flip pending->live NOW so
    # the demo is deterministic (no wait for a timer tick). Grants reach OPA on its next
    # bundle poll (≤ poll interval).
    reconcile(name)
    app.logger.info("REGISTER subject=%s name=%s prefix=%s", subject, name, prefix)
    return jsonify({"ok": True, "name": name, "registered_by": subject}), 201


@app.get("/discover")
def discover():
    subject, groups, err = authed_user()
    if err:
        return err

    # Only LIVE datasets are advertised — discovery never shows a dead (gone) or not-yet-
    # populated (pending) dataset. Existence is storage truth (reconcile); visibility is
    # the OPA predicate below. Discovery = OPA-visible ∩ live.
    with db() as cur:
        cur.execute("SELECT name, description, steward FROM datasets WHERE status = 'live' ORDER BY name")
        rows = cur.fetchall()

    visible = []
    for row in rows:
        name = row["name"]
        # PREDICATE per entry — OPA never returns the inventory; governance builds it.
        if opa_pred("visible", subject, groups, name):
            visible.append({
                "name": name,
                "description": row["description"],
                "steward": row["steward"],
                "can_read": opa_pred("allow", subject, groups, name),
            })
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
