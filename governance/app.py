"""
governance — the PAP + dataset registry. The single source of truth (Postgres-backed).

It is the descendant of minio_manager_service, but instead of mirroring policy into
backends it FEEDS OPA: it owns the dataset registry + all grants and publishes them to
OPA as a **bundle** (OPA pulls it). Durable, transactional state lives in a dedicated
`governance` Postgres database (created by the governance-bootstrap one-shot, schema +
seed managed here). It serves:
  - /bundle.tar.gz  — the OPA bundle (rego policies + data derived from the registry)
  - /discover       — Flow A: the metadata-VISIBILITY plane ("what exists that I could
                      request"), filtered through OPA per-entry. Returns names, never bytes.
  - /datasets/<n>   — dataset -> prefix, for the broker (single-sourced registry).

Two truths, reconciled not merged (Phase 3): storage is truth for existence/stats; the
registry is truth for meaning/grants. The `datasets` row carries both column groups, but
they are written by disjoint paths — meaning/grants by ingest+seed, existence/stats by
reconcile (added in Stage 3). The bundle is built from meaning/grants ONLY, so storage
churn never moves OPA.

Two permission planes live per dataset as separate grant sets:
  visibility (may you SEE it exists)  vs  access (may you READ the bytes).
So a dataset can be see-but-not-read (the Lake Formation model).

OPA is only ever a PREDICATE here: discovery enumerates the registry and asks OPA
"may S see dataset X?" per entry. OPA never returns a list.
"""
import gzip
import io
import json
import logging
import os
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
REGO_FILES = ["policy.rego", "blob.rego"]

# --- Storage / freshness (Phase 3) ---
RGW_ENDPOINT = os.environ.get("RGW_ENDPOINT", "http://ceph:8080")
RGW_KEY = os.environ.get("RGW_ACCESS_KEY", "")
RGW_SECRET = os.environ.get("RGW_SECRET_KEY", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "lakehouse")
EVENTS_ENDPOINT = os.environ.get("EVENTS_ENDPOINT", "http://governance:8000/events")
EVENTS_TOPIC = os.environ.get("EVENTS_TOPIC", "dataset-events")
RECONCILE_INTERVAL = int(os.environ.get("RECONCILE_INTERVAL", "30"))
# Short timeouts: notification wiring is best-effort; the reconcile timer (Stage 3) is the
# authority and self-heals, so governance must never hang/crash on RGW being slow/absent.
_boto_cfg = Config(signature_version="s3v4", connect_timeout=5, read_timeout=5,
                   retries={"max_attempts": 2})

# Full schema up front (incl. the existence/stats columns reconcile fills in Stage 3) so
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
_pool = None


def connect_pool(retries=30, delay=1):
    """The governance DB exists by now (bootstrap one-shot), but tolerate a slow start."""
    global _pool
    last = None
    for _ in range(retries):
        try:
            _pool = ThreadedConnectionPool(1, 8, dsn=DB_DSN)
            return
        except psycopg2.OperationalError as e:  # noqa: PERF203
            last = e
            app.logger.warning("waiting for governance DB: %s", e)
            time.sleep(delay)
    raise last


@contextmanager
def db(commit=False):
    """A pooled connection + RealDict cursor. Per-operation, thread-safe (request threads
    and, in Stage 3, the reconcile timer all borrow from the pool)."""
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
        "dataset_grants": {"groups": access_groups, "users": {}},
        "visibility_grants": {"groups": vis_groups, "users": {}},
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
    key = _jwks.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=KEYCLOAK_ISS,
                        options={"verify_aud": False})
    subject = claims.get("principal_name") or claims.get("preferred_username") or claims.get("sub")
    groups = claims.get("principal_roles") or claims.get("groups") or []
    return subject, groups


def opa_pred(rule, subject, groups, dataset):
    r = requests.post(f"{OPA_BASE}/v1/data/lakehouse/blob/{rule}", json={"input": {
        "subject": subject, "groups": groups, "action": "read", "dataset": dataset,
    }}, timeout=5)
    r.raise_for_status()
    return r.json().get("result") is True


def _s3():
    return boto3.client("s3", endpoint_url=RGW_ENDPOINT, aws_access_key_id=RGW_KEY,
                        aws_secret_access_key=RGW_SECRET, region_name="us-east-1",
                        config=_boto_cfg)


def ensure_notifications():
    """Wire RGW to push object create/remove events under datasets/ to our /events.
    Best-effort + idempotent: governance owns freshness, so it configures its own event
    subscription. If RGW lacks the notifications API, log and fall back to the reconcile
    timer (Stage 3) — never crash startup."""
    try:
        sns = boto3.client("sns", endpoint_url=RGW_ENDPOINT, aws_access_key_id=RGW_KEY,
                           aws_secret_access_key=RGW_SECRET, region_name="us-east-1",
                           config=_boto_cfg)
        # RGW carries the HTTP push target in the topic's attributes.
        arn = sns.create_topic(Name=EVENTS_TOPIC,
                               Attributes={"push-endpoint": EVENTS_ENDPOINT})["TopicArn"]
        _s3().put_bucket_notification_configuration(
            Bucket=S3_BUCKET,
            NotificationConfiguration={"TopicConfigurations": [{
                "Id": "dataset-freshness",
                "TopicArn": arn,
                "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "datasets/"}]}},
            }]},
        )
        app.logger.info("RGW notifications wired: topic=%s -> %s", arn, EVENTS_ENDPOINT)
    except Exception as e:  # noqa: BLE001
        app.logger.warning("RGW notification wiring failed (timer will still reconcile): %s", e)


def _stat_prefix(s3, prefix):
    """List a dataset's prefix; stats come straight from the listing (no GetObject)."""
    count, total, last = 0, 0, None
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for o in page.get("Contents", []):
            count += 1
            total += o["Size"]
            if last is None or o["LastModified"] > last:
                last = o["LastModified"]
    return count, total, last


def _next_status(current, count):
    """Lifecycle: any non-empty prefix is live. An EMPTY prefix is `gone` ONLY if it was
    live (was-populated-now-empty); a never-populated dataset stays `pending`, and a `gone`
    one stays gone. So new/empty != dead, and discovery never advertises a dead dataset."""
    if count > 0:
        return "live"
    if current == "live":
        return "gone"
    return current


def reconcile(name=None):
    """The ONLY writer of the existence/stats columns. With `name`: just that dataset (the
    event path). Without: a full sweep (the timer). Storage is the truth here; the registry
    grants are untouched, so reconcile never moves OPA."""
    with db() as cur:
        if name:
            cur.execute("SELECT name, prefix, status FROM datasets WHERE name = %s", (name,))
        else:
            cur.execute("SELECT name, prefix, status FROM datasets")
        rows = cur.fetchall()
    s3 = _s3()
    for row in rows:
        try:
            count, total, last = _stat_prefix(s3, row["prefix"])
        except Exception as e:  # noqa: BLE001
            app.logger.warning("reconcile %s: list failed: %s", row["name"], e)
            continue
        status = _next_status(row["status"], count)
        with db(commit=True) as cur:
            cur.execute(
                "UPDATE datasets SET status=%s, object_count=%s, total_bytes=%s, "
                "last_modified=%s, last_reconciled=now() WHERE name=%s",
                (status, count, total, last, row["name"]),
            )
        if status != row["status"]:
            app.logger.info("reconcile %s: %s -> %s (count=%s)",
                            row["name"], row["status"], status, count)


def _dataset_for_key(key):
    """The longest registered prefix the object key falls under (disambiguates nested
    prefixes like datasets/projx/ vs datasets/projx/public/)."""
    best = None
    with db() as cur:
        cur.execute("SELECT name, prefix FROM datasets")
        for r in cur.fetchall():
            if key.startswith(r["prefix"]) and (best is None or len(r["prefix"]) > len(best[1])):
                best = (r["name"], r["prefix"])
    return best[0] if best else None


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
    # reconcile (Stage 3), which reads storage truth itself; a missed/forged event is
    # harmless and self-heals on the next timer sweep. Unauthenticated by design
    # (trusted-network dev assumption). Stage 2: log; Stage 3: dispatch reconcile.
    body = request.get_json(silent=True) or {}
    records = body.get("Records", [])
    touched = set()
    for rec in records:
        key = rec.get("s3", {}).get("object", {}).get("key", "")
        app.logger.info("EVENT %s key=%s", rec.get("eventName", "?"), key)
        ds = _dataset_for_key(key)
        if ds:
            touched.add(ds)
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
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "missing bearer token"}), 401
    try:
        subject, groups = verify_user(auth[7:])
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return jsonify({"error": "invalid token"}), 401

    body = request.get_json(silent=True) or {}
    name, prefix = body.get("name"), body.get("prefix")
    if not name or not prefix:
        return jsonify({"error": "name and prefix are required"}), 400

    if not opa_pred("allow_register", subject, groups, name):
        app.logger.info("DENY register subject=%s groups=%s name=%s", subject, groups, name)
        return jsonify({"error": "forbidden", "subject": subject}), 403

    try:
        with db(commit=True) as cur:
            cur.execute(
                "INSERT INTO datasets (name, prefix, description, steward, visibility, access, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, 'pending')",
                (name, prefix, body.get("description"), subject,
                 body.get("visibility", []), body.get("access", [])),
            )
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "dataset already exists", "name": name}), 409

    # Synchronous reconcile: if the bytes are already uploaded, flip pending->live NOW so
    # the demo is deterministic (no wait for a timer tick). Grants reach OPA on its next
    # bundle poll (≤ poll interval).
    reconcile(name)
    app.logger.info("REGISTER subject=%s name=%s prefix=%s", subject, name, prefix)
    return jsonify({"ok": True, "name": name, "registered_by": subject}), 201


@app.get("/discover")
def discover():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "missing bearer token"}), 401
    try:
        subject, groups = verify_user(auth[7:])
    except Exception as e:  # noqa: BLE001
        app.logger.warning("token verification failed: %s", e)
        return jsonify({"error": "invalid token"}), 401

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
    ensure_notifications()    # best-effort; the reconcile timer is the authority
    reconcile()               # startup sweep: classify seeded datasets (pending -> live/gone) now
    threading.Thread(target=reconcile_loop, daemon=True).start()
    # use_reloader=False: a reloader spawns a second process — wrong for a service that
    # owns a connection pool and a single reconcile timer thread.
    app.run(host="0.0.0.0", port=8000, use_reloader=False)
