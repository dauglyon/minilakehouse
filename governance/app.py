"""
governance — the PAP + dataset registry, and the single source of truth (Postgres-backed).

It owns groups (each person's role in them), the dataset and table registries, and all
grants; OPA holds none, and Keycloak only proves who a person is. Every caller, governance
included, sends OPA only who is asking and what they name; OPA's rules fetch the grants they
need from the /internal/* lookups here, at decision time. Durable state lives in a dedicated
`governance` Postgres DB.

Two truths, reconciled not merged: storage is truth for existence; the registry is truth for
meaning/grants. The `datasets` row carries both, written by disjoint paths — meaning/grants by
ingest+seed, existence (status) by reconcile. Entries served to OPA carry
meaning/grants only, so storage churn never changes a decision.

Two permission planes per dataset, as separate grant sets: describe (may you list it and load
its metadata) vs read (may you read the bytes) — so a dataset can be described but not read.

Governance builds every list; OPA only says which of the candidates it was given pass.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import threading
import time
from xml.sax.saxutils import escape
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import boto3
import index_table
import jwt
import psycopg2
import requests
from botocore.config import Config
from cryptography.hazmat.primitives import serialization
from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring as parse_xml
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
PREFIX_RE = re.compile(r"^datasets/[A-Za-z0-9][A-Za-z0-9._/_-]{0,200}/$")
# A new group's name: BERDL's rule (minio_manager_service src/s3/utils/validators.py), 2 to 64
# lowercase letters and digits starting with a letter, and not one of its reserved names or
# `governance`, the namespace the gate answers itself.
GROUP_RE = re.compile(r"^[a-z][a-z0-9]{1,63}$")
RESERVED_GROUPS = {"admin", "root", "system", "all", "everyone", "public", "default", "minio",
                   "service", "backup", "warehouse", "governance"}
# A group named in a grant, a release or root ownership, made by anyone or by governance.
GROUP_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,254}$")
# What a grant names: a group, every role in it, or one role and those above it, in the
# `<group>#<role>` notation of Zanzibar and SpiceDB (_group_names).
GRANTEE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,254}(#(owner|admin|member|steward))?$")
ROLES = ("owner", "admin", "member", "viewer")
# The names each role holds besides the group's own, highest role first: an owner is also an
# admin and a member.
ROLE_NAMES = {"owner": ("owner", "admin", "member"), "admin": ("admin", "member"),
              "member": ("member",), "viewer": ()}
# The Keycloak realm role marking a platform admin, read from the verified token.
PLATFORM_ADMIN_ROLE = os.environ.get("PLATFORM_ADMIN_ROLE", "platform-admin")
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$")  # <catalog>.<namespace...>
SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,254}$")
# An input from outside the platform is named by the hash of its content (PROVENANCE.md 5.3).
EXTERNAL_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Governance signs each declaration it accepts with this key (pki.py), as a DSSE envelope.
SIGNING_KEY = os.environ.get("SIGNING_KEY", f"{os.environ.get('PKI_DIR', '/pki')}/signing.key")
DECLARATION_TYPE = "application/vnd.minilakehouse.derivation+json"
# Each engine catalog the event listener names, and the catalog its table ids start with:
# Trino's `iceberg` is Polaris's `lakehouse` (docs/HANDOFF-2026-10-22-groups.md section 4).
ENGINE_CATALOGS = dict(p.split("=", 1) for p in os.environ.get("ENGINE_CATALOGS", "iceberg=lakehouse").split(","))
# The grants of an entry, a folder and a namespace, and `revoked`: the groups whose own copies,
# in their personal space, carrying this as a source close to them (PROVENANCE.md 9).
GRANTS = ("describe", "read", "manage", "write", "delete", "detach", "revoked")
# The columns holding them: a file dataset stores `read` as `access`.
_GRANT_SQL = ", ".join(f'"{g}"' for g in GRANTS)
_DATASET_GRANT_SQL = ", ".join(f'"{"access" if g == "read" else g}"' for g in GRANTS)
# A collection's id: its group and a name, <group>:<name>. The colon is in no folder or table id.
COLLECTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_@.-]{0,254}:[a-z][a-z0-9_-]{0,62}$")
# A collection's grants (docs/HANDOFF-2026-10-22-groups.md section 5): `describe` and `read`
# reach every member, through nested collections; the others are the collection's own.
COLLECTION_GRANTS = ("describe", "read", "manage", "write", "delete")
_COLLECTION_GRANT_SQL = ", ".join(f'"{g}"' for g in COLLECTION_GRANTS)
# A person's personal group, and so the name of their space: u_<user>, for a user name that can
# name a folder and a namespace level.
PERSONAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,61}$")


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
PUBLISH_LOCK_KEY = 0x6D6C72   # arbitrary fixed key: serialize publishing, so published datasets never nest
COLLECTIONS_LOCK_KEY = 0x6D6C63  # arbitrary fixed key: serialize collection membership, so no cycle forms
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
    describe        TEXT[] NOT NULL DEFAULT '{}',
    access          TEXT[] NOT NULL DEFAULT '{}',
    manage          TEXT[] NOT NULL DEFAULT '{}',
    write           TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'gone',      -- live | gone: whether the folder holds anything
    last_reconciled TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS groups (
    name       TEXT PRIMARY KEY,
    created_by TEXT,                         -- null for a group the seed made
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS group_members (
    grp     TEXT NOT NULL,
    member  TEXT NOT NULL,                   -- a person's subject (the token's principal_name)
    role    TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    steward BOOLEAN NOT NULL DEFAULT false,  -- set by platform admins only, for a member or above
    PRIMARY KEY (grp, member)
);
-- A group's owners were groups (group_owners); they are now people holding the owner role.
ALTER TABLE group_members ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member';
ALTER TABLE group_members ADD COLUMN IF NOT EXISTS steward BOOLEAN NOT NULL DEFAULT false;
DROP TABLE IF EXISTS group_owners;
CREATE TABLE IF NOT EXISTS table_entries (
    id          TEXT PRIMARY KEY,            -- <catalog>.<namespace...>.<table>
    description TEXT,
    steward     TEXT,
    describe    TEXT[] NOT NULL DEFAULT '{}',
    read        TEXT[] NOT NULL DEFAULT '{}',
    manage      TEXT[] NOT NULL DEFAULT '{}',
    write       TEXT[] NOT NULL DEFAULT '{}',
    "delete"    TEXT[] NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'live',      -- live | gone
    location    TEXT                         -- learned from Polaris when the table is created
);
-- `manage` was called `share`; a volume made before the rename keeps that column.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'datasets' AND column_name = 'share') THEN
        ALTER TABLE datasets RENAME COLUMN share TO manage;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'table_entries' AND column_name = 'share') THEN
        ALTER TABLE table_entries RENAME COLUMN share TO manage;
    END IF;
END $$;
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS manage TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS write TEXT[] NOT NULL DEFAULT '{}';
-- The dataset index narrows its candidates to entries whose viewing grants name one of the
-- person's groups (_index_rows); these keep that query proportional to the matches.
-- Object count, bytes and last-modified were recorded by a periodic full listing and read by
-- nothing; status needs only whether a folder is empty.
ALTER TABLE datasets DROP COLUMN IF EXISTS object_count, DROP COLUMN IF EXISTS total_bytes,
    DROP COLUMN IF EXISTS last_modified;
-- The grant that lists a dataset and serves its metadata was called `visibility` on file
-- datasets and `see` on tables; a volume made before the rename keeps those columns.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'datasets' AND column_name = 'visibility') THEN
        ALTER TABLE datasets RENAME COLUMN visibility TO describe;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'table_entries' AND column_name = 'see') THEN
        ALTER TABLE table_entries RENAME COLUMN see TO describe;
    END IF;
END $$;
-- Who may detach a dataset from data derived from it (PROVENANCE.md 6.5).
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS detach TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS "delete" TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE table_entries ADD COLUMN IF NOT EXISTS detach TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS datasets_viewers ON datasets USING gin ((describe || access));
CREATE INDEX IF NOT EXISTS table_entries_viewers ON table_entries USING gin ((describe || read || write));
ALTER TABLE table_entries ADD COLUMN IF NOT EXISTS manage TEXT[] NOT NULL DEFAULT '{}';
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
DROP INDEX IF EXISTS accesses_session;
CREATE INDEX IF NOT EXISTS accesses_person ON accesses (person, mode, at);
-- Sources travel with stored files (PROVENANCE.md 6). A read keeps what it brought in: the
-- dataset read and every source its files carried then. A table credential handed to someone
-- in the table's write grant can write, so its time counts as a time they could have written.
ALTER TABLE accesses ADD COLUMN IF NOT EXISTS sources TEXT[];
ALTER TABLE accesses ADD COLUMN IF NOT EXISTS can_write BOOLEAN NOT NULL DEFAULT false;
-- For each source a read brought in through the dataset read, the datasets it arrived through,
-- once per path: {source: [[dataset, ...], ...]}. A release of any of them covers it (6.7).
ALTER TABLE accesses ADD COLUMN IF NOT EXISTS marks JSONB;
-- The folder a table write can write, when the gate knows it: a credential's location, or the
-- location a staged create's commit sets. A write counts toward a table only if it names no
-- location or the table's current one (6.2), so an abandoned staged create counts for nothing.
ALTER TABLE accesses ADD COLUMN IF NOT EXISTS location TEXT;
-- Releases (PROVENANCE.md 6.7): a holder of the target's `manage` asks the source's `manage`
-- holders to let a group read the target although the group may not read the source.
CREATE TABLE IF NOT EXISTS releases (
    id           BIGSERIAL PRIMARY KEY,
    target       TEXT NOT NULL,
    source       TEXT NOT NULL,
    grp          TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved     BOOLEAN,                    -- null until decided
    decided_by   TEXT,
    decided_at   TIMESTAMPTZ,
    withdrawn_by TEXT,
    withdrawn_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS releases_source ON releases (source, target);
CREATE INDEX IF NOT EXISTS accesses_dataset ON accesses (dataset, mode);
-- The files in each dataset's folder, as the last listing of it found them (6.2).
CREATE TABLE IF NOT EXISTS files (
    dataset       TEXT NOT NULL,             -- a file dataset's or a table's id
    key           TEXT NOT NULL,
    last_modified TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (dataset, key)
);
CREATE TABLE IF NOT EXISTS folder_listings (
    dataset   TEXT PRIMARY KEY,
    listed_at TIMESTAMPTZ NOT NULL
);
-- Declarations (PROVENANCE.md 5.3): one per target per accepted commit to
-- governance.derivations, with the rows as declared and the record governance signed.
CREATE TABLE IF NOT EXISTS declarations (
    id          BIGSERIAL PRIMARY KEY,
    person      TEXT NOT NULL,
    target      TEXT NOT NULL,
    declared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    envelope    JSONB NOT NULL               -- DSSE envelope over the record
);
CREATE TABLE IF NOT EXISTS declared_sources (
    declaration BIGINT NOT NULL REFERENCES declarations (id),
    source      TEXT,                        -- empty: the target was declared with no candidates
    source_type TEXT,                        -- table | files | external
    used        BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS declarations_person ON declarations (person, target);
-- A detach is a source that arrived through a read, marked unused; a declaration that puts
-- detached sources back is made by a holder of their `manage` (PROVENANCE.md 6.5).
ALTER TABLE declared_sources ADD COLUMN IF NOT EXISTS detached BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE declarations ADD COLUMN IF NOT EXISTS reattach BOOLEAN NOT NULL DEFAULT false;
-- Spaces and publishing (docs/HANDOFF-2026-10-22-groups.md sections 1 to 3). Each group's space
-- is the folder datasets/<group>/ and the namespace <catalog>.<group>, with default grants. A
-- folder is an entry from its first credential and is published by a steward, which gives it a
-- description and grants of its own; those count only while it is published. Datasets
-- registered before publishing existed were published by being registered.
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS published BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE datasets ALTER COLUMN published SET DEFAULT false;
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS created_by TEXT;     -- whose credential made the entry
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;
-- Status is whether the folder holds anything: live or gone. Nothing waits in `pending`.
UPDATE datasets SET status = 'gone' WHERE status = 'pending';
ALTER TABLE datasets ALTER COLUMN status SET DEFAULT 'gone';
UPDATE table_entries SET status = 'gone' WHERE status = 'pending';
-- A table has no grants of its own: its grants are its namespaces' and its space's. The
-- grant columns of table_entries are read only to keep a group name some grant used from
-- being created again.
-- Grants on a folder, reaching every entry under it.
CREATE TABLE IF NOT EXISTS folder_grants (
    prefix   TEXT PRIMARY KEY,                 -- datasets/<group>/<...>/
    describe TEXT[] NOT NULL DEFAULT '{}',
    read     TEXT[] NOT NULL DEFAULT '{}',
    manage   TEXT[] NOT NULL DEFAULT '{}',
    write    TEXT[] NOT NULL DEFAULT '{}',
    "delete" TEXT[] NOT NULL DEFAULT '{}',
    detach   TEXT[] NOT NULL DEFAULT '{}'
);
-- A namespace's grants, reaching every table under it, and whether it is published: one
-- dataset of its tables.
CREATE TABLE IF NOT EXISTS namespaces (
    id           TEXT PRIMARY KEY,             -- <catalog>.<namespace...>
    description  TEXT,
    published    BOOLEAN NOT NULL DEFAULT false,
    published_by TEXT,
    published_at TIMESTAMPTZ,
    describe     TEXT[] NOT NULL DEFAULT '{}',
    read         TEXT[] NOT NULL DEFAULT '{}',
    manage       TEXT[] NOT NULL DEFAULT '{}',
    write        TEXT[] NOT NULL DEFAULT '{}',
    "delete"     TEXT[] NOT NULL DEFAULT '{}',
    detach       TEXT[] NOT NULL DEFAULT '{}'
);
-- A file credential covers everything under its folder unless it was asked for the files
-- directly in the folder alone (docs/HANDOFF-2026-10-22-groups.md section 3).
ALTER TABLE accesses ADD COLUMN IF NOT EXISTS recursive BOOLEAN NOT NULL DEFAULT true;
-- `revoked` beside the six grants (PROVENANCE.md 9), and who added and removed each group.
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS revoked TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE folder_grants ADD COLUMN IF NOT EXISTS revoked TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE namespaces ADD COLUMN IF NOT EXISTS revoked TEXT[] NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS revocations (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL,                 -- dataset | folder | namespace
    entry      TEXT NOT NULL,                 -- its id, or a folder's prefix
    grp        TEXT NOT NULL,
    added_by   TEXT NOT NULL,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_by TEXT,
    removed_at TIMESTAMPTZ
);
-- Transfers (docs/HANDOFF-2026-10-22-groups.md section 1): a folder or table moved into another
-- group's space keeps its old entry, with status `moved` and the new one in `moved_to`.
ALTER TABLE datasets ADD COLUMN IF NOT EXISTS moved_to TEXT;
ALTER TABLE table_entries ADD COLUMN IF NOT EXISTS moved_to TEXT;
CREATE TABLE IF NOT EXISTS transfers (
    id      BIGSERIAL PRIMARY KEY,
    kind    TEXT NOT NULL,                    -- files | table
    from_id TEXT NOT NULL,
    to_id   TEXT NOT NULL,
    by      TEXT NOT NULL,
    at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    session BIGINT REFERENCES sessions (id),  -- a folder's: the session its copies were logged in
    done_at TIMESTAMPTZ
);
-- A folder's transfer is under way until done or until the broker's credential for it expires;
-- meanwhile nothing in or around either folder is published.
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS expires TIMESTAMPTZ;
UPDATE transfers SET expires = at + interval '15 minutes' WHERE expires IS NULL;
-- Stored sources (docs/PLAN-2026-10-24.md item 3e): what carried() last worked out for an
-- entry, for its whole folder and for the files directly in it, with the entry's version then.
-- Every change carried() reads from bumps the version of each entry it can change, in the
-- change's own transaction, and a stored row counts only while its version is current.
CREATE TABLE IF NOT EXISTS entry_sources (
    dataset TEXT NOT NULL,
    direct  BOOLEAN NOT NULL,
    version BIGINT NOT NULL,
    sources JSONB NOT NULL,
    PRIMARY KEY (dataset, direct)
);
CREATE TABLE IF NOT EXISTS sources_version (
    dataset TEXT PRIMARY KEY,
    version BIGINT NOT NULL
);
-- Collections (docs/HANDOFF-2026-10-22-groups.md section 5): published datasets and other
-- collections, by reference, owned by a group. A collection holds no data.
CREATE TABLE IF NOT EXISTS collections (
    id          TEXT PRIMARY KEY,             -- <group>:<name>
    owner       TEXT NOT NULL,                -- the group
    description TEXT,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    describe    TEXT[] NOT NULL DEFAULT '{}',
    read        TEXT[] NOT NULL DEFAULT '{}',
    manage      TEXT[] NOT NULL DEFAULT '{}',
    write       TEXT[] NOT NULL DEFAULT '{}',
    "delete"    TEXT[] NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS collection_members (
    collection  TEXT NOT NULL REFERENCES collections (id) ON DELETE CASCADE,
    member      TEXT NOT NULL,                -- a published folder's id, a published namespace's, a collection's
    member_kind TEXT NOT NULL,                -- files | namespace | collection
    added_by    TEXT NOT NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (collection, member)
);
CREATE INDEX IF NOT EXISTS collection_members_member ON collection_members (member);
-- Statements an engine reported (docs/HANDOFF-2026-10-22-groups.md section 4): each completed
-- statement that read or wrote a table, with what it read and wrote, the session the access
-- log puts it in, and whether it returned rows to the client. Drafts are worked out from these.
CREATE TABLE IF NOT EXISTS engine_statements (
    id           BIGSERIAL PRIMARY KEY,
    engine       TEXT NOT NULL,
    statement_id TEXT NOT NULL,
    person       TEXT NOT NULL,
    session      BIGINT NOT NULL REFERENCES sessions (id),
    target       TEXT,                         -- the table it wrote, if any
    inputs       TEXT[] NOT NULL,              -- the tables it read
    to_client    BOOLEAN NOT NULL,             -- it wrote no table, so what it read went to the client
    started      TIMESTAMPTZ NOT NULL,
    ended        TIMESTAMPTZ NOT NULL,
    event        JSONB NOT NULL,
    UNIQUE (engine, statement_id)
);
CREATE INDEX IF NOT EXISTS engine_statements_person ON engine_statements (person, session);
-- Roots gave groups folders and namespaces to register under; spaces replace them.
DROP TABLE IF EXISTS register_grants;
DROP TABLE IF EXISTS namespace_owners;
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
                'INSERT INTO datasets (id, prefix, description, steward, published, published_at, '
                'describe, access, manage, write, detach, "delete") '
                "VALUES (%s, %s, %s, %s, %s, CASE WHEN %s THEN now() END, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO NOTHING",
                (derive_id(d["prefix"]), d["prefix"], d.get("description"), d.get("steward"),
                 d.get("published", False), d.get("published", False),
                 d.get("describe", []), d.get("read", []), d.get("manage", []), d.get("write", []),
                 d.get("detach", []), d.get("delete", [])),
            )
        stewards = reg.get("stewards", {})
        for grp, people in reg.get("groups", {}).items():   # {group: {person: role}}
            cur.execute("INSERT INTO groups (name) VALUES (%s) ON CONFLICT DO NOTHING", (grp,))
            for m, role in people.items():
                cur.execute("INSERT INTO group_members (grp, member, role, steward) VALUES (%s, %s, %s, %s) "
                            "ON CONFLICT DO NOTHING", (grp, m, role, m in stewards.get(grp, [])))
        for n in reg.get("namespaces", []):
            if not NAMESPACE_RE.match(n["id"]):
                raise ValueError(f"registry.json: bad namespace id {n['id']!r}")
            cur.execute(
                f"INSERT INTO namespaces (id, description, published, published_by, published_at, {_GRANT_SQL}) "
                f"VALUES (%s, %s, %s, %s, CASE WHEN %s THEN now() END{', %s' * len(GRANTS)}) "
                "ON CONFLICT (id) DO NOTHING",
                (n["id"], n.get("description"), n.get("published", False), n.get("steward"),
                 n.get("published", False), *(n.get(g, []) for g in GRANTS)))
        app.logger.info("seeded governance registry from %s", REGISTRY_PATH)
        return [derive_id(d["prefix"]) for d in reg.get("datasets", [])]


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


def platform_admin(claims):
    """Whether the verified token carries the Keycloak realm role marking a platform admin."""
    return PLATFORM_ADMIN_ROLE in ((claims.get("realm_access") or {}).get("roles") or [])


def _personal(subject):
    """The name of a person's personal group and space, u_<user>, or None for a user name that
    cannot name a folder and a namespace level."""
    return f"u_{subject}" if PERSONAL_RE.match(subject) else None


def _ensure_personal(subject):
    """Create the person's personal group, with them as its only owner, if it does not exist yet
    (docs/HANDOFF-2026-10-22-groups.md section 1). No other group can take the name: the name
    rule refuses underscores."""
    name = _personal(subject)
    if name is None:
        return
    with db(commit=True) as cur:
        cur.execute("INSERT INTO groups (name, created_by) VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING name",
                    (name, subject))
        if cur.fetchone():
            cur.execute("INSERT INTO group_members (grp, member, role) VALUES (%s, %s, 'owner') "
                        "ON CONFLICT DO NOTHING", (name, subject))
            app.logger.info("PERSONAL group=%s", name)


def _is_personal(group):
    return group is not None and group.startswith("u_")


def _group_names(cur, subject):
    """The names a person holds grants through, as (read, write) lists: each group they are in,
    `<g>`, with `<g>#<role>` for their role and those below it and `<g>#steward` if they are
    its steward. A grant naming a group gives `describe` and `read` to everyone in it and every
    other grant to its members and above, so a viewer's names are in `read` only."""
    cur.execute("SELECT grp, role, steward FROM group_members WHERE member = %s", (subject,))
    read, write = [], []
    for r in cur.fetchall():
        names = [r["grp"], *(f"{r['grp']}#{x}" for x in ROLE_NAMES[r["role"]])]
        names += [f"{r['grp']}#steward"] if r["steward"] else []
        read += names
        write += names if r["role"] != "viewer" else []
    return sorted(read), sorted(write)


def opa(rule, inp, package="blob"):
    """Evaluate one lakehouse.<package> rule; returns its result."""
    r = _http.post(f"{OPA_BASE}/v1/data/lakehouse/{package}/{rule}", json={"input": inp},
                   timeout=5)
    r.raise_for_status()
    return r.json().get("result")


internal_app = Flask("internal")
# The certificate names that may call each internal route; every other route is a grant lookup,
# OPA's alone.
INTERNAL_CALLERS = {"/internal/table-events": {"gate"}, "/internal/accesses": {"gate", "broker"},
                    "/internal/transfers": {"broker"}, "/internal/drafts": {"trino"}}


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


# Status follows the folder: non-empty => live, empty => gone; a moved entry stays moved. Set
# under the row lock, so two checks of one dataset at once leave the later listing's answer.
_RECONCILE_SQL = """
WITH prev AS (SELECT status AS old FROM datasets WHERE id = %(n)s FOR UPDATE)
UPDATE datasets d SET status = CASE WHEN d.status = 'moved' THEN 'moved' WHEN %(nonempty)s THEN 'live'
                                    ELSE 'gone' END,
    last_reconciled = now()
FROM prev WHERE d.id = %(n)s
RETURNING prev.old AS old, d.status AS new
"""


def _table_folder(location):
    """A table's folder as a key prefix: s3://<bucket>/warehouse/db/t1-<uuid> -> warehouse/db/t1-<uuid>/.
    None for a location outside warehouse/, where Polaris's catalog confines tables
    (polaris/bootstrap.sh allowedLocations), so no table folder overlaps a file dataset's."""
    head = f"s3://{S3_BUCKET}/warehouse/"
    if not location or not location.startswith(head):
        return None
    rest = location[len(head):]
    rest = rest[:-1] if rest.endswith("/") else rest
    # Only a location already in its exact form: a normalized one could name a prefix that is
    # not where the files are.
    if not rest or any(part in ("", ".", "..") for part in rest.split("/")):
        return None
    return f"warehouse/{rest}/"


def _folders():
    """(id, key prefix) for every dataset and table with a folder."""
    with db() as cur:
        cur.execute("SELECT id, prefix FROM datasets")
        folders = [(r["id"], r["prefix"]) for r in cur.fetchall()]
        cur.execute("SELECT id, location FROM table_entries WHERE location IS NOT NULL")
        folders += [(r["id"], f) for r in cur.fetchall() if (f := _table_folder(r["location"]))]
    return folders


def _folder(ds_id):
    """The key prefix of a file dataset's folder, tracked or not, or of a table's; None for a
    table whose folder is unknown or an id that names no folder."""
    with db() as cur:
        cur.execute("SELECT prefix FROM datasets WHERE id = %s", (ds_id,))
        if row := cur.fetchone():
            return row["prefix"]
        cur.execute("SELECT location FROM table_entries WHERE id = %s", (ds_id,))
        row = cur.fetchone()
    if row or TABLE_ID_RE.match(ds_id):
        return _table_folder(row["location"]) if row else None
    return f"datasets/{ds_id}/" if _confined_prefix(f"datasets/{ds_id}/") else None


def _invalidate(cur, ids):
    """Mark the stored sources of these entries, and of every tracked folder inside or containing
    one of them, out of date: a file belongs to every credential whose folder holds it."""
    ids = sorted({i for i in ids if i})
    cur.execute("SELECT DISTINCT b.id FROM datasets a JOIN datasets b ON starts_with(b.prefix, a.prefix) "
                "OR starts_with(a.prefix, b.prefix) WHERE a.id = ANY(%s)", (ids,))
    ids = sorted({*ids, *(r["id"] for r in cur.fetchall())})
    cur.execute("INSERT INTO sources_version (dataset, version) SELECT unnest(%s::text[]), 1 "
                "ON CONFLICT (dataset) DO UPDATE SET version = sources_version.version + 1", (ids,))


def _invalidate_writes_of(cur, person):
    """Mark out of date the stored sources of every entry the person could have written in the
    last FILE_TIME_SLACK + CLOCK_TOLERANCE seconds: a read they make now counts toward a file
    that recent (PROVENANCE.md 8)."""
    cur.execute("SELECT DISTINCT dataset FROM accesses WHERE person = %s AND (mode = 'write' OR can_write) "
                "AND COALESCE(expires, at) >= now() - %s * interval '1 second'",
                (person, FILE_TIME_SLACK + CLOCK_TOLERANCE))
    _invalidate(cur, [r["dataset"] for r in cur.fetchall()])


def _listing(prefix):
    """(key, last modified, ETag) for every object under the prefix."""
    return [(o["Key"], o["LastModified"], o["ETag"])
            for page in _s3.get_paginator("list_objects_v2").paginate(Bucket=S3_BUCKET, Prefix=prefix)
            for o in page.get("Contents", [])]


def list_folder(ds_id, found=None):
    """Record every file in the dataset's folder with its last-modified time, replacing what
    the previous listing found, from a listing made now or the one given; returns whether the
    folder holds anything. Storage decides (PROVENANCE.md 6.2): a file stops counting only when
    a listing no longer shows it."""
    prefix = _folder(ds_id)
    if prefix is None:
        return False
    found = _listing(prefix) if found is None else found
    with db(commit=True) as cur:
        # A storage event and a lookup can list one folder at once; each replaces the rows whole.
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"list:{ds_id}",))
        cur.execute("DELETE FROM files WHERE dataset = %s", (ds_id,))
        for key, modified, _ in found:
            cur.execute("INSERT INTO files (dataset, key, last_modified) VALUES (%s, %s, %s)",
                        (ds_id, key, modified))
        cur.execute("INSERT INTO folder_listings (dataset, listed_at) VALUES (%s, now()) "
                    "ON CONFLICT (dataset) DO UPDATE SET listed_at = now()", (ds_id,))
        cur.execute("INSERT INTO sources_version (dataset, version) VALUES (%s, 1) "
                    "ON CONFLICT (dataset) DO UPDATE SET version = sources_version.version + 1", (ds_id,))
    return bool(found)


# Seconds a file's last-modified time may differ from the access log's clock.
CLOCK_TOLERANCE = 5
# A listing gives a file's last-modified time in whole seconds, rounded down, so a file can
# look older than a read made just before it was written. Every comparison of a listed time
# with the access log leans the safe way by this much: a read counts toward a file it may have
# come up to this long after, and a declaration covers a file only from this long after it.
FILE_TIME_SLACK = 2

# The sources a dataset's files carry (PROVENANCE.md 6, rule 2). A file belongs to every write
# credential and commit for the dataset that was valid when the file was last modified; it
# carries what each such writer had brought in before that time, through their session's reads
# and, from the credential's issue on, their login's reads, minus what that writer's latest
# declaration of the dataset made after the file marked unused, unless a `manage` holder of the
# source has put it back since (6.5). A dataset is not its own source.
# A commit or create the gate logged since the last listing counts as having written a file at
# its time, since the gate logs it before Polaris sees it. A credential that can write counts
# only for files a listing finds from its time, and carried() lists again once it expires, in
# case a notification was lost. Counting a valid credential as writing now would hold a dataset
# to everything its writer reads for as long as the credential lasts, up to an hour for
# Polaris's, cleaning included; it would protect only the seconds before the listing a write's
# notification triggers, and anyone holding a credential reads new files in the folder until it
# expires whatever governance knows. A dataset whose folder cannot be listed counts every write
# ever logged for it as having written a file.
# Whether a logged write counts toward dataset %(t)s at folder %(loc)s: it names no location (a
# file credential, a commit to an existing table), or the table's folder, or a location a commit
# the gate logged for the table names, which covers a table whose creation report was lost. A
# staged create abandoned before its commit was logged names a folder nothing else does. Every
# table commit is logged before Polaris sees it and counts toward its own table, so a table
# whose folder is unknown still carries its writers' reads. Trailing slashes are ignored: a
# create's location comes from the client, the others from Polaris.
_COUNTS_SQL = """(location IS NULL OR rtrim(location, '/') = rtrim(%(loc)s, '/') OR rtrim(location, '/') IN (
          SELECT rtrim(c.location, '/') FROM accesses c WHERE c.dataset = %(t)s AND c.mode = 'write'
          AND c.expires IS NULL AND c.location IS NOT NULL))"""

# The writes a table's files may come from: those logged for the table (_COUNTS_SQL).
_TABLE_WRITES = """
    SELECT person, session, sid, at, dataset AS wds, '' AS wprefix, true AS recursive,
           expires IS NULL AS instant, COALESCE(expires, at) AS until
    FROM accesses WHERE dataset = %(t)s AND (mode = 'write' OR can_write)
      AND """ + _COUNTS_SQL

# The writes a folder's files may come from: every write credential for a tracked folder inside
# or containing it. Folders nest until one is published, and a credential for a folder covers
# everything under it, or only the files directly in it, so a file belongs to each credential
# that covers it, whichever folder the credential was asked for.
_FOLDER_WRITES = """
    SELECT a.person, a.session, a.sid, a.at, a.dataset AS wds, d.prefix AS wprefix, a.recursive,
           a.expires IS NULL AS instant, COALESCE(a.expires, a.at) AS until
    FROM accesses a JOIN datasets d ON d.id = a.dataset
    WHERE a.kind = 'files' AND a.mode = 'write'
      AND (starts_with(d.prefix, %(prefix)s) OR starts_with(%(prefix)s, d.prefix))"""

# `wds` is the dataset a write was logged for: a writer's declaration of it covers the files
# that write made, and so does a putting back on it (6.5). With %(direct)s, only the files
# directly in the folder count, as for a credential covering those alone.
_CARRIED_SQL = """
WITH f AS (
    SELECT key, last_modified AS lm FROM files WHERE dataset = %(t)s
      AND (NOT %(direct)s OR strpos(substr(key, length(%(prefix)s) + 1), '/') = 0)
), w AS ({writes}
), fw AS (
    SELECT f.lm, w.person, w.session, w.sid, w.at, w.wds FROM f JOIN w
      ON starts_with(f.key, w.wprefix)
     AND (w.recursive OR strpos(substr(f.key, length(w.wprefix) + 1), '/') = 0)
     AND f.lm BETWEEN w.at - %(tol)s * interval '1 second' AND w.until + %(tol)s * interval '1 second'
    UNION ALL
    SELECT LEAST(now(), w.until), w.person, w.session, w.sid, w.at, w.wds FROM w
    LEFT JOIN folder_listings l ON l.dataset = %(t)s
    WHERE %(unlisted)s OR (w.instant AND w.until + %(tol)s * interval '1 second' > l.listed_at)
), brought AS (  -- with each path the source arrived by: [] for the dataset read itself
    SELECT DISTINCT fw.person, fw.lm, fw.wds, s.source, p.path
    FROM fw JOIN accesses r ON r.person = fw.person AND r.mode = 'read'
         AND r.at < fw.lm + %(slack)s * interval '1 second'
         AND (r.session = fw.session OR (r.sid = fw.sid AND r.at >= fw.at))
    CROSS JOIN LATERAL unnest(COALESCE(r.sources, ARRAY[r.dataset])) AS s(source)
    CROSS JOIN LATERAL jsonb_array_elements(COALESCE(r.marks -> s.source, '[[]]'::jsonb)) AS p(path)
), covered AS (  -- each file's source with the writer's declaration covering the file, if any
    SELECT b.source, b.path, b.wds, (
        SELECT max(d.id) FROM declarations d
        WHERE d.person = b.person AND d.target = b.wds AND NOT d.reattach
          AND d.declared_at >= b.lm + %(slack)s * interval '1 second') AS declaration
    FROM brought b WHERE b.source <> %(t)s
)
SELECT c.source, bool_and(c.declaration IS NOT NULL) AS declared, jsonb_agg(DISTINCT c.path) AS paths
FROM covered c
WHERE NOT EXISTS (
    SELECT 1 FROM declared_sources ds JOIN declarations dd ON dd.id = ds.declaration
    WHERE ds.declaration = c.declaration AND ds.source = c.source AND NOT ds.used
      AND NOT EXISTS (
        SELECT 1 FROM declarations r JOIN declared_sources rs ON rs.declaration = r.id
        WHERE r.reattach AND r.target = c.wds AND rs.source = c.source
          AND r.declared_at > dd.declared_at))
GROUP BY c.source ORDER BY 1
"""


def carried(ds_id, direct=False, stored=True):
    """The sources the files in a dataset's folder carry, or with direct only the files directly
    in it, each with whether a declaration says it was used (declared) rather than its being
    there because a writer has not declared yet, and the paths it arrived by, each the datasets
    it passed through, as [{id, declared, paths}]. The answer is stored and reused until
    something it was worked out from changes (_invalidate), except for an entry whose folder is
    unknown, which counts every write as made now; stored=False works it out regardless.
    The folder is listed first if it never has been, if a credential that could write it has
    expired since the last listing, so that what it wrote, or did not, is settled by storage
    even if a notification was lost, or if it is not tracked, since no notification lists it."""
    with db() as cur:
        cur.execute("SELECT prefix FROM datasets WHERE id = %s", (ds_id,))
        row = cur.fetchone()
        location = None
        if row is None and TABLE_ID_RE.match(ds_id):
            cur.execute("SELECT location FROM table_entries WHERE id = %s", (ds_id,))
            location = (cur.fetchone() or {}).get("location")
            prefix, writes, untracked = None, _TABLE_WRITES, False
            folder = _table_folder(location)
        else:
            prefix = row["prefix"] if row else f"datasets/{ds_id}/"
            if not _confined_prefix(prefix):
                return []
            writes, untracked, folder = _FOLDER_WRITES, row is None, prefix
        params = {"t": ds_id, "loc": location, "prefix": prefix, "tol": CLOCK_TOLERANCE,
                  "slack": FILE_TIME_SLACK, "unlisted": folder is None, "direct": direct and prefix is not None}
        cur.execute("SELECT listed_at FROM folder_listings WHERE dataset = %s", (ds_id,))
        listed = cur.fetchone()
        stale = untracked or (listed is None and folder is not None)
        if listed and not stale:
            cur.execute(f"SELECT 1 FROM ({writes}) w WHERE w.until + %(tol)s * interval '1 second' "
                        "> %(listed)s AND w.until < now() LIMIT 1", {**params, "listed": listed["listed_at"]})
            stale = cur.fetchone() is not None
    if stale:
        list_folder(ds_id)
    keep = stored and folder is not None and not untracked
    with db(commit=keep) as cur:
        # The version is read before the sources, so a change committed in between leaves this
        # answer stored under a version that is no longer current.
        cur.execute("SELECT COALESCE((SELECT version FROM sources_version WHERE dataset = %s), 0) AS v", (ds_id,))
        version = cur.fetchone()["v"]
        if keep:
            cur.execute("SELECT sources FROM entry_sources WHERE dataset = %s AND direct = %s AND version = %s",
                        (ds_id, params["direct"], version))
            if row := cur.fetchone():
                return row["sources"]
        cur.execute(_CARRIED_SQL.format(writes=writes), params)
        sources = [{"id": r["source"], "declared": r["declared"], "paths": r["paths"]} for r in cur.fetchall()]
        if keep:
            cur.execute("INSERT INTO entry_sources (dataset, direct, version, sources) VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT (dataset, direct) DO UPDATE SET version = EXCLUDED.version, "
                        "sources = EXCLUDED.sources", (ds_id, params["direct"], version, json.dumps(sources)))
        return sources


# --- Effective grants (docs/HANDOFF-2026-10-22-groups.md sections 1 to 3) ---
# An entry's grants are layers: a published dataset's own, each folder's or namespace's above
# it, and its space's defaults. Governance serves their union; the read API shows each layer.


def _file_space(prefix):
    """The group whose space holds a folder, datasets/<group>/..., whether or not it exists."""
    return prefix.split("/")[1]


def _table_space(name):
    """The group whose space holds a namespace or a table, <catalog>.<group>..., or None."""
    parts = name.split(".")
    return parts[1] if len(parts) > 1 else None


def _parent(table_id):
    return table_id.rsplit(".", 1)[0]


def _spaces(cur, names):
    """{group: its space's default grants} for each of these names that is a group: `describe`
    and `read` for everyone in it, `write` for its members and above, `delete` for its admins,
    `manage` for its stewards."""
    cur.execute("SELECT name FROM groups WHERE name = ANY(%s)", (sorted(n for n in names if n),))
    return {r["name"]: {"describe": [r["name"]], "read": [r["name"]], "write": [r["name"]],
                        "delete": [f"{r['name']}#admin"], "manage": [f"{r['name']}#steward"],
                        "detach": [], "revoked": []}
            for r in cur.fetchall()}


def _grants_of(row, read_col="read"):
    return {g: sorted(row[read_col if g == "read" else g]) for g in GRANTS}


def _union(layers):
    """Every name any layer grants, per grant. An inherited `detach` narrows: the union is empty
    only when every layer's is."""
    return {g: sorted({n for _, grants in layers for n in grants[g]}) for g in GRANTS}


def _folder_layers(cur, items):
    """{id: [(where, grants)]} for folders, items [(id, prefix, own grants or None)]: the
    folder's own grants when it is a published dataset (where "own"), those of each folder above
    it, nearest first (where its prefix), and its space's defaults (where "space"). A folder's
    grants reach the entries under it, not one at the folder itself, whose own grants are set by
    publishing it: unpublished data is reached through the folders above it alone."""
    prefixes = sorted({p for _, p, _ in items})
    cur.execute(f"SELECT prefix, {_GRANT_SQL} FROM folder_grants "
                "WHERE EXISTS (SELECT 1 FROM unnest(%s::text[]) p WHERE starts_with(p, prefix) "
                "AND p <> prefix)", (prefixes,))
    folders = sorted(cur.fetchall(), key=lambda f: -len(f["prefix"]))
    spaces = _spaces(cur, {_file_space(p) for p in prefixes})
    out = {}
    for i, prefix, own in items:
        layers = [("own", own)] if own else []
        layers += [(f["prefix"], _grants_of(f)) for f in folders
                   if prefix.startswith(f["prefix"]) and prefix != f["prefix"]]
        if _file_space(prefix) in spaces:
            layers.append(("space", spaces[_file_space(prefix)]))
        out[i] = layers
    return out


def _namespace_layers(cur, names):
    """{namespace id: ([(where, grants)], the nearest published namespace at or above it, or
    None)}: the grants of the namespace and of each one above it, nearest first, its space's
    defaults, and the describe and read of each collection holding a published one of them."""
    cur.execute(f"SELECT id, description, published, published_by, {_GRANT_SQL} FROM namespaces "
                "WHERE EXISTS (SELECT 1 FROM unnest(%s::text[]) n "
                "WHERE n = id OR starts_with(n, id || '.'))", (sorted(set(names)),))
    rows = sorted(cur.fetchall(), key=lambda r: -len(r["id"]))
    spaces = _spaces(cur, {_table_space(n) for n in names})
    held = _collection_layers(cur, [r["id"] for r in rows if r["published"]])
    out = {}
    for n in names:
        above = [r for r in rows if n == r["id"] or n.startswith(r["id"] + ".")]
        layers = [(r["id"], _grants_of(r)) for r in above]
        layers += [l for r in above for l in held.get(r["id"], [])]
        if _table_space(n) in spaces:
            layers.append(("space", spaces[_table_space(n)]))
        out[n] = (layers, next((r for r in above if r["published"]), None))
    return out


# Every collection holding each of these members, directly or through other collections, with
# its own describe and read.
_UP_SQL = """
WITH RECURSIVE up(member, collection) AS (
    SELECT member, collection FROM collection_members WHERE member = ANY(%s)
    UNION
    SELECT up.member, cm.collection FROM up JOIN collection_members cm ON cm.member = up.collection
)
SELECT up.member, c.id, c.describe, c.read FROM up JOIN collections c ON c.id = up.collection
"""


def _collection_layers(cur, members):
    """{member: [(where, grants)]}: for each published folder, published namespace or collection,
    the `describe` and `read` of every collection holding it, directly or through others, each
    as a layer (where "collection <id>") with no other grant (docs/HANDOFF-2026-10-22-groups.md
    section 5)."""
    cur.execute(_UP_SQL, (sorted(set(members)),))
    out = {}
    for r in cur.fetchall():
        out.setdefault(r["member"], []).append(
            (f"collection {r['id']}", {**{g: [] for g in GRANTS}, "describe": sorted(r["describe"]),
                                       "read": sorted(r["read"])}))
    return {m: sorted(ls, key=lambda l: l[0]) for m, ls in out.items()}


_DATASET_SQL = (f"SELECT id, prefix, description, steward, published, status, moved_to, {_DATASET_GRANT_SQL} "
                "FROM datasets WHERE id = ANY(%s)")


def _tenants(cur, names):
    """The names among these that are groups with a steward."""
    cur.execute("SELECT DISTINCT grp FROM group_members WHERE steward AND grp = ANY(%s)", (sorted(n for n in names if n),))
    return {r["grp"] for r in cur.fetchall()}


def _file_entries(ids, would_be=False):
    """({id: entry}, {id: layers}) for file dataset ids: each tracked folder and, with would_be,
    each untracked folder in a group's space (`tracked` false), which its first credential will
    make an entry. An entry has its effective grants (`access` for read, as stored), its space,
    whether it is published, and the published datasets it sits inside or contains, since no
    credential for it may reach one (handoff section 3). Without sources."""
    with db() as cur:
        cur.execute(_DATASET_SQL, (ids,))
        rows = {r["id"]: r for r in cur.fetchall()}
        items = [(i, r["prefix"], _grants_of(r, "access") if r["published"] else None) for i, r in rows.items()]
        if would_be:
            items += [(i, f"datasets/{i}/", None) for i in ids
                      if i not in rows and _confined_prefix(f"datasets/{i}/")]
        layers = _folder_layers(cur, items)
        # A published folder in a collection also has the collection's describe and read.
        held = _collection_layers(cur, [i for i, _, own in items if own is not None])
        layers = {i: ls + held.get(i, []) for i, ls in layers.items()}
        cur.execute("SELECT id, prefix FROM datasets WHERE published")
        published = cur.fetchall()
        cur.execute("SELECT id, prefix FROM datasets WHERE status = 'moved'")
        moved = cur.fetchall()
        tenants = _tenants(cur, {_file_space(p) for _, p, _ in items})
    entries = {}
    for i, prefix, _ in items:
        if i not in rows and not any(where == "space" for where, _ in layers[i]):
            continue
        eff = _union(layers[i])
        entries[i] = {"id": i, "prefix": prefix, "tracked": i in rows,
                      "published": i in rows and rows[i]["published"], "space": _file_space(prefix),
                      "tenant": _file_space(prefix) in tenants,
                      "status": rows[i]["status"] if i in rows else None,
                      "moved_to": rows[i]["moved_to"] if i in rows else None,
                      "inside_moved": sorted(m["id"] for m in moved
                                             if prefix.startswith(m["prefix"]) and prefix != m["prefix"]),
                      **{("access" if g == "read" else g): eff[g] for g in GRANTS},
                      "inside_published": sorted(p["id"] for p in published
                                                 if prefix.startswith(p["prefix"]) and prefix != p["prefix"]),
                      "contains_published": sorted(p["id"] for p in published
                                                   if p["prefix"].startswith(prefix) and prefix != p["prefix"])}
    return entries, layers


def _table_entries(ids, would_be=False):
    """({id: entry}, {id: layers}) for table ids: each table with an entry and, with would_be,
    any other table id whose namespace has grants, the one allow_create decides on (status
    None). A table has no grants of its own: its effective grants are its namespaces' and its
    space's, and it is published when a namespace at or above it is. Without sources."""
    with db() as cur:
        cur.execute("SELECT id, status, location, moved_to FROM table_entries WHERE id = ANY(%s)", (ids,))
        rows = {r["id"]: r for r in cur.fetchall()}
        wanted = [i for i in ids if i in rows or (would_be and TABLE_ID_RE.match(i))]
        ns = _namespace_layers(cur, [_parent(i) for i in wanted]) if wanted else {}
        tenants = _tenants(cur, {_table_space(i) for i in wanted})
    entries, layers = {}, {}
    for i in wanted:
        layers[i], pub = ns[_parent(i)]
        if i not in rows and not layers[i]:
            continue
        entries[i] = {"id": i, "status": rows[i]["status"] if i in rows else None, "space": _table_space(i),
                      "tenant": _table_space(i) in tenants,
                      "moved_to": rows[i]["moved_to"] if i in rows else None,
                      "published": pub is not None, "namespace": _parent(i),
                      "description": pub["description"] if pub else None,
                      "steward": pub["published_by"] if pub else None, **_union(layers[i])}
    return entries, layers


def _collection_entries(ids):
    """{id: entry} for collections: their own grants, with `describe` and `read` also those of
    every collection holding them, the owning group, and their members as [{id, kind}]."""
    with db() as cur:
        cur.execute(f"SELECT id, owner, description, {_COLLECTION_GRANT_SQL} FROM collections WHERE id = ANY(%s)",
                    (list(ids),))
        rows = {r["id"]: r for r in cur.fetchall()}
        held = _collection_layers(cur, list(rows))
        cur.execute("SELECT collection, member, member_kind FROM collection_members WHERE collection = ANY(%s) "
                    "ORDER BY member", (list(rows),))
        members = {}
        for m in cur.fetchall():
            members.setdefault(m["collection"], []).append({"id": m["member"], "kind": m["member_kind"]})
    out = {}
    for i, r in rows.items():
        own = {g: sorted(r[g]) for g in COLLECTION_GRANTS}
        out[i] = {"id": i, "owner": r["owner"], "description": r["description"], **own,
                  "describe": sorted({*own["describe"], *(n for _, l in held.get(i, []) for n in l["describe"])}),
                  "read": sorted({*own["read"], *(n for _, l in held.get(i, []) for n in l["read"])}),
                  "members": members.get(i, [])}
    return out


def _effective(ids):
    """{id: effective grants, `read` by that name} for the ids that have an entry, file datasets
    and tables alike."""
    with db() as cur:
        cur.execute("SELECT id FROM datasets WHERE id = ANY(%s)", (list(ids),))
        files = [r["id"] for r in cur.fetchall()]
    out = {i: {**e, "read": e["access"]} for i, e in _file_entries(files)[0].items()}
    tables = [i for i in ids if i not in out and TABLE_ID_RE.match(i)]
    out.update(_table_entries(tables)[0] if tables else {})
    return out


def _source_read(ids):
    """{id: {read, revoked}}: each source's effective `read`, a table's `write` included, as rule
    3 checks it (PROVENANCE.md 6), and its effective `revoked`. A source that moved is looked up
    as the entry it moved to, so data built from the old folder or table is checked against the
    new one's grants (docs/HANDOFF-2026-10-22-groups.md section 1). A source with no entry is
    absent and admits no one."""
    found = _effective(ids)
    final = {}
    for i in list(found):
        j, seen = i, set()
        while found.get(j, {}).get("status") == "moved" and found[j].get("moved_to") and j not in seen:
            seen.add(j)
            j = found[j]["moved_to"]
            if j not in found:
                found.update(_effective([j]))
        final[i] = found.get(j)
    return {i: {"read": sorted(set(e["read"]) | (set(e["write"]) if TABLE_ID_RE.match(i) else set())),
                "revoked": e["revoked"]}
            for i, e in final.items() if e is not None}


def _released(target, sources):
    """{source: [[group]]}: for each carried source, one list per path it arrived by, of the
    groups an approved release not withdrawn lets past it, made on this target or on a dataset
    that path passed through (PROVENANCE.md 6.7)."""
    with db() as cur:
        cur.execute("SELECT target, source, grp FROM releases WHERE source = ANY(%s) AND approved "
                    "AND withdrawn_at IS NULL", ([c["id"] for c in sources],))
        active = {}
        for r in cur.fetchall():
            active.setdefault((r["source"], r["target"]), set()).add(r["grp"])
    return {c["id"]: [sorted(set().union(*(active.get((c["id"], d), set()) for d in {*path, target})))
                      for path in c["paths"]]
            for c in sources}


def _with_sources(ds_id, entry, direct=False):
    """The entry with the sources its files carry, or with direct those directly in its folder:
    each source's effective `read`, whether a declaration says it was used, and the groups
    released past it on each path it arrived by. OPA's rules decide what they mean
    (PROVENANCE.md 6, rule 3); a source with no entry has no grants, so it admits no one."""
    sources = carried(ds_id, direct)
    read = _source_read([c["id"] for c in sources])
    released = _released(ds_id, sources)
    return {**entry, "sources": [{"id": c["id"], "declared": c["declared"], "released": released[c["id"]],
                                  **read.get(c["id"], {"read": [], "revoked": []})} for c in sources]}


def reconcile(ds_id):
    """The ONLY writer of `status`: set one dataset live or gone from whether its folder holds
    anything, from a listing that also records its files (list_folder). Storage is the truth here; grants are untouched, so reconcile never moves OPA.
    There is no periodic sweep: each bucket notification triggers this for the dataset it
    names, and the notification topic is persistent (rgw_setup.py), so a check that fails here
    raises and the event is delivered again."""
    with db() as cur:
        cur.execute("SELECT prefix FROM datasets WHERE id = %s", (ds_id,))
        row = cur.fetchone()
    if row is None:
        return
    nonempty = list_folder(ds_id)
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
    # {id: entry} for the named folders: each tracked one, and each untracked one in a group's
    # space, which a first credential would make an entry (_file_entries); any other id is
    # absent. Each with the sources its files carry, or with "recursive": false the files
    # directly in it, which is what a credential for those alone reaches.
    body = request.get_json(silent=True) or {}
    ids, recursive = body.get("ids"), body.get("recursive", True)
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids) or not isinstance(recursive, bool):
        return jsonify({"error": "ids must be a list of strings"}), 400
    entries, _ = _file_entries(ids, would_be=True)
    return jsonify({"entries": {i: _with_sources(i, e, direct=not recursive) for i, e in entries.items()}})


@internal_app.post("/internal/folders")
def internal_folders():
    # {id: {id, prefix, space, grants}} for folders in a group's space, named as dataset ids
    # are: the grants of the folder itself and of the folders above it, and its space's, which
    # decide who may change the folder's grants. Any other id is absent.
    if (ids := _ids_from_body()) is None:
        return jsonify({"error": "ids must be a list of strings"}), 400
    items = [(i, f"datasets/{i}/") for i in ids if _confined_prefix(f"datasets/{i}/")]
    with db() as cur:
        layers = _folder_layers(cur, [(i, p, None) for i, p in items])
        cur.execute(f"SELECT prefix, {_GRANT_SQL} FROM folder_grants WHERE prefix = ANY(%s)",
                    ([p for _, p in items],))
        own = {r["prefix"]: _grants_of(r) for r in cur.fetchall()}
    entries = {i: {"id": i, "prefix": p, "space": _file_space(p),
                   **_union(([(p, own[p])] if p in own else []) + layers[i])}
               for i, p in items if any(where == "space" for where, _ in layers[i])}
    return jsonify({"entries": entries})


@internal_app.post("/internal/collections")
def internal_collections():
    # {id: entry} for the named collections (_collection_entries); an unknown id is absent.
    if (ids := _ids_from_body()) is None:
        return jsonify({"error": "ids must be a list of strings"}), 400
    return jsonify({"entries": _collection_entries(ids)})


@internal_app.get("/internal/groups/<subject>")
def internal_groups(subject):
    # The names the subject holds grants through, and their personal space, whose own copies rule
    # 3 does not cut (PROVENANCE.md 9).
    with db() as cur:
        read, write = _group_names(cur, subject)
    return jsonify({"groups": read, "write_groups": write, "personal": _personal(subject) or ""})


def _ids_from_body():
    ids = (request.get_json(silent=True) or {}).get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        return None
    return ids


@internal_app.get("/internal/tables/<table_id>")
def internal_table(table_id):
    # A table's effective grants and sources, or those a table of that id would have, which
    # allow_create decides on (status null); 404 for an id with no grants anywhere, so its
    # rules deny.
    entries, _ = _table_entries([table_id], would_be=True)
    if table_id not in entries:
        return jsonify({"error": "not found"}), 404
    return jsonify(_with_sources(table_id, entries[table_id])), 200


@internal_app.post("/internal/tables")
def internal_tables():
    if (ids := _ids_from_body()) is None:
        return jsonify({"error": "ids must be a list of strings"}), 400
    entries, _ = _table_entries(ids)
    return jsonify({"entries": {i: _with_sources(i, e) for i, e in entries.items()}})


@internal_app.post("/internal/namespaces")
def internal_namespaces():
    # {id: {id, space, published, the six grants, below}}: a namespace's effective grants (its
    # own, those above it, its space's), and in `below` the names holding describe, read or
    # write on some namespace under it, so that a person can reach what they were granted
    # deeper down. Ids are compared with starts_with, not LIKE, so "_" and "%" in a name are
    # plain characters.
    if (ids := _ids_from_body()) is None:
        return jsonify({"error": "ids must be a list of strings"}), 400
    entries = {}
    with db() as cur:
        ns = _namespace_layers(cur, ids)
        for i in ids:
            cur.execute("SELECT DISTINCT unnest(describe || read || write) AS n FROM namespaces "
                        "WHERE starts_with(id, %s || '.')", (i,))
            below = sorted(r["n"] for r in cur.fetchall())
            layers, pub = ns[i]
            entries[i] = {"id": i, "space": _table_space(i), "published": pub is not None,
                          **_union(layers), "below": below}
    return jsonify({"entries": entries})


@internal_app.post("/internal/table-events")
def table_events():
    # The gate's report that Polaris created or dropped a table: created makes the table's entry,
    # or makes it live again with its new folder, dropped sets it gone.
    body = request.get_json(silent=True) or {}
    table_id, event = body.get("id"), body.get("event")
    if not isinstance(table_id, str) or not TABLE_ID_RE.match(table_id) or event not in ("created", "dropped"):
        return jsonify({"error": "id and event (created|dropped) required"}), 400
    with db(commit=True) as cur:
        if event == "created":
            cur.execute("INSERT INTO table_entries (id, status, location) VALUES (%s, 'live', %s) "
                        "ON CONFLICT (id) DO UPDATE SET status = 'live', moved_to = NULL, "
                        "location = COALESCE(EXCLUDED.location, table_entries.location) RETURNING id",
                        (table_id, body.get("location")))
        else:   # a table moved and then dropped keeps the record of its move
            cur.execute("UPDATE table_entries SET status = CASE WHEN status = 'moved' THEN 'moved' "
                        "ELSE 'gone' END WHERE id = %s RETURNING id", (table_id,))
        changed = cur.fetchone() is not None
        _invalidate(cur, [table_id])
    app.logger.info("TABLE %s %s%s", event, table_id, "" if changed else " (no entry; ignored)")
    return jsonify({"ok": True, "changed": changed})


def _brought(ds_id, direct=False):
    """What a read of this dataset brings in (PROVENANCE.md 6, rule 1): the dataset and what its
    files carry, and for each carried source the datasets it arrived through on each path, this
    one and those the path had passed (6.7), as (sources, marks)."""
    sources = carried(ds_id, direct)
    return ([ds_id, *(c["id"] for c in sources)],
            json.dumps({c["id"]: [list(p) for p in sorted({tuple(sorted({*path, ds_id})) for path in c["paths"]})]
                        for c in sources}))


@internal_app.post("/internal/transfers")
def internal_transfers():
    # The broker's move of a folder into another group's space (docs/HANDOFF-2026-10-22-groups.md
    # section 1), once OPA's allow_transfer has decided, in two phases.
    #   begin {person, sub, sid, from, to, expires}: the destination must have no entry or an empty
    #     unpublished one, hold nothing in storage, and neither sit in nor hold a published
    #     dataset, or the move would publish without a steward; the old folder must not have
    #     moved. Governance lists the old folder, records the transfer, makes the destination's
    #     entry, and logs, in a session of the person's own for this transfer, a read of the old
    #     folder and a write of the new one until expires, under a login id of the transfer's, so
    #     the copies carry what the old folder carried (rule 2) and nothing else the person read.
    #     Answers {transfer, files: [{key, etag}]}: the files that listing found, which are all the
    #     broker copies, each only while its ETag still matches, so a file written into the old
    #     folder after the listing is never copied with less than it carries.
    #   done {transfer}: once every file is copied and before the originals are deleted, the old
    #     entry is moved to the new one and the write ends now; refused, and the broker removes its
    #     copies, if the broker's credential has expired or a dataset in or around either folder
    #     was published meanwhile.
    body = request.get_json(silent=True) or {}
    if body.get("phase") == "done":
        with db(commit=True) as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (PUBLISH_LOCK_KEY,))
            cur.execute("SELECT from_id, to_id, session FROM transfers WHERE id = %s AND kind = 'files' "
                        "AND done_at IS NULL AND expires > now() FOR UPDATE", (body.get("transfer"),))
            t = cur.fetchone()
            if t is None:
                return jsonify({"error": "no such transfer under way"}), 404
            cur.execute("SELECT id FROM datasets WHERE published AND EXISTS (SELECT 1 FROM unnest(%s::text[]) p "
                        "WHERE starts_with(prefix, p) OR starts_with(p, prefix)) LIMIT 1",
                        ([f"datasets/{t['from_id']}/", f"datasets/{t['to_id']}/"],))
            if cur.fetchone():
                return jsonify({"error": "a dataset in or around the folders was published"}), 409
            cur.execute("UPDATE transfers SET done_at = now() WHERE id = %s", (body.get("transfer"),))
            cur.execute("UPDATE datasets SET status = 'moved', moved_to = %s WHERE id = %s", (t["to_id"], t["from_id"]))
            cur.execute("UPDATE accesses SET expires = now() WHERE session = %s AND mode = 'write'", (t["session"],))
            _invalidate(cur, [t["from_id"], t["to_id"]])
        reconcile(t["to_id"])
        list_folder(t["from_id"])
        app.logger.info("TRANSFER done %s -> %s", t["from_id"], t["to_id"])
        return jsonify({"ok": True})
    src, dst = body.get("from"), body.get("to")
    if (body.get("phase") != "begin" or not all(isinstance(body.get(k), str) for k in ("person", "sub", "sid"))
            or not all(isinstance(f, str) and _confined_prefix(f"datasets/{f}/") for f in (src, dst))
            or not isinstance(body.get("expires"), int)):
        return jsonify({"error": "begin {person, sub, sid, from, to, expires} or done {transfer}"}), 400
    entries, _ = _file_entries([src, dst], would_be=True)
    if (src not in entries or not entries[src]["tracked"] or entries[src]["status"] == "moved"
            or entries[src]["published"] or entries[src]["inside_published"] or entries[src]["contains_published"]
            or entries[src]["inside_moved"]):
        return jsonify({"error": f"{src} cannot be moved: it has moved, is published, or sits in or holds a "
                                 "published dataset"}), 409
    if dst in entries and (entries[dst]["tracked"] and entries[dst]["status"] != "gone"
                           or entries[dst]["published"] or entries[dst]["inside_published"]
                           or entries[dst]["contains_published"] or entries[dst]["inside_moved"]):
        return jsonify({"error": f"{dst} exists, is published, or sits in or holds a published dataset"}), 409
    if _s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"datasets/{dst}/", MaxKeys=1).get("KeyCount"):
        return jsonify({"error": f"{dst} exists, is published, or sits in or holds a published dataset"}), 409
    # Listed now, so the copies carry what every file in it carries, a file written moments ago
    # included; the broker copies these files and no others.
    found = _listing(f"datasets/{src}/")
    list_folder(src, found)
    brought, marks = _brought(src)
    with db(commit=True) as cur:
        # Under the publishing lock, so a dataset published in or around either folder since the
        # check above is seen, and none can be published there until the transfer ends.
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (PUBLISH_LOCK_KEY,))
        cur.execute("SELECT id FROM datasets WHERE published AND EXISTS (SELECT 1 FROM unnest(%s::text[]) p "
                    "WHERE starts_with(prefix, p) OR starts_with(p, prefix)) LIMIT 1",
                    ([f"datasets/{src}/", f"datasets/{dst}/"],))
        if cur.fetchone():
            return jsonify({"error": f"a dataset in or around {src} or {dst} is published"}), 409
        cur.execute("INSERT INTO transfers (kind, from_id, to_id, by, expires) "
                    "VALUES ('files', %s, %s, %s, to_timestamp(%s / 1000.0)) RETURNING id",
                    (src, dst, body["person"], body["expires"]))
        tid = cur.fetchone()["id"]
        cur.execute("INSERT INTO sessions (person, name) VALUES (%s, %s) RETURNING id",
                    (body["person"], f"transfer {tid}: {src} -> {dst}"))
        session = cur.fetchone()["id"]
        cur.execute("UPDATE transfers SET session = %s WHERE id = %s", (session, tid))
        cur.execute("INSERT INTO datasets (id, prefix, created_by) VALUES (%s, %s, %s) ON CONFLICT (id) DO NOTHING",
                    (dst, f"datasets/{dst}/", body["person"]))
        for dataset, mode, sources, m in ((src, "read", brought, marks), (dst, "write", None, None)):
            cur.execute("INSERT INTO accesses (person, sub, sid, session, dataset, kind, mode, expires, sources, marks) "
                        "VALUES (%s, %s, %s, %s, %s, 'files', %s, to_timestamp(%s / 1000.0), %s, %s)",
                        (body["person"], body["sub"], f"transfer:{tid}", session, dataset, mode, body["expires"],
                         sources, m))
        _invalidate(cur, [src, dst])
    app.logger.info("TRANSFER begin %s %s -> %s (%s)", tid, src, dst, body["person"])
    return jsonify({"transfer": tid, "files": [{"key": k, "etag": e} for k, _, e in found]})


def _engine_table(ref):
    """A table id from an event's {catalogName, schema, table}, or None for one outside the
    catalogs governance knows, or in the governance namespace, which the gate answers itself."""
    if not isinstance(ref, dict) or ref.get("catalogName") not in ENGINE_CATALOGS:
        return None
    schema, table = ref.get("schema"), ref.get("table")
    if not isinstance(schema, str) or not isinstance(table, str) or schema.split(".")[0] == "governance":
        return None
    tid = f"{ENGINE_CATALOGS[ref['catalogName']]}.{schema}.{table}"
    return tid if TABLE_ID_RE.match(tid) else None


def _instant(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if isinstance(v, str) else None


@internal_app.post("/internal/drafts")
def internal_drafts():
    # A completed statement from Trino's HTTP event listener (QueryCompletedEvent), which knows
    # Trino by its client certificate. A statement that read or wrote a table is kept if the
    # access log bears it out: a statement that wrote a table needs the person's write of it,
    # logged by the gate within the statement's time, which gives its session; every table it
    # read needs the person's read of it, logged in that session (or, for a statement that
    # wrote nothing, within its time). Anything else is dropped and logged: an engine speaks
    # only about reads the log shows it made. Always answers 200 for an event it understood,
    # so the listener does not send it again.
    ev = request.get_json(silent=True) or {}
    meta, ctx, io = ev.get("metadata") or {}, ev.get("context") or {}, ev.get("ioMetadata") or {}
    person, sid = ctx.get("user"), meta.get("queryId")
    started, ended = _instant(ev.get("createTime")), _instant(ev.get("endTime"))
    if not all(isinstance(v, str) for v in (person, sid)) or started is None or ended is None:
        return jsonify({"error": "not a completed-statement event"}), 400
    if meta.get("queryState") != "FINISHED":
        return jsonify({"ok": True, "kept": False})
    target = _engine_table(io.get("output"))
    inputs = sorted({t for t in (_engine_table(i) for i in io.get("inputs") or []) if t and t != target})
    if not inputs and target is None:
        return jsonify({"ok": True, "kept": False})
    window = {"p": person, "from": started - timedelta(seconds=CLOCK_TOLERANCE),
              "to": ended + timedelta(seconds=CLOCK_TOLERANCE)}
    with db(commit=True) as cur:
        if target is not None:
            cur.execute("SELECT session FROM accesses WHERE person = %(p)s AND dataset = %(t)s AND mode = 'write' "
                        "AND at BETWEEN %(from)s AND %(to)s ORDER BY at DESC LIMIT 1", {**window, "t": target})
        else:
            cur.execute("SELECT session FROM accesses WHERE person = %(p)s AND dataset = ANY(%(i)s) AND mode = 'read' "
                        "AND at BETWEEN %(from)s AND %(to)s ORDER BY at DESC LIMIT 1", {**window, "i": inputs})
        row = cur.fetchone()
        if row is None:
            app.logger.info("DRAFT drop %s %s: no logged %s in its time", person, sid,
                            "write of " + target if target else "read")
            return jsonify({"ok": True, "kept": False})
        session = row["session"]
        cur.execute("SELECT DISTINCT dataset FROM accesses WHERE person = %s AND session = %s AND mode = 'read' "
                    "AND dataset = ANY(%s) AND at <= %s", (person, session, inputs, window["to"]))
        if unread := sorted(set(inputs) - {r["dataset"] for r in cur.fetchall()}):
            app.logger.info("DRAFT drop %s %s: reads the log does not show: %s", person, sid, ", ".join(unread))
            return jsonify({"ok": True, "kept": False})
        cur.execute("INSERT INTO engine_statements (engine, statement_id, person, session, target, inputs, to_client, "
                    "started, ended, event) VALUES ('trino', %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (engine, statement_id) DO NOTHING",
                    (sid, person, session, target, inputs, target is None, started, ended, json.dumps(ev)))
    app.logger.info("DRAFT keep %s %s -> %s from %s", person, sid, target or "client", ", ".join(inputs) or "nothing")
    return jsonify({"ok": True, "kept": True})


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
                    and e.get("kind") in ("files", "table") and e.get("mode") in ("read", "write", "delete")
                    and (e.get("expires") is None or isinstance(e["expires"], int))
                    and isinstance(e.get("can_write", False), bool) and isinstance(e.get("recursive", True), bool)
                    and (e.get("location") is None or isinstance(e["location"], str))
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
    _ensure_personal(body["person"])
    # A folder is an entry from its first credential (docs/HANDOFF-2026-10-22-groups.md section
    # 3), read or write: a read must bring in what the folder's files carry, which only a tracked
    # folder's listing keeps up to date. The broker asks only after OPA allowed the credential.
    new = [e["dataset"] for e in body["entries"] if e["kind"] == "files"
           and _confined_prefix(f"datasets/{e['dataset']}/")]
    if new:
        with db(commit=True) as cur:
            cur.execute("INSERT INTO datasets (id, prefix, created_by) SELECT i, 'datasets/' || i || '/', %s "
                        "FROM unnest(%s::text[]) i ON CONFLICT (id) DO NOTHING RETURNING id",
                        (body["person"], new))
            new = [r["id"] for r in cur.fetchall()]
        for ds in new:
            reconcile(ds)
            app.logger.info("TRACK %s (first credential, %s)", ds, body["person"])
    # A read keeps the sources it brought in: the dataset and what its files carry now (rule 1),
    # and, for each carried source, the datasets it arrived through on each path: this one and
    # those the path had passed (6.7).
    brought, marks = {}, {}
    for i, e in enumerate(body["entries"]):
        brought[i], marks[i] = (_brought(e["dataset"], direct=not e.get("recursive", True))
                                if e["mode"] == "read" else (None, None))
    with db(commit=True) as cur:
        session = _pointer(cur, body["person"], body["sid"], create=True)
        for i, e in enumerate(body["entries"]):
            cur.execute("INSERT INTO accesses (person, sub, sid, session, dataset, kind, mode, expires, "
                        "sources, can_write, marks, location, recursive) VALUES (%s, %s, %s, %s, %s, %s, %s, "
                        "to_timestamp(%s / 1000.0), %s, %s, %s, %s, %s)",
                        (body["person"], body["sub"], body["sid"], session, e["dataset"], e["kind"],
                         e["mode"], e.get("expires"), brought[i], e.get("can_write", False), marks[i],
                         e.get("location"), e.get("recursive", True)))
        _invalidate(cur, [e["dataset"] for e in body["entries"] if e["mode"] == "write" or e.get("can_write")])
        if any(e["mode"] == "read" for e in body["entries"]):
            _invalidate_writes_of(cur, body["person"])
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
    registry = _folders()   # once, not once per record
    with db() as cur:
        cur.execute("SELECT id FROM datasets")
        file_datasets = {r["id"] for r in cur.fetchall()}
    touched = set()
    for rec in records:
        key = rec.get("s3", {}).get("object", {}).get("key", "")
        app.logger.info("EVENT %s key=%s", rec.get("eventName", "?"), key)
        # Every folder the key falls under: a nested or overlapping folder must be listed too.
        matches = {i for i, prefix in registry if key.startswith(prefix)}
        if matches:
            touched |= matches
        else:
            app.logger.info("EVENT key=%s is ungoverned (no registered dataset)", key)
    try:
        for ds in touched:
            # A file dataset's status follows its folder; a table's comes from the gate.
            reconcile(ds) if ds in file_datasets else list_folder(ds)
    except Exception as e:  # noqa: BLE001 — RGW redelivers on a non-2xx answer
        app.logger.warning("/events: check failed, asking RGW to redeliver: %s", e)
        return jsonify({"error": "check failed"}), 503
    return jsonify({"ok": True, "received": len(records), "reconciled": sorted(touched)})


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
    _ensure_personal(subject)
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


# What each kind of grant change names and where its grants are stored: a published dataset's
# own (`read` stored as `access`), a folder's, a namespace's. A table has none of its own.
_GRANT_COLS = {"dataset": ("datasets", "id", {g: ("access" if g == "read" else g) for g in GRANTS}),
               "folder": ("folder_grants", "prefix", {g: g for g in GRANTS}),
               "namespace": ("namespaces", "id", {g: g for g in GRANTS})}


def _valid_changes(changes):
    return isinstance(changes, list) and changes and all(
        isinstance(c, dict) and isinstance(c.get("group"), str) and GRANTEE_RE.match(c["group"])
        and set(c) <= {"group", "add", "remove"}
        and all(isinstance(c.get(k, []), list) and set(c.get(k, [])) <= set(GRANTS) for k in ("add", "remove"))
        for c in changes)


@app.patch("/permissions/<kind>/<path:entry_id>")
def change_permissions(kind, entry_id):
    # Change which groups hold which grants on a published dataset, a folder or a namespace
    # (docs/HANDOFF-2026-10-22-groups.md sections 1 to 3). The body follows Unity Catalog's
    # permissions API: {"changes": [{"group": g, "add": [grant], "remove": [grant]}]}. authZ =
    # OPA's allow_change for the kind over every grant the changes name (WHITEPAPER 4.4):
    # `describe` and `read` by holders of `manage`, the others by a steward of the group whose
    # space holds it. It is asked while this transaction holds a lock on what it changes, so
    # the grants OPA fetches are the ones this write replaces. An unknown or unpublished dataset
    # is refused as a denied change is. OPA's lookups into /internal/* during that decision
    # borrow pool connections too, so beyond POOL_MAX concurrent changes a lookup times out and
    # the change is refused rather than deadlocking.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    if kind == "table":
        return jsonify({"error": "a table's grants are its namespace's: change "
                                 "/permissions/namespace/<namespace>"}), 400
    if kind not in _GRANT_COLS:
        return jsonify({"error": "not found"}), 404
    changes = (request.get_json(silent=True) or {}).get("changes")
    if not _valid_changes(changes):
        return jsonify({"error": "changes must be [{group, add: [grant], remove: [grant]}] "
                                 f"with grants from {sorted(GRANTS)}"}), 400
    named = sorted({g for c in changes for k in ("add", "remove") for g in c.get(k, [])})
    if not named:
        return jsonify({"error": "changes name no grant"}), 400
    table, key_col, cols = _GRANT_COLS[kind]
    key = {"dataset": entry_id, "folder": f"datasets/{entry_id}/", "namespace": entry_id}[kind]
    if (kind == "folder" and not _confined_prefix(key)) or (kind == "namespace" and not NAMESPACE_RE.match(key)):
        return jsonify({"error": "not found"}), 404
    if _is_personal(_table_space(key) if kind == "namespace" else entry_id.split("/")[0]):
        return jsonify({"error": "a personal space is granted to no one else; transfer it to share it"}), 403
    rule, package, inp = {"dataset": ("allow_change", "blob", {"dataset": entry_id}),
                          "folder": ("allow_change_folder", "blob", {"folder": entry_id}),
                          "namespace": ("allow_change", "tables", {"id": entry_id})}[kind]
    col_sql = ", ".join(f'"{c}"' for c in cols.values())
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"grants:{kind}:{key}",))
        cur.execute(f"SELECT {col_sql}{', published' if kind == 'dataset' else ''} FROM {table} "
                    f"WHERE {key_col} = %s", (key,))
        row = cur.fetchone()
        allowed = opa(rule, {"subject": subject, **inp, "grants": named,
                             "platform_admin": platform_admin(claims)}, package=package) is True
        if not allowed or (kind == "dataset" and not (row and row["published"])):
            app.logger.info("DENY change subject=%s %s=%s grants=%s", subject, kind, entry_id, named)
            return jsonify({"error": "forbidden"}), 403
        sets = {g: set(row[c]) if row else set() for g, c in cols.items()}
        for c in changes:
            for g in c.get("add", []):
                sets[g].add(c["group"])
            for g in c.get("remove", []):
                sets[g].discard(c["group"])
        values = [sorted(sets[g]) for g in cols]
        if kind == "dataset":
            cur.execute(f"UPDATE {table} SET " + ", ".join(f'"{c}" = %s' for c in cols.values())
                        + f" WHERE {key_col} = %s", values + [key])
        else:   # a folder's or namespace's grants are a row of their own, made on first change
            cur.execute(f"INSERT INTO {table} ({key_col}, {col_sql}) VALUES (%s{', %s' * len(cols)}) "
                        f"ON CONFLICT ({key_col}) DO UPDATE SET "
                        + ", ".join(f'"{c}" = EXCLUDED."{c}"' for c in cols.values()), [key] + values)
        # Who added each group to `revoked`, and who took it out (PROVENANCE.md 9).
        for c in changes:
            if "revoked" in c.get("add", []) and c["group"] not in (row["revoked"] if row else []):
                cur.execute("INSERT INTO revocations (kind, entry, grp, added_by) VALUES (%s, %s, %s, %s)",
                            (kind, key, c["group"], subject))
            if "revoked" in c.get("remove", []):
                cur.execute("UPDATE revocations SET removed_by = %s, removed_at = now() WHERE kind = %s "
                            "AND entry = %s AND grp = %s AND removed_at IS NULL", (subject, kind, key, c["group"]))
    app.logger.info("CHANGE subject=%s %s=%s changes=%s", subject, kind, entry_id, changes)
    return jsonify({"ok": True, "id": entry_id, "grants": {g: sorted(v) for g, v in sets.items()}})


@app.post("/transfers")
def transfer_table():
    # Record a table's move into another group's space (docs/HANDOFF-2026-10-22-groups.md section
    # 1), {"from", "to"}: the caller has copied it (CREATE TABLE <to> AS SELECT * FROM <from>), and
    # drops the original after. authZ = OPA's tables.allow_transfer, as for folders, which the
    # broker moves (POST /transfers there). The copy must carry the original as a source: then the
    # record lets its readers past it, the original being looked up as the copy.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    body = request.get_json(silent=True) or {}
    src, dst = body.get("from"), body.get("to")
    if not all(isinstance(t, str) and TABLE_ID_RE.match(t) for t in (src, dst)) or src == dst:
        return jsonify({"error": "from and to must be two table ids; a folder moves through the broker"}), 400
    if opa("allow_transfer", {"subject": subject, "from": src, "to": dst}, package="tables") is not True:
        app.logger.info("DENY transfer subject=%s from=%s to=%s", subject, src, dst)
        return jsonify({"error": "forbidden"}), 403
    if src not in [c["id"] for c in carried(dst)]:
        return jsonify({"error": f"copy it first: CREATE TABLE {dst} AS SELECT * FROM {src}"}), 409
    with db(commit=True) as cur:
        cur.execute("UPDATE table_entries SET status = 'moved', moved_to = %s WHERE id = %s AND status = 'live' "
                    "RETURNING id", (dst, src))
        if cur.fetchone() is None:
            return jsonify({"error": f"{src} cannot be moved"}), 409
        cur.execute("INSERT INTO transfers (kind, from_id, to_id, by, done_at) VALUES ('table', %s, %s, %s, now()) "
                    "RETURNING id", (src, dst, subject))
        tid = cur.fetchone()["id"]
    app.logger.info("TRANSFER table %s -> %s (%s)", src, dst, subject)
    return jsonify({"ok": True, "from": src, "to": dst, "transfer": tid})


# Collections (docs/HANDOFF-2026-10-22-groups.md section 5). A collection belongs to a group,
# whose space's defaults it takes: describe, read and write for the group, manage for its
# stewards, delete for its admins.


@app.post("/collections")
def create_collection():
    # {"group", "name", "description"}: a member or above of the group (OPA's
    # lakehouse.collections.allow_create). Its id is <group>:<name>.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    body = request.get_json(silent=True) or {}
    group, name = body.get("group"), body.get("name")
    cid = f"{group}:{name}"
    if not (isinstance(group, str) and isinstance(name, str) and COLLECTION_RE.match(cid)
            and isinstance(body.get("description", ""), str) and set(body) <= {"group", "name", "description"}):
        return jsonify({"error": "body is {group, name, description}; a name is lowercase letters, digits, _ and -"}), 400
    if opa("allow_create", {"subject": subject, "group": group, "platform_admin": platform_admin(claims)},
           package="collections") is not True:
        return jsonify({"error": "forbidden"}), 403
    with db(commit=True) as cur:
        cur.execute(f"INSERT INTO collections (id, owner, description, created_by, {_COLLECTION_GRANT_SQL}) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING RETURNING id",
                    (cid, group, body.get("description"), subject, [group], [group], [f"{group}#steward"],
                     [group], [f"{group}#admin"]))
        if cur.fetchone() is None:
            return jsonify({"error": f"{cid} exists"}), 409
    app.logger.info("COLLECTION create %s (%s)", cid, subject)
    return jsonify({"ok": True, "id": cid, **_collection_entries([cid])[cid]}), 201


@app.patch("/collections/<cid>")
def change_collection(cid):
    # {"description"} with `write` on it, and {"changes": [{group, add, remove}]} as in the
    # permissions API: `describe` and `read` by its `manage` holders, `manage`, `write` and
    # `delete` by the owning group's stewards (OPA's allow_change), decided under a lock on it.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    body = request.get_json(silent=True) or {}
    changes = body.get("changes", [])
    changes_ok = not changes or (_valid_changes(changes) and all(
        set(c.get(k, [])) <= set(COLLECTION_GRANTS) for c in changes for k in ("add", "remove")))
    if not (body and set(body) <= {"description", "changes"} and isinstance(body.get("description", ""), str)
            and changes_ok):
        return jsonify({"error": "body is {description, changes: [{group, add: [grant], remove: [grant]}]} "
                                 f"with grants from {list(COLLECTION_GRANTS)}"}), 400
    named = sorted({g for c in changes for k in ("add", "remove") for g in c.get(k, [])})
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"collection:{cid}",))
        cur.execute(f"SELECT {_COLLECTION_GRANT_SQL} FROM collections WHERE id = %s", (cid,))
        row = cur.fetchone()
        inp = {"subject": subject, "collection": cid, "platform_admin": platform_admin(claims)}
        if row is None or ("description" in body and opa("allow_write", inp, package="collections") is not True) \
                or (named and opa("allow_change", {**inp, "grants": named}, package="collections") is not True):
            return jsonify({"error": "forbidden"}), 403
        sets = {g: set(row[g]) for g in COLLECTION_GRANTS}
        for c in changes:
            for g in c.get("add", []):
                sets[g].add(c["group"])
            for g in c.get("remove", []):
                sets[g].discard(c["group"])
        cur.execute("UPDATE collections SET description = COALESCE(%s, description), "
                    + ", ".join(f'"{g}" = %s' for g in COLLECTION_GRANTS) + " WHERE id = %s",
                    (body.get("description"), *(sorted(sets[g]) for g in COLLECTION_GRANTS), cid))
    app.logger.info("COLLECTION change %s (%s) %s", cid, subject, body)
    return jsonify({"ok": True, **_collection_entries([cid])[cid]})


def _member_kind(member):
    """files | namespace | collection for a published folder, a published namespace or a
    collection; None for anything else."""
    with db() as cur:
        if COLLECTION_RE.match(member):
            cur.execute("SELECT 1 FROM collections WHERE id = %s", (member,))
            return "collection" if cur.fetchone() else None
        cur.execute("SELECT 1 FROM datasets WHERE id = %s AND published AND status <> 'moved'", (member,))
        if cur.fetchone():
            return "files"
        cur.execute("SELECT 1 FROM namespaces WHERE id = %s AND published", (member,))
        return "namespace" if cur.fetchone() else None


@app.route("/collections/<cid>/members/<path:member>", methods=["POST", "DELETE"])
def change_member(cid, member):
    # Add (POST) a published dataset or a collection: `write` on the collection and `manage` on
    # what is added, whose holders so consent to it joining (OPA's allow_add); a collection that
    # would come to hold itself is refused. Remove (DELETE): `write` on the collection, or
    # `manage` on the member (allow_remove). Additions take one lock, so two cannot make a cycle
    # between them.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (COLLECTIONS_LOCK_KEY,))
        cur.execute("SELECT 1 FROM collections WHERE id = %s", (cid,))
        exists = cur.fetchone() is not None
        # A member is removed as what it was added as, whatever it has become since.
        cur.execute("SELECT member_kind FROM collection_members WHERE collection = %s AND member = %s", (cid, member))
        held = cur.fetchone()
    kind = held["member_kind"] if request.method == "DELETE" and held else _member_kind(member)
    inp = {"subject": subject, "collection": cid, "member": member, "kind": kind,
           "platform_admin": platform_admin(claims)}
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (COLLECTIONS_LOCK_KEY,))
        if not exists or kind is None:
            return jsonify({"error": "forbidden"}), 403
        if request.method == "DELETE":
            if opa("allow_remove", inp, package="collections") is not True:
                return jsonify({"error": "forbidden"}), 403
            cur.execute("DELETE FROM collection_members WHERE collection = %s AND member = %s", (cid, member))
        else:
            if opa("allow_add", inp, package="collections") is not True:
                return jsonify({"error": "forbidden"}), 403
            if kind == "collection":
                cur.execute("WITH RECURSIVE down(id) AS (SELECT %s::text UNION SELECT cm.member FROM down "
                            "JOIN collection_members cm ON cm.collection = down.id) "
                            "SELECT 1 FROM down WHERE id = %s", (member, cid))
                if cur.fetchone():
                    return jsonify({"error": f"{member} holds {cid}: adding it would make a cycle"}), 409
            cur.execute("INSERT INTO collection_members (collection, member, member_kind, added_by) "
                        "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING", (cid, member, kind, subject))
    app.logger.info("COLLECTION %s %s %s (%s)", "add" if request.method == "POST" else "remove", cid, member, subject)
    return jsonify({"ok": True, **_collection_entries([cid])[cid]})


@app.delete("/collections/<cid>")
def delete_collection(cid):
    # Its `delete` holders (the owning group's admins by default); its members are untouched.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (COLLECTIONS_LOCK_KEY,))
        if opa("allow_delete", {"subject": subject, "collection": cid}, package="collections") is not True:
            return jsonify({"error": "forbidden"}), 403
        cur.execute("DELETE FROM collection_members WHERE member = %s", (cid,))
        cur.execute("DELETE FROM collections WHERE id = %s", (cid,))
    app.logger.info("COLLECTION delete %s (%s)", cid, subject)
    return jsonify({"ok": True, "id": cid})


@app.get("/collections/<cid>")
def get_collection(cid):
    # For those who may describe it: its description, grants, and the members they may
    # describe, with a count of the others.
    subject, err = authed_user()
    if err:
        return err
    c = opa("discover", {"subject": subject, "collections": [cid]}, package="collections") or {}
    if cid not in c.get("visible", []):
        return jsonify({"error": "not found"}), 404
    e = _collection_entries([cid])[cid]
    shown = _describable(subject, [m["id"] for m in e["members"] if m["kind"] != "collection"])
    shown |= set((opa("discover", {"subject": subject, "collections": [m["id"] for m in e["members"]
                                                                       if m["kind"] == "collection"]},
                      package="collections") or {}).get("visible", []))
    return jsonify({**{k: v for k, v in e.items() if k != "members"}, "can_read": cid in c.get("readable", []),
                    "members": [m for m in e["members"] if m["id"] in shown],
                    "hidden_members": len([m for m in e["members"] if m["id"] not in shown])})


def _publish_body(body):
    """The description and own grants a publish names, or None when malformed."""
    if not isinstance(body, dict) or not set(body) <= {"description", *GRANTS}:
        return None
    if "description" in body and not isinstance(body["description"], str):
        return None
    return body if all(_names(body[g], GRANTEE_RE) for g in GRANTS if g in body) else None


@app.patch("/datasets/<path:ds_id>")
def publish_dataset(ds_id):
    # Publish a folder (docs/HANDOFF-2026-10-22-groups.md section 3): give its entry a
    # description and grants of its own, {"description", "describe": [group], ...}; a grant not
    # named keeps what it had, and publishing again changes them. authZ = OPA's
    # blob.allow_publish, a steward of the group whose space holds it. Refused for a folder
    # with no entry and for one inside or containing another published dataset, since
    # published datasets do not nest: the check and the write hold one lock.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    body = _publish_body(request.get_json(silent=True))
    if body is None:
        return jsonify({"error": f"body is {{description, {', '.join(GRANTS)}}}"}), 400
    if _is_personal(ds_id.split("/")[0]):
        return jsonify({"error": "nothing in a personal space is published; transfer it to share it"}), 403
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (PUBLISH_LOCK_KEY,))
        cur.execute(f"SELECT prefix, {_DATASET_GRANT_SQL} FROM datasets WHERE id = %s FOR UPDATE", (ds_id,))
        row = cur.fetchone()
        if row is None or opa("allow_publish", {"subject": subject, "dataset": ds_id,
                                                "platform_admin": platform_admin(claims)}) is not True:
            app.logger.info("DENY publish subject=%s dataset=%s", subject, ds_id)
            return jsonify({"error": "forbidden"}), 403
        cur.execute("SELECT id FROM datasets WHERE published AND id <> %(i)s AND (starts_with(prefix, %(p)s) "
                    "OR starts_with(%(p)s, prefix)) ORDER BY id", {"i": ds_id, "p": row["prefix"]})
        if nested := [r["id"] for r in cur.fetchall()]:
            return jsonify({"error": f"{ds_id} is inside or contains a published dataset: {', '.join(nested)}"}), 409
        # A folder being moved, or one in or around it, is published only after the move.
        cur.execute("SELECT from_id FROM transfers t, unnest(ARRAY[t.from_id, t.to_id]) f WHERE t.kind = 'files' "
                    "AND t.done_at IS NULL AND t.expires > now() AND (starts_with(%(p)s, 'datasets/' || f || '/') "
                    "OR starts_with('datasets/' || f || '/', %(p)s)) LIMIT 1", {"p": row["prefix"]})
        if moving := cur.fetchone():
            return jsonify({"error": f"{ds_id} is in or around a folder being moved ({moving['from_id']})"}), 409
        own = {g: sorted(set(body[g])) if g in body else sorted(row["access" if g == "read" else g])
               for g in GRANTS}
        cur.execute("UPDATE datasets SET published = true, published_at = now(), steward = %s, "
                    "description = COALESCE(%s, description), "
                    + ", ".join(f'"{"access" if g == "read" else g}" = %s' for g in GRANTS) + " WHERE id = %s",
                    (subject, body.get("description"), *(own[g] for g in GRANTS), ds_id))
    app.logger.info("PUBLISH subject=%s dataset=%s", subject, ds_id)
    return jsonify({"ok": True, "id": ds_id, "published": True, "grants": own})


@app.patch("/namespaces/<ns_id>")
def publish_namespace(ns_id):
    # Publish a namespace as one dataset of its tables (handoff section 3), the same body and
    # rule as publish_dataset (tables.allow_publish). Refused inside or around another published
    # namespace.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    body = _publish_body(request.get_json(silent=True))
    if body is None or not NAMESPACE_RE.match(ns_id):
        return jsonify({"error": f"body is {{description, {', '.join(GRANTS)}}}"}), 400
    if _is_personal(_table_space(ns_id)):
        return jsonify({"error": "nothing in a personal space is published; transfer it to share it"}), 403
    with db(commit=True) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (PUBLISH_LOCK_KEY,))
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"grants:namespace:{ns_id}",))
        if opa("allow_publish", {"subject": subject, "id": ns_id, "platform_admin": platform_admin(claims)},
               package="tables") is not True:
            app.logger.info("DENY publish subject=%s namespace=%s", subject, ns_id)
            return jsonify({"error": "forbidden"}), 403
        cur.execute("SELECT id FROM namespaces WHERE published AND id <> %(i)s AND (starts_with(id, %(i)s || '.') "
                    "OR starts_with(%(i)s, id || '.')) ORDER BY id", {"i": ns_id})
        if nested := [r["id"] for r in cur.fetchall()]:
            return jsonify({"error": f"{ns_id} is inside or contains a published namespace: {', '.join(nested)}"}), 409
        cur.execute(f"SELECT {_GRANT_SQL} FROM namespaces WHERE id = %s", (ns_id,))
        row = cur.fetchone() or {g: [] for g in GRANTS}
        own = {g: sorted(set(body[g])) if g in body else sorted(row[g]) for g in GRANTS}
        cur.execute(f"INSERT INTO namespaces (id, description, published, published_by, published_at, {_GRANT_SQL}) "
                    f"VALUES (%s, %s, true, %s, now(){', %s' * len(GRANTS)}) ON CONFLICT (id) DO UPDATE SET "
                    "published = true, published_by = EXCLUDED.published_by, published_at = now(), "
                    "description = COALESCE(EXCLUDED.description, namespaces.description), "
                    + ", ".join(f'"{g}" = EXCLUDED."{g}"' for g in GRANTS),
                    (ns_id, body.get("description"), subject, *(own[g] for g in GRANTS)))
    app.logger.info("PUBLISH subject=%s namespace=%s", subject, ns_id)
    return jsonify({"ok": True, "id": ns_id, "published": True, "grants": own})


def _lock_group(cur, name):
    # Every writer of a group's people takes this lock, so the roles OPA fetches while it is held
    # are the ones the write replaces.
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("group:" + name,))


def _names(v, pattern):
    return isinstance(v, list) and all(isinstance(x, str) and pattern.match(x) for x in v)


# A name some grant or release already names, alone or as `<name>#<role>`, or whose space
# holds an entry or grants: creating it would hand its owner those grants, so it is refused.
_NAME_IN_USE_SQL = """
SELECT EXISTS (SELECT 1 FROM groups WHERE name = %(g)s)
    OR EXISTS (SELECT 1 FROM group_members WHERE grp = %(g)s)
    OR EXISTS (SELECT 1 FROM datasets, unnest(describe || access || manage || write || detach || "delete") n
               WHERE split_part(n, '#', 1) = %(g)s)
    OR EXISTS (SELECT 1 FROM table_entries, unnest(describe || read || manage || write || "delete" || detach) n
               WHERE split_part(n, '#', 1) = %(g)s)
    OR EXISTS (SELECT 1 FROM releases WHERE split_part(grp, '#', 1) = %(g)s)
    OR EXISTS (SELECT 1 FROM folder_grants, unnest(describe || read || manage || write || "delete" || detach) n
               WHERE split_part(n, '#', 1) = %(g)s)
    OR EXISTS (SELECT 1 FROM folder_grants WHERE split_part(prefix, '/', 2) = %(g)s)
    OR EXISTS (SELECT 1 FROM namespaces, unnest(describe || read || manage || write || "delete" || detach) n
               WHERE split_part(n, '#', 1) = %(g)s)
    OR EXISTS (SELECT 1 FROM namespaces WHERE split_part(id, '.', 2) = %(g)s)
    OR EXISTS (SELECT 1 FROM collections WHERE owner = %(g)s)
    OR EXISTS (SELECT 1 FROM collections, unnest(describe || read || manage || write || "delete") n
               WHERE split_part(n, '#', 1) = %(g)s)
    -- A space with entries in it: the new group's defaults would reach them.
    OR EXISTS (SELECT 1 FROM datasets WHERE split_part(prefix, '/', 2) = %(g)s)
    OR EXISTS (SELECT 1 FROM table_entries WHERE split_part(id, '.', 2) = %(g)s) AS used
"""


def _people(cur, name):
    """{person: {role, steward}} for a group's people."""
    cur.execute("SELECT member, role, steward FROM group_members WHERE grp = %s", (name,))
    return {r["member"]: {"role": r["role"], "steward": r["steward"]} for r in cur.fetchall()}


def _group_view(name, people):
    return {"group": name, "tenant": any(p["steward"] for p in people.values()),
            **{f"{role}s": sorted(m for m, p in people.items() if p["role"] == role) for role in ROLES},
            "stewards": sorted(m for m, p in people.items() if p["steward"])}


@app.post("/groups")
def create_group():
    # Create a group, {"name"}; the caller becomes its owner (docs/HANDOFF-2026-10-22-groups.md
    # section 1). authZ = OPA's lakehouse.groups.allow_create; the name follows GROUP_RE and is
    # not reserved or in use.
    subject, err = authed_user()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    name = body.get("name")
    if set(body) != {"name"} or not isinstance(name, str) or not GROUP_RE.match(name) \
            or name in RESERVED_GROUPS:
        return jsonify({"error": "body is {name}: 2 to 64 lowercase letters and digits, starting "
                                 "with a letter, and not " + ", ".join(sorted(RESERVED_GROUPS))}), 400
    if opa("allow_create", {"subject": subject}, package="groups") is not True:
        app.logger.info("DENY create-group subject=%s group=%s", subject, name)
        return jsonify({"error": "forbidden"}), 403
    with db(commit=True) as cur:
        _lock_group(cur, name)
        cur.execute(_NAME_IN_USE_SQL, {"g": name})
        if cur.fetchone()["used"]:
            return jsonify({"error": "group name in use"}), 409
        cur.execute("INSERT INTO groups (name, created_by) VALUES (%s, %s)", (name, subject))
        cur.execute("INSERT INTO group_members (grp, member, role) VALUES (%s, %s, 'owner')", (name, subject))
    app.logger.info("CREATE-GROUP subject=%s group=%s", subject, name)
    return jsonify({"ok": True, **_group_view(name, {subject: {"role": "owner", "steward": False}})}), 201


# The body's fields and the role each sets.
_ROLE_FIELDS = {"owners": "owner", "admins": "admin", "members": "member", "viewers": "viewer"}


@app.patch("/groups/<name>")
def change_group(name):
    # Add people to a role, or remove them from the group:
    # {"owners"|"admins"|"members"|"viewers": {"add": [subject], "remove": [subject]}}. A person
    # holds one role, so adding someone already in the group moves them. authZ = OPA's
    # lakehouse.groups.allow_change over every role the change names or moves someone out of,
    # asked while this transaction holds the group's lock. An unknown group is refused exactly
    # as a denied change. Refused: a change leaving no owner, and one leaving a steward a viewer
    # or out of the group, since only platform admins remove a steward.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    body = request.get_json(silent=True) or {}
    if not (body and set(body) <= _ROLE_FIELDS.keys() and all(
            isinstance(body[f], dict) and body[f] and set(body[f]) <= {"add", "remove"}
            and all(_names(v, SUBJECT_RE) for v in body[f].values())
            for f in body)):
        return jsonify({"error": "body is {owners|admins|members|viewers: {add: [subject], remove: [subject]}}"}), 400
    if _is_personal(name):
        return jsonify({"error": f"{name} is a personal group: it has its person alone"}), 403
    with db(commit=True) as cur:
        _lock_group(cur, name)
        cur.execute("SELECT 1 FROM groups WHERE name = %s", (name,))
        exists = cur.fetchone() is not None
        people = _people(cur, name)
        roles = {m: p["role"] for m, p in people.items()}
        for f, ops in body.items():
            for m in ops.get("remove", []):
                if roles.get(m) == _ROLE_FIELDS[f]:
                    del roles[m]
            for m in ops.get("add", []):
                roles[m] = _ROLE_FIELDS[f]
        moved = {m for m in {*people, *roles} if roles.get(m) != (people.get(m) or {}).get("role")}
        touched = {_ROLE_FIELDS[f] for f in body} | {people[m]["role"] for m in moved if m in people}
        if not exists or opa("allow_change", {"subject": subject, "group": name, "roles": sorted(touched),
                                              "platform_admin": platform_admin(claims)},
                             package="groups") is not True:
            app.logger.info("DENY change-group subject=%s group=%s", subject, name)
            return jsonify({"error": "forbidden"}), 403
        if "owner" not in roles.values():
            return jsonify({"error": "a group keeps at least one owner"}), 409
        if demoted := sorted(m for m in moved if m in people and people[m]["steward"]
                             and roles.get(m) in (None, "viewer")):
            return jsonify({"error": f"{', '.join(demoted)}: a steward is a member or above; "
                                     "a platform admin removes the steward first"}), 409
        for m in moved:
            if m in roles:
                cur.execute("INSERT INTO group_members (grp, member, role) VALUES (%s, %s, %s) "
                            "ON CONFLICT (grp, member) DO UPDATE SET role = EXCLUDED.role", (name, m, roles[m]))
            else:
                cur.execute("DELETE FROM group_members WHERE grp = %s AND member = %s", (name, m))
        people = _people(cur, name)
    app.logger.info("CHANGE-GROUP subject=%s group=%s change=%s", subject, name, body)
    return jsonify({"ok": True, **_group_view(name, people)})


@app.route("/groups/<name>/stewards/<person>", methods=["PUT", "DELETE"])
def change_steward(name, person):
    # Appoint (PUT) or remove (DELETE) a steward: platform admins only (OPA's
    # lakehouse.groups.allow_steward). A steward is a member or above of the group; a group with
    # one is a tenant.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    if _is_personal(name):
        return jsonify({"error": f"{name} is a personal group: it has its person alone"}), 403
    with db(commit=True) as cur:
        _lock_group(cur, name)
        if opa("allow_steward", {"subject": subject, "group": name, "platform_admin": platform_admin(claims)},
               package="groups") is not True:
            app.logger.info("DENY steward subject=%s group=%s person=%s", subject, name, person)
            return jsonify({"error": "forbidden"}), 403
        people = _people(cur, name)
        if request.method == "PUT" and (people.get(person) or {}).get("role") in (None, "viewer"):
            return jsonify({"error": f"{person} is not a member or above of {name}"}), 409
        cur.execute("UPDATE group_members SET steward = %s WHERE grp = %s AND member = %s",
                    (request.method == "PUT", name, person))
        people = _people(cur, name)
    app.logger.info("STEWARD %s subject=%s group=%s person=%s", request.method, subject, name, person)
    return jsonify({"ok": True, **_group_view(name, people)})


@app.delete("/groups/<name>")
def delete_group(name):
    # Delete a group: its owners (OPA's lakehouse.groups.allow_delete). Refused while its space
    # holds data. Grants naming it and entries in its space stay, and keep its name from being
    # created again.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    if _is_personal(name):
        return jsonify({"error": f"{name} is a personal group: it has its person alone"}), 403
    with db(commit=True) as cur:
        _lock_group(cur, name)
        cur.execute("SELECT 1 FROM groups WHERE name = %s", (name,))
        if cur.fetchone() is None or opa("allow_delete", {
                "subject": subject, "group": name, "platform_admin": platform_admin(claims)},
                package="groups") is not True:
            app.logger.info("DENY delete-group subject=%s group=%s", subject, name)
            return jsonify({"error": "forbidden"}), 403
        cur.execute("SELECT EXISTS (SELECT 1 FROM datasets WHERE split_part(prefix, '/', 2) = %(g)s "
                    "AND status = 'live') OR EXISTS (SELECT 1 FROM table_entries WHERE "
                    "split_part(id, '.', 2) = %(g)s AND status = 'live') AS holds", {"g": name})
        if cur.fetchone()["holds"]:
            return jsonify({"error": f"{name}'s space holds data; delete or transfer it first"}), 409
        # A collection's owner decides who changes it; a group recreated under the name would.
        cur.execute("SELECT 1 FROM collections WHERE owner = %s LIMIT 1", (name,))
        if cur.fetchone():
            return jsonify({"error": f"{name} owns collections; delete them first"}), 409
        cur.execute("DELETE FROM group_members WHERE grp = %s", (name,))
        cur.execute("DELETE FROM groups WHERE name = %s", (name,))
    app.logger.info("DELETE-GROUP subject=%s group=%s", subject, name)
    return jsonify({"ok": True, "group": name})


# The read API (docs/HANDOFF-2026-10-22-groups.md section 1), narrowed by the same OPA rules as
# the writes.


@app.get("/me")
def me():
    # The caller's groups with their role in each, whether they are its steward and whether it
    # is a tenant; and whether they are a platform admin.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    _ensure_personal(subject)
    with db() as cur:
        cur.execute("SELECT m.grp, m.role, m.steward, EXISTS (SELECT 1 FROM group_members s "
                    "WHERE s.grp = m.grp AND s.steward) AS tenant FROM group_members m "
                    "WHERE m.member = %s ORDER BY m.grp", (subject,))
        groups = [{"group": r["grp"], "role": r["role"], "steward": r["steward"], "tenant": r["tenant"]}
                  for r in cur.fetchall()]
    return jsonify({"subject": subject, "platform_admin": platform_admin(claims), "groups": groups})


@app.get("/groups/<name>")
def get_group(name):
    # A group's people by role and its stewards, for its viewers and above (OPA's
    # lakehouse.groups.allow_view). An unknown group is refused exactly as a denied one.
    claims, err = authed_claims()
    if err:
        return err
    subject = subject_of(claims)
    with db() as cur:
        cur.execute("SELECT created_by, created_at FROM groups WHERE name = %s", (name,))
        row = cur.fetchone()
        if row is None or opa("allow_view", {"subject": subject, "group": name,
                                             "platform_admin": platform_admin(claims)},
                              package="groups") is not True:
            return jsonify({"error": "not found"}), 404
        people = _people(cur, name)
    return jsonify({**_group_view(name, people), "created_by": row["created_by"],
                    "created_at": row["created_at"]})


def _implied(name):
    """Every name a holder of this grantee name holds: `<g>#admin` is also `<g>#member` and `<g>`."""
    g, _, role = name.partition("#")
    if not role:
        return [g]
    return sorted({g, f"{g}#member", f"{g}#{role}", *(f"{g}#{x}" for x in ROLE_NAMES.get(role, ()))})


def _describable(subject, ids):
    """The ids among these that the subject may describe."""
    tables = [i for i in ids if TABLE_ID_RE.match(i)]
    files = [i for i in ids if not TABLE_ID_RE.match(i)]
    seen = set(opa("discover", {"subject": subject, "datasets": files})["visible"]) if files else set()
    if tables:
        seen |= set(opa("decide", {"subject": subject, "tables": tables, "namespaces": []},
                        package="tables")["tables"])
    return seen


def _entry_view(kind, entry_id):
    """An entry for someone who may describe it: its effective grants and each layer they come
    from, the names in its read (a table's write included) all of whose holders pass every
    source, whether it is published, its status, whether the caller may read it, and, when they
    may not, why: whether they hold `read` at all, the carried sources that refuse them, each
    named only if they may describe it, and releases of it to them that were withdrawn. A holder
    of its `manage` also gets who added each group to its `revoked`, and when (PROVENANCE.md 9)."""
    subject, err = authed_user()
    if err:
        return err
    if kind == "dataset":
        package, key = "blob", "dataset"
        d = opa("discover", {"subject": subject, "datasets": [entry_id]})
        visible, readable = entry_id in d["visible"], entry_id in d["readable"]
        entries, layers = _file_entries([entry_id])
    else:
        package, key = "tables", "id"
        t = opa("decide", {"subject": subject, "tables": [entry_id], "namespaces": []}, package="tables")
        visible, readable = entry_id in t["tables"], entry_id in t["readable"]
        entries, layers = _table_entries([entry_id])
    if not visible or entry_id not in entries:
        return jsonify({"error": "not found"}), 404
    e = entries[entry_id]
    with db() as cur:
        read_names, write_names = _group_names(cur, subject)
        if kind == "dataset":
            cur.execute("SELECT description, steward, status FROM datasets WHERE id = %s", (entry_id,))
            e = {**e, **cur.fetchone(), "read": e["access"]}
        # The rows revoked was set on: the dataset's own, the folders' and namespaces' above it.
        where = [("dataset" if w == "own" else "folder" if kind == "dataset" else "namespace",
                  entry_id if w == "own" else w) for w, _ in layers[entry_id] if w != "space"]
        cur.execute("SELECT grp, added_by, added_at, removed_by, removed_at FROM revocations "
                    "WHERE (kind, entry) IN (SELECT * FROM unnest(%s::text[], %s::text[])) ORDER BY id",
                    ([k for k, _ in where], [i for _, i in where]))
        revocations = cur.fetchall()
    grants = {g: e[g] for g in GRANTS}
    readers = sorted(set(grants["read"]) | (set(grants["write"]) if kind == "table" else set()))
    effective = opa("effective_read", {key: entry_id, "holders": {n: _implied(n) for n in readers}},
                    package=package) or []
    out = {"id": entry_id, "kind": "files" if kind == "dataset" else "table",
           **{k: e.get(k) for k in ("prefix", "namespace", "description", "steward", "status", "published")
              if k in e},
           "grants": grants, "layers": [{"from": where, "grants": g} for where, g in layers[entry_id]],
           "effective_read": sorted(effective), "can_read": readable}
    if set(write_names) & set(grants["manage"]):
        out["revocations"] = [{"group": r["grp"], **{k: r[k] for k in ("added_by", "added_at", "removed_by",
                                                                    "removed_at")}} for r in revocations]
        # Every collection it reaches, which its manage holders consented to (handoff section 5).
        out["collections"] = sorted(w.split(" ", 1)[1] for w, _ in layers[entry_id] if w.startswith("collection "))
    if not readable:
        blocking = sorted(opa("blocking", {"subject": subject, key: entry_id}, package=package) or [])
        named = _describable(subject, blocking) if blocking else set()
        with db() as cur:
            cur.execute("SELECT source, grp, withdrawn_by, withdrawn_at FROM releases WHERE target = %s "
                        "AND approved AND withdrawn_at IS NOT NULL AND grp = ANY(%s) ORDER BY id",
                        (entry_id, read_names))
            withdrawn = cur.fetchall()
        named |= _describable(subject, sorted({r["source"] for r in withdrawn})) if withdrawn else set()
        out["why"] = {"holds_read": bool(set(read_names) & set(readers)),
                      "sources": [s for s in blocking if s in named],
                      "hidden_sources": len([s for s in blocking if s not in named]),
                      "withdrawn_releases": [{"source": r["source"] if r["source"] in named else None,
                                              "group": r["grp"], "withdrawn_at": r["withdrawn_at"]}
                                             for r in withdrawn]}
    return jsonify(out)


@app.get("/datasets/<path:ds_id>")
def get_dataset(ds_id):
    return _entry_view("dataset", ds_id)


@app.get("/tables/<table_id>")
def get_table(table_id):
    return _entry_view("table", table_id)


# The candidates for a person's dataset index: live entries some viewing grant could show them,
# by any layer (_folder_layers, _namespace_layers): an entry in the space of a group they are
# in, a dataset whose own describe or read names them, an entry under a folder whose describe
# or read does, a table under a namespace whose describe, read or write does.
_INDEX_FILES_SQL = """
SELECT id FROM datasets d WHERE status = 'live' AND (
    split_part(prefix, '/', 2) = ANY(%(groups)s) OR (describe || access) && %(names)s::text[]
    OR id = ANY(%(held)s)
    OR EXISTS (SELECT 1 FROM folder_grants f WHERE starts_with(d.prefix, f.prefix) AND d.prefix <> f.prefix
               AND (f.describe || f.read) && %(names)s::text[]))
"""
_INDEX_TABLES_SQL = """
SELECT id FROM table_entries t WHERE status = 'live' AND (
    split_part(id, '.', 2) = ANY(%(groups)s)
    OR EXISTS (SELECT 1 FROM unnest(%(held)s::text[]) h WHERE starts_with(t.id, h || '.'))
    OR EXISTS (SELECT 1 FROM namespaces n WHERE starts_with(t.id, n.id || '.')
               AND (n.describe || n.read || n.write) && %(names)s::text[]))
"""
# Every collection some of whose own describe or read names the person, and what they hold,
# directly or through other collections.
_HELD_SQL = """
WITH RECURSIVE down(id, kind) AS (
    SELECT id, 'collection' FROM collections WHERE (describe || read) && %(names)s::text[]
    UNION
    SELECT cm.member, cm.member_kind FROM down JOIN collection_members cm ON cm.collection = down.id
)
SELECT id, kind FROM down
"""


def _index_rows(subject):
    """Every live dataset and table the subject may see, with whether they may read it and
    whether it is published. Only live entries: existence is storage's truth (reconcile, the
    gate's reports), who may view them OPA's; governance builds the list, OPA says which
    candidates pass.

    The candidates are only entries some layer of whose viewing grants names the subject. Those
    are the grants OPA's viewing rules test (blob.rego `visible`, tables.rego `viewable`), so the
    narrowing drops only entries OPA would refuse, and OPA's cost follows what the person may
    see rather than the catalog's size. seed/check-index-narrowing.py checks the two agree."""
    with db() as cur:
        names, _ = _group_names(cur, subject)
        cur.execute(_HELD_SQL, {"names": names})
        held = cur.fetchall()
        params = {"names": names, "groups": sorted({n.split("#")[0] for n in names}),
                  "held": [h["id"] for h in held if h["kind"] != "collection"]}
        cur.execute(_INDEX_FILES_SQL, params)
        files = [r["id"] for r in cur.fetchall()]
        cur.execute(_INDEX_TABLES_SQL, params)
        tables = [r["id"] for r in cur.fetchall()]
    f = (opa("discover", {"subject": subject, "datasets": files}) if files else {"visible": [], "readable": []})
    t = (opa("decide", {"subject": subject, "tables": tables, "namespaces": []}, package="tables")
         if tables else {"tables": [], "readable": []})
    with db() as cur:
        cur.execute("SELECT id, description, steward, published FROM datasets WHERE id = ANY(%s)", (f["visible"],))
        rows = [{"id": r["id"], "kind": "files", "description": r["description"], "steward": r["steward"],
                 "can_read": r["id"] in f["readable"], "published": r["published"]} for r in cur.fetchall()]
    shown, _ = _table_entries(t["tables"]) if t["tables"] else ({}, {})
    rows += [{"id": i, "kind": "table", "description": e["description"], "steward": e["steward"],
              "can_read": i in t["readable"], "published": e["published"]} for i, e in shown.items()]
    collections = sorted({h["id"] for h in held if h["kind"] == "collection"})
    c = (opa("discover", {"subject": subject, "collections": collections}, package="collections")
         if collections else {"visible": [], "readable": []})
    for i, e in _collection_entries(c["visible"]).items():
        rows.append({"id": i, "kind": "collection", "description": e["description"], "steward": e["owner"],
                     "can_read": i in c["readable"], "published": True})
    return sorted(rows, key=lambda r: (r["kind"], r["id"]))


def _draft_rows(subject):
    """governance.drafts (docs/HANDOFF-2026-10-22-groups.md section 4): for each table the
    subject wrote with a statement an engine reported, a draft of its declaration. Each of their
    candidates for it (governance.lineage, read directly) is `used` if a statement writing it in
    that session read it, `unused` if it is a table the engine read in that session and every
    read of it there wrote its rows into a table, and has no row otherwise: a file read, a source
    that arrived through a read, or a table whose rows went to the client, which only the person
    can account for. A candidate of several sessions is used if any says so and unused only if
    all do. A draft changes no one's access; confirming it is an insert into derivations."""
    with db() as cur:
        cur.execute("SELECT s.name AS session, e.statement_id, e.target, e.inputs, e.to_client, e.engine "
                    "FROM engine_statements e JOIN sessions s ON s.id = e.session WHERE e.person = %s "
                    "ORDER BY e.id", (subject,))
        statements = cur.fetchall()
    written = {}   # target -> {session: inputs of the statements writing it there}, and the last statement
    read, shown = {}, {}   # session -> tables read by any statement; those whose rows went to the client
    last = {}
    for st in statements:
        read.setdefault(st["session"], set()).update(st["inputs"])
        if st["to_client"]:
            shown.setdefault(st["session"], set()).update(st["inputs"])
        if st["target"]:
            written.setdefault(st["target"], {}).setdefault(st["session"], set()).update(st["inputs"])
            last[st["target"]] = (st["engine"], st["statement_id"])
    if not written:
        return []
    verdicts = {}   # (target, source) -> [verdict per session], source_type
    for r in _lineage_rows(subject):
        t, src = r["target"], r["source"]
        if t not in written or src is None or not r["direct"]:
            continue
        sess = r["session"]
        if src in written[t].get(sess, set()):
            v = True
        elif r["source_type"] == "table" and src in read.get(sess, set()) and src not in shown.get(sess, set()):
            v = False
        else:
            v = None
        verdicts.setdefault((t, src, r["source_type"]), []).append(v)
    rows = []
    for (t, src, kind), vs in sorted(verdicts.items()):
        used = True if True in vs else (False if all(v is False for v in vs) else None)
        if used is not None:
            rows.append({"source": src, "source_type": kind, "target": t, "used": used,
                         "engine": last[t][0], "statement_id": last[t][1]})
    return rows


def _collection_member_rows(subject):
    """governance.collection_members: for each collection the subject's index lists, the
    members it lists too."""
    seen = {r["id"]: r["kind"] for r in _index_rows(subject)}
    collections = _collection_entries([i for i, k in seen.items() if k == "collection"])
    tables = {i for i, k in seen.items() if k == "table"}
    return [{"collection": c, "member": m["id"], "kind": m["kind"]}
            for c, e in sorted(collections.items()) for m in e["members"]
            if m["id"] in seen or (m["kind"] == "namespace" and any(t.startswith(m["id"] + ".") for t in tables))]


def _session_rows(subject, sid):
    """The person's sessions; `current` marks the one this login's next access would be
    stamped with."""
    with db() as cur:
        current = _pointer(cur, subject, sid)
        cur.execute("SELECT id, name, started, last_used FROM sessions WHERE person = %s "
                    "ORDER BY started", (subject,))
        return [{"name": r["name"], "started": r["started"], "last_used": r["last_used"],
                 "current": r["id"] == current} for r in cur.fetchall()]


# The person's lineage (PROVENANCE.md 5.2), in the shape of Unity Catalog's
# system.access.table_lineage: a read is a row with no target; a write is a row for each read
# it may have used, or one row with no source when there is none. A read also brings in the
# sources its dataset's files carried then (6, rule 1), which appear with direct false; a source
# both read directly and brought in has a row of each. A write may have used the
# reads of its session before it and, for a file write credential, the reads its login made
# while the credential was valid, which covers a credential carried across a session switch.
# A table write happens at its commit; a file write credential counts as a write until it
# expires, since governance never sees the file writes themselves. A dataset is never paired
# with itself. Repeated events of one shape are one row, at the latest event's time.
_LINEAGE_SQL = """
WITH a AS (
    SELECT id, session, sid, dataset, kind, mode, at, COALESCE(sources, ARRAY[dataset]) AS sources,
           CASE WHEN kind = 'files' THEN COALESCE(expires, 'infinity') ELSE at END AS until
    FROM accesses a WHERE person = %(p)s
      AND (a.mode <> 'write' OR a.location IS NULL
           OR rtrim(a.location, '/') = (SELECT rtrim(t.location, '/') FROM table_entries t WHERE t.id = a.dataset)
           OR rtrim(a.location, '/') IN (SELECT rtrim(c.location, '/') FROM accesses c WHERE c.dataset = a.dataset
                             AND c.mode = 'write' AND c.expires IS NULL AND c.location IS NOT NULL))
), reads AS (  -- each read once per source it brought in; direct for the dataset read
    SELECT a.id, a.session, a.sid, a.at, src.source, src.source = a.dataset AS direct
    FROM a CROSS JOIN LATERAL unnest(a.sources) AS src(source) WHERE a.mode = 'read'
), pairs AS (
    SELECT w.id AS write_id, w.session, r.source, r.direct,
           w.dataset AS target, w.kind AS target_type, w.at AS event_time
    FROM a w JOIN reads r ON r.at < w.until AND r.source <> w.dataset
         AND (r.session = w.session OR (w.kind = 'files' AND r.sid = w.sid AND r.at >= w.at))
    WHERE w.mode = 'write'
), events AS (
    SELECT session, source, direct, target, target_type, event_time FROM pairs
    UNION ALL
    SELECT session, NULL, NULL, dataset, kind, at FROM a w
    WHERE mode = 'write' AND NOT EXISTS (SELECT 1 FROM pairs p WHERE p.write_id = w.id)
    UNION ALL
    SELECT session, source, direct, NULL, NULL, at FROM reads
)
SELECT e.source,
       CASE WHEN e.source IS NULL THEN NULL
            WHEN EXISTS (SELECT 1 FROM table_entries t WHERE t.id = e.source) THEN 'table'
            ELSE 'files' END AS source_type,
       e.target, e.target_type, s.name AS session, max(e.event_time) AS event_time, e.direct
FROM events e JOIN sessions s ON s.id = e.session
GROUP BY e.source, e.direct, e.target, e.target_type, s.name
ORDER BY s.name, e.target NULLS FIRST, e.source NULLS FIRST
"""


def _lineage_rows(subject):
    with db() as cur:
        cur.execute(_LINEAGE_SQL, {"p": subject})
        return cur.fetchall()


# What governance.derivations shows a person (PROVENANCE.md 5.3, 6.5): their own declarations;
# every row marking a source unused, detaches included, and every putting back, of a source
# whose `manage` names one of their groups or which sits in the space of a group they are an
# admin of (docs/HANDOFF-2026-10-22-groups.md section 1: a plain group's space has no `manage`
# holders); and every putting back on a target they have declared. The query returns the
# candidates with what each is; `manage` is effective, so it is checked after (_derivation_rows).
_DERIVATIONS_SQL = """
SELECT s.source, s.source_type, d.target, s.used, d.person AS declared_by, d.declared_at,
       d.person = %(p)s AS own, NOT s.used OR s.detached OR d.reattach AS to_owners,
       d.reattach AND d.target IN (SELECT target FROM declarations WHERE person = %(p)s) AS on_mine
FROM declarations d JOIN declared_sources s ON s.declaration = d.id
WHERE d.person = %(p)s OR NOT s.used OR s.detached OR d.reattach
ORDER BY d.id, s.source NULLS FIRST
"""


def _managed(subject, ids):
    """The ids among these whose effective `manage` names one of the subject's groups."""
    with db() as cur:
        _, names = _group_names(cur, subject)
    return {i for i, e in _effective([i for i in ids if i]).items() if set(e["manage"]) & set(names)}


def _space_of_source(source, source_type):
    if source_type == "table":
        return _table_space(source)
    return source.split("/")[0] if source_type == "files" else None


def _derivation_rows(subject):
    with db() as cur:
        cur.execute(_DERIVATIONS_SQL, {"p": subject})
        rows = cur.fetchall()
        _, names = _group_names(cur, subject)
    managed = _managed(subject, {r["source"] for r in rows if r["to_owners"] and not r["own"]})
    admin_of = {n.split("#")[0] for n in names if n.endswith("#admin")}
    return [{k: r[k] for k in ("source", "source_type", "target", "used", "declared_by", "declared_at")}
            for r in rows if r["own"] or r["on_mine"] or (r["to_owners"] and r["source"] and (
                r["source"] in managed or _space_of_source(r["source"], r["source_type"]) in admin_of))]


def _may_write(subject, target):
    if TABLE_ID_RE.match(target):
        return opa("allow_write", {"subject": subject, "id": target}, package="tables") is True
    return (opa("vend_write", {"subject": subject, "dataset": target}) or {}).get("allow") is True


def _check_target(subject, target, rows, lineage):
    """The declared sources of one target, after the rule of PROVENANCE.md 5.3 for this person:
    every candidate of theirs gets one `used` value, and nothing else is named but outside
    inputs by hash. Raises index_table.Refused."""
    written = [r for r in lineage if r["target"] == target]
    if not written:
        raise index_table.Refused(403, "ForbiddenException", f"{target}: you have not written it")
    if not _may_write(subject, target):
        raise index_table.Refused(403, "ForbiddenException", f"{target}: not in your write grant")
    candidates = {r["source"]: r["source_type"] for r in written if r["source"] is not None and r["direct"]}
    # Sources that arrived through one of those reads (6, rule 1). Marking one unused detaches
    # it even if it was also read directly: the files written after carry it either way.
    arrived = {r["source"]: r["source_type"] for r in written
               if r["source"] is not None and r["direct"] is False}
    known = {**arrived, **candidates}
    declared, types, errors = {}, {}, []
    for r in rows:
        source, kind = r.get("source"), r.get("source_type")
        if source is None:
            continue
        if kind == "external":
            if not EXTERNAL_RE.match(source):
                errors.append(f"an outside input is named sha256:<64 hex digits>, not {source}")
        elif source not in known:
            errors.append(f"not a candidate: {source} (an outside input needs source_type 'external')")
            continue
        elif kind not in (None, known[source]):
            errors.append(f"{source} is {known[source]}, not {kind}")
        if declared.setdefault(source, r["used"]) != r["used"]:
            errors.append(f"{source} declared both used and unused")
        types[source] = kind or known.get(source)
    if missing := sorted(set(candidates) - set(declared)):
        errors.append("not declared: " + ", ".join(missing))
    # OPA decides every source marked unused (6.5): a direct read, or a detach.
    unused = [{"id": src, "direct": src not in arrived} for src, used in declared.items()
              if not used and types.get(src) != "external"]
    if unused and not errors:
        allowed = set(opa("allowed", {"subject": subject, "target": target, "sources": unused},
                          package="derivations") or [])
        errors += [f"you may not {'mark it unused' if u['direct'] else 'detach it'}: {u['id']}"
                   for u in unused if u["id"] not in allowed]
    if errors:
        raise index_table.Refused(400, "BadRequestException", f"{target}: " + "; ".join(errors))
    return {"candidates": sorted(candidates), "arrived": sorted(arrived),
            "sources": [{"source": s, "source_type": types[s], "used": u,
                         "detached": not u and s in arrived and types[s] != "external"}
                        for s, u in sorted(declared.items())]}


def _check_reattach(subject, target, rows):
    """A declaration by someone who did not write the target: allowed only to put back sources
    detached from it, by a holder of each one's `manage` (PROVENANCE.md 6.5)."""
    named = [r for r in rows if r.get("source") is not None]
    sources = sorted({r["source"] for r in named})
    refused = index_table.Refused(403, "ForbiddenException", f"{target}: you have not written it")
    if not named or any(not r["used"] or r.get("source_type") == "external" for r in named):
        raise refused
    holders = set(opa("may_reattach", {"subject": subject, "target": target,
                                       "sources": [{"id": src, "direct": False} for src in sources]},
                      package="derivations") or [])
    if set(sources) - holders:
        raise refused
    with db() as cur:
        cur.execute("SELECT DISTINCT s.source, s.source_type FROM declarations d "
                    "JOIN declared_sources s ON s.declaration = d.id "
                    "WHERE d.target = %s AND s.detached AND s.source = ANY(%s)", (target, sources))
        detached = {r["source"]: r["source_type"] for r in cur.fetchall()}
    if never := sorted(set(sources) - set(detached)):
        raise index_table.Refused(400, "BadRequestException",
                                  f"{target}: you have not written it, and nobody detached {', '.join(never)} from it")
    return {"reattach": True, "sources": [{"source": src, "source_type": detached[src], "used": True,
                                           "detached": False} for src in sources]}


def _sign(record):
    """A DSSE envelope over the record, signed with governance's key."""
    with open(SIGNING_KEY, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(DECLARATION_TYPE), DECLARATION_TYPE.encode(), len(payload), payload)
    raw_pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"payloadType": DECLARATION_TYPE, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": hashlib.sha256(raw_pub).hexdigest()[:16],
                            "sig": base64.b64encode(key.sign(pae)).decode()}]}


def _declare(subject, rows):
    """Check and store the rows of one commit to governance.derivations: one declaration per
    target named, all stored in one transaction, or the commit is refused."""
    if not rows or not all(isinstance(r.get("target"), str) and isinstance(r.get("used"), bool)
                           for r in rows):
        raise index_table.Refused(400, "BadRequestException", "every row needs a target and used")
    if any(r.get("declared_by") is not None or r.get("declared_at") is not None for r in rows):
        raise index_table.Refused(400, "BadRequestException",
                                  "declared_by and declared_at are filled in by governance; "
                                  "insert into (source, source_type, target, used)")
    by_target = {}
    for r in rows:
        by_target.setdefault(r["target"], []).append(r)
    lineage = _lineage_rows(subject)
    written = {r["target"] for r in lineage if r["target"] is not None}
    checked = {t: (_check_target(subject, t, trs, lineage) if t in written
                   else _check_reattach(subject, t, trs))
               for t, trs in sorted(by_target.items())}
    now = datetime.now(timezone.utc)
    with db(commit=True) as cur:
        for target, c in checked.items():
            record = {"person": subject, "target": target, "declared_at": now.isoformat(), **c}
            cur.execute("INSERT INTO declarations (person, target, declared_at, envelope, reattach) "
                        "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                        (subject, target, now, json.dumps(_sign(record)), c.get("reattach", False)))
            declaration = cur.fetchone()["id"]
            for src in c["sources"] or [{"source": None, "source_type": None, "used": True, "detached": False}]:
                cur.execute("INSERT INTO declared_sources (declaration, source, source_type, used, detached) "
                            "VALUES (%s, %s, %s, %s, %s)",
                            (declaration, src["source"], src["source_type"], src["used"], src["detached"]))
        # A declaration of a target covers the files written with credentials for it, which the
        # folders inside and around it hold too.
        _invalidate(cur, list(checked))
    app.logger.info("DECLARE person=%s %s", subject, " ".join(
        f"{t}:{'put back ' if c.get('reattach') else ''}{sum(s['used'] for s in c['sources'])}/{len(c['sources'])}"
        for t, c in checked.items()))


@app.post("/declarations")
def declare():
    # The same declaration as an insert into governance.derivations (PROVENANCE.md 5.3), for a
    # client with no Iceberg engine: {"rows": [{source, source_type, target, used}]}, checked,
    # stored and signed by the same code. The check depends only on the person, not the login.
    subject, err = authed_user()
    if err:
        return err
    rows = (request.get_json(silent=True) or {}).get("rows")
    if not (isinstance(rows, list) and rows and all(
            isinstance(r, dict) and set(r) <= {"source", "source_type", "target", "used"} for r in rows)):
        return jsonify({"error": "rows must be [{source, source_type, target, used}]"}), 400
    try:
        _declare(subject, [{"source": r.get("source"), "source_type": r.get("source_type"),
                            "target": r.get("target"), "used": r.get("used"),
                            "declared_by": None, "declared_at": None} for r in rows])
    except index_table.Refused as e:
        app.logger.info("REFUSE declaration person=%s: %s", subject, e.message)
        return jsonify({"error": e.message}), e.status
    return jsonify({"ok": True, "targets": sorted({r["target"] for r in rows})}), 201


def _kind(entry_id):
    """("tables", "id") for a table id, ("blob", "dataset") for a file dataset's: the OPA package
    deciding about it and the input key it names the entry by."""
    return ("tables", "id") if TABLE_ID_RE.match(entry_id) else ("blob", "dataset")


def _own_read(entry_id):
    """The names in an entry's effective read grant (a table's write included), or None if it
    has no entry."""
    read = _source_read([entry_id]).get(entry_id)
    return None if read is None else set(read["read"])


@app.post("/releases")
def request_release():
    # Ask a source's `manage` holders to let a group read a target built from it (PROVENANCE.md
    # 6.7): {target, source, group}, by someone who may change who reads the target, once the
    # group is in its read grant and its declarations mark the source used.
    subject, err = authed_user()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    target, source, grp = body.get("target"), body.get("source"), body.get("group")
    if not all(isinstance(v, str) and v for v in (target, source, grp)) or not GRANTEE_RE.match(grp):
        return jsonify({"error": "target, source and group required"}), 400
    package, key = _kind(target)
    readers = _own_read(target)
    if readers is None or opa("allow_change", {"subject": subject, key: target, "grants": ["read"]},
                              package=package) is not True:
        return jsonify({"error": "forbidden"}), 403
    if grp not in readers:
        return jsonify({"error": f"add {grp} to {target}'s read grant first"}), 409
    carried_by = {c["id"]: c for c in carried(target)}
    if source not in carried_by:
        return jsonify({"error": f"{source} is not a source of {target}"}), 409
    if not carried_by[source]["declared"]:
        return jsonify({"error": f"declare {target}'s sources first: {source} is undeclared"}), 409
    if grp in (_own_read(source) or set()):
        return jsonify({"error": f"{grp} may already read {source}"}), 409
    with db(commit=True) as cur:
        cur.execute("SELECT 1 FROM releases WHERE target = %s AND source = %s AND grp = %s "
                    "AND withdrawn_at IS NULL AND approved IS NOT FALSE", (target, source, grp))
        if cur.fetchone():
            return jsonify({"error": "already requested or released"}), 409
        cur.execute("INSERT INTO releases (target, source, grp, requested_by) VALUES (%s, %s, %s, %s) "
                    "RETURNING id", (target, source, grp, subject))
        rid = cur.fetchone()["id"]
    app.logger.info("RELEASE-REQUEST id=%s subject=%s target=%s source=%s group=%s",
                    rid, subject, target, source, grp)
    return jsonify({"id": rid, "status": "pending"}), 201


def _may_release(subject, source):
    """Whether the subject may approve, decline or withdraw releases past this source: a holder
    of its `manage`, as opa/derivations.rego may_release decides."""
    return source in (opa("may_release", {"subject": subject, "sources": [{"id": source}]},
                          package="derivations") or [])


@app.post("/releases/<int:rid>/<decision>")
def decide_release(rid, decision):
    subject, err = authed_user()
    if err:
        return err
    if decision not in ("approve", "decline"):
        return jsonify({"error": "not found"}), 404
    with db(commit=True) as cur:
        cur.execute("SELECT source FROM releases WHERE id = %s AND approved IS NULL "
                    "AND withdrawn_at IS NULL FOR UPDATE", (rid,))
        row = cur.fetchone()
        if row is None or not _may_release(subject, row["source"]):
            return jsonify({"error": "no pending request you may decide"}), 404
        cur.execute("UPDATE releases SET approved = %s, decided_by = %s, decided_at = now() WHERE id = %s",
                    (decision == "approve", subject, rid))
    app.logger.info("RELEASE-%s id=%s subject=%s", decision.upper(), rid, subject)
    return jsonify({"id": rid, "status": "approved" if decision == "approve" else "declined"})


@app.delete("/releases/<int:rid>")
def withdraw_release(rid):
    # Withdrawn by a `manage` holder of the source, or, while pending, by whoever asked.
    subject, err = authed_user()
    if err:
        return err
    with db(commit=True) as cur:
        cur.execute("SELECT source, requested_by, approved FROM releases WHERE id = %s "
                    "AND withdrawn_at IS NULL AND approved IS NOT FALSE FOR UPDATE", (rid,))
        row = cur.fetchone()
        if row is None or not (_may_release(subject, row["source"])
                               or (row["approved"] is None and row["requested_by"] == subject)):
            return jsonify({"error": "no release you may withdraw"}), 404
        cur.execute("UPDATE releases SET withdrawn_by = %s, withdrawn_at = now() WHERE id = %s",
                    (subject, rid))
    app.logger.info("RELEASE-WITHDRAW id=%s subject=%s", rid, subject)
    return jsonify({"id": rid, "status": "withdrawn"})


# governance.releases: the releases a person asked for, and those on targets or past sources
# whose `manage` one of their groups holds.
_RELEASES_SQL = """
SELECT r.id::text AS id, r.target, r.source, r.grp AS grantee,
       CASE WHEN r.withdrawn_at IS NOT NULL THEN 'withdrawn' WHEN r.approved THEN 'approved'
            WHEN r.approved = false THEN 'declined' ELSE 'pending' END AS status,
       r.requested_by, r.requested_at, r.decided_by, r.decided_at, r.withdrawn_by, r.withdrawn_at
FROM releases r ORDER BY r.id
"""


def _release_rows(subject):
    with db() as cur:
        cur.execute(_RELEASES_SQL)
        rows = cur.fetchall()
    managed = _managed(subject, {i for r in rows for i in (r["target"], r["source"])})
    return [r for r in rows if r["requested_by"] == subject or {r["target"], r["source"]} & managed]


def _grant_rows(subject):
    """governance.grants: every grant on the entries governance.datasets lists for the subject,
    one row per name, as Unity Catalog's privilege views list them, with where an inherited one
    comes from: a folder's prefix, a namespace's id, or `space`."""
    seen = _index_rows(subject)
    files = [r["id"] for r in seen if r["kind"] == "files"]
    tables = [r["id"] for r in seen if r["kind"] == "table"]
    layers = {**(_file_entries(files)[1] if files else {}), **(_table_entries(tables)[1] if tables else {})}
    layers.update({i: [("own", {**{g: [] for g in GRANTS}, **{g: e[g] for g in COLLECTION_GRANTS}})]
                   for i, e in _collection_entries([r["id"] for r in seen if r["kind"] == "collection"]).items()})
    kinds = {r["id"]: r["kind"] for r in seen}
    rows = {(i, g, n): None if where == "own" else where
            for i, ls in layers.items() for where, grants in reversed(ls) for g in GRANTS for n in grants[g]}
    return sorted(({"entry": i, "kind": kinds[i], "privilege_type": g, "grantee": n, "inherited_from": where}
                   for (i, g, n), where in rows.items()),
                  key=lambda r: (r["entry"], r["privilege_type"], r["grantee"]))


def _iceberg_error(status, kind, message):
    return jsonify({"error": {"message": message, "type": kind, "code": status}}), status


def _switch_session(subject, sid, rows):
    """Point this login at the session named by the one row inserted into governance.sessions
    (PROVENANCE.md 3): the person's session of that name, started now if they have none.
    Returns whether it was started. Raises index_table.Refused."""
    def refuse(message):
        return index_table.Refused(400, "BadRequestException", message)
    if len(rows) != 1:
        raise refuse("insert one session name")
    row = rows[0]
    if any(row.get(k) is not None for k in ("started", "last_used", "current")):
        raise refuse("started, last_used and current are filled in by governance; insert into (name)")
    name = row.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise refuse("a session name is 1 to 200 characters, not all spaces")
    with db(commit=True) as cur:
        # xmax is 0 on a row this statement inserted, and set on one it updated.
        cur.execute("INSERT INTO sessions (person, name) VALUES (%s, %s) ON CONFLICT (person, name) "
                    "DO UPDATE SET last_used = now() RETURNING id, xmax = 0 AS started", (subject, name))
        row = cur.fetchone()
        cur.execute("INSERT INTO logins (person, sid, session) VALUES (%s, %s, %s) "
                    "ON CONFLICT (person, sid) DO UPDATE SET session = EXCLUDED.session",
                    (subject, sid, row["id"]))
    app.logger.info("SESSION person=%s -> %s (%s)", subject, name, "started" if row["started"] else "resumed")
    return row["started"]


@app.post("/sessions")
def switch_session():
    # The same lever as an insert into governance.sessions (PROVENANCE.md 3), for a client with
    # no Iceberg engine: {"name"}. It moves the pointer of the login the token was issued to.
    claims, err = authed_claims()
    if err:
        return err
    subject, sid = subject_of(claims), claims.get("sid") or ""
    body = request.get_json(silent=True) or {}
    if set(body) != {"name"}:
        return jsonify({"error": "body is {name}"}), 400
    try:
        started = _switch_session(subject, sid, [{"name": body["name"]}])
    except index_table.Refused as e:
        return jsonify({"error": e.message}), e.status
    return jsonify({"ok": True, "session": body["name"], "started": started}), 201 if started else 200


@app.post("/index/commit")
def index_commit():
    # The gate's answer to an engine's commit to one of <catalog>.governance's tables, on the
    # person's own token. Two accept one: a row inserted into sessions switches the login's
    # session, and derivations' rows are a declaration, checked and stored before the commit is
    # accepted (PROVENANCE.md 5.3, 5.5).
    claims, err = authed_claims(CATALOG_AUDIENCE)
    if err:
        return err
    body = request.get_json(silent=True) or {}
    name = body.get("table")
    if name not in index_table.WRITABLE:
        return _iceberg_error(403, "ForbiddenException", f"governance.{name} is read-only")
    subject, sid = subject_of(claims), claims.get("sid") or ""
    check = {"derivations": lambda rows: _declare(subject, rows),
             "sessions": lambda rows: _switch_session(subject, sid, rows)}[name]
    try:
        built = index_table.commit(subject, name, body.get("commit") or {}, check)
    except index_table.Refused as e:
        app.logger.info("REFUSE governance.%s person=%s: %s", name, subject, e.message)
        return _iceberg_error(e.status, e.kind, e.message)
    return jsonify(built)


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
    elif name == "lineage":
        rows = _lineage_rows(subject)
    elif name == "derivations":
        rows = _derivation_rows(subject)
    elif name == "releases":
        rows = _release_rows(subject)
    elif name == "grants":
        rows = _grant_rows(subject)
    elif name == "collection_members":
        rows = _collection_member_rows(subject)
    elif name == "drafts":
        rows = _draft_rows(subject)
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


# The S3 calls engines make on the governance tables' files, served on INDEX_PORT to requests
# addressed to governance-index.storage. The signature names the person; they may read only
# their own prefix, and write only under their own tables (index_table.writable_key), within
# their upload quota (index_table.MAX_UPLOAD).
index_app = Flask("index")
index_app.config["MAX_CONTENT_LENGTH"] = index_table.MAX_UPLOAD


def _signer():
    raw_path, _, raw_query = (request.environ.get("RAW_URI") or request.path).partition("?")
    return index_table.verify(request.method, raw_path, raw_query, request.headers)


def _xml(tag, inner, status=200):
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><{tag}>{inner}</{tag}>', status=status,
                    content_type="application/xml")


def _xml_texts(suffix):
    """The text of every element in the request's XML body whose tag ends with suffix. defusedxml
    refuses document type declarations, so no entity can expand."""
    try:
        root = parse_xml(request.get_data())
    except (ParseError, DefusedXmlException) as e:
        raise index_table.S3Error(400, "MalformedXML") from e
    return [e.text or "" for e in root.iter() if e.tag.endswith(suffix)]


def _payload():
    """The request body: decoded from aws-chunked encoding when the engine streams it, else
    checked against the hash the signature covers. None when the hash does not match. Chunk
    signatures are not checked: the request's own signature already names the person, and the
    bytes are that person's own upload."""
    raw = request.get_data()
    declared = request.headers.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
    if declared.startswith("STREAMING-"):
        out, i = bytearray(), 0
        while (j := raw.find(b"\r\n", i)) >= 0:
            size = int(raw[i:j].split(b";")[0], 16)
            if size == 0:
                break
            out += raw[j + 2:j + 2 + size]
            i = j + 2 + size + 2
        return bytes(out)
    if re.fullmatch(r"[0-9a-f]{64}", declared) and hashlib.sha256(raw).hexdigest() != declared:
        return None
    return raw


@index_app.errorhandler(index_table.S3Error)
def _refused_upload(e):
    return _s3_error(e.status, e.code)


@index_app.post("/")
def index_delete_objects():
    # DeleteObjects names its keys in the body; an engine sends it to abandon a write.
    subject = _signer()
    if subject is None or "delete" not in request.args:
        return _s3_error(403, "AccessDenied")
    keys = _xml_texts("Key")
    for k in keys:
        if index_table.writable_key(subject, k):
            index_table.delete(k)
    return _xml("DeleteResult", "".join(f"<Deleted><Key>{escape(k)}</Key></Deleted>" for k in keys))


@index_app.route("/<path:key>", methods=["PUT", "POST", "DELETE"])
def index_write(key):
    subject = _signer()
    if subject is None or not index_table.writable_key(subject, key):
        return _s3_error(403, "AccessDenied")
    args, upload = request.args, request.args.get("uploadId")
    if request.method == "POST" and "uploads" in args:   # CreateMultipartUpload
        upload = index_table.start_upload(subject, key)
        return _xml("InitiateMultipartUploadResult",
                    f"<Bucket>{index_table.BUCKET}</Bucket><Key>{escape(key)}</Key><UploadId>{upload}</UploadId>")
    if request.method == "POST" and upload:                # CompleteMultipartUpload
        numbers = [int(n) for n in _xml_texts("PartNumber") if n.isdigit()]
        data = index_table.complete_upload(subject, upload, key, numbers)
        etag = f'"{hashlib.md5(data).hexdigest()}-{len(numbers)}"'
        return _xml("CompleteMultipartUploadResult",
                    f"<Bucket>{index_table.BUCKET}</Bucket><Key>{escape(key)}</Key><ETag>{escape(etag)}</ETag>")
    if request.method == "DELETE":
        if upload:                                         # AbortMultipartUpload
            index_table.abort_upload(subject, upload, key)
        else:                                              # DeleteObject
            index_table.delete(key)
        return Response(status=204)
    if request.method != "PUT":
        return _s3_error(400, "InvalidRequest")
    data = _payload()
    if data is None:
        return _s3_error(400, "XAmzContentSHA256Mismatch")
    if upload:                                             # UploadPart
        number = args.get("partNumber", "")
        if not number.isdigit():
            return _s3_error(400, "InvalidArgument")
        index_table.put_part(subject, upload, key, int(number), data)
    else:                                                  # PutObject
        index_table.put(subject, key, data)
    return Response(status=200, headers={"ETag": f'"{hashlib.md5(data).hexdigest()}"'})


@index_app.route("/<path:key>", methods=["GET", "HEAD"])
def index_object(key):
    subject = _signer()
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
