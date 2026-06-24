# minilakehouse — Phase 0

A docker-compose prototype proving **Flow B**: OPA-gated Iceberg table access through
Trino → Polaris → Ceph RGW, with per-table STS credential vending and **real per-user
identity** reaching the policy engine.

See `DESIGN.md` for the architecture and `idp-shim/app.py` for the identity layer.

## What it proves

A user queries an Iceberg table through Trino. Their **real identity** reaches OPA (the
one policy brain), OPA decides, and Polaris vends a short-lived, per-table STS
credential that Trino uses to read the files directly from RGW.

- **alice** is granted `db.t1` → her query returns rows.
- **bob** is not → his query is denied at the credential vend; no credential is issued.

OPA is consulted **once, at the vend** — never on the byte path.

## The pieces

| Service | Role |
|---|---|
| **keycloak** | OIDC identity provider (users alice/bob, groups) |
| **idp-shim** | Trusted identity layer: turns Trino's per-user assertion into a real signed token Polaris accepts. Polaris's OIDC issuer. |
| **governance** | The PAP + dataset registry (single source of truth), **Postgres-backed**. Owns the registry + all grants, publishes them to OPA as a bundle, serves discovery (Flow A) + dataset→prefix, **keeps the registry fresh** (RGW events + a reconcile timer) and accepts **governed ingest** (`POST /datasets`, OPA-gated). |
| **opa** | The Policy Decision Point. Pulls policy + data from governance as a bundle (`opa/policy.rego`, `opa/blob.rego` + grants derived from the registry). |
| **polaris** | Iceberg REST catalog. Authorizer delegates to OPA; vends per-table STS. Holds only identities, no rules. |
| **trino** | Query engine. Reads tables via Polaris with vended credentials. |
| **broker** | Blob vending broker (Flow C). Verifies the user's own token, asks OPA, vends a credential scoped to one dataset's prefix. The true end-to-end plane. |
| **ceph** | Ceph RGW: S3 + native STS. Enforces the vended (table or blob) credential. |
| **postgres** | Polaris metastore **and** the durable `governance` registry database. |

Why the shim exists: Trino can only *assert* the end user (an unsigned note Keycloak
won't trust), so a real per-user token can't reach Polaris through Trino directly. The
shim is the one trusted place that converts "our Trino says this is alice" into a real
signed alice token. Polaris/OPA then enforce on the real identity — so the (open)
Polaris API has no skeleton key.

## Run it

```bash
docker compose up -d --build          # ~all services build/pull and come up

# wait until everything is healthy
docker compose ps

# seed the demo table once, as its owner alice (a "writer" in opa/data.json).
# NOTE: you can't seed as `root` through Trino — the idp-shim refuses to mint a
# token for the internal admin (the engine must not be able to assert root).
docker compose exec -T trino trino --user alice -f /seed/seed-table.sql
```

## The demo

```bash
# ALLOW — alice is granted db.t1
docker compose exec -T trino trino --user alice --execute "SELECT * FROM iceberg.db.t1"
#  -> returns: 1

# DENY — bob has no grant; denied at the credential vend
docker compose exec -T trino trino --user bob --execute "SELECT * FROM iceberg.db.t1"
#  -> Query failed: Failed to load table: t1 in db namespace

# See OPA decide, on the real per-user identity:
docker compose logs opa | grep LOAD_TABLE_WITH
#  -> alice ... "result":{"allow":true}   |   bob ... "result":{"allow":false}
```

To change who can read what, edit `opa/data.json` (OPA hot-reloads via `--watch`) —
the rules live entirely in OPA, never in Polaris.

## Flow C — blob datasets (the true end-to-end plane)

Phase 1 adds the plane tables can't give you: **non-tabular data, accessed by a client
presenting its *own* token to a broker — no engine in the byte path**, so it's safe even
against a compromised engine. The broker verifies the user's token, asks OPA the yes/no
question, and vends a credential **narrowed to exactly the requested dataset's prefix**.

`alice` (group `jgi-writers`) is granted `projx-public` but not `projx-private`; `bob`
neither. (Grants in `opa/blob-data.json`; the dataset→prefix registry in
`broker/datasets.json`.)

```bash
# get alice's OWN Keycloak token (real signed token; the broker verifies it)
ALICE=$(curl -s http://localhost:18080/realms/lakehouse/protocol/openid-connect/token \
  -d grant_type=password -d client_id=trino -d client_secret=trino-secret \
  -d username=alice -d password=alice | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# ALLOW — alice may read projx-public; broker returns a scoped, temporary credential
curl -s http://localhost:19091/vend -H "Authorization: Bearer $ALICE" \
  -H 'Content-Type: application/json' -d '{"dataset":"projx-public"}'
#  -> {"access_key_id":...,"session_token":...,"prefix":"datasets/projx/public/",...}
#     Those creds read datasets/projx/public/* but are DENIED datasets/projx/private/* by RGW.

# DENY — alice is not granted projx-private  (and bob is granted nothing)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:19091/vend \
  -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d '{"dataset":"projx-private"}'        # -> 403
```

OPA is consulted as a **predicate** — "may this subject read this named dataset?" → yes/no.
It never enumerates paths; the broker owns the dataset→prefix mapping and binds the prefix
into the credential's session policy itself.

## Flow A — discovery (the metadata-visibility plane)

The other half of governance: **"what exists that I could request"**, separate from
"what I can read." The **governance** service owns a dataset registry
(`governance/registry.json`) with two independent grant sets per dataset — `visibility`
(may you *see* it exists) and `access` (may you *read* it). Discovery enumerates the
registry and filters each entry through OPA's *visibility* predicate. The point is
**see-but-not-read**: `alice` can discover `projx-private` exists, but cannot read it.

```bash
ALICE=$(curl -s http://localhost:18080/realms/lakehouse/protocol/openid-connect/token \
  -d grant_type=password -d client_id=trino -d client_secret=trino-secret \
  -d username=alice -d password=alice | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s http://localhost:19092/discover -H "Authorization: Bearer $ALICE" | python3 -m json.tool
#  -> projx-public  (can_read: true)
#     projx-private (can_read: FALSE  <- visible, but not readable)
#     (projy-secret is absent — alice can't even see it exists)
```

Discovery returns **names, never bytes or credentials** — to actually read, the client
goes to the broker (Flow C), which independently enforces the *access* plane. So
requesting `projx-private` from the broker returns 403 even though alice can see it.

OPA is, again, a **predicate** — governance asks "may this subject *see* dataset X?"
per registry entry; OPA never returns the inventory. Governance is the single source of
truth: it owns the registry + all grants and **publishes them to OPA as a bundle** (OPA
pulls it; the `opa/*.json` files are gone).

## Registry freshness + governed ingest (Phase 3)

The registry is the **mutable single source of truth**, so it lives in a real datastore (a
`governance` Postgres database) and is kept **honest against storage**. Two truths,
reconciled not merged: storage owns *existence/stats*, the registry owns *meaning/grants*.

- **Freshness.** `reconcile()` lists a dataset's prefix and sets `status`:
  non-empty → `live`; emptied-after-being-live → `gone`. Discovery advertises only `live`
  datasets — never a dead one. It runs on a timer (convergence) **and** is triggered by RGW
  bucket notifications (near-real-time). Events carry no authority; a missed one self-heals
  on the next sweep.
- **Register-at-ingest.** A *new* dataset is born through a governed write path that
  registers it **with its meaning** — only a human can supply name/boundary/grants. The
  endpoint is authenticated by the caller's own token and **authorized by OPA** (the
  `stewards` capability lives in the bundle, not in governance).

Demos run **in-network** (service hostnames), so the token issuer matches what governance
validates:

```bash
# governed ingest of a NEW dataset `projz`, as alice (a steward): upload + register
docker compose exec governance python /seed/ingest-demo.py
#  -> uploaded 2 objects under datasets/projz/
#     register: 201 {'name': 'projz', 'ok': True, 'registered_by': 'alice'}

# within one OPA bundle poll (≤10s) alice can discover AND read projz:
docker compose exec -T governance python - <<'PY'
import requests
KC="http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
t=requests.post(KC,data=dict(grant_type="password",client_id="trino",client_secret="trino-secret",username="alice",password="alice")).json()["access_token"]
h={"Authorization":f"Bearer {t}"}
print("discover:",[e["name"] for e in requests.get("http://governance:8000/discover",headers=h).json()["visible"]])
print("vend projz:",requests.post("http://broker:9100/vend",headers=h,json={"dataset":"projz"}).status_code)
PY
#  -> discover: ['projx-private', 'projx-public', 'projz']
#     vend projz: 200

# freshness: delete projz's objects -> within a tick it flips to `gone` and leaves discovery;
# re-add an object -> `live` again. A reconcile timer converges even if an event is dropped.
```

`bob` (not in `stewards`) is denied at registration (`POST /datasets` → 403) — ingest authz
is the same OPA brain that gates reads.

## Security model (after the post-audit hardening)

- **idp-shim is not a minting oracle.** Token-exchange requires the caller to prove it
  is the engine (the trino client secret, or a service token the shim already issued),
  and the shim refuses to mint reserved principals (`root`, `trino_svc`) — so the engine
  can relay end users but never escalate to admin.
- **OPA denies by default.** Four lanes: `root` (admin), the credential vend (gated on a
  per-table grant), read-only/metadata ops (any authed principal), and write/DDL ops
  (`writers` only). Everything else — principal/role/grant/catalog/policy/credential
  management — is root-only. So `bob`, denied data, also cannot drop the catalog or
  create principals.
- **STS role is least-privilege.** Specific object/bucket actions (no `s3:*`), scoped to
  the `warehouse/` prefix, so a missing per-table session policy fails to the warehouse,
  not the whole bucket (and can't reach future blob datasets).

## Notes / prototype limitations

- The idp-shim's "is the engine" check is the trino client secret; production must bind
  it to the engine more strongly (mTLS / network policy). The end-user subject it relays
  is still the engine's (trusted) assertion — see DESIGN §9b on the trust boundary.
- Decisions key on the username (`actor.principal`). Group-based rules need governance
  to publish group membership into OPA's data (not into Polaris).
- `writers` is a coarse global list (a writer may write any namespace); a real model
  would scope it per-namespace.
- Metadata visibility (listing) is open by design; data is protected by the vend gate.
  A separate metadata-visibility plane is a later phase.
- Plaintext/no-TLS, hardcoded dev secrets, OPA debug API exposed — all prototype-only.
- Re-running the `polaris-setup` one-shot drops & recreates the catalog (re-seed after).
