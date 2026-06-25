# minilakehouse

An experimental **unified lakehouse Policy Decision Point (PDP)**: one external policy brain
(OPA) answers every authorization question, and every other service either *asks* OPA (a PEP)
or *obeys* a short-lived credential OPA gated (vending). OPA sits on the **decision path,
never the byte path**.

It collapses what is usually four drifting authorization layers (object-store IAM, catalog
RBAC, an engine plugin, per-service interceptors) into a single source of truth — across both
**Iceberg tables** (Trino → Polaris → Ceph RGW STS) and **non-tabular blob datasets** (a
vending broker) — with a real **metadata-visibility plane** (see-but-not-read) and a
**governed registry** kept honest against storage.

> A working `docker-compose` prototype. Dev-environment only: plaintext/no-TLS and dev
> credentials in `.env`. `DESIGN.md` has the full architecture and rationale.

## Contents

- [The idea](#the-idea)
- [Components](#components)
- [Run it](#run-it)
- [Flow A — discovery (see-but-not-read)](#flow-a--discovery-see-but-not-read)
- [Flow B — Iceberg tables](#flow-b--iceberg-tables)
- [Flow C — blob datasets](#flow-c--blob-datasets)
- [Registry freshness & governed ingest](#registry-freshness--governed-ingest)
- [Security model](#security-model)
- [Limitations](#limitations)

## The idea

Three roles, in XACML terms:

- **PDP** — OPA. Answers "is this allowed?" for one named resource at a time. It is a
  **predicate, never an enumerator**: it says yes/no on a resource you name, it never returns
  a list.
- **PAP** — the **governance** service. The single source of truth: it owns the dataset
  registry and all grants, and **publishes them to OPA as a bundle** (OPA pulls it). Nothing
  edits OPA directly.
- **PEP** — Polaris, Trino, the broker. They ask the PDP, then enforce — either by refusing,
  or by vending a credential scoped to exactly what was allowed.

Two independent permission **planes** per dataset:

- **visibility** — may you *see it exists*? (discovery, Flow A)
- **access** — may you *read the bytes*? (vending, Flows B/C)

So a dataset can be **see-but-not-read** (the Lake Formation model): `alice` can discover
`projx/private` exists but cannot read it.

**Why the idp-shim exists (tables):** Trino can only *assert* the end user (an unsigned note
Keycloak won't trust), so a real per-user token can't reach Polaris through Trino directly.
The shim is the one trusted place that converts "our Trino says this is alice" into a real
signed alice token. Polaris/OPA then enforce on the real identity — so the (open) Polaris API
has no skeleton key. The **broker (blobs)** needs no shim: the client presents its *own*
Keycloak token, which the broker verifies cryptographically — true end-to-end, no engine in
the byte path.

## Components

| Service | Role |
|---|---|
| **keycloak** | OIDC identity provider (users `alice`/`bob`, groups, the engine + shim service accounts). |
| **idp-shim** | Trusted identity layer for the table plane: turns Trino's per-user assertion into a real signed token Polaris validates. Polaris's OIDC issuer. |
| **governance** | The PAP + dataset registry (single source of truth), Postgres-backed. Publishes grants to OPA as a bundle, serves discovery (Flow A) + dataset→prefix, keeps the registry fresh (RGW events + a reconcile timer), and accepts governed ingest (`POST /datasets`). |
| **opa** | The PDP. Pulls policy + data from governance as a bundle (`opa/policy.rego` = tables, `opa/blob.rego` = blobs; grants derived from the registry). |
| **polaris** | Iceberg REST catalog. Delegates authorization to OPA; vends per-table STS. Holds identities, no rules. |
| **trino** | Query engine. Reads tables via Polaris with vended credentials. |
| **broker** | Blob vending broker (Flow C). Verifies the user's own token, asks OPA, vends a credential scoped to one dataset's prefix. |
| **ceph** | Ceph RGW: S3 + native STS. Enforces the vended (table or blob) credential. |
| **postgres** | Polaris metastore **and** the durable `governance` registry database. |

A one-shot `rgw-setup` configures bucket notifications + a least-privilege bucket policy at
startup, so the long-lived governance service never holds the RGW admin key.

## Run it

```bash
docker compose up -d --build      # build/pull and start everything
docker compose ps                 # wait until all services are healthy

# Seed the demo Iceberg table once, as its owner alice. (You cannot seed as root — the
# idp-shim refuses to mint a token for the internal admin, so the engine can't assert it.)
docker compose exec -T trino trino --user alice -f /seed/seed-table.sql
```

**About the demos below:** the discovery/blob demos present a user's *own* Keycloak token to
governance/the broker, which validate the token's issuer. Run them **in-network** (service
hostnames) so the issuer matches — the snippets use `docker compose exec` from inside a
container that already has `requests`/`boto3`. (A token fetched from the host `localhost` port
has a different issuer and would be rejected.)

## Flow A — discovery (see-but-not-read)

*"What exists that I could request?"* — separate from "what can I read." Governance
enumerates its registry and filters each entry through OPA's **visibility** predicate,
returning dataset **ids** only (never bytes or credentials). A dataset's id is the
tenant-qualified slice of its prefix: `datasets/projx/public/` → `projx/public`.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def tok(u): return requests.post(KC, data=dict(grant_type="password", client_id="trino",
    client_secret="trino-secret", username=u, password=u)).json()["access_token"]
for u in ("alice", "bob"):
    seen = requests.get("http://governance:8000/discover",
                        headers={"Authorization": f"Bearer {tok(u)}"}).json()["visible"]
    print(f"{u} sees:", [(e["id"], e["can_read"]) for e in seen])
PY
#  alice sees: [('projx/private', False), ('projx/public', True)]
#         ^ projx/private is VISIBLE but can_read=False — see-but-not-read
#  bob   sees: []
#         ^ bob is in no group with a visibility grant, so he sees nothing
```

OPA is a **predicate** here: governance asks "may S *see* dataset X?" per entry. It never
returns the inventory.

## Flow B — Iceberg tables

A user queries an Iceberg table through Trino. Their **real identity** (via the idp-shim)
reaches OPA; OPA decides; Polaris vends a short-lived, per-table STS credential that Trino
uses to read the files directly from RGW. OPA is consulted **once, at the vend** — never on
the byte path.

```bash
# ALLOW — alice is granted db.t1
docker compose exec -T trino trino --user alice --execute "SELECT * FROM iceberg.db.t1"
#  -> 1

# DENY — bob has no grant; denied at the credential vend (no credential is issued)
docker compose exec -T trino trino --user bob --execute "SELECT * FROM iceberg.db.t1"
#  -> Query failed: Failed to load table: t1 in db namespace

# See OPA decide, on the real per-user identity:
docker compose logs opa | grep LOAD_TABLE_WITH
#  -> alice ... "allow":true   |   bob ... "allow":false
```

## Flow C — blob datasets

The plane tables can't give you: **non-tabular data, accessed by a client presenting its own
token to a broker — no engine in the byte path**, so it's safe even against a compromised
engine. The broker verifies the token, asks OPA the yes/no question, and vends a credential
**narrowed to exactly the requested dataset's prefix**.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def tok(u): return requests.post(KC, data=dict(grant_type="password", client_id="trino",
    client_secret="trino-secret", username=u, password=u)).json()["access_token"]
def vend(u, ds): return requests.post("http://broker:9100/vend",
    headers={"Authorization": f"Bearer {tok(u)}"}, json={"dataset": ds}).status_code
print("alice projx/public :", vend("alice", "projx/public"))    # 200 -> scoped temp creds
print("alice projx/private:", vend("alice", "projx/private"))   # 403 -> visible but not readable
print("bob   projx/public :", vend("bob",   "projx/public"))    # 403 -> bob is granted nothing
PY
```

The returned credential reads `datasets/projx/public/*` but is **denied** sibling prefixes by
RGW — the broker derives the prefix from the id (`datasets/<id>/`) and binds it into the
credential's session policy itself. OPA never sees a path; it answers only "may S read X?".

## Registry freshness & governed ingest

The registry is the **mutable single source of truth**, so it lives in a real datastore (a
`governance` Postgres database) and is kept **honest against storage**. Two truths, reconciled
not merged: storage owns *existence/stats*, the registry owns *meaning/grants*.

- **Freshness.** `reconcile()` lists a dataset's prefix and sets `status`: non-empty → `live`;
  emptied-after-being-live → `gone`. Discovery advertises only `live` datasets. It runs on a
  timer (convergence) **and** is triggered by RGW bucket notifications (near-real-time); a
  missed event self-heals on the next sweep.
- **Register-at-ingest.** A *new* dataset is born through a governed write path that registers
  it **with its meaning** (prefix, description, grants — only a human can supply these; the id
  derives from the prefix). Authenticated by the caller's own token, **authorized by OPA**: the
  steward must be in the `stewards` group *and* the prefix must sit under a root one of their groups owns.

```bash
# Governed ingest of a NEW dataset, as alice (a steward who owns datasets/projz/):
docker compose exec governance python /seed/ingest-demo.py
#  -> uploaded 2 objects under datasets/projz/
#     register: 201 {'id': 'projz', 'ok': True, 'registered_by': 'alice'}

# Within one OPA bundle poll (<=10s) alice can discover AND read projz; she is DENIED
# registering under another group's namespace:
docker compose exec -T governance python - <<'PY'
import time, requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
t = requests.post(KC, data=dict(grant_type="password", client_id="trino",
    client_secret="trino-secret", username="alice", password="alice")).json()["access_token"]
h = {"Authorization": f"Bearer {t}"}
time.sleep(10)
print("discover:", [e["id"] for e in requests.get("http://governance:8000/discover", headers=h).json()["visible"]])
print("vend projz:", requests.post("http://broker:9100/vend", headers=h, json={"dataset": "projz"}).status_code)
print("register under datasets/projw/ (not owned):",
      requests.post("http://governance:8000/datasets", headers=h,
                    json={"prefix": "datasets/projw/x/"}).status_code)
PY
#  -> discover: ['projx/private', 'projx/public', 'projz']
#     vend projz: 200
#     register under datasets/projw/ (not owned): 403
```

Delete `projz`'s objects and within a tick it flips to `gone` and leaves discovery; re-add one
and it returns `live`. `bob` (not a steward) is denied registration entirely.

Because an id is the prefix's tenant slice, two stewards in different groups can each register
a dataset called `results` (`projx/results` and `projw/results`) — names never collide across
tenants, and neither can see the other's.

## Security model

- **One policy brain, deny-by-default.** Nothing is granted that OPA didn't allow, across both
  planes. Tables (`opa/policy.rego`): `root` / per-table vend grant / read-only metadata (any
  authed principal — this is the *visibility* half of see-but-not-read for tables) / writes &
  DDL (`writers`). Blobs (`opa/blob.rego`): `allow` (read) / `visible` (see) / `allow_register`
  (ingest), all group-based and published by governance.
- **Real, end-to-end identity.** Tables: the idp-shim converts Trino's assertion into a signed
  token Polaris validates — its signing key is **persisted** (a restart doesn't rotate it and
  break every cached token), it **refuses reserved principals** (`root`, `trino_svc`), and the
  engine proves itself with a **dedicated secret** distinct from the Keycloak client secret end
  users log in with (so a logged-in user can't drive the shim to mint arbitrary identities).
  Blobs: the broker verifies the user's **own** token (no engine in the byte path).
- **Least privilege on every credential.** STS roles use specific actions (no `s3:*`), prefix-
  scoped (`warehouse/` for tables, `datasets/` for blobs); the broker narrows further per
  request to one dataset prefix. The long-lived governance service holds only a **read-only RGW
  reader** (ListBucket on `datasets/*`, via a bucket policy) and a **realm-scoped `view-users`
  Keycloak service account** — never an admin key. Admin-only RGW setup runs in a one-shot.
- **Governed ingest is scoped.** A steward may register only under a prefix one of their groups
  owns (per-group ownership in OPA), prefixes are confined to `datasets/<...>/` (no traversal), and
  the overlap check + insert are serialized so two registrations can't claim overlapping
  prefixes.
- **Tenant-scoped identity.** Dataset ids are derived from per-tenant prefixes, not a global
  name, so names never collide across tenants and a registration leaks nothing cross-tenant.

## Limitations

- The shim trusts the engine's *asserted* end-user subject; binding "this caller is our engine"
  to the transport (mTLS / network policy) is future work — the engine proof is a shared secret
  today. See the trust-boundary discussion in `DESIGN.md`.
- Table-plane `writers` is a coarse global list (a writer may write any namespace); a real model
  would scope it per-namespace.
- No de-registration yet (a steward explicitly retiring a dataset, vs. it going `gone` because
  its bytes vanished). Discovery is blob-only; table discovery is via the catalog's own listing.
- Plaintext/no-TLS, dev credentials in `.env`, the OPA debug API exposed — all dev-only.
- RGW storage is ephemeral (no volume), so `docker compose down` then `up` clears it: the
  `projx` demo blobs are re-seeded automatically, but re-seed the table (the command above)
  and re-run the ingest demo for `projz`. (Re-running the `polaris-setup` one-shot likewise
  drops & recreates the catalog — re-seed the table after.)
