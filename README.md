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
- [Changing grants](#changing-grants)
- [Changing groups](#changing-groups)
- [Assigning roots](#assigning-roots)
- [Sessions and the access log](#sessions-and-the-access-log)
- [Security model](#security-model)
- [Limitations](#limitations)

## The idea

Three roles, in XACML terms:

- **PDP** — OPA. Answers "is this allowed?" for one named resource at a time. It is a
  **predicate, never an enumerator**: it says yes/no on a resource you name, it never returns
  a list.
- **PAP** — the **governance** service. The single source of truth: it holds the only copy
  of the dataset registry and all grants. OPA holds the rules and gets the relevant entry
  from governance with each decision, so a grant change applies at the next decision.
- **PEP** — Polaris, Trino, the broker. They ask the PDP, then enforce — either by refusing,
  or by vending a credential scoped to exactly what was allowed.

Two independent permission **planes** per dataset:

- **visibility** — may you *see it exists*? (discovery, Flow A)
- **access** — may you *read the bytes*? (vending, Flows B/C)

So a dataset can be **see-but-not-read** (the Lake Formation model): `alice` can discover
`projx/private` exists but cannot read it.

**How the user's identity reaches Polaris (tables):** the user connects to Trino with their
Keycloak token and attaches the same token as the Trino extra credential `token`. Trino's
Iceberg connector sends that token to Polaris as the bearer, unexchanged, so Polaris and OPA
decide on the person's own token and the engine never names a user itself. The **broker
(blobs)** gets the client's *own* Keycloak token directly and verifies it — no engine in the
byte path.

## Components

| Service | Role |
|---|---|
| **keycloak** | OIDC identity provider and the only token issuer (users `alice`/`bob`/`carol`, the `trino` login client and its service account). Proves who a person is; holds no groups. |
| **governance** | The PAP + dataset and table registries (single source of truth), Postgres-backed. Holds group membership and every grant. Serves them to OPA (`/internal/*`, closed to everyone else), serves the dataset index (Flow A), keeps the registry fresh (persistent RGW bucket notifications), accepts governed ingest (`POST /datasets`), table registration (`POST /tables`), grant changes (`PATCH /permissions/...`), group changes (`POST /groups`, `PATCH /groups/<name>`) and root ownership changes (`PATCH /roots/...`), keeps the access log and each login's current session, builds and serves each person's tables in the `governance` namespace, and creates each person's Polaris account on first use. |
| **opa** | The PDP, reachable only by its callers. Rules only (`opa/policy.rego` = Polaris's checks, `opa/tables.rego` = who may view a table or namespace, `opa/blob.rego` = blobs, `opa/groups.rego` = group administration). Every caller sends only who is asking and the ids it names; each rule fetches the person's groups and the grants it needs from governance (`opa/governance.rego`). |
| **polaris** | Iceberg REST catalog. Validates the user's Keycloak token; delegates authorization to OPA; vends per-table STS. Holds identities, no rules. |
| **gate** | The only way to Polaris. Verifies the token, trims listings to what the caller may view, answers "does not exist" for names they may not view, and, if Polaris refuses a table load that asked for a credential, repeats it without one, so DESCRIBE works for people who may view but not read. Decides which tables and schemas may be created, and reports creates and drops to governance. Has governance log every table credential it passes on and every table write it forwards, and refuses the request when that fails. Answers for the `governance` namespace's tables itself. |
| **trino** | Query engine. Authenticates users by their Keycloak token, forwards it to Polaris, reads tables with the credentials Polaris vends. |
| **loginproxy** | Sits in front of Trino so a client session outlives the 5-minute token. Speaks Trino's external-authentication (browser OAuth2) protocol to the client, holds the person's refresh token, and puts a fresh token on every forwarded request as the bearer and the `token` extra credential. |
| **broker** | Blob vending broker (Flow C). Verifies the user's own token, asks OPA about the named dataset, vends a credential scoped to the prefix in OPA's decision: to read (get and list, on the dataset's `read`) or to write (put and delete, no get, on its `write`). Has governance log each credential before returning it. |
| **ceph** | Ceph RGW: S3 + native STS. Enforces the vended (table or blob) credential. |
| **postgres** | Polaris metastore **and** the durable `governance` registry database. |

A one-shot `rgw-setup` configures bucket notifications + a least-privilege bucket policy at
startup, so the long-lived governance service never holds the RGW admin key.

## Run it

```bash
docker compose up -d --build      # build/pull and start everything
docker compose ps                 # wait until all services are healthy

# q <user> <trino args>: run the Trino CLI as <user> with a fresh Keycloak token. Trino takes
# the token twice: --access-token authenticates the user to Trino, --extra-credential token=...
# is what Trino forwards to Polaris. --user must equal the token's username (no impersonation).
# Tokens go only over HTTPS; the container's self-signed keystore doubles as the truststore.
q() {
  u=$1; shift
  T=$(docker compose exec -T governance python /seed/user_token.py "$u")
  docker compose exec -T trino trino --server https://localhost:8443 \
    --truststore-path /tmp/trino-tls.p12 --truststore-password trino-tls-dev \
    --user "$u" --access-token "$T" --extra-credential token="$T" "$@"
}

# Seed the demo Iceberg table once, as its owner alice.
q alice -f /seed/seed-table.sql
```

Keycloak access tokens last 5 minutes; `q` fetches a fresh one per command. A real client
instead logs in once through the **loginproxy**, which refreshes on its behalf:

```bash
# Log in once (browserless helper, standing in for the CLI's browser handshake) and reuse the
# session token across commands; the proxy swaps in a fresh Keycloak token on every request,
# so the session lasts as long as the person's Keycloak login, not 5 minutes.
SID=$(docker compose exec -T governance python /seed/proxy_login.py alice)
pq() { docker compose exec -T trino trino --server https://loginproxy:9200 --insecure \
         --user alice --access-token "$SID" "$@"; }
pq --execute "SELECT * FROM iceberg.db.t1"      # -> 1
# A real CLI user runs instead:  trino --server https://<proxy> --external-authentication
```

`--insecure` skips verifying the proxy's self-signed dev cert (dev only); the proxy verifies
Trino's cert, pinned at startup.

**About the demos below:** the blob demos present a user's *own* Keycloak token to
governance/the broker, which validate the token's issuer. Run them **in-network** (service
hostnames) so the issuer matches — the snippets use `docker compose exec` from inside a
container that already has `requests`/`boto3`. (A token fetched from the host `localhost` port
has a different issuer and would be rejected.) Each service accepts only tokens issued for it,
so each demo asks Keycloak for that service's audience: `scope=openid aud-broker`,
`aud-governance`, or `aud-polaris` for Trino and the catalog (`keycloak/setup.py`).

## Flow A — discovery (see-but-not-read)

*"What exists that I could request?"* — separate from "what can I read." Every engine
connected to the catalog can query the answer as an Iceberg table, `governance.datasets`: one
row per live dataset or table the person may see, with whether they may read it, and never
bytes or credentials. A file dataset's id is the tenant-qualified slice of its prefix:
`datasets/projx/public/` → `projx/public`.

```bash
q alice --execute "SELECT * FROM iceberg.governance.datasets"
#  -> "projx/private","files","projx private data","alice","false"
#     "projx/public","files","projx public data","alice","true"
#     "lakehouse.db.t1","table","demo table","alice","true"
#         ^ projx/private is visible but can_read is false: see-but-not-read
q bob --execute "SELECT count(*) FROM iceberg.governance.datasets"
#  -> "0"     bob is in no group with a grant, so he sees nothing
```

The gate answers for this table itself. Governance builds its files for the person loading
it (one database query, then one OPA decision per kind: governance builds the candidate list
and OPA says which candidates pass; the candidates are only entries whose viewing grants
name one of the person's groups, so the work follows what the person may see, not the
catalog's size, and `seed/check-index-narrowing.py` checks that this drops nothing OPA would
show), keeps them in memory, and serves them from an S3-style endpoint that accepts only the
short-lived credential issued with that load, signed per request. Every dataset's actual
data stays in Ceph. The file paths carry a hash of the rows, so a grant change appears at
the next query and no cache can serve one person's rows to another.

Engines reach storage at one address, `storage.internal:8080`, with the bucket in the host
name, as AWS S3 routes buckets: Docker DNS sends `lakehouse.storage.internal` to Ceph and
`governance-index.storage.internal` to governance, so no engine needs a setting that names
the index. The names end in `.internal`, which never resolves publicly, so a location naming
any other bucket reaches no host at all. Ceph accepts that addressing because `rgw_dns_name`
lists `storage.internal` (`ceph/rgw-entrypoint.sh`).

## Flow B — Iceberg tables

A user queries an Iceberg table through Trino with their own Keycloak token, which Trino
forwards to Polaris. OPA decides on that token's principal, fetching the table's grants from
governance; Polaris vends a short-lived, per-table STS credential that Trino uses to read the
files directly from RGW. OPA is consulted at the vend — never on the byte path.

```bash
# (q is defined under "Run it")
# ALLOW — alice is granted db.t1
q alice --execute "SELECT * FROM iceberg.db.t1"
#  -> "1"

# DENY — bob authenticates fine but has no grant, so for him the table and its schema do not
# exist: the same answer as for a name nobody created
q bob --execute "SELECT * FROM iceberg.db.t1"
#  -> Query ... failed: line 1:15: Schema 'db' does not exist

# A new table is registered first, by a steward whose group owns the schema, with its grants;
# then someone in its `write` grant creates it. An unregistered table is refused.
docker compose exec -T governance python -c "
import subprocess, requests
t = subprocess.run(['python', '/seed/user_token.py', 'alice', 'governance'], capture_output=True, text=True).stdout.strip()
print(requests.post('http://localhost:8000/tables', headers={'Authorization': 'Bearer ' + t},
      json={'id': 'lakehouse.db.t2', 'read': ['jgi-writers'], 'write': ['jgi-writers']}).json())"
#  -> {'id': 'lakehouse.db.t2', 'ok': True, 'status': 'pending'}
q alice --execute "CREATE TABLE iceberg.db.t2 AS SELECT 2 AS y"
#  -> CREATE TABLE: 1 row      (governance now lists lakehouse.db.t2 as live)

# See what OPA was asked, on the real per-user identity (bob is refused at the schema check,
# which the gate answers as not-found):
docker compose logs opa | grep -E 'LOAD_TABLE_WITH|NAMESPACE_EXISTS'
#  -> alice ... LOAD_TABLE_WITH_WRITE_DELEGATION   |   bob ... NAMESPACE_EXISTS
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
    client_secret="trino-secret", username=u, password=u,
    scope="openid aud-broker")).json()["access_token"]
def vend(u, ds): return requests.post("http://broker:9100/vend",
    headers={"Authorization": f"Bearer {tok(u)}"}, json={"dataset": ds}).status_code
print("alice projx/public :", vend("alice", "projx/public"))    # 200 -> scoped temp creds
print("alice projx/private:", vend("alice", "projx/private"))   # 403 -> visible but not readable
print("bob   projx/public :", vend("bob",   "projx/public"))    # 403 -> bob is granted nothing
PY
```

The returned credential reads `datasets/projx/public/*` but is **denied** sibling prefixes by
RGW — OPA's decision carries the prefix the dataset was registered with, and the broker
scopes the session policy to it. A dataset id that doesn't exist gets the same 403 as a
denied one.

## Registry freshness & governed ingest

The registry is the **mutable single source of truth**, so it lives in a real datastore (a
`governance` Postgres database) and is kept **honest against storage**. Two truths, reconciled
not merged: storage owns *existence*, the registry owns *meaning/grants*.

- **Freshness.** Each object created or deleted under a dataset's folder makes RGW notify
  governance, which checks that one folder (a listing capped at one object) and sets `status`:
  non-empty → `live`; emptied-after-being-live → `gone`. The dataset index lists only `live`
  datasets. The notification topic is persistent: RGW queues each event and retries it until
  governance accepts it, so an event sent while governance is down arrives once it is back.
  There is no periodic sweep.
- **Register-at-ingest.** A *new* dataset is born through a governed write path that registers
  it **with its meaning** (prefix, description, grants — only a human can supply these; the id
  derives from the prefix). Authenticated by the caller's own token, **authorized by OPA**: the
  steward must be in the `stewards` group *and* the prefix must sit under a root one of their groups owns.
  The upload uses a write credential from the broker (`"mode": "write"`), which the dataset's
  `write` grant allows: it puts and deletes in that folder only and cannot read or list.

```bash
# Governed ingest of a NEW dataset, as alice (a steward who owns datasets/projz/):
docker compose exec governance python /seed/ingest-demo.py
#  -> register: 201 {'id': 'projz', 'ok': True, 'registered_by': 'alice'}
#     uploaded 2 objects under datasets/projz/ with a write credential

# alice finds and reads projz at once; she is DENIED registering under another group's
# namespace:
docker compose exec -T governance python - <<'PY'
import requests
from pyiceberg.catalog.rest import RestCatalog
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def tok(aud): return requests.post(KC, data=dict(grant_type="password", client_id="trino",
    client_secret="trino-secret", username="alice", password="alice",
    scope=f"openid aud-{aud}")).json()["access_token"]
index = RestCatalog("gate", uri="http://gate:8182/api/catalog", warehouse="lakehouse",
                    token=tok("polaris")).load_table("governance.datasets")
print("index:", [r["id"] for r in index.scan().to_arrow().to_pylist()])
print("vend projz:", requests.post("http://broker:9100/vend", json={"dataset": "projz"},
      headers={"Authorization": "Bearer " + tok("broker")}).status_code)
print("register under datasets/projw/ (not owned):",
      requests.post("http://governance:8000/datasets", json={"prefix": "datasets/projw/x/"},
                    headers={"Authorization": "Bearer " + tok("governance")}).status_code)
PY
#  -> index: ['projx/private', 'projx/public', 'projz', 'lakehouse.db.t1']
#     vend projz: 200
#     register under datasets/projw/ (not owned): 403
```

Delete `projz`'s objects and it flips to `gone` and leaves the index; re-add one
and it returns `live`. `bob` (not a steward) is denied registration entirely.

Because an id is the prefix's tenant slice, two stewards in different groups can each register
a dataset called `results` (`projx/results` and `projw/results`) — names never collide across
tenants, and neither can see the other's.

## Changing grants

`PATCH /permissions/<dataset|table>/<id>` adds and removes groups from an entry's grants, in
the shape of Unity Catalog's permissions API. OPA decides each change (`allow_change`):
`see` and `read` change only for someone in a group holding the entry's `share`; `share`, and
a table's `write` and `delete`, only for someone whose group owns the root the entry sits
under (the prefix root or namespace that registration checks). A change applies at the next
decision.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def h(aud): return {"Authorization": "Bearer " + requests.post(KC, data=dict(grant_type="password",
    client_id="trino", client_secret="trino-secret", username="alice", password="alice",
    scope=f"openid aud-{aud}")).json()["access_token"]}
def change(op):
    return requests.patch("http://governance:8000/permissions/dataset/projx/private",
        headers=h("governance"),
        json={"changes": [{"group": "jgi-writers", op: ["read"]}]}).json()["grants"]["read"]
vend = lambda: requests.post("http://broker:9100/vend", headers=h("broker"),
                             json={"dataset": "projx/private"}).status_code
print("grant read :", change("add"), vend())
print("revoke read:", change("remove"), vend())
PY
#  -> grant read : ['jgi-writers'] 200
#     revoke read: [] 403
```

alice may change `read` on `projx/private` because `jgi-writers` holds its `share`; bob gets
403 for any change, the same answer as for an id that does not exist.

## Changing groups

Each group has owners, which are themselves groups. Anyone in one of a group's owners may add
and remove its members and owners (`PATCH /groups/<name>`); only `group-admins` may create a
group (`POST /groups`), naming its first owners. OPA decides both (`opa/groups.rego`). A change
that would leave a group without an owner is refused, and so is creating a group under a name
some grant or ownership already uses, since whoever joined it would hold those grants. The
seed has `jgi-writers` and `projw-team` own themselves, and `group-admins` (carol) own
`stewards`, `no-access` and itself.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def h(u, aud): return {"Authorization": "Bearer " + requests.post(KC, data=dict(
    grant_type="password", client_id="trino", client_secret="trino-secret", username=u,
    password=u, scope=f"openid aud-{aud}")).json()["access_token"]}
def members(op):  # alice is in jgi-writers, which owns itself
    return requests.patch("http://governance:8000/groups/jgi-writers",
        headers=h("alice", "governance"), json={"members": {op: ["bob"]}}).json()["members"]
vend = lambda: requests.post("http://broker:9100/vend", headers=h("bob", "broker"),
                             json={"dataset": "projx/public"}).status_code
print("add bob   :", members("add"), vend())
print("remove bob:", members("remove"), vend())
PY
#  -> add bob   : ['alice', 'bob'] 200
#     remove bob: ['alice'] 403
```

## Assigning roots

A group owning a prefix root (`datasets/projx/`) or a namespace (`lakehouse.db`) owns
everything under it: its members may change `share`, `write` and `delete` on what is
registered there, and those who are also in `stewards` may register there.
`PATCH /roots/<dataset|namespace>/<id>` adds and removes a root's owners (a dataset root is
named like a dataset id: `projx/sub` is `datasets/projx/sub/`). OPA decides
(`allow_change_root`): `group-admins` assign top-level roots (`datasets/<name>/`,
`<catalog>.<namespace>`), and anyone in a group owning a root or one above it may change its
owners. So an owner can hand part of its tree to another group, and can always take it back.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def h(u): return {"Authorization": "Bearer " + requests.post(KC, data=dict(grant_type="password",
    client_id="trino", client_secret="trino-secret", username=u, password=u,
    scope="openid aud-governance")).json()["access_token"]}
def owners(u, root, op, group):
    r = requests.patch(f"http://governance:8000/roots/dataset/{root}", headers=h(u),
                       json={"owners": {op: [group]}})
    return r.status_code, r.json().get("owners")
# alice's jgi-writers owns datasets/projx/; carol is in projw-team
print("alice gives projx/sub to projw-team    :", owners("alice", "projx/sub", "add", "projw-team"))
print("carol passes projx/sub/t2 to no-access :", owners("carol", "projx/sub/t2", "add", "no-access"))
print("bob tries to take projx/sub            :", owners("bob", "projx/sub", "add", "no-access"))
print("alice takes both back                  :", owners("alice", "projx/sub/t2", "remove", "no-access"),
      owners("alice", "projx/sub", "remove", "projw-team"))
PY
#  -> alice gives projx/sub to projw-team    : (200, ['projw-team'])
#     carol passes projx/sub/t2 to no-access : (200, ['no-access'])
#     bob tries to take projx/sub            : (403, None)
#     alice takes both back                  : (200, []) (200, [])
```

## Sessions and the access log

Build step 1 of `PROVENANCE.md`. Governance logs every dataset credential handed to a person
and every table write, stamped with the session the person's login points at, before the gate
or the broker passes it on; when the log fails, the request is refused. A person's first
access starts a session named `default`, and a new login continues the most recently used
session. Naming and switching sessions, and declaring what an output was derived from, are
not built yet.

After alice's reads in Flow B and Flow C:

```bash
q alice --execute "SELECT * FROM iceberg.governance.sessions"
#  -> "default","2026-10-22 23:21:58.824845 UTC","2026-10-22 23:21:59.143470 UTC","true"
q alice --execute "SELECT dataset, kind, session FROM iceberg.governance.accessed"
#  -> "lakehouse.db.t1","table","default"
#     "projx/public","files","default"
q bob --execute "SELECT count(*) FROM iceberg.governance.accessed"
#  -> "0"     bob's refused read handed him no credential, so nothing is logged
```

`accessed` holds the current session's reads. A table someone writes to is also read: loading
it to append hands out a credential that can read it.

## Security model

- **One policy brain, deny-by-default.** Nothing is granted that OPA didn't allow, across both
  planes, all by group. Tables (`opa/policy.rego`): `root` / read credential (`read` or
  `write`) / viewing a table's columns and location (`see`, `read` or `write`) / viewing a
  schema (its owners, or any grant on a table in it) / listings (anyone; the gate trims them
  to what may be viewed) / creating (a registered table with the person in its `write`, or a
  schema under one their group owns) / writes and read-write credentials (`write`) /
  dropping a table or view, files included (`delete`). Blobs (`opa/blob.rego`): `vend`
  (read) / `vend_write` (write) / `visible` (see or read) / `allow_register` (ingest). Grant changes (`allow_change` in
  both): `see` and `read` by `share` holders; `share`, `write` and `delete` by root owners.
  Group changes (`opa/groups.rego`): a group's owners change its members and owners;
  `group-admins` create groups. Root ownership (`allow_change_root` in `blob.rego` and
  `tables.rego`): `group-admins` for top-level roots, owners of a root or one above it below. Group membership and every grant
  come from governance at decision time; tokens carry no groups.
- **Real, end-to-end identity.** Every decision is made on the user's own Keycloak token.
  Each service accepts only tokens issued for it (audience `polaris` for Trino, the gate and
  Polaris; `broker`; `governance`). Tables: Trino and Polaris both validate it (issuer,
  expiry, audience); Trino's username is the token's `principal_name` and impersonation is
  refused; the engine's own service account is granted nothing. Blobs: the broker verifies the
  user's **own** token (no engine in the byte path).
- **Entry lookups answer only OPA.** Governance's `/internal/*` returns grants for datasets a
  user can't see, so it is served only on a TLS listener that requires OPA's client
  certificate (`governance/pki.py`). OPA reads the key from a file, which, unlike its
  environment, its query API cannot return; and only its callers can reach OPA at all. The
  gate's table create/drop reports use the same listener with a certificate named `gate`.
- **Storage events carry a secret.** RGW puts a shared secret (the topic's opaque data) in
  every bucket notification; governance refuses events without it.
- **Least privilege on every credential.** STS roles use specific actions (no `s3:*`), prefix-
  scoped (`warehouse/` for tables, `datasets/` for blobs); the broker narrows further per
  request to one dataset prefix. No long-lived service holds an admin key: Polaris and the
  broker each authenticate as an RGW user that can only assume its vending role, and
  governance holds a **read-only RGW reader** (ListBucket on `datasets/*`, via a bucket
  policy). Admin-only RGW setup runs in a one-shot.
- **Governed ingest is scoped.** A steward may register only under a prefix one of their groups
  owns (per-group ownership in OPA), prefixes are confined to `datasets/<...>/` (no traversal), and
  the overlap check + insert are serialized so two registrations can't claim overlapping
  prefixes.
- **Tenant-scoped identity.** Dataset ids are derived from per-tenant prefixes, not a global
  name, so names never collide across tenants and a registration leaks nothing cross-tenant.

## Limitations

- A client that logs in through the **loginproxy** stays connected as long as the person's
  Keycloak login lasts (the proxy refreshes for it). A client pointed straight at Trino with
  one token (the `q` helper) is cut off after 5 minutes. The proxy holds sessions in memory,
  so restarting it logs everyone out.
- With `see` only, DESCRIBE works through Trino (via the `gate`) and SELECT fails; an INSERT
  fails with "Failed to initialize the vended credentials" rather than access denied.
- A refused create's first line is Trino's own ("Failed to create transaction"); the gate's
  reason is the error's cause, which the CLI prints with `--debug`.
- Polaris 1.5 needs an account for every person; the gate has governance create it the first
  time each person shows up. When a Polaris release has the `external` credential mode, that
  step goes away.
- Every decision reads governance: if governance is down, every read is denied.
- The dataset index's files are held in governance's memory: a restart drops them and the next
  load rebuilds them.
- Plaintext/no-TLS everywhere except Trino's token port, which uses a self-signed keystore
  generated at container start; dev credentials in `.env` — all dev-only.
- Ceph keeps its data on the `ceph_data` volume across restarts and recreation;
  `docker compose down -v` clears it, after which re-seed the table (the command above) and
  re-run the ingest demo for `projz`. Re-running the `polaris-setup` one-shot drops and
  recreates the catalog, so re-seed the table after that too.
