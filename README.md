# minilakehouse

An experimental **unified lakehouse Policy Decision Point (PDP)**: one external policy brain
(OPA) answers every authorization question, and every other service either *asks* OPA (a PEP)
or *obeys* a short-lived credential OPA gated (vending). OPA sits on the **decision path,
never the byte path**.

It collapses what is usually four drifting authorization layers (object-store IAM, catalog
RBAC, an engine plugin, per-service interceptors) into a single source of truth — across both
**Iceberg tables** (Trino → Polaris → Ceph RGW STS) and **non-tabular blob datasets** (a
vending broker) — with a real **metadata-visibility plane** (describe-but-not-read) and a
**governed registry** kept honest against storage.

> A working `docker-compose` prototype. Dev-environment only: plaintext/no-TLS and dev
> credentials in `.env`. `DESIGN.md` has the full architecture and rationale.

## Contents

- [The idea](#the-idea)
- [Components](#components)
- [Run it](#run-it)
- [Flow A — discovery (describe-but-not-read)](#flow-a--discovery-describe-but-not-read)
- [Flow B — Iceberg tables](#flow-b--iceberg-tables)
- [Flow C — blob datasets](#flow-c--blob-datasets)
- [Registry freshness & governed ingest](#registry-freshness--governed-ingest)
- [Spaces and publishing](#spaces-and-publishing)
- [Collections](#collections)
- [Changing grants](#changing-grants)
- [Changing groups](#changing-groups)
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

- **describe** — may you list it and load its metadata? (discovery, Flow A)
- **access** — may you *read the bytes*? (vending, Flows B/C)

So a dataset can be **describe-but-not-read** (the Lake Formation model): `alice` can discover
`projw/private` exists but cannot read it.

**How the user's identity reaches Polaris (tables):** the user connects to Trino with their
Keycloak token and attaches the same token as the Trino extra credential `token`. Trino's
Iceberg connector sends that token to Polaris as the bearer, unexchanged, so Polaris and OPA
decide on the person's own token and the engine never names a user itself. The **broker
(blobs)** gets the client's *own* Keycloak token directly and verifies it — no engine in the
byte path.

## Components

| Service | Role |
|---|---|
| **keycloak** | OIDC identity provider and the only token issuer (users `alice`/`bob`/`carol`, the `trino` login client and its service account). Proves who a person is; holds no groups. Its realm role `platform-admin` (carol) marks platform admins. |
| **governance** | The PAP + dataset and table registries (single source of truth), Postgres-backed. Holds group membership and every grant. Serves them to OPA (`/internal/*`, closed to everyone else), serves the dataset index (Flow A), keeps the registry fresh (persistent RGW bucket notifications), makes a folder an entry at its first credential, accepts publishing (`PATCH /datasets/<id>`, `PATCH /namespaces/<id>`), grant changes (`PATCH /permissions/...`) and group changes (`POST /groups`, `PATCH` and `DELETE /groups/<name>`, `PUT` and `DELETE /groups/<name>/stewards/<person>`), answers `GET /me`, `GET /groups/<name>`, `GET /datasets/<id>` and `GET /tables/<id>`, keeps the access log and each login's current session, builds and serves each person's tables in the `governance` namespace, and creates each person's Polaris account on first use. |
| **opa** | The PDP, reachable only by its callers. Rules only (`opa/policy.rego` = Polaris's checks, `opa/tables.rego` = who may view a table or namespace, `opa/blob.rego` = blobs, `opa/groups.rego` = group administration). Every caller sends only who is asking and the ids it names; each rule fetches the person's groups and the grants it needs from governance (`opa/governance.rego`). |
| **polaris** | Iceberg REST catalog. Validates the user's Keycloak token; delegates authorization to OPA; vends per-table STS. Holds identities, no rules. |
| **gate** | The only way to Polaris. Verifies the token, trims listings to what the caller may view, answers "does not exist" for names they may not view, and, if Polaris refuses a table load that asked for a credential, repeats it without one, so DESCRIBE works for people who may view but not read; such a load carries only the current version, without row or file counts or the writer's name, and so does a view load by someone who may only describe the view. Refuses a view that would run with its owner's rights. Decides which tables and schemas may be created, and reports creates and drops to governance. Has governance log every table credential it passes on and every table write it forwards, and refuses the request when that fails. Answers for the `governance` namespace's tables itself. |
| **trino** | Query engine. Authenticates users by their Keycloak token, forwards it to Polaris, reads tables with the credentials Polaris vends. Reports every completed statement's inputs and output to governance, which drafts declarations from them. |
| **loginproxy** | Sits in front of Trino so a client session outlives the 5-minute token. Speaks Trino's external-authentication (browser OAuth2) protocol to the client, holds the person's refresh token, and puts a fresh token on every forwarded request as the bearer and the `token` extra credential. |
| **broker** | Blob vending broker (Flow C). Verifies the user's own token, asks OPA about the named folder, vends a credential scoped to the prefix in OPA's decision: to read (get and list, on the dataset's `read`) to write (put and delete, no get, on its `write`, refused to anyone who may not read a source its files carry), or to delete (list and delete, no get or put, on its `delete`, which sources do not narrow). Has governance log each credential before returning it. Moves a folder into another group's space (`POST /transfers`) by server-side copy. |
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
pq --execute "SELECT * FROM iceberg.jgi.t1"     # -> 1
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

## Flow A — discovery (describe-but-not-read)

*"What exists that I could request?"* — separate from "what can I read." Every engine
connected to the catalog can query the answer as an Iceberg table, `governance.datasets`: one
row per live dataset or table the person may see, with whether they may read it and whether it
is published, and never bytes or credentials. A file dataset's id is its folder without the
`datasets/` root, and starts with the group whose space holds it: `datasets/jgi/public/` →
`jgi/public`.

```bash
q alice --execute "SELECT * FROM iceberg.governance.datasets"
#  -> "jgi/public","files","jgi public data","alice","true","true"
#     "projw/private","files","projw private data","carol","false","true"
#     "lakehouse.jgi.t1","table","","","true","false"
#         ^ projw/private is visible but can_read is false: describe-but-not-read
#         ^ t1 is in jgi's space and not published, so only jgi sees it
q bob --execute "SELECT count(*) FROM iceberg.governance.datasets"
#  -> "0"     bob's group noaccess has an empty space and no grants
```

The gate answers for this table itself. Governance builds its files for the person loading
it (one database query, then one OPA decision per kind: governance builds the candidate list
and OPA says which candidates pass; the candidates are only entries some of whose grants
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
# ALLOW — alice is in jgi, whose space holds jgi.t1
q alice --execute "SELECT * FROM iceberg.jgi.t1"
#  -> "1"

# DENY — bob authenticates fine but has no grant, so for him the table and its schema do not
# exist: the same answer as for a name nobody created
q bob --execute "SELECT * FROM iceberg.jgi.t1"
#  -> Query ... failed: line 1:15: Schema 'jgi' does not exist

# A member creates a table in their group's space with no step first; it is listed to the
# group, unpublished, until a steward publishes its namespace (see "Spaces and publishing").
q alice --execute "CREATE TABLE iceberg.jgi.t2 AS SELECT 2 AS y"
#  -> CREATE TABLE: 1 row

# See what OPA was asked, on the real per-user identity (bob is refused at the schema check,
# which the gate answers as not-found):
docker compose logs opa | grep -E 'LOAD_TABLE_WITH|NAMESPACE_EXISTS'
#  -> alice ... LOAD_TABLE_WITH_WRITE_DELEGATION   |   bob ... NAMESPACE_EXISTS
```

## Flow C — blob datasets

The plane tables can't give you: **non-tabular data, accessed by a client presenting its own
token to a broker — no engine in the byte path**, so it's safe even against a compromised
engine. The broker verifies the token, asks OPA the yes/no question, and vends a credential
**narrowed to exactly the requested folder**.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def tok(u): return requests.post(KC, data=dict(grant_type="password", client_id="trino",
    client_secret="trino-secret", username=u, password=u,
    scope="openid aud-broker")).json()["access_token"]
def vend(u, ds): return requests.post("http://broker:9100/vend",
    headers={"Authorization": f"Bearer {tok(u)}"}, json={"folder": ds}).status_code
print("alice jgi/public   :", vend("alice", "jgi/public"))      # 200 -> scoped temp creds
print("alice projw/private:", vend("alice", "projw/private"))   # 403 -> visible but not readable
print("bob   jgi/public   :", vend("bob",   "jgi/public"))      # 403 -> bob is granted nothing
PY
```

The returned credential reads `datasets/jgi/public/*` but is **denied** sibling prefixes by
RGW — OPA's decision carries the entry's folder, and the broker scopes the session policy to
it. A dataset id that doesn't exist gets the same 403 as a denied one.

A credential covers everything under the folder, as `aws s3 sync` and `ls --recursive` need,
unless the request says `"recursive": false`: then it covers the files directly in the folder
and lists the folder one level at a time, showing its files and its subfolders' names. No
credential reaches into a published dataset but its own, so a folder with one under it opens
only that way; someone it is open to who asks for a recursive credential gets

    datasets/jgi/ contains published datasets, so it can't be opened recursively. Open it with
    "recursive": false for the files directly in it, or open its subfolders and datasets separately.

What a read brings in, and which files a write is counted for, follow what the credential
covers (`seed/check-credentials.py`).

## Registry freshness & governed ingest

The registry is the **mutable single source of truth**, so it lives in a real datastore (a
`governance` Postgres database) and is kept **honest against storage**. Two truths, reconciled
not merged: storage owns *existence*, the registry owns *meaning/grants*.

- **Freshness.** Each object created or deleted under a tracked folder makes RGW notify
  governance, which lists that folder, recording each file's time for attribution
  (`PROVENANCE.md` 6.2), and sets `status`: non-empty → `live`, empty → `gone`. The dataset
  index lists only `live` entries. The notification topic is persistent: RGW queues each event
  and retries it until governance accepts it, so an event sent while governance is down
  arrives once it is back. There is no periodic sweep.
- **Write, then publish.** A member writes into a folder of their group's space with a write
  credential from the broker (`"mode": "write"`): it puts and deletes in that folder only and
  cannot read or list. The first credential for a folder makes it an entry, not yet
  published. A steward then publishes it **with its meaning** (description and grants — only
  a human can supply these; the id is the folder), authenticated by their own token and
  **authorized by OPA** (`allow_publish`: a steward of the group whose space holds it).

```bash
# Governed ingest of a NEW dataset, as alice (a member and the steward of jgi):
docker compose exec governance python /seed/ingest-demo.py
#  -> uploaded 2 objects under datasets/jgi/projz/ with a write credential
#     publish: 200 {'grants': {..., 'describe': ['projw'], ...}, 'id': 'jgi/projz', 'ok': True, 'published': True}

# alice finds and reads jgi/projz at once; she is DENIED publishing in another group's space:
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
print("vend jgi/projz:", requests.post("http://broker:9100/vend", json={"folder": "jgi/projz"},
      headers={"Authorization": "Bearer " + tok("broker")}).status_code)
print("publish projw/private (projw's space):",
      requests.patch("http://governance:8000/datasets/projw/private", json={"description": "x"},
                     headers={"Authorization": "Bearer " + tok("governance")}).status_code)
PY
#  -> index: ['jgi/projz', 'jgi/public', 'projw/private', 'lakehouse.jgi.t1', 'lakehouse.jgi.t2']
#     vend jgi/projz: 200
#     publish projw/private (projw's space): 403
```

Delete `jgi/projz`'s objects and it flips to `gone` and leaves the index; re-add one and it
returns `live`. `bob` (a steward of nothing) is denied publishing entirely.

Because an id begins with its space, two groups can each have a dataset called `results`
(`jgi/results` and `projw/results`) — names never collide across groups, and neither can see
the other's.

## Spaces and publishing

Every group has a space: the folder `datasets/<group>/` and the namespace `lakehouse.<group>`
(Trino's schema `iceberg.<group>`, with schemas inside it named `iceberg."<group>.<name>"`).
Its members write there with no step first, and a steward publishes what is to be shared
(`docs/HANDOFF-2026-10-22-groups.md` sections 1 to 3).

- A space's default grants: `describe` and `read` for everyone in the group, `write` for its
  members and above, `delete` for its admins (`<g>#admin`), `manage` for its stewards
  (`<g>#steward`), `detach` empty.
- A folder becomes an entry the first time someone is given a credential for it. Until it is
  published it has no description, its grants are those set on the folder and above it, and it
  is listed only to those who may read it. A table becomes an entry when it is created.
- A steward publishes a folder with `PATCH /datasets/<id>` and a namespace, one dataset of its
  tables, with `PATCH /namespaces/<id>`: `{"description", "describe": [...], "read": [...],
  ...}`. Published datasets do not nest: publishing one inside or around another is refused,
  and no credential for a folder reaches into a published dataset under it.
- Grants can also be set on any folder (`PATCH /permissions/folder/<id>`) and any namespace
  (`PATCH /permissions/namespace/<id>`), whether or not it exists yet. They reach the folder's
  own files and every entry under it, published or not, and every table created there later. A table has no grants of
  its own.
- An entry's grants are the union of its own (while published), those set on its folder or
  namespace and on every one above it, and its space's. `GET /datasets/<id>` and `GET /tables/<id>` show each
  layer, and `governance.grants` names where each inherited grant comes from.
- A group whose space holds data cannot be deleted, and a group cannot be created under a name
  whose space already has entries.
- Each person has a personal space, that of the group `u_<user>`, made at their first
  appearance with them its only owner. No one else joins it, nothing in it is published or
  granted to anyone else, and a person's own reads and writes there are not cut by what their
  data was made from (`PROVENANCE.md` 9): losing `read` on a source leaves them their own
  copies, as a download would. A source's stewards close those copies by adding the person to
  the source's `revoked` (`{"group": "u_alice", "add": ["revoked"]}`); its `manage` holders see
  who added whom in `GET /datasets/<id>`.
- A declaration marking a folder or table of a space unused is shown in `governance.derivations`
  to the space's admins, as well as to its `manage` holders.
- A folder or table moves from a personal space, or a plain group's space, into another group's
  space: by its person, or an owner or admin of the plain group, into a group they are a member
  or above of, at a path that does not exist and is not inside a published dataset. A folder
  moves through the broker, `POST /transfers {"from": "u_alice/work", "to": "jgi/work"}`, which
  copies each object server-side and deletes the originals; the copies are logged as written in
  a session of the move's own after a read of the old folder, so they carry what it carried. A
  table is copied by its mover (`CREATE TABLE iceberg.jgi.t AS SELECT * FROM iceberg.u_alice.t`),
  the move recorded with governance's `POST /transfers` with the two table ids, and the original
  dropped. The old entry stays, `moved` to the new one: data built from the old folder or table
  is checked against the new one's grants, and a credential for the old path is refused with the
  new path named to anyone who may describe it.

## Collections

A collection (`docs/HANDOFF-2026-10-22-groups.md` section 5) groups published datasets, folders
and namespaces alike, and other collections, by reference; it holds no data and no credential
is issued for it. It belongs to a group, never a personal one, and is named `<group>:<name>`;
it takes its group's space defaults. Its `describe` and `read` reach every member, through nested collections, still
cut by each member's sources; its `manage`, `write` and `delete` are its own. Adding a member
takes `write` on the collection and `manage` on the member, whose holders so consent; removing
takes either, and a collection that would come to hold itself is refused.
`POST /collections {"group", "name", "description"}`, `PATCH /collections/<id>` (description,
and grant changes in the permissions API's shape), `POST` and `DELETE
/collections/<id>/members/<member>`, `DELETE /collections/<id>` and `GET /collections/<id>`.
`governance.datasets` lists collections (kind `collection`) and `governance.collection_members`
their members, to those who may describe them.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def h(u, aud): return {"Authorization": "Bearer " + requests.post(KC, data=dict(grant_type="password",
    client_id="trino", client_secret="trino-secret", username=u, password=u,
    scope=f"openid aud-{aud}")).json()["access_token"]}
G, A = "http://governance:8000", h("alice", "governance")
vend = lambda: requests.post("http://broker:9100/vend", headers=h("carol", "broker"),
                             json={"folder": "jgi/public"}).status_code
print("create :", requests.post(f"{G}/collections", headers=A, json={"group": "jgi", "name": "forprojw"}).status_code)
requests.patch(f"{G}/collections/jgi:forprojw", headers=A, json={"changes": [{"group": "projw", "add": ["read"]}]})
print("add    :", requests.post(f"{G}/collections/jgi:forprojw/members/jgi/public", headers=A).status_code, vend())
print("remove :", requests.delete(f"{G}/collections/jgi:forprojw/members/jgi/public", headers=A).status_code, vend())
requests.delete(f"{G}/collections/jgi:forprojw", headers=A)
PY
#  -> create : 201
#     add    : 200 200        carol, in projw, reads jgi/public through the collection
#     remove : 200 403
```

## Changing grants

`PATCH /permissions/<dataset|folder|namespace>/<id>` adds and removes groups from a published
dataset's, a folder's or a namespace's grants, in the shape of Unity Catalog's permissions
API. OPA decides each change (`allow_change`, `allow_change_folder`): `describe` and `read`
change only for someone in a group holding its `manage` (the space's stewards by default);
`manage`, `write`, `delete` and `detach` only for a steward of the group whose space holds it,
or a platform admin. A change applies at the next decision.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def h(u, aud): return {"Authorization": "Bearer " + requests.post(KC, data=dict(grant_type="password",
    client_id="trino", client_secret="trino-secret", username=u, password=u,
    scope=f"openid aud-{aud}")).json()["access_token"]}
def change(op):  # carol stewards projw
    return requests.patch("http://governance:8000/permissions/dataset/projw/private",
        headers=h("carol", "governance"),
        json={"changes": [{"group": "jgi", op: ["read"]}]}).json()["grants"]["read"]
vend = lambda: requests.post("http://broker:9100/vend", headers=h("alice", "broker"),
                             json={"folder": "projw/private"}).status_code
print("grant read :", change("add"), vend())
print("revoke read:", change("remove"), vend())
PY
#  -> grant read : ['jgi'] 200
#     revoke read: [] 403
```

carol may change `read` on `projw/private` because her space gives its stewards `manage`;
anyone else gets 403 for any change, the same answer as for an id that does not exist.

## Changing groups

Each person holds one role in a group, owner, admin, member or viewer, and a member or above
can also be its steward (`docs/HANDOFF-2026-10-22-groups.md` section 1). A grant naming a group
gives `describe` and `read` to everyone in it and every other grant to its members and above,
so a viewer reads and never writes. A grant can also name a role in the notation of Zanzibar
and SpiceDB: `jgi#admin` is jgi's admins and owners, `jgi#member` its members and above,
`jgi#owner` its owners, `jgi#steward` its stewards.

- Anyone signed in creates a group, `POST /groups {"name"}`, and becomes its owner. A name is 2
  to 64 lowercase letters and digits starting with a letter, as BERDL requires, and not
  reserved (BERDL's list and `governance`); a name some grant already uses is refused,
  since its owner would hold those grants, and so is one whose space already has entries.
- `PATCH /groups/<name>` adds people to a role, moving them if they hold another, or removes
  them: owners change owners and admins; owners, admins and stewards change members and
  viewers. A change leaving no owner is refused.
- Platform admins are people whose Keycloak token carries the realm role `platform-admin`
  (carol). They hold no role in any group, appoint and remove stewards
  (`PUT` and `DELETE /groups/<name>/stewards/<person>`), change any group's people and delete
  it, and pass every check that asks for a steward. A credential, a move or a change to
  `describe` or `read` takes a grant or role they hold only by joining a group (`WHITEPAPER.md`
  4.4). A group with a steward is a tenant; a change leaving a steward a viewer or
  out of the group is refused until a platform admin removes the steward.
- `DELETE /groups/<name>` is its owners', refused while its space holds data.
- `GET /me`, `GET /groups/<name>` (its viewers and above), `GET /datasets/<id>` and
  `GET /tables/<id>` (those who may describe it) read the same state back; for someone who may
  describe an entry but not read it, the last two say why.

OPA decides each (`opa/groups.rego`). The seed has alice own and steward `jgi`, carol own and
steward `projw`, and bob own `noaccess`.

```bash
docker compose exec -T governance python - <<'PY'
import requests
KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"
def h(u, aud): return {"Authorization": "Bearer " + requests.post(KC, data=dict(
    grant_type="password", client_id="trino", client_secret="trino-secret", username=u,
    password=u, scope=f"openid aud-{aud}")).json()["access_token"]}
def viewers(op):  # alice owns jgi
    return requests.patch("http://governance:8000/groups/jgi",
        headers=h("alice", "governance"), json={"viewers": {op: ["bob"]}}).json()["viewers"]
vend = lambda mode: requests.post("http://broker:9100/vend", headers=h("bob", "broker"),
                                  json={"folder": "jgi/public", "mode": mode}).status_code
print("bob a viewer:", viewers("add"), vend("read"), vend("write"))
print("bob removed :", viewers("remove"), vend("read"))
PY
#  -> bob a viewer: ['bob'] 200 403
#     bob removed : [] 403
```

## Sessions and the access log

Build step 1 of `PROVENANCE.md`. Governance logs every dataset credential handed to a person
and every table write, stamped with the session the person's login points at, before the gate
or the broker passes it on; when the log fails, the request is refused. A person's first
access starts a session named `default`, and a new login continues the most recently used
session. Inserting a name into `governance.sessions` points the login at the person's session
of that name, started then if they have none; `POST /sessions {"name": ...}` does the same for a
client with no Iceberg engine.

```bash
q alice --execute "INSERT INTO iceberg.governance.sessions (name) VALUES ('run7')"
#  -> INSERT: 1 row      (a new login continues run7, the most recently used session)
```

`governance.lineage` has the shape of Unity Catalog's `system.access.table_lineage`: a read
is a row with an empty target, and a write is a row for each read of its session before it.
A table write happens at its commit; a file write credential counts as a write until it
expires. After Flow B and Flow C:

```bash
q alice --execute "SELECT * FROM iceberg.governance.sessions"
#  -> "default","2026-10-22 23:21:58.824845 UTC","2026-10-22 23:21:59.143470 UTC","true"
q alice --execute "SELECT source, target, session FROM iceberg.governance.lineage"
#  -> "jgi/public","","default"
#     "lakehouse.jgi.t1","","default"
#     "lakehouse.jgi.t1","lakehouse.jgi.t2","default"
q bob --execute "SELECT count(*) FROM iceberg.governance.lineage WHERE source = 'lakehouse.jgi.t1'"
#  -> "0"     bob's refused read handed him no credential, so nothing is logged
```

`t2` is paired with `t1` although `CREATE TABLE t2 AS SELECT 2 AS y` read nothing: the session
had read `t1` before it. Rows are per session, so an output's candidates (`WHERE target =
'<id>'`) are everything its session read before writing it, and declaring which were used
narrows that. A declaration is an insert into `governance.derivations` covering every one of
the person's own candidates of the target; governance checks it at the commit, stores it, and
signs it. An input from outside the platform is a row with `source_type` `external` and its
`sha256:` hash as the source.

```bash
q alice --execute "INSERT INTO iceberg.governance.derivations (source, source_type, target, used)
  SELECT DISTINCT source, source_type, target, false
  FROM iceberg.governance.lineage WHERE target = 'lakehouse.jgi.t2'"
#  -> INSERT: 1 row
q alice --execute "INSERT INTO iceberg.governance.derivations (source, source_type, target, used) VALUES (NULL, NULL, 'lakehouse.jgi.t2', true)"
#  -> Query ... failed: Failed to commit the transaction during insert: Malformed request:
#     lakehouse.jgi.t2: not declared: lakehouse.jgi.t1
q alice --execute "SELECT source, source_type, target, used, declared_by FROM iceberg.governance.derivations"
#  -> "lakehouse.jgi.t1","table","lakehouse.jgi.t2","false","alice"
```

An insert names its four columns; governance fills in `declared_by` and `declared_at`.

Who may read a dataset follows what its files were made from (`PROVENANCE.md` section 6):
each file carries the datasets its writer had read before writing it, minus those declared
unused, and a dataset's `read` is cut down to groups that may also read every one of them. A
source that arrived through a read, such as `t1` in a copy of a table made from it, can be
detached by naming it unused once its data is gone; its `detach` grant says who may, and
holders of its `manage` see every detach and can put the source back. A write needs no
declaration: until the writer declares, everything that could be in the data limits who may
read it, and declaring widens that. The same declaration can be posted to governance as
`POST /declarations` with `{"rows": [{source, source_type, target, used}]}`, for a client with
no Iceberg engine; it is checked, stored and signed by the same code.

Trino reports every statement to governance (its HTTP event listener, `trino/etc/event-listener.properties`),
and `governance.drafts` drafts each declaration from what the statements writing a table read
(`PROVENANCE.md` 5.6): `used` for what they read, `unused` for a table the engine only ever read
into tables in that session, and no row for what only the person can account for, a file read
or a table whose rows went to the client. A draft changes nothing; confirming it is the insert:

```bash
# A session of its own, so what the demos above had alice read is no candidate of t3
q alice --execute "INSERT INTO iceberg.governance.sessions (name) VALUES ('drafts')"
q alice --execute "CREATE TABLE iceberg.jgi.t3 AS SELECT x + 1 AS x FROM iceberg.jgi.t1"
q alice --execute "SELECT source, source_type, target, used, engine FROM iceberg.governance.drafts
  WHERE target = 'lakehouse.jgi.t3'"
#  -> "lakehouse.jgi.t1","table","lakehouse.jgi.t3","true","trino"
q alice --execute "INSERT INTO iceberg.governance.derivations (source, source_type, target, used)
  SELECT source, source_type, target, used FROM iceberg.governance.drafts WHERE target = 'lakehouse.jgi.t3'"
#  -> INSERT: 1 row
```

A release (`PROVENANCE.md` 6.7) lets a group read a dataset built from a source the group may
not read, with the source's owners' approval. A `manage` holder of the target asks, once the
group is in the target's `read` and the target's declarations mark the source used; a `manage`
holder of the source approves or declines, and any of them can withdraw it. What the group
builds from the target stays readable to it; data that took the source by another path does
not. Run in-network, as alice, who holds `manage` on both `rel1` and `t1` as jgi's steward,
once she has built `lakehouse.jgi.shared.rel1` from `t1`, given projw `read` on the namespace
`lakehouse.jgi.shared` (`PATCH /permissions/namespace/lakehouse.jgi.shared`), and declared it
with `t1` used:

```bash
docker compose exec -T governance python -c "
import subprocess, requests
t = subprocess.run(['python', '/seed/user_token.py', 'alice', 'governance'], capture_output=True, text=True).stdout.strip()
h = {'Authorization': 'Bearer ' + t}
r = requests.post('http://localhost:8000/releases', headers=h,
                  json={'target': 'lakehouse.jgi.shared.rel1', 'source': 'lakehouse.jgi.t1', 'group': 'projw'})
print(r.json())
print(requests.post(f'http://localhost:8000/releases/{r.json()[\"id\"]}/approve', headers=h).json())"
#  -> {'id': 1, 'status': 'pending'}     (409 'declare lakehouse.jgi.shared.rel1's sources first: ...' before declaring)
#  -> {'id': 1, 'status': 'approved'}    (DELETE /releases/1 withdraws it)
q carol --execute 'SELECT * FROM iceberg."jgi.shared".rel1'
#  -> "1","10"
q alice --execute "SELECT id, target, source, grantee, status FROM iceberg.governance.releases"
#  -> "1","lakehouse.jgi.shared.rel1","lakehouse.jgi.t1","projw","approved"
```

`governance.grants` lists every grant on the entries `governance.datasets` shows the person,
with Unity Catalog's column names (`privilege_type`, `grantee`). Changing grants and releasing
are HTTP calls, since Trino's Iceberg connector refuses `GRANT` ("This connector does not
support grants on tables").

## Security model

- **One policy brain, deny-by-default.** Nothing is granted that OPA didn't allow, across both
  planes, all by group. Tables (`opa/policy.rego`): `root` / read credential (`read` or
  `write`) / viewing a table's columns and location (`describe`, `read` or `write`) / viewing a
  schema (`describe`, `read` or `write` on it or on one inside it) / listings (anyone; the gate
  trims them to what may be viewed) / creating a table or a schema (`write` on the schema it
  goes in) / writes and read-write credentials (`write`) / dropping a table or view, files
  included (`delete`). A table's grants are its schema's, those above it and its space's.
  Blobs (`opa/blob.rego`): `vend` (read) / `vend_write` (write) / `vend_delete` (delete) /
  `visible` (describe or read) / `allow_publish` (a steward of the space's group). Grant
  changes (`allow_change` in both, `allow_change_folder`): `describe` and `read` by `manage`
  holders, sources being the business of releases; `manage`, `write`, `delete` and `detach` by
  stewards of the space's group. Group changes (`opa/groups.rego`): anyone creates a group;
  owners change owners and admins; owners, admins and stewards change members and viewers;
  platform admins change stewards. Platform admins, marked by a Keycloak realm role in the
  token, pass every check on a group's people and every check that asks for a steward. Group membership and every grant come from
  governance at decision time; tokens carry no groups.
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
- **Publishing is scoped.** A steward publishes only in their group's space, folders are
  confined to `datasets/<...>/` (no traversal), and publishing holds one lock, so two published
  datasets never nest and no credential reaches into a published dataset but its own.
- **Space-scoped identity.** A dataset's id begins with the group whose space holds it, not a
  global name, so names never collide across groups.

## Limitations

- A client that logs in through the **loginproxy** stays connected as long as the person's
  Keycloak login lasts (the proxy refreshes for it). A client pointed straight at Trino with
  one token (the `q` helper) is cut off after 5 minutes. The proxy holds sessions in memory,
  so restarting it logs everyone out.
- With `describe` only, DESCRIBE works through Trino (via the `gate`) and SELECT fails; an INSERT
  fails with "Failed to initialize the vended credentials" rather than access denied.
- A refused create's first line is Trino's own ("Failed to create transaction"); the gate's
  reason is the error's cause, which the CLI prints with `--debug`.
- Views must be created with `SECURITY INVOKER`. Trino's default, a view that runs with its
  owner's rights, is refused ("Failed to create view"; the cause names `SECURITY INVOKER`).
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
