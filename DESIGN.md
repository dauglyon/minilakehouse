# minilakehouse — Design

An experimental **unified lakehouse Policy Decision Point (PDP)**: one external policy brain
(OPA) answers every authorization question, and every other component either *asks* it (a
PEP) or *obeys* a short-lived credential it gated (vending). OPA is on the **decision path,
never the byte path**.

This document is the architecture and rationale. For a quickstart and runnable demos, see
`README.md`.

## Contents

- [1. The problem](#1-the-problem)
- [2. Principles](#2-principles)
- [3. Architecture](#3-architecture)
- [4. Request flows](#4-request-flows)
- [5. The OPA contract](#5-the-opa-contract)
- [6. Non-tabular data & registry freshness](#6-non-tabular-data--registry-freshness)
- [7. Credential vending](#7-credential-vending)
- [8. Security model](#8-security-model)
- [9. Prior art](#9-prior-art)
- [10. Implementation notes & key decisions](#10-implementation-notes--key-decisions)
- [11. Limitations & deferred work](#11-limitations--deferred-work)
- [Glossary](#glossary)

## 1. The problem

A typical multi-tool lakehouse reimplements authorization in several places that drift
apart: object-store IAM policies, catalog RBAC, an engine access-control plugin, and
per-service interceptors — four copies of "who can access what," kept in sync by hand. (This
prototype descends from one such internal stack.) The goal is to make the policy **external
and single-sourced**, and reduce every other component to either *asking* it (a Policy
Enforcement Point) or *obeying* its answer (credential vending).

It also serves a requirement table-centric catalogs don't: **non-tabular data** (raw
files/blobs over S3) under the *same* governance model as tables.

## 2. Principles

1. **Policy is external and single-sourced.** One service (governance) holds the only copy
   of the grant model; **OPA**, the one PDP, holds the rules and receives the relevant entry
   with each decision. Nothing re-decides or mirrors policy into a backend.
2. **Two permission planes** (the AWS Lake Formation model): **metadata-visibility** (may you
   *see a thing exists*?) drives discovery; **data-access** (may you *read the bytes*?) drives
   vending. A dataset can be visible-but-not-readable (*describe-but-not-read*).
3. **Discovery and access are separate.** Discovery returns *names*; access returns *scoped
   credentials*. Neither enumerates the whole bucket.
4. **OPA is a predicate, never an enumerator.** It answers yes/no about one named resource;
   it never returns a list. The caller (governance/broker) builds any list and owns the
   resource→prefix mapping.
5. **Vending is lazy and per-resource.** You get a credential scoped to the one table or
   dataset you are opening — never "a credential for everything."
6. **OPA decides; STS carries; S3 enforces.** OPA is in the decision path, never the byte
   path — no per-object policy call. Revocation lag is bounded by credential TTL, an accepted
   trade for keeping OPA off the hot path.
7. **Real identity reaches the decision.** The end user's identity — not an engine service
   account — is what OPA decides on.

## 3. Architecture

```
 IDENTITY
   Keycloak (OIDC) — users and the engine's service account. The only token issuer.
   Trino           — authenticates each user's Keycloak token and forwards that same token
                     to Polaris as the bearer (extra credential `token`), unexchanged.

 POLICY (control plane — decides, never touches bytes)
   governance (PAP)                          OPA (PDP)
   • Postgres-backed dataset and       ◄──   • rules only, no grants: vend / discover /
     table registries, group membership        allow_publish / allow_change (blobs),
     and grants (the only copy)                table lanes (view/read/write/delete/
   • serves them to OPA (/internal/*)          create/change), group changes, transfers
   • serves the dataset index                • every rule fetches the groups and grants
   • keeps the registry fresh vs storage       it needs from governance, per decision
   • accepts publishing, grant and group
     changes (asks OPA)

 ENFORCEMENT (PEPs — ask POLICY, then act)
   TABLES                                    BLOBS / FILES
   Trino ─► Polaris (Iceberg REST)           client ─► broker (verifies the user's
     loadTable: Authorizer ─► OPA                       OWN token) ─► OPA (allow?)
     on allow, mint per-table STS                       on allow, AssumeRole with a
     scoped to the table's files                        session policy = the folder

 DATA PLANE (bytes — STS-scoped, no OPA in this path)
   Ceph RGW (S3 + STS) enforces the vended credential; engine/client reads directly.
```

### Components

| Component | Role |
|-----------|------|
| **Keycloak** | OIDC IdP and the only token issuer — users (`alice`/`bob`/`carol`) and the `trino` client: users log in through it, and its service account (`service-account-trino`, granted nothing) is Trino's identity for its own catalog calls. |
| **Trino** | Query engine. Its JWT authenticator validates the user's Keycloak token; its Iceberg connector sends the token the user attached as the extra credential `token` to Polaris as the bearer. Its HTTP event listener sends every completed statement to governance's internal listener, with a client certificate named `trino`, from which governance drafts declarations (`PROVENANCE.md` 5.6). |
| **login-proxy** | In front of Trino so a client session outlives the 5-minute token. Speaks Trino's external-authentication (browser OAuth2) protocol to the client and holds the person's refresh token; forwards a fresh access token on every request as the bearer and the `token` extra credential. Trino is unchanged but for `http-server.process-forwarded=true`, so its nextUris point back at the proxy. |
| **governance** | PAP + dataset and table registries, Postgres-backed. Holds group membership and the only copy of every grant, serves them to OPA (`/internal/*`), serves the dataset index, keeps the registry fresh, makes a folder an entry at its first credential, accepts publishing and grant, group and steward changes, keeps collections, records transfers, answers the read routes (`GET /me`, `/groups/<name>`, `/datasets/<id>`, `/tables/<id>`), records the table lifecycle the gate reports, keeps the access log and each login's session pointer (`PROVENANCE.md`), builds and serves each person's tables in the `governance` namespace (`datasets`, `sessions`, `lineage`, `derivations`, `releases`, `grants`, `collection_members`, `drafts`), drafts declarations from the statements Trino reports, accepts declarations as commits to `governance.derivations` and signs them, and creates each person's Polaris principal on first use. Holds only a least-privilege RGW reader. |
| **OPA** | The PDP, reachable only by its callers. Loads only the rules from `opa/`: `policy.rego` (Polaris's checks), `tables.rego` (who may view a table or namespace, shared by Polaris's checks and the gate), `blob.rego` (blobs), `groups.rego` (group administration), and `governance.rego`, the one fetch every rule uses to get groups and grants from governance. |
| **gate** | The only way to Polaris. Verifies the caller's token; trims listings to what the caller may view (`tables.rego`), paging the result with its own tokens; turns a refusal for a name the caller may not view into not-found; repeats a table load Polaris refused once without the credential request, so a person who may view a table but not read it gets its metadata, cut to the current version without counts unless OPA's `tables.load` allows the rest, and cuts a view's responses the same way for someone who may only describe it; refuses a view that would run with its owner's rights; decides table and namespace creation, which Polaris authorizes against the parent only; reports table creates and drops to governance; has governance log each table credential it passes on and each table write it forwards, refusing the request when the log fails; has governance create a person's Polaris principal before their first request; answers for the `governance` namespace's tables itself. Holds no permissions; Polaris and OPA decide everything it forwards. |
| **Polaris** | Iceberg REST catalog. Validates Keycloak tokens (audience `polaris`); its Authorizer delegates every operation to OPA; vends per-table STS. Holds identities, no rules. |
| **broker** | Blob vending bridge: verifies the client's own token, asks OPA about the named folder, `AssumeRole`s a credential scoped to the prefix in OPA's decision, the whole folder or with `"recursive": false` the files directly in it: `blob-vendor` to read (get, list), `blob-writer` to write (put, delete, no get), `blob-deleter` to delete (list, delete, no get or put), and has governance log it before returning it. Moves a folder into another group's space by server-side copy under `blob-mover` (`POST /transfers`). No engine in the byte path. |
| **Ceph RGW** | Object store + native STS + bucket notifications. Enforces the vended credential. |
| **Postgres** | Polaris metastore and the durable `governance` registry database. |
| **rgw-setup** (one-shot) | Admin-credentialed startup step: sets the bucket policy granting the governance reader `ListBucket` on `datasets/*`, and wires bucket notifications — so the long-lived governance service never holds the admin key. |

## 4. Request flows

**Flow A — discovery ("what can I see?")** — returns names, no credentials.
1. Client presents its own token to governance.
2. Governance sends the ids of every live dataset to OPA in one decision; OPA fetches their
   entries and returns the ids the caller may see and the ids the caller may read.
3. Returns the visible names + descriptions (annotated with `can_read`). No bytes.
   (Tables are additionally listable via Polaris's own catalog metadata; the registry covers
   blobs and is kept fresh against storage.)

**Flow B — read a table** — lazy, per-table.
1. The user connects to Trino with their Keycloak token and attaches the same token as the
   extra credential `token`. Trino → Polaris `loadTable(X)` with that token as the bearer.
2. Polaris's Authorizer asks OPA: may this user read X? OPA fetches X's readers from
   governance.
3. On allow, Polaris mints a per-table STS credential scoped to X's files.
4. The gate has governance log the read against the person's current session, then passes
   the credential on; when the log fails, the load is refused.
5. Trino reads X's files from RGW directly — no OPA, no broker on the byte path.

**Flow C — read a blob dataset** — lazy, per-folder, true end-to-end.
1. Client presents its **own** Keycloak token to the broker, naming folder X.
2. The broker cryptographically verifies the token → subject + groups.
3. The broker asks OPA: may this subject read X? OPA fetches X's entry from governance, or the
   entry X would be if no credential has named it yet, and returns allow plus X's folder. An
   unknown X gets the same 403 as a denied one.
4. On allow, the broker `AssumeRole`s with an inline session policy scoped to that prefix
   (narrowing a broad role; the client can't widen it).
5. The broker has governance log the credential against the person's current session, then
   returns it; when the log fails, the request is refused.
6. The client reads those objects from RGW directly — no engine in the byte path.

## 5. The OPA contract

OPA never derives identity: the trusted caller verifies the token and passes the subject in
`input`, with the ids it names and never a group or a grant. OPA holds the rules and no
data; every rule fetches the person's groups and the grants it needs from governance through
`opa/governance.rego`, at decision time, so a membership or grant change applies at the next
decision.

```
rule            caller      input                              fetches                      result
vend            broker      {subject, dataset: id,             POST /internal/datasets      {allow, prefix} or
                             recursive}                                                       {allow: false, recursive_refused
vend_write      broker      as vend                            POST /internal/datasets       | moved_to}
vend_delete     broker      as vend                            POST /internal/datasets
discover        governance  {subject, datasets: [id]}          POST /internal/datasets      {visible: [id], readable: [id]}
allow_publish   governance  {subject, dataset: id,             POST /internal/datasets      true | false
                             platform_admin}
allow_change    governance  {subject, dataset: id,             POST /internal/datasets      true | false
                             grants: [grant], platform_admin}
allow_change_folder  governance  {subject, folder: id,         POST /internal/folders       true | false
                                  grants: [grant], platform_admin}
allow_transfer  broker      {subject, from: id, to: id}        POST /internal/datasets      true | false
blocking        governance  {subject, dataset: id}             POST /internal/datasets      [id]: sources refusing the subject
effective_read  governance  {dataset: id,                      POST /internal/datasets      [name]: names in read all of whose
                             holders: {name: [name]}}                                         holders pass every source
table lanes     Polaris     {actor, action, resource}          GET /internal/tables/<id>,   true | false
                                                                 POST /internal/namespaces
tables.decide   gate,       {subject, tables: [id],            POST /internal/tables,       {tables: [id], namespaces: [id],
                governance   namespaces: [id]}                   POST /internal/namespaces     readable: [id]}
tables.allow_create     gate        {subject, id}              GET /internal/tables/<id>    true | false
tables.allow_namespace  gate        {subject, id}              POST /internal/namespaces    true | false
tables.allow_publish    governance  {subject, id,              POST /internal/namespaces    true | false
                                     platform_admin}
tables.allow_change     governance  {subject, id (namespace),  POST /internal/namespaces    true | false
                                     grants: [grant],
                                     platform_admin}
tables.allow_transfer   governance  {subject, from: id,        GET /internal/tables/<id>    true | false
                                     to: id}
tables.blocking, tables.effective_read   as blocking and effective_read, for a table id
tables.allow_write      governance  {subject, id}              GET /internal/tables/<id>    true | false
tables.load             gate        {subject, id, credential,  GET /internal/tables/<id>,   {write, history,
                                     properties: {key: value}}   with a credential only       properties: [key]}
derivations.allowed     governance  {subject, target,          POST /internal/tables,       [id]: sources that may be
                                     sources: [{id, direct}]}    POST /internal/datasets      marked unused
derivations.may_release governance  {subject, sources: [{id}]} POST /internal/tables,       [id]: sources whose releases
                                                                 POST /internal/datasets      the subject decides
collections.allow_create, allow_write, allow_change, allow_add, allow_remove, allow_delete
                        governance  {subject, collection,      POST /internal/collections,  true | false
                                     member, kind, grants,       and the member's entry
                                     platform_admin}
collections.discover    governance  {subject, collections}     POST /internal/collections   {visible: [id], readable: [id]}
groups.allow_create     governance  {subject}                  —                            true | false
groups.allow_change     governance  {subject, group, roles,    —                            true | false
                                     platform_admin}
groups.allow_steward, allow_delete, allow_view
                        governance  {subject, group,           —                            true | false
                                     platform_admin}
```

Every rule also fetches `GET /internal/groups/<subject>`, except the shipped `tables.load` on a load without a credential, which fetches nothing. It returns the names the person holds grants through, `<g>` for each group and `<g>#member`, `<g>#admin`, `<g>#owner` and `<g>#steward` for their role in it and those below it, in two lists: every name, which `describe`, `read` and a source's `read` are checked against, and the names of the groups they are more than a viewer in, which every other grant is checked against (`governance.holder`), and the person's personal space. `platform_admin` is whether the caller's verified token carries the Keycloak realm role `platform-admin`; it passes every `groups` check and every check that asks for a steward, and `collections.allow_create`. Rules that ask for a grant (credentials, moves, `describe` and `read` changes) do not take it.

An entry's grants are layers (`docs/HANDOFF-2026-10-22-groups.md` sections 1 to 3): a published
folder's own, those set on the folder or namespace and on every one above it, and its space's
defaults; a table has none
of its own; and the `describe` and `read` of every collection holding the dataset, directly or
through other collections. Governance serves their union, and answers for a folder no
credential has named yet as for an entry, so its first credential is decided like any other.

One path for every caller because it is the only one Polaris can use: Polaris builds its own
input and cannot attach an entry. Each decision makes at most one fetch; a failed fetch
denies. Measured: a one-table `SELECT` makes one governance read, a denied one two (Polaris
retries a denied write-credential load as a read-credential load), and a vend request one. Governance builds every candidate list and OPA says which candidates pass.
Entries carry the registry's grants, cut down by the sources the dataset's files carry
(`PROVENANCE.md` 6), so a file written or removed can change who may read a dataset. Status
decides nothing but listing, except `moved`: a moved folder gets no credential, and a moved
table is read and written only at its new id.

## 6. Non-tabular data & registry freshness

Table catalogs have a registry by construction; raw blobs do not. Discovery splits in two:

- **"What can I access right now?"** — easy: the folders the subject's grants reach, which
  governance holds. List *within* a granted folder via a scoped credential.
- **"What exists that I could request?"** — hard: it can't come from grants (you have none
  yet) or scoped listing (you can't list it). It needs a **registry whose entries' existence
  and description are visible independent of data access** — the metadata-visibility plane.
  This is what catalogs give tables for free and nothing gives blobs, so **the registry is
  the core of this project.**

The registry (`governance`) holds, per folder written into: its prefix, whether it is
published, a published dataset's description, publisher and grants of its own, and its status;
beside them the grants on folders and namespaces, and each group's space.

### Freshness

A registry beside storage drifts, so it is reconciled against storage continuously:

- **Two truths, reconciled not merged.** Storage is truth for *existence*; the registry is
  truth for *meaning/grants*. A `datasets` row carries both, written by disjoint paths —
  meaning/grants by publishing, grant changes and the seed, `status` by `reconcile()` only.
- **Status `live`, `gone`, `moved`.** `reconcile()` lists a folder and sets `status`: non-empty
  → `live`, empty → `gone`; a folder moved into another group's space stays `moved`. The
  dataset index lists only `live` entries.
- **Events are the only trigger, and they are persistent.** RGW notifies governance of each
  object created or deleted under `datasets/`; governance checks every tracked folder the key
  falls under. The topic is persistent (`rgw_setup.py`): RGW queues each event in RADOS and
  retries it, with no expiry or retry limit by default, until governance answers 2xx, and
  governance answers 503 when a check fails, so an event is never dropped for governance being
  down or storage being slow. There is no periodic sweep. Events carry no authority — they only
  trigger a check, which reads storage itself, so a forged event can only cause a check. A
  folder's first credential, and the first seed, check it once.
- **Write, then publish** (`docs/HANDOFF-2026-10-22-groups.md` section 3). Members write into
  their group's space with no step first; the first credential for a folder makes it an entry.
  A steward then publishes it with its meaning (description and grants — only a human can
  supply these; its id is its path under `datasets/`). There is no auto-discovery of datasets
  from raw storage: a dataset's boundary and meaning are human, not derivable from objects.
  Published datasets do not nest.

## 7. Credential vending

- **Lazy, per-resource, STS.** Tables: Polaris vends on `loadTable`, scoped to the table's
  files. Blobs: the broker vends on folder-open, scoped to the folder, recursively unless the
  request says `"recursive": false`, when the credential gets and puts `<folder>*` but not
  `<folder>*/*` and lists one level. A folder with a published dataset under it opens only that
  way, so no credential reaches into a published dataset but its own.
- **Why a broker is unavoidable for blobs:** OPA's yes/no must be *bound into a credential the
  client cannot forge*. Only a trusted server-side step can do that. The broker holds no
  policy logic — it is a token → OPA → `AssumeRole` bridge.
- **A session policy can only narrow.** The role the broker assumes permits a superset (the
  whole `datasets/` area); the per-request session policy narrows it to one folder.
  Safe because only the broker builds the session policy, and it builds it from a prefix
  governance confines (`datasets/<...>/`, no traversal).
- **Scope in the STS role + session policy, not bucket policy** — RGW bucket policies don't
  support username interpolation (`${aws:username}`).

## 8. Security model

- **One policy brain, deny-by-default.** Nothing is granted that OPA didn't allow, across
  both planes. Tables (`policy.rego`), all by group: `root` / read-credential vend (`read` or
  `write`) / viewing a table (`describe`, `read` or `write`) / viewing a namespace
  (`describe`, `read` or `write` on it or on one under it) / catalog listings (anyone; the gate
  trims them to what the two view lanes allow) / creating (the gate decides the name: `write`
  on the namespace a table or namespace goes in) / writes and read-write credentials (`write`)
  / dropping a table or view (`delete`) / dropping a namespace (`delete`), changing its
  properties (`write`) — anything unnamed, including rename, register and set-location, is
  root-only. A table's grants are its namespaces' and its space's. Polaris is on a
  network only the gate and its setup jobs share, so every client call passes the gate. Blobs (`blob.rego`): `vend` (read) / `vend_write`
  (write) / `visible` (describe or read) / `allow_publish` (a steward of the space's group) /
  `allow_transfer`, all by group. Governance holds group membership; tokens carry no groups.
- **Grant changes are decided like access.** `PATCH /permissions/<dataset|folder|namespace>/<id>`
  adds or removes groups from a published dataset's, a folder's or a namespace's grants.
  OPA's `allow_change` (`allow_change_folder` for a folder) decides it while governance holds a
  lock on what it changes, so the grants OPA fetches are the ones the write replaces:
  `describe` and `read` change only for a group holding its `manage`; `manage`, `write`,
  `delete`, `detach` and `revoked` only for a steward of the group whose space holds it, or a
  platform admin. Nothing in a personal space is granted or published, by anyone. An unknown
  or unpublished dataset is refused exactly as a denied change.
- **Groups have roles** (`docs/HANDOFF-2026-10-22-groups.md` section 1). Each person in a group
  (`group_members`) is its owner, admin, member or viewer, and a member or above can be its
  steward. Anyone signed in creates a group (`POST /groups`) and becomes its owner; the name
  follows BERDL's rule. `PATCH /groups/<name>` adds people to a role or removes them, decided
  by `groups.allow_change` over every role the change touches, under a per-group advisory
  lock: owners change owners and admins, owners, admins and stewards change members and
  viewers. Platform admins appoint and remove stewards (`PUT` and
  `DELETE /groups/<name>/stewards/<person>`). Governance refuses a change that leaves a group
  without an owner or a steward a viewer, and refuses to create a group under a name any grant
  or ownership already uses, alone or with a role: a dangling grant to that name would
  otherwise pass to the new group's owner, and one whose space has entries. `DELETE
  /groups/<name>` is refused while the group's space holds data. A personal group, `u_<user>`,
  is made at the person's first appearance and has them alone.
- **The dataset index is built per person, on demand.** The gate answers a catalog load of
  `governance.datasets` by calling governance's `POST /index/load` with the person's token.
  Governance computes that person's rows (live datasets from `discover`, live tables from
  `tables.decide`), builds an Iceberg table of them in memory with pyiceberg under
  `s3://governance-index/<subject>/<hash of the rows>/`, and returns its metadata with a
  15-minute storage credential bound to the person. Its S3-style endpoint checks each
  request's SigV4 signature against that credential and serves only the person's own prefix.
  Nothing is written to storage, and the row hash in every path means a cache keyed by path
  never returns stale rows or another person's. Every dataset's actual data stays in Ceph.
  Engines find the files at the one storage address they already use (names under
  `.internal`, reserved for private networks: an unaliased bucket name resolves nowhere, so
  a file location cannot steer a signed request to a public host, as `<name>.storage`
  could): with the bucket in the host name, Docker DNS sends
  `governance-index.storage.internal` to governance's port 8080 and
  `lakehouse.storage.internal` to Ceph. Trino takes only the credential from the catalog,
  never a storage address (`S3VendedCredentials.java` in Trino 484), so this is how its
  reads of the index reach governance with no setting that names the index. Ceph accepts
  bucket-in-host addressing because `rgw_dns_name` lists `storage.internal`; it lists
  `ceph`, `localhost` and `127.0.0.1` too, because RGW reads an unlisted host name as a
  bucket name.
- **The index's work follows what a person may see.** Governance offers OPA only the live
  entries some layer of whose viewing grants names one of the person's groups: entries in the
  spaces of their groups, datasets whose own `describe` or `read` names them, and entries under
  a folder or namespace whose grants do. Those are the grants OPA's viewing rules test, so the
  narrowing drops only entries OPA would refuse and OPA still decides each candidate. Measured
  at 50,000 live datasets with 5,003 visible to alice, before spaces: a load took 2.39 s
  offering OPA every entry and 0.25 s narrowed; not measured since. `seed/check-index-narrowing.py`
  compares the narrowed rows with OPA's decision over every entry for every person in a group;
  a rule that makes an entry visible by anything other than those grants must change the
  narrowing query too. The gate's table listings still grow with the whole catalog.
- **Spaces, publishing and transfers** (`docs/HANDOFF-2026-10-22-groups.md` sections 1 to 3).
  Each group's space is `datasets/<group>/` and `<catalog>.<group>`; its defaults give the group
  `describe` and `read`, its members `write`, its admins `delete`, its stewards `manage`.
  Publishing (`PATCH /datasets/<id>`, `PATCH /namespaces/<id>`) holds one advisory lock, so two
  published datasets never nest. A transfer moves a folder from a personal or plain group's
  space into another group's, at a path that is empty, unpublished and holds nothing published;
  the broker copies exactly the files governance listed, each while its ETag matches, so a file
  written meanwhile is never copied without what it carries.
- **Real, end-to-end identity.** Every decision is made on the user's own Keycloak token.
  Tables: Trino authenticates the token and relays it to Polaris unchanged; Trino's username
  is the token's `principal_name`, and Trino's default access control refuses impersonation,
  so a client cannot run as someone else. The engine holds no credential that names a user:
  its own service account is granted nothing. Blobs: the broker verifies the user's *own*
  token — no engine in the byte path.
- **Token checks: one audience per service.** Every service verifies signature, issuer,
  expiry and its own audience: Trino, the gate and Polaris `polaris`, the broker `broker`,
  governance `governance`, so a token issued for one is refused by the others. A client asks
  for an audience with the optional client scope `aud-<service>` on the login client
  (`keycloak/setup.py`), and a token carries only the audiences it asked for. Governance's two
  endpoints the gate calls for the catalog (`POST /index/load`, `POST /principals/me`) take the
  person's catalog token, audience `polaris`. Governance and the broker also pin `azp` to the
  login client, so a token minted for another realm client can't be replayed.
- **Grant lookups answer only OPA.** `/internal/*` returns grants for datasets the user cannot
  see, so governance serves it only on a TLS listener (port 8443) that requires a client
  certificate from the internal CA with the name `opa` (`governance/pki.py` makes the CA and
  every certificate, each on its own volume). The same listener takes the gate's table
  create/drop reports, from a certificate named `gate`, and access log entries from `gate`
  and `broker`; each name may call only its own routes. OPA reads its key from a mounted file: OPA's API
  evaluates any query it receives, including one that reads its environment, so a bearer in
  the environment was readable by anyone who could reach OPA, and a file is not. OPA is also on
  a network shared only with its callers (Polaris, the broker, governance, the gate) and
  publishes no host port.
- **Every access is logged before it reaches the person** (`PROVENANCE.md` 4.1). Governance's
  `accesses` table holds one row per credential handed out and per table write: person,
  Keycloak subject, login (`sid`), session, dataset, `files` or `table`, `read` or `write`,
  time, credential expiry. The broker logs each credential after `AssumeRole` and before
  returning it. The gate checks every response it forwards for a storage credential and
  logs one wherever it appears: on a create, staged or not, as a write of the new table;
  anywhere else (a load, a refresh from Polaris's credentials endpoint) as a read of the
  table the path names; on a path naming no table it refuses the request. It also logs a 304
  to a credentialed load as a read, since the engine then reuses a credential it already
  holds, and a write before forwarding a create that is not staged, a commit, or a
  multi-table commit, so a failed log stops the write before Polaris sees it. Each row is stamped with the session the
  login points at when it is written (`logins`); a login's first row points it at the
  person's most recently used session, or at a new `default` one. A token with no `sid`, which
  is every service-account token, is one login per account. `governance.sessions` and
  `governance.lineage` are served like the dataset index. `lineage` has the shape of Unity
  Catalog's `system.access.table_lineage`: a read is a row with an empty target; a write is a
  row for each read it may have used, which are its session's earlier reads and, for a file
  write credential, the reads its login made while the credential was valid. A table write
  happens at its commit; a file write credential counts as a write until it expires, since
  governance never sees the file writes.
- **Who may read follows the sources a dataset's files carry** (`PROVENANCE.md` 6). Each read
  in the access log keeps what it brought in: the dataset and every source its files carried
  then. Governance lists each dataset's and table's folder when Ceph notifies it of a change
  (its reader may list `datasets/` and `warehouse/`), records every file's last-modified
  time, and attributes each file to the write credentials and commits valid at that time,
  so a file carries what its writers had read before writing it, minus what they declared
  unused. The lookups OPA makes return each dataset's own grants and the sources its files
  carry, with each source's own `read` and whether a declaration says it was used;
  OPA's rules let a person read or write only if they may also read every
  source or a release covers them (`PROVENANCE.md` 6.7), and change `describe` and `read` with
  `manage` on the entry itself; a source's own `manage` holders decide releases past it.
  `describe` and `delete` are not cut. How undeclared data is treated is a rule a deployment
  can change. A commit counts before a listing can see its files.
- **A table's history comes with a credential.** A table load that hands out no storage
  credential carries the table's columns, partitioning, properties and current version: the
  gate removes earlier versions and schemas, column statistics, and the row and file counts
  and writer names in version summaries. OPA's `tables.load`, the gate's one decision on a
  table request, says whether a person gets the whole metadata and which properties such a
  load keeps; the shipped rules give a table's whole metadata to nobody on a load without a
  credential and keep every property. A view never comes with a credential, so the decision
  says who gets a view's whole metadata: the shipped rules give it to those who may read or
  write the view, as a table's readers and writers get theirs with their credential, and
  anyone who may only describe it gets the current version, query text included.
- **A view runs with the rights of whoever queries it.** The gate refuses creating or
  changing a view so that it runs with its owner's rights (Trino's default, marked by the
  property `trino.run-as-owner`): Trino would read the view's tables as the owner without
  the owner's token, which the catalog does not accept. Reading through a view is logged as a
  read of the tables it uses, so provenance follows the tables; a view has no files and
  carries no sources.
- **A declaration is a commit, checked before it is accepted** (`PROVENANCE.md` 5.3, 5.5). An
  engine inserting into `governance.derivations` uploads its files to governance's S3-style
  endpoint and commits through the gate. The endpoint takes uploads only under the signer's
  own governance tables, never over an existing file, at most 64 MiB per person counting open
  multipart parts. Governance checks the commit's requirements against the table the person
  last loaded, reads only files under that person's own table, accepts only appended rows, and refuses the commit unless every target was written by the person, is in
  their `write`, and has each of their own candidates declared used or unused, outside inputs
  named by `sha256:` hash. An accepted declaration is stored with a DSSE envelope signed by
  governance's Ed25519 key, which the `pki` job makes beside governance's server certificate.
- **Storage events carry a secret.** RGW adds the notification topic's opaque data, a shared
  secret, to every event it sends; `/events` refuses a delivery whose events lack it. The
  secret is not in the push URL, which governance's request log would record. A forged event
  could only trigger a check of one folder, never set a status.
- **Least privilege on every credential.** STS roles use specific actions (no `s3:*`),
  prefix-scoped (`warehouse/` for tables, `datasets/` for blobs); the broker narrows further
  per request. No long-lived service holds an admin key: Polaris authenticates as
  `polaris-catalog` and the broker as `blob-broker`, each able only to assume its vending
  role, and governance holds a read-only RGW reader (`ListBucket` on `datasets/*`, via a
  bucket policy). Admin-only RGW setup runs in the `rgw-setup` one-shot.
- **Publishing is scoped.** The caller must be a steward of the group whose space holds the
  folder or namespace. Prefixes are confined
  to `datasets/<...>/` with no traversal, and the overlap check and the publish are serialized
  (an advisory lock) so two published datasets can't nest.

## 9. Prior art

This is the PDP/PEP (XACML/ABAC) pattern ported onto open lakehouse parts, not a new idea:

| Source | What we take |
|--------|--------------|
| **AWS Lake Formation** | The two-plane model (metadata vs storage) and "effective permissions → vended scope." |
| **Apache Ranger + Atlas** | External PDP + discovery/classification driving policy. OPA in Ranger's seat; the registry in Atlas's. |
| **Cloudera RAZ** | Proof an external-policy object-store authorization service works at scale. The broker is the STS (not hot-path) variant. |
| **Polaris 1.5** | A pluggable Authorizer SPI that delegates the table-vend decision to OPA. |

## 10. Implementation notes & key decisions

A chronological-ish log of decisions and hard-won details — for context, not current-state
reference (the sections above are current-state).

- **Catalog = Polaris.** Polaris 1.5's OPA authorizer calls OPA at `loadTable` and the
  decision gates STS vending, so the vend decision is your policy's. Blob vending is then ours to build (the broker), which is the project's actual
  contribution.
- **STS against Ceph RGW works**, with non-obvious requirements: `rgw_sts_key` (16 alnum) +
  `rgw_s3_auth_use_sts` in `ceph.conf`; an empty-account role ARN (`radosgw-admin role create`,
  not the IAM API, which mints a per-instance account id); and `kmsUnavailable: true` on the
  catalog storage config — otherwise Polaris's read sub-scope policy includes `kms:*` actions
  RGW rejects (which makes table *writes* work but *reads* fail).
- **Identity propagation needed a new component.** Trino can't forward a real end-user
  credential to Polaris: `session=USER` conveys the user as an *unsigned, self-issued JWT*,
  which Keycloak refuses and Polaris's authenticator rejects. The **idp-shim** is the one
  trusted place that turns "our Trino asserts alice" into a real signed alice token. The
  `trino_svc` service principal it uses for non-user calls is granted nothing in OPA.
  (Superseded by the extra-credential path below; the shim is removed.)
- **The shim's signing key must persist.** It originally generated the key in memory at every
  start, so any shim restart rotated it and invalidated every token Trino held *and* Polaris's
  cached JWKS — silently breaking the table plane until both refreshed. The key now loads from
  a persistent volume (stable `kid`). (Idle token *expiry* is a non-issue: the shim correctly
  rejects an expired engine token and Trino re-authenticates; only key *rotation* was the bug.)
- **Polaris is off the RGW admin key.** Polaris authenticates as `polaris-catalog`, an RGW
  user with no S3 rights that the `polaris-vendor` role's trust policy names. Polaris builds
  its own file access for a table from a credential scoped to that table's locations
  (`IcebergCatalog.loadFileIOForTableLike` in 1.5.0), so table create, commit and purge work
  with the role alone. RGW needs no capability on the assuming user for `AssumeRole`; the
  trust policy decides. `ceph/sts-bootstrap.sh` sets each role's trust on every run with
  `radosgw-admin role-trust-policy modify` (`role update` changes only the session duration).
- **Governance is off the RGW admin key.** Wiring notifications and setting the reader's bucket
  policy need bucket-owner rights, so that runs once in the `rgw-setup` one-shot; the
  long-lived governance service authenticates as a read-only `governance-reader` (ListBucket on
  `datasets/*`), since `reconcile()` only needs to list (stats come from the listing, no
  GetObject). Likewise the shim uses a realm-scoped `view-users` service account, not Keycloak
  master-admin.
- **Registry on Postgres.** The registry is the *mutable* source of truth, so it lives in a
  dedicated `governance` database (created idempotently at runtime by a bootstrap one-shot —
  there are no init scripts and the volume persists across `down`). Reconcile's status
  transition is a single atomic `UPDATE` under a row lock (no read-modify-write race between
  concurrent events); the seed and publishing use advisory locks.
- **RGW notifications on this image.** Ceph 20.2.1 supports them, but the image's `ceph.conf`
  narrows the enabled APIs and drops `notifications`; the entrypoint re-adds it. Topics are
  created via the SNS/S3 API (boto3) — `radosgw-admin` has no `topic create`.
- **Ceph keeps its data.** The image's own startup runs the OSD on memstore (RAM) and deletes
  the cluster at every start. `ceph/start.sh` replaces it: the cluster lives on the `ceph_data`
  volume with a BlueStore OSD on a sparse 20 GB file, created at the first start and reused at
  every later one, so restarts and container recreation keep buckets, tables and roles.
- **The engine relays the user's token instead of naming the user.** Trino copies a query's
  extra credentials into its per-user Iceberg catalog session, and the Iceberg REST client
  sends a credential named `token` as the bearer before attempting any exchange (read in the
  Trino 484 and Iceberg 1.12.0 sources). So Polaris validates Keycloak tokens directly, the
  shim and its signing key are gone, and the engine can no longer mint anyone. Trino 484 is
  pinned because its catalog session cache key includes the query id, so each query uses the
  token attached to it. Extra credentials are not part of Trino's serialized query info,
  unlike the username.
- **Grants left OPA.** OPA used to pull every grant from governance as a bundle, so a change
  waited for the next poll and OPA held a copy of the whole grant model. Now governance holds
  the only copy, callers send OPA only ids, and every rule fetches what it needs with
  `http.send`. Callers passing the entry themselves was tried first and dropped: Polaris
  cannot attach one, so tables needed a second path. The cost is a governance read per
  decision, and a governance outage denies every read.
- **Groups moved to governance.** The first prototype put groups in Keycloak so they would
  travel in the token, and every service read them from there. Polaris passes OPA only the
  principal's name, so table rules never saw a group. Governance now holds membership beside
  the grants, OPA fetches a person's groups by name like everything else, and tables are
  granted by group like files. A membership change applies at the next request instead of
  at token expiry.
- **Post-audit hardening** (a security review caught these): the shim's token-exchange
  requires the caller to prove it's the engine and refuses reserved principals; the OPA policy
  is deny-by-default with explicit lanes; STS roles are least-privilege. A later pass added
  per-group register ownership, the `azp` check, the bundle bearer, and the governance reader
  split above.

## 11. Limitations & deferred work

- A client that logs in through the **login-proxy** keeps its session as long as the person's
  Keycloak login lasts: the proxy holds the refresh token and swaps a fresh access token onto
  every request. A client that instead points straight at Trino with a single token (the `q`
  helper, or `--access-token`) is cut off when that token expires after 5 minutes; Trino's own
  Iceberg-client token exchange only extends the engine's catalog session, not the client's
  connection. The proxy keeps its sessions in memory, so a proxy restart logs everyone out.
- A person with `describe` and no `read` who tries to write a table gets Trino's "Failed to
  initialize the vended credentials" rather than access denied: the gate's retry returns the
  table without a credential and Trino stops there. A refused create's first line is Trino's
  own ("Failed to create transaction", "Failed to create namespace"); the gate's reason is
  the error's cause, which the CLI prints with `--debug`.
- A person who may describe a table but not read it still sees, in the cut metadata, the
  current version's write time and sequence number and the metadata file's name, whose
  leading number counts the table's commits. Kept for now (2026-10-23).
- Polaris 1.5 refuses a token whose name has no stored principal, so the gate has governance
  create each person's on first use (`POST /principals/me`, as the `provisioner` principal,
  which OPA confines to creating principals). When a Polaris release includes the `external`
  credential mode (PR #5119), switch the realm to it and remove the provisioner, that
  endpoint and the gate's call. Until then, a principal deleted while the gate remembers
  creating it costs one refused request, and Polaris logs that request's token. A query run without the
  `token` extra credential falls back to exchanging Trino's unsigned assertion, which
  Keycloak refuses.
- Polaris maps an external token's `principal_name` onto the principal of the same name; the
  gate refuses tokens naming Polaris's own principals (`root`, `provisioner`).
- Every decision reads governance: a governance outage denies every read, and table checks
  are uncached. Every credential and every table write is also logged in governance first, so
  an outage refuses those even where a decision would pass.
- The dataset index's files live in governance's memory (a restart drops them; the next load rebuilds them).
- Dev-environment only: plaintext/no-TLS except Trino's HTTPS port (Trino's clients send a
  token only over TLS; the container generates a self-signed keystore at each start), dev
  credentials in `.env`, and the OPA debug image.

## Glossary

- **PDP** — Policy Decision Point (OPA): answers "is this allowed?"
- **PAP** — Policy Administration Point (governance): owns the grants and serves them to
  each decision.
- **PEP** — Policy Enforcement Point (Polaris, the broker): asks the PDP, then enforces.
- **Vending** — minting a short-lived, scoped storage credential (STS).
- **Metadata-visibility plane** — permission to list a thing and load its metadata: the `describe` grant.
- **Data-access plane** — permission to *read the bytes*.
- **describe-but-not-read** — listed and describable, not readable (`describe` granted, `read` not).
