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
   vending. A dataset can be visible-but-not-readable (*see-but-not-read*).
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
     table registries, group membership        allow_register / allow_change (blobs),
     and grants (the only copy)                table lanes (view/read/write/delete/
   • serves them to OPA (/internal/*)          create/change), group and root changes
   • serves the dataset index                • every rule fetches the groups and grants
   • keeps the registry fresh vs storage       it needs from governance, per decision
   • accepts grant, group and root
     ownership changes (asks OPA)

 ENFORCEMENT (PEPs — ask POLICY, then act)
   TABLES                                    BLOBS / FILES
   Trino ─► Polaris (Iceberg REST)           client ─► broker (verifies the user's
     loadTable: Authorizer ─► OPA                       OWN token) ─► OPA (allow?)
     on allow, mint per-table STS                       on allow, AssumeRole with a
     scoped to the table's files                        session policy = the dataset prefix

 DATA PLANE (bytes — STS-scoped, no OPA in this path)
   Ceph RGW (S3 + STS) enforces the vended credential; engine/client reads directly.
```

### Components

| Component | Role |
|-----------|------|
| **Keycloak** | OIDC IdP and the only token issuer — users (`alice`/`bob`/`carol`) and the `trino` client: users log in through it, and its service account (`service-account-trino`, granted nothing) is Trino's identity for its own catalog calls. |
| **Trino** | Query engine. Its JWT authenticator validates the user's Keycloak token; its Iceberg connector sends the token the user attached as the extra credential `token` to Polaris as the bearer. |
| **login-proxy** | In front of Trino so a client session outlives the 5-minute token. Speaks Trino's external-authentication (browser OAuth2) protocol to the client and holds the person's refresh token; forwards a fresh access token on every request as the bearer and the `token` extra credential. Trino is unchanged but for `http-server.process-forwarded=true`, so its nextUris point back at the proxy. |
| **governance** | PAP + dataset and table registries, Postgres-backed. Holds group membership and the only copy of every grant, serves them to OPA (`/internal/*`), serves the dataset index, keeps the registry fresh, accepts governed ingest, table registration, and grant, group and root ownership changes, records the table lifecycle the gate reports, builds and serves each person's dataset index table, and creates each person's Polaris principal on first use. Holds only a least-privilege RGW reader. |
| **OPA** | The PDP, reachable only by its callers. Loads only the rules from `opa/`: `policy.rego` (Polaris's checks), `tables.rego` (who may view a table or namespace, shared by Polaris's checks and the gate), `blob.rego` (blobs), `groups.rego` (group administration), and `governance.rego`, the one fetch every rule uses to get groups and grants from governance. |
| **gate** | The only way to Polaris. Verifies the caller's token; trims listings to what the caller may view (`tables.rego`), paging the result with its own tokens; turns a refusal for a name the caller may not view into not-found; repeats a table load Polaris refused once without the credential request, so a person who may view a table but not read it gets its metadata; decides table and namespace creation, which Polaris authorizes against the parent only; reports table creates and drops to governance; has governance create a person's Polaris principal before their first request; answers for the dataset index table, `governance.datasets`, itself. Holds no permissions; Polaris and OPA decide everything it forwards. |
| **Polaris** | Iceberg REST catalog. Validates Keycloak tokens (audience `polaris`); its Authorizer delegates every operation to OPA; vends per-table STS. Holds identities, no rules. |
| **broker** | Blob vending bridge: verifies the client's own token, asks OPA about the named dataset, `AssumeRole`s a credential scoped to the prefix in OPA's decision: `blob-vendor` to read (get, list), `blob-writer` to write (put, delete, no get). No engine in the byte path. |
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
4. Trino reads X's files from RGW directly — no OPA, no broker on the byte path.

**Flow C — read a blob dataset** — lazy, per-dataset, true end-to-end.
1. Client presents its **own** Keycloak token to the broker, naming dataset X.
2. The broker cryptographically verifies the token → subject + groups.
3. The broker asks OPA: may this subject read X? OPA fetches X's entry from governance and
   returns allow plus X's registered prefix. An unknown X gets the same 403 as a denied one.
4. On allow, the broker `AssumeRole`s with an inline session policy scoped to that prefix
   (narrowing a broad role; the client can't widen it).
5. The client reads those objects from RGW directly — no engine in the byte path.

## 5. The OPA contract

OPA never derives identity: the trusted caller verifies the token and passes the subject in
`input`, with the ids it names and never a group or a grant. OPA holds the rules and no
data; every rule fetches the person's groups and the grants it needs from governance through
`opa/governance.rego`, at decision time, so a membership or grant change applies at the next
decision.

```
rule            caller      input                              fetches                      result
vend            broker      {subject, dataset: id}             POST /internal/datasets      {allow, prefix}
vend_write      broker      {subject, dataset: id}             POST /internal/datasets      {allow, prefix}
discover        governance  {subject, datasets: [id]}          POST /internal/datasets      {visible: [id], readable: [id]}
allow_register  governance  {subject, prefix}                  GET /internal/register-grants  true | false
allow_change    governance  {subject, dataset: id,             POST /internal/datasets,     true | false
                             grants: [grant]}                    GET /internal/register-grants
table lanes     Polaris     {actor, action, resource}          GET /internal/tables/<id>,   true | false
                                                                 POST /internal/namespaces
tables.decide   gate,       {subject, tables: [id],            POST /internal/tables,       {tables: [id], namespaces: [id],
                governance   namespaces: [id]}                   POST /internal/namespaces     readable: [id]}
tables.allow_create     gate        {subject, id}              GET /internal/tables/<id>    true | false
tables.allow_namespace  gate        {subject, id}              POST /internal/namespaces    true | false
tables.allow_register   governance  {subject, id}              POST /internal/namespaces    true | false
tables.allow_change     governance  {subject, id,              GET /internal/tables/<id>,   true | false
                                     grants: [grant]}            POST /internal/namespaces
groups.allow_create     governance  {subject}                  —                            true | false
groups.allow_change     governance  {subject, group}           GET /internal/group-owners/<group>  true | false
allow_change_root       governance  {subject, prefix}          GET /internal/register-grants  true | false
tables.allow_change_root  governance  {subject, id}            POST /internal/namespaces    true | false
```

Every rule also fetches `GET /internal/groups/<subject>`.

One path for every caller because it is the only one Polaris can use: Polaris builds its own
input and cannot attach an entry. Each decision makes at most one fetch; a failed fetch
denies. Measured: a one-table `SELECT` makes one governance read, a denied one two (Polaris
retries a denied write-credential load as a read-credential load), and a vend request one. Governance builds every candidate list and OPA says which candidates pass.
Entries carry only the registry's *meaning/grants*, so storage churn never changes a
decision.

## 6. Non-tabular data & registry freshness

Table catalogs have a registry by construction; raw blobs do not. Discovery splits in two:

- **"What can I access right now?"** — easy: the subject's grant set (prefix roots), which
  governance holds. List *within* a granted prefix via a scoped credential.
- **"What exists that I could request?"** — hard: it can't come from grants (you have none
  yet) or scoped listing (you can't list it). It needs a **registry whose entries' existence
  and description are visible independent of data access** — the metadata-visibility plane.
  This is what catalogs give tables for free and nothing gives blobs, so **the registry is
  the core of this project.**

The registry (`governance`) holds, per dataset: `prefix, description, steward`, and the two
grant sets `visibility` / `access`.

### Freshness

A registry beside storage drifts, so it is reconciled against storage continuously:

- **Two truths, reconciled not merged.** Storage is truth for *existence*; the registry is
  truth for *meaning/grants*. A `datasets` row carries both, written by disjoint paths —
  meaning/grants by ingest+seed, `status` by `reconcile()` only.
- **Lifecycle `pending → live → gone`.** `reconcile()` lists a dataset's prefix, at most one
  object, and sets `status`: non-empty → `live`; emptied-after-being-live → `gone`; a
  never-populated dataset stays `pending`. The dataset index lists only `live` datasets.
- **Events are the only trigger, and they are persistent.** RGW notifies governance of each
  object created or deleted under `datasets/`; governance checks the dataset the key falls
  under. The topic is persistent (`rgw_setup.py`): RGW queues each event in RADOS and retries
  it, with no expiry or retry limit by default, until governance answers 2xx, and governance
  answers 503 when a check fails, so an event is never dropped for governance being down or
  storage being slow. There is no periodic sweep. Events carry no authority — they only
  trigger a check, which reads storage itself, so a forged event can only cause a check.
  Registration, and the first seed, check a new dataset's folder once.
- **Register-at-ingest** brings *new* datasets in: a steward uploads objects, then registers
  the dataset with its meaning (prefix, description, grants — only a human can supply these;
  its id derives from the prefix). There is no auto-discovery of datasets from raw storage: a
  dataset's boundary and meaning are human, not derivable from objects.

## 7. Credential vending

- **Lazy, per-resource, STS.** Tables: Polaris vends on `loadTable`, scoped to the table's
  files. Blobs: the broker vends on dataset-open, scoped to the dataset prefix.
- **Why a broker is unavoidable for blobs:** OPA's yes/no must be *bound into a credential the
  client cannot forge*. Only a trusted server-side step can do that. The broker holds no
  policy logic — it is a token → OPA → `AssumeRole` bridge.
- **A session policy can only narrow.** The role the broker assumes permits a superset (the
  whole `datasets/` area); the per-request session policy narrows it to one dataset's prefix.
  Safe because only the broker builds the session policy, and it builds it from a prefix
  confined at registration.
- **Scope in the STS role + session policy, not bucket policy** — RGW bucket policies don't
  support username interpolation (`${aws:username}`).

## 8. Security model

- **One policy brain, deny-by-default.** Nothing is granted that OPA didn't allow, across
  both planes. Tables (`policy.rego`), all by group: `root` / read-credential vend (`read` or
  `write`) / viewing a table (`see`, `read` or `write`) / viewing a namespace (its owners, or
  any grant on a table under it) / catalog listings (anyone; the gate trims them to what the
  two view lanes allow) / creating (the gate decides the name: a registered, pending table
  with the person in its `write`, or a namespace under one their group owns) / writes and
  read-write credentials (`write`) / dropping a table or view (`delete`) / dropping a
  namespace (its owners) — anything unnamed, including rename, register and set-location, is
  root-only. Polaris is on a
  network only the gate and its setup jobs share, so every client call passes the gate. Blobs (`blob.rego`): `vend` (read) / `vend_write`
  (write) / `visible` (see or read) / `allow_register` (ingest), all by group. Governance holds group membership; tokens
  carry no groups.
- **Grant changes are decided like access.** `PATCH /permissions/<dataset|table>/<id>` adds
  or removes groups from an entry's grants. OPA's `allow_change` decides it while
  governance holds the entry's row lock, so the entry OPA fetches is the one the write
  replaces: `see` and `read` change only for a group holding the entry's `share`; `share`,
  and a table's `write` and `delete`, only for a group owning the root (the prefix root or
  namespace registration checks). An unknown id is refused exactly as a denied change.
- **Groups are administered by their owners.** A group's owners are groups (`group_owners`);
  anyone in one of them may change its members and owners (`PATCH /groups/<name>`), decided
  by `groups.allow_change` under a per-group advisory lock. Only `group-admins` may create a
  group (`POST /groups`). Governance refuses a change that leaves a group without an owner,
  and refuses to create a group under a name any grant or ownership already uses: a dangling
  grant to that name would otherwise pass to whoever joined the new group.
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
  entries whose viewing grants name one of the person's groups (GIN indexes on
  `visibility || access` and `see || read || write`), which are exactly the grants OPA's
  visibility rules test, so the narrowing drops only entries OPA would refuse and OPA still
  decides each candidate. Measured at 50,000 live datasets with 5,003 visible to alice: a load
  took 2.39 s offering OPA every entry and 0.25 s narrowed. `seed/check-index-narrowing.py`
  compares the narrowed rows with OPA's decision over every entry for every person in a group;
  a rule that makes an entry visible by anything other than those grants must change the
  narrowing query too. The gate's table listings still grow with the whole catalog.
- **Root ownership delegates downward.** A group owning a prefix root (`register_grants`) or
  a namespace (`namespace_owners`) owns everything under it. `PATCH /roots/<dataset|namespace>/<id>`
  changes one root's owners, decided by `allow_change_root` (`blob.rego`, `tables.rego`):
  `group-admins` for a top-level root (`datasets/<name>/`, `<catalog>.<namespace>`), and
  anyone in a group owning that root or one above it. Changes take one advisory lock, so the
  ownership OPA reads is the ownership the write replaces. Because an owner of a root owns
  every root below it, a delegated subtree can always be taken back from above, and nothing
  tracks who delegated what.
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
  both certificates, each on its own volume). OPA reads its key from a mounted file: OPA's API
  evaluates any query it receives, including one that reads its environment, so a bearer in
  the environment was readable by anyone who could reach OPA, and a file is not. OPA is also on
  a network shared only with its callers (Polaris, the broker, governance, the gate) and
  publishes no host port.
- **Least privilege on every credential.** STS roles use specific actions (no `s3:*`),
  prefix-scoped (`warehouse/` for tables, `datasets/` for blobs); the broker narrows further
  per request. No long-lived service holds an admin key: Polaris authenticates as
  `polaris-catalog` and the broker as `blob-broker`, each able only to assume its vending
  role, and governance holds a read-only RGW reader (`ListBucket` on `datasets/*`, via a
  bucket policy). Admin-only RGW setup runs in the `rgw-setup` one-shot.
- **Governed ingest is scoped.** A steward must be in the `stewards` group *and* the prefix
  must sit under a root one of their groups owns (per-group ownership in OPA). Prefixes are confined
  to `datasets/<...>/` with no traversal, and the overlap-check + insert are serialized (an
  advisory lock) so two registrations can't claim overlapping prefixes.

## 9. Prior art

This is the PDP/PEP (XACML/ABAC) pattern ported onto open lakehouse parts, not a new idea:

| Source | What we take |
|--------|--------------|
| **AWS Lake Formation** | The two-plane model (metadata vs storage) and "effective permissions → vended scope." |
| **Apache Ranger + Atlas** | External PDP + discovery/classification driving policy. OPA in Ranger's seat; the registry in Atlas's. |
| **Cloudera RAZ** | Proof an external-policy object-store authorization service works at scale. The broker is the STS (not hot-path) variant. |
| **Polaris 1.5** | A pluggable Authorizer SPI that delegates the table-vend decision to OPA — the one open catalog that does. |

## 10. Implementation notes & key decisions

A chronological-ish log of decisions and hard-won details — for context, not current-state
reference (the sections above are current-state).

- **Catalog = Polaris.** Polaris 1.5's OPA authorizer calls OPA at `loadTable` and the
  decision gates STS vending — the one open catalog that delegates the vend decision to your
  policy. Blob vending is then ours to build (the broker), which is the project's actual
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
  concurrent events and register); the seed and register paths use advisory locks.
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
- A person with `see` and no `read` who tries to write a table gets Trino's "Failed to
  initialize the vended credentials" rather than access denied: the gate's retry returns the
  table without a credential and Trino stops there. A refused create's first line is Trino's
  own ("Failed to create transaction", "Failed to create namespace"); the gate's reason is
  the error's cause, which the CLI prints with `--debug`.
- `share` carries only its change right, since derived datasets (its widening right) are
  not built.
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
  are uncached.
- The dataset index's files live in governance's memory (a restart drops them; the next load rebuilds them).
- Dev-environment only: plaintext/no-TLS except Trino's HTTPS port (Trino's clients send a
  token only over TLS; the container generates a self-signed keystore at each start), dev
  credentials in `.env`, the OPA debug image, and unauthenticated `/events`
  (trusted-network).

## Glossary

- **PDP** — Policy Decision Point (OPA): answers "is this allowed?"
- **PAP** — Policy Administration Point (governance): owns the grants and serves them to
  each decision.
- **PEP** — Policy Enforcement Point (Polaris, the broker): asks the PDP, then enforces.
- **Vending** — minting a short-lived, scoped storage credential (STS).
- **Metadata-visibility plane** — permission to *see a thing exists*.
- **Data-access plane** — permission to *read the bytes*.
- **see-but-not-read** — visible in discovery yet not readable (visibility granted, access not).
