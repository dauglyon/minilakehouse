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
   Keycloak (OIDC) — users, groups, the engine's service account. The only token issuer.
   Trino           — authenticates each user's Keycloak token and forwards that same token
                     to Polaris as the bearer (extra credential `token`), unexchanged.

 POLICY (control plane — decides, never touches bytes)
   governance (PAP)                          OPA (PDP)
   • Postgres-backed dataset registry  ◄──   • rules only, no grants: vend / discover /
     + table grants (the only copy)            allow_register (blobs), table lanes
   • serves grants to OPA (/internal/*)        (root/vend/read/write)
   • serves discovery (Flow A)               • every rule fetches the grants it needs
   • keeps the registry fresh vs storage       from governance, per decision

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
| **Keycloak** | OIDC IdP and the only token issuer — users (`alice`/`bob`/`carol`), groups, and the `trino` client: users log in through it, and its service account (`service-account-trino`, granted nothing) is Trino's identity for its own catalog calls. |
| **Trino** | Query engine. Its JWT authenticator validates the user's Keycloak token; its Iceberg connector sends the token the user attached as the extra credential `token` to Polaris as the bearer. |
| **governance** | PAP + dataset registry, Postgres-backed. Holds the only copy of every grant, serves them to OPA (`/internal/*`), serves discovery, keeps the registry fresh, and accepts governed ingest. Holds only a least-privilege RGW reader. |
| **OPA** | The PDP. Loads only the rules from `opa/`: `policy.rego` (tables), `blob.rego` (blobs), and `governance.rego`, the one fetch every rule uses to get grants from governance. |
| **gate** | Proxy between Trino and Polaris. Repeats a table load Polaris refused once without the credential request, so a person who may view a table but not read it gets its metadata. Holds no permissions; Polaris and OPA decide both attempts. |
| **Polaris** | Iceberg REST catalog. Validates Keycloak tokens (audience `polaris`); its Authorizer delegates every operation to OPA; vends per-table STS. Holds identities, no rules. |
| **broker** | Blob vending bridge: verifies the client's own token, asks OPA about the named dataset, `AssumeRole`s a credential scoped to the prefix in OPA's decision. No engine in the byte path. |
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

OPA never derives identity: the trusted caller verifies the token and passes the subject +
groups in `input`, with the ids it names and never a grant. OPA holds the rules and no
grants; every rule that needs one fetches it from governance through `opa/governance.rego`,
at decision time, so a grant change applies at the next decision.

```
rule            caller      input                              fetches                      result
vend            broker      {subject, groups, dataset: id}     POST /internal/datasets      {allow, prefix}
discover        governance  {subject, groups, datasets: [id]}  POST /internal/datasets      {visible: [id], readable: [id]}
allow_register  governance  {subject, groups, prefix}          GET /internal/register-grants  true | false
table lanes     Polaris     {actor, action, resource}          GET /internal/tables/<fqn>,  true | false
                                                                 /internal/table-writers
```

One path for every caller because it is the only one Polaris can use: Polaris builds its own
input and cannot attach an entry. Each decision makes at most one fetch; a failed fetch
denies. Measured: a one-table `SELECT` makes one governance read, a denied one two (Polaris
retries a denied write-credential load as a read-credential load), and a discovery or vend
request one. Governance builds every candidate list and OPA says which candidates pass.
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

- **Two truths, reconciled not merged.** Storage is truth for *existence/stats*; the registry
  is truth for *meaning/grants*. A `datasets` row carries both, written by disjoint paths —
  meaning/grants by ingest+seed, existence/stats by `reconcile()` only.
- **Lifecycle `pending → live → gone`.** `reconcile()` lists a dataset's prefix and sets
  `status`: non-empty → `live`; emptied-after-being-live → `gone`; a never-populated dataset
  stays `pending`. Discovery advertises only `live` datasets.
- **One reconcile path, two triggers.** A periodic timer (convergence) and RGW bucket
  notifications (near-real-time). Events carry no authority — they only *trigger* a reconcile,
  which reads storage truth itself, so a missed or forged event self-heals on the next sweep.
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
  both planes. Tables (`policy.rego`): `root` / read-credential vend (`read`) / viewing a
  table (`see` or `read`) / catalog listings (anyone) / writes, DDL and read-write
  credentials (`writers`) — anything unnamed is root-only. Blobs (`blob.rego`): `allow` (read) / `visible`
  (see) / `allow_register` (ingest), all group-based.
- **Real, end-to-end identity.** Every decision is made on the user's own Keycloak token.
  Tables: Trino authenticates the token and relays it to Polaris unchanged; Trino's username
  is the token's `principal_name`, and Trino's default access control refuses impersonation,
  so a client cannot run as someone else. The engine holds no credential that names a user:
  its own service account is granted nothing. Blobs: the broker verifies the user's *own*
  token — no engine in the byte path.
- **Token checks.** Trino and Polaris verify signature, issuer, expiry, and audience
  `polaris`. Governance and the broker verify signature, issuer, and expiry, and pin `azp` to
  the login client (so a token minted for another realm client can't be replayed).
- **Grant lookups are closed.** `/internal/*` returns grants for datasets the user cannot
  see, so it requires a bearer (`ENTRY_TOKEN`) held only by OPA.
- **Least privilege on every credential.** STS roles use specific actions (no `s3:*`),
  prefix-scoped (`warehouse/` for tables, `datasets/` for blobs); the broker narrows further
  per request. The long-lived governance service holds only a read-only RGW reader
  (`ListBucket` on `datasets/*`, via a bucket policy) — never an admin key. Admin-only RGW
  setup runs in the `rgw-setup` one-shot.
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
  the timer, events, and register); the seed and register paths use advisory locks.
- **RGW notifications on this image.** Ceph 20.2.1 supports them, but the image's `ceph.conf`
  narrows the enabled APIs and drops `notifications`; the entrypoint re-adds it. Topics are
  created via the SNS/S3 API (boto3) — `radosgw-admin` has no `topic create`. RGW data here is
  ephemeral (no volume), so it re-bootstraps on container *recreate* — the table re-seed and
  blob re-seed are expected post-`up` steps.
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
- **Post-audit hardening** (a security review caught these): the shim's token-exchange
  requires the caller to prove it's the engine and refuses reserved principals; the OPA policy
  is deny-by-default with explicit lanes; STS roles are least-privilege. A later pass added
  per-group register ownership, the `azp` check, the bundle bearer, and the governance reader
  split above.

## 11. Limitations & deferred work

- Trino keeps a user's token alive by token exchange (standard exchange, enabled for the
  `trino` client in the realm file) while the user's Keycloak login session is active: an
  exchange does not count as activity, so refresh stops once that session idles out (30
  minutes by default), and a query fails at its next Polaris call after that. Each refresh
  first fails six times (Iceberg authenticates its first attempt with the user's bearer,
  which Keycloak rejects) and then succeeds with the engine's client credential, logging four
  retry warnings.
- Table listings are not trimmed, so every table's name is visible to everyone. The gate
  (`gate/app.py`) does one thing so far: Trino asks for a credential on every table load and
  Polaris refuses the whole load without one, so the gate repeats a refused load once
  without the credential request. A person with `see` and no `read` can then DESCRIBE a
  table through Trino; reading it fails at storage. Polaris is still reachable directly. A query run without the `token` extra credential falls back to exchanging
  Trino's unsigned assertion, which Keycloak refuses.
- Polaris maps an external token's `principal_name` onto the principal of the same name, so
  Keycloak must have no user named `root` (Polaris's internal admin).
- Every decision reads governance: a governance outage denies every read, and table checks
  are uncached.
- Table-plane `writers` is a coarse global list (a writer may write any namespace); a real
  model would scope it per-namespace.
- No de-registration yet (a steward explicitly retiring a dataset, vs. it going `gone` because
  its bytes vanished). Discovery is blob-only; table discovery rides Polaris's own listing.
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
