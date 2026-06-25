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

1. **Policy is external and single-sourced.** One service (governance) owns the grant model
   and publishes it to **OPA**, the one PDP. Nothing re-decides or mirrors policy into a
   backend.
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
   Keycloak (OIDC) — users, groups, service accounts.
   idp-shim        — turns Trino's per-user assertion into a real signed token Polaris
                     validates (it is Polaris's OIDC issuer). The one trusted converter.

 POLICY (control plane — decides, never touches bytes)
   governance (PAP)                          OPA (PDP)
   • Postgres-backed dataset registry  ──►   • predicate over published grants:
     + table grants                            allow / visible / allow_register (blobs),
   • publishes a signed-pull bundle            table lanes (root/vend/read/write)
   • serves discovery + dataset→prefix       • never enumerates; answers yes/no
   • keeps the registry fresh vs storage

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
| **Keycloak** | OIDC IdP — users (`alice`/`bob`), groups, and two service accounts (the engine login client, and a realm-scoped `view-users` account the shim uses). |
| **idp-shim** | The trusted identity layer for the table plane. Trino can only *assert* the end user (an unsigned note); the shim converts that into a real signed per-user token Polaris validates. Polaris's OIDC issuer. |
| **governance** | PAP + dataset registry, Postgres-backed. Owns the registry + all grants, publishes them to OPA as a bundle, serves discovery and dataset→prefix, keeps the registry fresh, and accepts governed ingest. Holds only a least-privilege RGW reader. |
| **OPA** | The PDP. Pulls policy + data from governance as a bundle (authenticated). A predicate: `opa/policy.rego` (tables), `opa/blob.rego` (blobs). |
| **Polaris** | Iceberg REST catalog. Its Authorizer delegates `loadTable` to OPA; vends per-table STS. Holds identities, no rules. |
| **broker** | Blob vending bridge: verifies the client's own token, asks OPA, `AssumeRole`s a credential scoped to one dataset prefix. No engine in the byte path. |
| **Ceph RGW** | Object store + native STS + bucket notifications. Enforces the vended credential. |
| **Postgres** | Polaris metastore and the durable `governance` registry database. |
| **rgw-setup** (one-shot) | Admin-credentialed startup step: sets the bucket policy granting the governance reader `ListBucket` on `datasets/*`, and wires bucket notifications — so the long-lived governance service never holds the admin key. |

## 4. Request flows

**Flow A — discovery ("what can I see?")** — returns names, no credentials.
1. Client presents its own token to governance.
2. Governance enumerates its registry and, per entry, asks OPA the *visibility* predicate.
3. Returns the visible names + descriptions (annotated with `can_read`). No bytes.
   (Tables are additionally listable via Polaris's own catalog metadata; the registry covers
   blobs and is kept fresh against storage.)

**Flow B — read a table** — lazy, per-table.
1. Trino → Polaris `loadTable(X)`, carrying the real per-user identity (via the idp-shim).
2. Polaris's Authorizer asks OPA: may this user read X?
3. On allow, Polaris mints a per-table STS credential scoped to X's files.
4. Trino reads X's files from RGW directly — no OPA, no broker on the byte path.

**Flow C — read a blob dataset** — lazy, per-dataset, true end-to-end.
1. Client presents its **own** Keycloak token to the broker, naming dataset X.
2. The broker cryptographically verifies the token → subject + groups.
3. The broker asks OPA the predicate: may this subject read X?
4. On allow, the broker `AssumeRole`s with an inline session policy scoped to X's prefix
   (narrowing a broad role; the client can't widen it).
5. The client reads those objects from RGW directly — no engine in the byte path.

## 5. The OPA contract

OPA never derives identity: the trusted caller verifies the token and passes the subject +
groups in `input`. OPA combines `input` with `data` (the grants governance publishes) and the
Rego policy, and returns a **boolean**:

```
input  → { subject, groups, action, dataset }     (blobs)
output → true | false
```

It is a **predicate, never an enumerator**. For discovery, governance enumerates its registry
itself and calls the predicate per candidate; OPA never returns the inventory. For access, OPA
answers yes/no on the *named* resource, and the caller binds the resource's prefix into the
credential. The bundle data is built from the registry's *meaning/grants* only, so storage
churn never changes what OPA decides.

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
  the dataset with its meaning (name, prefix, description, grants — only a human can supply
  these). There is no auto-discovery of datasets from raw storage: a dataset's boundary and
  meaning are human, not derivable from objects.

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
  both planes. Tables (`policy.rego`): `root` / per-table vend grant / read-only metadata /
  writer DDL — anything unnamed is root-only. Blobs (`blob.rego`): `allow` (read) / `visible`
  (see) / `allow_register` (ingest), all group-based.
- **Real, end-to-end identity.** Tables: the idp-shim converts Trino's assertion into a signed
  token Polaris validates — its signing key is *persisted* (a restart doesn't rotate it and
  invalidate cached tokens), it refuses reserved principals (`root`, the service principal),
  and the engine proves itself with a *dedicated* secret distinct from the Keycloak client
  secret end users log in with (so a logged-in user can't drive the shim to mint arbitrary
  identities). Blobs: the broker verifies the user's *own* token — no engine in the byte path.
- **Token checks.** Governance and the broker verify signature, issuer, and expiry, and pin
  `azp` to the login client (so a token minted for another realm client can't be replayed).
- **Least privilege on every credential.** STS roles use specific actions (no `s3:*`),
  prefix-scoped (`warehouse/` for tables, `datasets/` for blobs); the broker narrows further
  per request. The long-lived governance service holds only a read-only RGW reader
  (`ListBucket` on `datasets/*`, via a bucket policy) and a realm-scoped `view-users` Keycloak
  service account — never an admin key. Admin-only RGW setup runs in the `rgw-setup` one-shot.
- **Governed ingest is scoped.** A steward must be in the `stewards` group *and* the prefix
  must sit under a root their group owns (per-group ownership in OPA). Prefixes are confined
  to `datasets/<...>/` with no traversal, and the overlap-check + insert are serialized (an
  advisory lock) so two registrations can't claim overlapping prefixes.
- **Bundle pull is authenticated.** The bundle is the full grant model, so OPA presents a
  shared bearer to pull it (the link is also internal/trusted-network).

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
- **Post-audit hardening** (a security review caught these): the shim's token-exchange
  requires the caller to prove it's the engine and refuses reserved principals; the OPA policy
  is deny-by-default with explicit lanes; STS roles are least-privilege. A later pass added
  per-group register ownership, the `azp` check, the bundle bearer, and the governance reader
  split above.

## 11. Limitations & deferred work

- The shim trusts the engine's *asserted* end-user subject; binding "this caller is our
  engine" to the transport (mTLS / network policy) is deferred — the engine proof is a shared
  secret today.
- Table-plane `writers` is a coarse global list (a writer may write any namespace); a real
  model would scope it per-namespace.
- No de-registration yet (a steward explicitly retiring a dataset, vs. it going `gone` because
  its bytes vanished). Discovery is blob-only; table discovery rides Polaris's own listing.
- Dev-environment only: plaintext/no-TLS, dev credentials in `.env`, the OPA debug image, and
  unauthenticated `/events` (trusted-network).

## Glossary

- **PDP** — Policy Decision Point (OPA): answers "is this allowed?"
- **PAP** — Policy Administration Point (governance): owns and publishes the grants.
- **PEP** — Policy Enforcement Point (Polaris, the broker): asks the PDP, then enforces.
- **Vending** — minting a short-lived, scoped storage credential (STS).
- **Metadata-visibility plane** — permission to *see a thing exists*.
- **Data-access plane** — permission to *read the bytes*.
- **see-but-not-read** — visible in discovery yet not readable (visibility granted, access not).
