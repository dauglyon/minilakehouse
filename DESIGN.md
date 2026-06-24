# minilakehouse — Design

**Status:** Draft / working hypothesis · **Last updated:** 2026-06-22

An experimental prototype of a **unified lakehouse Policy Decision Point (PDP)**.
Descendant of the BERDL lakehouse architecture in `../brainstorm`. The thesis:
collapse today's four scattered authorization layers into **one external policy
brain**, with everything else reduced to enforcement points that ask it and a
credential mechanism that obeys it.

---

## 1. Problem

In the current BERDL stack, authorization is reimplemented in four places that
drift apart:

- **MinIO IAM policies** (S3 path level) — written by `minio_manager_service`
- **Polaris RBAC** (Iceberg catalog level) — mirrored by the same service,
  which is *why* it exploded into a catalog-per-user + catalog-per-tenant +
  RO/RW-group-variant mess to fake isolation around Polaris's coarse grants
- **Trino `SystemAccessControl` plugin** (`trino_access_control`) — namespace
  isolation re-derived in Java
- **Spark gRPC interceptors** — namespace validation re-derived again

Four copies of "who can access what," kept in sync by hand. The goal of this
prototype is to make the **policy external and single-sourced**, and make every
other component either *ask* it (a Policy Enforcement Point, PEP) or *obey* its
answer (credential vending).

We also have a requirement the table-centric catalogs don't natively serve:
**non-tabular data** (raw files / blobs) accessible via S3, under the *same*
governance model as tables.

---

## 2. Core principles (invariants)

1. **One identity.** A single OIDC IdP (Keycloak) issues one token used by
   users, engines, the catalog, the broker, and the object store.
2. **Policy is external and single-sourced.** The governance service owns the
   grant model and publishes it to **OPA**, the one PDP. Nothing re-decides.
3. **Two permission planes** (borrowed wholesale from AWS Lake Formation):
   - **metadata-visibility** — may you *see that a thing exists* / its
     description (drives discovery)
   - **data-access** — may you *read the bytes* (drives vending)
4. **Discovery and access are separate.** Discovery returns *names*; access
   returns *scoped credentials*. Neither enumerates the whole bucket.
5. **Vending is lazy and per-resource.** You get a credential scoped to the one
   table / one dataset you are opening — never "a credential for everything."
6. **OPA decides; STS carries; S3 enforces.** OPA is in the *decision* path,
   never the *byte* path. No per-object policy call (no hot path). Revocation
   lag is bounded by credential TTL — an accepted trade for avoiding the hot
   path.

---

## 3. Architecture

```
╔══════════════════════════════════════════════════════════════════════════╗
║ LAYER 0 — IDENTITY                                                         ║
║   Keycloak (OIDC)  ──issues one JWT (sub, groups)──►  used by EVERYONE     ║
║                       users · Trino · Polaris · broker · RGW               ║
╚══════════════════════════════════════════════════════════════════════════╝
        │ same token authenticates every actor below
        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║ LAYER 1 — POLICY  (control plane · decides · never touches bytes)          ║
║                                                                            ║
║   Governance service (PAP)              OPA (PDP)                          ║
║   • grant model: subject → resource     • access:  "can S do A on X?"      ║
║   • registry: namespaces / datasets       → allow + scope                  ║
║     + descriptions + stewards           • discovery: "what can S see?"     ║
║   • publishes grants as ──────────────►   → returns identifier set         ║
║     OPA data (bundle/pull)                                                 ║
║                                                                            ║
║   Encodes TWO permission planes:                                          ║
║     (a) METADATA-VISIBILITY = may you SEE it exists / its description      ║
║     (b) DATA-ACCESS         = may you READ the bytes                       ║
╚══════════════════════════════════════════════════════════════════════════╝
        │ enforcement points ASK Layer 1, then act
        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║ LAYER 2 — ENFORCEMENT  (PEPs)                                              ║
║                                                                            ║
║   TABLES                              BLOBS / FILES                        ║
║   Trino ──► Polaris (Iceberg REST)    Client ──► Vending broker (thin,     ║
║              │ loadTable(X)                       ~100 lines, no logic)    ║
║              │ Authorizer ──► OPA                 │ validate JWT → subject ║
║              │   (DATA-ACCESS)                    │ ──► OPA: paths for X    ║
║              │ mint STS scoped to                 │ AssumeRole, session    ║
║              ▼ table X's location                 ▼ policy = OPA's paths   ║
╚══════════════════════════════════════════════════════════════════════════╝
        │ hands back a credential scoped to exactly what OPA allowed
        ▼
╔══════════════════════════════════════════════════════════════════════════╗
║ LAYER 3 — DATA PLANE  (bytes · STS-scoped · NO OPA in this path)           ║
║   Ceph RGW (S3 + native STS/OIDC) ── enforces the scoped credential ──►    ║
║   engine/client reads objects DIRECTLY.  Revocation lag = credential TTL.  ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Components

| Component | Role | Notes |
|-----------|------|-------|
| **Keycloak** | OIDC IdP | One token for all actors. Groups/claims governance-controlled. |
| **Governance service** | PAP + registry | Owns grant model + the non-tabular **dataset registry** (names, descriptions, prefixes, stewards). Publishes grants to OPA. Descendant of `minio_manager_service`, but it **stops writing into backends** — it feeds OPA instead of mirroring into MinIO/Polaris. |
| **OPA** | PDP | The one decision engine. Two query shapes: discovery (returns identifier set) and access (returns allow + scope). |
| **Polaris** | Iceberg catalog + table vending | Authorizer SPI delegates the `loadTable` check to OPA; vends STS scoped to the table location. **Tabular only.** |
| **Vending broker** | Non-tabular vend bridge | Thin, stateless, *no policy logic*. Token → ask OPA for paths → `AssumeRole` with a session policy = those paths → return scoped creds. |
| **Trino** | Query engine (PEP) | Reads Iceberg via Polaris. Can use Trino's native OPA access control for query-level authz against the **same** OPA — likely **replacing** the bespoke `trino_access_control` plugin. |
| **Ceph RGW** | Object store + STS | Native `AssumeRoleWithWebIdentity` (OIDC) + session policies + bucket notifications. The reason RGW, not MinIO: MinIO lacks this. |

---

## 4. Request flows

```
FLOW A — DISCOVERY  "what can I see?"   (the HARD part · returns names, NO creds)
  1. Client + JWT ──► Governance: "list what I can see"
  2. Governance reads its registry (all namespaces/datasets)
  3. filters via OPA (METADATA-VISIBILITY plane): which may S see exist?
  4. returns names + descriptions + locations         ← no bytes, no credential
     • tables also listable natively via Polaris (OPA-gated catalog metadata)
     • blobs come from the registry, kept fresh by RGW bucket-notifications
       + steward curation  ← this freshness mechanism is the open problem

FLOW B — ACCESS, TABLE  "read table X"   (lazy · per-table)
  1. Trino ──► Polaris: loadTable(X) + JWT
  2. Polaris Authorizer ──► OPA (DATA-ACCESS): may S read X?
  3. allow ──► Polaris mints STS scoped to X's storage location
  4. Trino reads X's files from RGW directly      ← no OPA, no broker

FLOW C — ACCESS, BLOB  "open dataset X"   (lazy · per-dataset)
  1. Client + JWT ──► Vending broker, names dataset X
  2. broker validates JWT → subject S
  3. broker ──► OPA (DATA-ACCESS): granted paths for S under X?  → path set
  4. broker ──► RGW STS AssumeRole, session policy = that path set (narrows
     a broad role; client can't forge it)
  5. broker returns scoped temp creds
  6. client ListBucket within X (lists contents) + GetObject from RGW directly
                                                  ← no OPA in this path
```

---

## 5. The OPA contract

OPA never derives identity. The **trusted caller** validates the JWT and passes
the subject in `input`. OPA combines `input` (the request) with `data` (the
grant table the governance service publishes) and the Rego policy.

Two query shapes:

```
DISCOVERY (enumerate):
  input  → { subject: "alice", action: "see" }
  output → { visible: ["ns/jgi", "ns/projX", ...] }      # identifiers only

ACCESS (per-resource):
  input  → { subject: "alice", action: "read", resource: "ns/projX" }
  output → { allow: true }     # PREDICATE ONLY — OPA never returns paths
```

**OPA is a predicate, never an enumerator** (corrected from an earlier draft of this
section that returned `paths`). For access, OPA answers yes/no on the *named* resource;
the resource's prefix comes from the **registry/broker**, which binds it into the
credential's session policy itself. OPA never emits a path list. Discovery (Flow A)
likewise filters registry entries through per-entry yes/no calls — the registry builds
the list, OPA gates each candidate. Neither builds a credential covering the whole grant
set.

---

## 6. Non-tabular data — the hard part

Table catalogs have a registry *by construction*; raw blobs do not. Discovery
splits into two sub-problems:

- **"What can I access right now?"** — *easy*. It is the subject's grant set
  (the prefix roots), which governance already holds. List *within* a granted
  prefix via a scoped credential for contents. Never a whole-bucket walk.
- **"What exists that I could *request*?"** — *hard*. Cannot come from grants
  (none yet) or scoped listing (can't list it). Requires a **registry whose
  entries' existence + description are visible independent of data access** —
  exactly the metadata-visibility plane. This is what catalogs give tables for
  free and nothing gives blobs.

**So the registry is the real core of this project.** Polaris is *not* used for
non-tabular vending (its generic-table credential vending is upstream roadmap,
not implemented). Instead:

- Governance hosts a **dataset registry**: `namespace/dataset → {prefix,
  description, owner/steward, visibility grants, access grants}`.
- Discovery = query the registry, filtered by OPA's metadata-visibility plane.
- Access = broker + RGW STS scoped to the dataset's prefix, gated by OPA's
  data-access plane.

### Freshness (open problem)

A registry separate from storage drifts. Two mitigations, to be decided:

- **Register-at-ingest** — every dataset that lands is registered by the
  governed write path (DTS, ingestion jobs). Stays exact; requires controlling
  all write paths.
- **Event-driven indexing** — RGW **bucket notifications** (→ Kafka/HTTP) feed
  an indexer that maintains the registry. Decouples from the write path; eventual
  consistency; still needs a convention for what groups objects into a *named,
  described dataset*, and a steward to describe it.

Likely a hybrid: stewards curate dataset entries (BERDL already has a
tenant/steward model); events/scans keep freshness and stats.

---

## 7. Credential vending model

- **Lazy, per-resource, STS.** Tables: Polaris vends on `loadTable`, scoped to
  the table location (per-table — *not* coarser; coarse scoping is the source of
  Polaris's recent vending CVEs). Blobs: broker vends on dataset-open, scoped to
  the dataset prefix.
- **Why a broker is unavoidable for blobs:** OPA's path answer must be *bound
  into a credential the client cannot forge*. Only a trusted server-side step can
  do that binding. The broker holds **no policy logic** — it is a dumb
  token→OPA→`AssumeRole` bridge. (This is the minimal honest form of the
  "vending service" — justified, not avoided.)
- **Security constraint:** an STS **session policy can only narrow** the role it
  assumes. The role the broker assumes permits a superset (e.g. the data
  bucket); OPA's path list narrows it. Safe because *only the broker* constructs
  the session policy — the client never does, and cannot forge the signed JWT's
  claims.
- **RGW caveat:** RGW **bucket policies do not support string interpolation**
  (`${aws:username}`). Do scoping in the **STS role + session policy**, not in
  bucket policy.
- **Fallback (not default):** RGW also has per-request OPA authorization
  (`rgw_opa_url`). That is the live-decision / instant-revocation option, but it
  is the hot path we are avoiding. Reserve for prefixes ABAC/STS can't express.

---

## 8. Prior art we are porting from

This is **not greenfield as an architecture** — it is the PDP/PEP/PIP (XACML/ABAC)
pattern, shipped for a decade. We are porting it onto open lakehouse parts.

| Source | What we take |
|--------|--------------|
| **AWS Lake Formation** | The two-plane permission model (metadata vs storage) and "effective permissions → vended scope". The blueprint. |
| **Apache Ranger + Atlas** | External PDP + discovery/classification, with tag-sync so classification drives policy. OPA sits in Ranger's seat; our registry in Atlas's seat. |
| **Cloudera RAZ** | Proof that an external-policy-driven object-store authorization service works at scale. Our broker is the **STS (not hot-path)** variant of RAZ. |
| **Immuta / Privacera** | The "universal data access governance" feature decomposition (policy plane + discovery/classification + enforcement). We are an open, lakehouse-scoped version. |
| **Polaris 1.5** | Pluggable Authorizer SPI → OPA *in the vend path*. The one open catalog that delegates the table-vend decision to your policy. |

---

## 9. Open decisions (not yet made)

1. **Catalog fork.** Polaris (delegates the vend decision to our OPA, but
   tabular only → we build blob vending via the broker) **vs** Gravitino
   (already vends filesets, but decides on *its own* RBAC/Ranger, not our OPA).
   Current lean: **Polaris**, because policy-aligned vending is the
   non-negotiable and Polaris is the only open catalog that supports it. Blob
   vending is then ours to build — which is the project's actual contribution.
2. **Registry freshness mechanism** (§6): register-at-ingest vs event-indexing
   vs hybrid.
3. **Ad-hoc / fine-grained grants.** Group/tenant/home-prefix grants map cleanly
   to OPA + broker. Truly per-user, per-prefix ad-hoc shares either become
   groups, or ride the broker's session-policy injection. Decide the cutoff.
4. **Trino authz.** Replace `trino_access_control` with Trino's native OPA
   access control against the same OPA? (Likely yes — collapses one of the four
   layers.)
5. **Staleness budget.** Credential TTL sets revocation lag. Pick TTLs per plane.

---

## 9b. Phase 0 results (implemented 2026-06-23)

Flow B is built and proven end-to-end (`docker compose up --build` → seed → alice
reads, bob denied; OPA decides on the real per-user identity). Key outcomes and
decisions that emerged during implementation:

- **Catalog fork (open decision #1): resolved → Polaris.** Polaris 1.5's OPA authorizer
  works (`polaris.authorization.type=opa`); it calls OPA at `loadTable` and the decision
  gates STS vending. OPA holds all rules; Polaris holds only identities.
- **STS-against-RGW (the spike): WORKS, not just blog-attested.** Polaris assumes a
  `radosgw-admin`-created role and vends per-table session-token credentials against the
  Ceph RGW test image. Required: `rgw_sts_key` (16 alnum) + `rgw_s3_auth_use_sts` in
  ceph.conf, an empty-account role ARN, and **`kmsUnavailable:true`** on the catalog
  (else Polaris's read subscope policy includes `kms:*` actions RGW rejects). The static
  `stsUnavailable` + `SKIP_CREDENTIAL_SUBSCOPING_INDIRECTION` detour was abandoned — it's
  a dev-only anti-pattern that hands ambient creds to every client.
- **Identity propagation (Stage B, the pivotal risk): GO — but it required a new
  component.** Trino cannot forward a real end-user credential to Polaris: `session=USER`
  conveys the user only as an **unsigned, self-issued JWT** (confirmed in Trino source),
  which Keycloak refuses (`invalid_issuer`), and Polaris's authenticator rejects
  unmanaged principals. So we added an **`idp-shim`** — a small trusted identity layer
  that sits where Trino fetches OAuth tokens and is Polaris's OIDC issuer. It turns
  "our Trino asserts alice" into a **real signed alice token**; Polaris validates it and
  resolves the real principal; OPA decides on the real user. This is a genuine addition
  to the architecture (§3 had Keycloak issuing tokens directly; in practice the engine
  hop needs the shim).
- **Trust model (settled with the open-Polaris-API constraint):** every call to Polaris
  carries a real signed identity and is OPA-gated on it, so an exposed Polaris API has no
  skeleton key. "We trust our Trino" is encoded in exactly one auditable place — the shim
  — and the `trino_svc` service principal is granted nothing in OPA. True end-to-end
  user creds (safe against a compromised engine) are only achievable on the *direct*
  client/broker path (no engine in the byte path) — that's the blob plane (Phase 1).
- **Trino query-level authz (open decision #4): deferred.** The per-user gate currently
  lives at the credential vend (OPA via Polaris), which is sufficient for whole-table
  access. Trino-native OPA access control would add query-/column-level controls later.
- **Principals:** external identities must be pre-registered in Polaris as bare names
  (no roles, no grants) — an identity sync, not a rule sync. OPA filters token groups
  against Polaris grants, so `actor.roles` arrives empty; decisions key on the username,
  and group membership (for group rules) is OPA data, not Polaris state.

### Security hardening (post-audit)

A subagent security audit caught three real issues, since fixed and verified:
- **The idp-shim was a token-minting oracle** (its token-exchange path checked neither
  caller nor subject). Now it requires the caller to prove it is the engine (client
  secret or a shim-issued service token) and refuses to mint reserved principals
  (`root`, `trino_svc`) — so the engine relays end users but cannot escalate to admin.
  Consequence: **`root` is no longer assertable through Trino**, so the demo table is
  seeded as its owner `alice` (a "writer"), not root.
- **The OPA policy denied by default** with explicit lanes (admin / grant-gated vend /
  read-only ops / writer DDL); previously every non-vend operation fell through to allow,
  letting a denied user drop the catalog or create principals.
- **The STS role is least-privilege** (specific actions, scoped to a `warehouse/`
  sub-prefix) instead of `s3:*` on the whole bucket — so a missing per-table session
  policy fails closed-ish to the warehouse, not the whole bucket.

Two subtleties worth carrying forward: the credential-vend authz target for *creating* a
table is the **namespace** (the table doesn't exist yet), so create-and-vend is gated as
a namespace write, not a table grant; and `data` self-reference in Rego (`object.get(data,
…)`) causes a recursion error — read the specific subtree (`data.writers`) instead.

## 9c. Phase 1 results (implemented 2026-06-23)

Flow C is built and proven end-to-end — the **true end-to-end plane**, where the client
presents its *own* token and no engine sits in the byte path.

- **The broker** (`broker/app.py`, ~120 lines): client `POST /vend` with its own Keycloak
  token + a dataset name → broker **cryptographically verifies the token** (JWKS, issuer,
  expiry — no engine-trust, the inverse of the idp-shim) → asks OPA the predicate → on
  allow, `AssumeRole` on the `blob-vendor` role with an inline session policy scoped to the
  dataset's prefix → returns the scoped temp credential. The client reads those bytes
  directly from RGW.
- **RGW session-policy narrowing works** (the load-bearing spike): the assumed credential's
  permissions are the *intersection* of the role's policy (`datasets/*` read) and the
  session policy (one dataset prefix). Proven: alice's `projx-public` credential reads
  `public/` but is **RGW-denied** on `private/`.
- **OPA is a predicate, not an enumerator** (§5, now corrected). The broker holds the
  dataset→prefix registry (`broker/datasets.json`, a stand-in for the Phase-2 registry);
  OPA only answers yes/no on the named dataset (`opa/blob.rego`). Because the client
  presented its own token, the broker passes the user's **real groups** to OPA (unlike the
  Polaris path, where Polaris filtered token groups) — so blob grants work by group cleanly.
- **Plane separation:** blobs live under `s3://lakehouse/datasets/`, the `blob-vendor` role
  is read-only and confined there; tables under `s3://lakehouse/warehouse/`. Neither role's
  credential can reach the other plane.
- **The trust boundary, realized:** tables-via-Trino are engine-trusted (the idp-shim); the
  broker plane is genuinely end-to-end (the user's own verified credential), safe even
  against a compromised engine. Both ask the one OPA.

## 9d. Phase 2 results (implemented 2026-06-23)

Flow A is built — the **metadata-visibility plane** and **discovery**, the project's
novel core (catalogs give tables this for free; nothing gives blobs it).

- **The governance service** (`governance/app.py`) is the **single source of truth** (the
  PAP + registry). It owns the dataset registry (`governance/registry.json`:
  `{prefix, description, steward, visibility, access}` per dataset) *and* all grants, and
  **publishes them to OPA as a bundle** — OPA pulls policy+data from governance
  (`opa/config.yaml`, bundle mode), and the hand-edited `opa/*.json` grant files are gone.
  This realizes "policy external **and** single-sourced **and** published."
- **Two planes, separate grants.** `visibility` (may you *see* it exists) vs `access`
  (may you *read* the bytes), as independent grant sets. So `projx-private` is **visible**
  to `jgi-writers` but **readable by nobody** — the see-but-not-read (Lake Formation)
  model, proven: alice discovers it (`can_read=false`) yet the broker denies her a read.
- **Discovery (Flow A)** = `governance /discover`: verify the user's own token, enumerate
  the registry, ask OPA the **visibility predicate** per entry, return names +
  descriptions (annotated with `can_read`). **No bytes, no credentials.** OPA stays a
  predicate — governance builds the list, OPA gates each candidate; OPA never enumerates
  (this is the §5 correction, now realized in code).
- **The broker is single-sourced too:** it resolves dataset→prefix from governance's
  registry (`/datasets/<name>`), not a static file.
- Scope (locked with the user): blob-dataset discovery only (table discovery via Polaris
  is comparatively free); grant-publish via **bundle/pull** (OPA stays read-only, no
  writable data API — consistent with the audit). Registry **freshness** (§6) remains
  Phase 3.

## 9e. Phase 3 results (implemented 2026-06-24)

Registry **freshness** (§6) is built, and the registry became a **real datastore** along
the way — Phase 2 had left it as a stateless re-read of a JSON file, which was a skipped
piece of infrastructure for a system whose registry is the *mutable* single source of truth.

- **Governance on Postgres.** Governance now owns a dedicated `governance` database
  (alongside Polaris's `polaris` DB in the same `postgres:16` server). A
  `governance-bootstrap` one-shot `CREATE DATABASE`s it idempotently at **runtime** — there
  are no `/docker-entrypoint-initdb.d` scripts and the volume persists across `down`, so an
  init-script path would never run on an existing volume. Governance creates its schema
  (`CREATE TABLE IF NOT EXISTS`), **seeds once** from `registry.json` if empty (now just a
  fixture), and serves bundle/`discover`/`datasets`/ingest/reconcile transactionally
  (psycopg2 pool). Proven durable: a runtime write survives `restart governance`.
- **Two truths, reconciled not merged.** Each `datasets` row carries two column groups
  written by **disjoint** paths: *meaning/grants* (`prefix, description, steward,
  visibility[], access[]`) by ingest+seed, and *existence/stats* (`status, object_count,
  total_bytes, last_modified`) by `reconcile()` only. The OPA bundle is built from
  meaning/grants **only**, so storage churn never moves OPA. Discovery = **OPA-visible ∩
  `status='live'`**.
- **Lifecycle `pending → live → gone`.** `reconcile()` lists a dataset's prefix
  (`list_objects_v2` — stats come from the listing, no GetObject) and sets `status`:
  non-empty → `live`; empty → `gone` **only if it was live** (was-populated-now-empty),
  else it stays `pending`. So a freshly-registered, not-yet-populated dataset is never
  wrongly killed, and discovery never advertises a dead one.
- **One reconcile path, two triggers.** A periodic **timer** (full sweep, convergence) and
  **RGW bucket notifications** (per-dataset, near-real-time). Events carry **no authority** —
  `/events` is unauthenticated (trusted-network dev assumption); an event only *triggers* a
  reconcile, which reads storage truth itself, so a missed/forged/duplicate event is
  harmless and self-heals on the next sweep. The event handler maps object-key → owning
  dataset by **longest registered prefix**; a key under no registered prefix is logged
  "ungoverned" and ignored.
- **RGW notifications on this image.** Ceph 20.2.1 (tentacle) supports notifications, but
  the image's `ceph.conf` explicitly narrows `rgw enable apis` to `s3, admin, iam, sts`
  (dropping `notifications`); the entrypoint re-adds it. Topic + bucket-notification are
  created via the SNS/S3 API (boto3) — `radosgw-admin` has no `topic create`. Governance
  wires its own subscription at startup, best-effort: if it failed, the timer still
  reconciles (clean degradation). **Note:** RGW (no persistent volume here) re-bootstraps
  on container *recreate*, so its data is ephemeral — the table re-seed and blob re-seed are
  expected post-`up` steps.
- **Register-at-ingest.** `POST /datasets` is **authN by the caller's own token** and
  **authZ by OPA** — the `stewards` capability lives in the published bundle
  (`allow_register`), not hardcoded in governance, keeping the one-policy-brain invariant.
  It inserts the dataset (`pending`, `steward = subject`) then reconciles synchronously, so
  a governed ingest (upload objects, then register) is deterministically `live`. New grants
  reach OPA on its next bundle poll (≤ poll interval). Proven: alice (a steward) ingests
  `projz` and then discovers+reads it; bob (not a steward) is denied at registration (403).
- **idp-shim key persistence (robustness fix made this session).** The shim used to
  generate its RS256 signing key in-memory at every start, so *any* shim restart (laptop
  sleep, Docker restart, a redeploy) rotated the key and invalidated every token Trino held
  **and** Polaris's cached JWKS — silently breaking the whole table plane until both
  refreshed. (The earlier "derive `kid` from the key so Polaris refetches" only fixed the
  Polaris side, not Trino's cached tokens.) The key is now **loaded-or-generated from a
  persistent volume** (`SHIM_KEY_PATH`, `shim_key` volume) → stable `kid`, seamless
  restarts (verified: restart the shim, Flow B keeps working with Trino untouched). Note
  the discipline here: idle token *expiry* must NOT be "fixed" by disabling expiry checks —
  the shim correctly rejects an expired engine token and Trino re-authenticates with the
  client secret (self-heals); only key *rotation* was the real bug.
- **Honest limits.** No auto-discovery of datasets from raw storage — a dataset's *meaning*
  (name, boundary, grants) is human; the machine can at most flag ungoverned objects, which
  governed ingest makes moot. **De-registration** (a steward explicitly retiring a dataset,
  vs. it going `gone` because its bytes vanished) is a deferred explicit action, not built.
  **Governance holds the RGW admin key** (it needs bucket-owner rights to wire notifications;
  reconcile reuses it to list). This is acceptable because governance is already the trusted
  PAP that publishes the policy bundle — its compromise is total regardless of RGW scoping.
  A stricter deployment would split notification-setup into a one-shot (admin) and give the
  long-lived service a read-only `ListBucket`-on-`datasets/*` reader.

## 10. Build plan (phased)

- **Phase 0 — spine.** docker-compose: Keycloak + Polaris + Trino + Ceph/RGW +
  OPA. Prove Flow B end to end: a subject OPA *allows* gets vended creds and
  reads an Iceberg table via Trino; a subject OPA *denies* gets nothing. No
  bespoke vending service anywhere on this path.
- **Phase 1 — blob access.** Vending broker + RGW STS. Prove Flow C: open one
  registered dataset, broker scopes STS to its prefix via OPA, client
  lists/reads; denied subject gets nothing.
- **Phase 2 — discovery.** Governance dataset registry + the metadata-visibility
  plane. Prove Flow A: browse what exists and is requestable, separate from what
  is readable.
- **Phase 3 — freshness.** Wire RGW bucket notifications and/or register-at-ingest
  to keep the registry honest against storage.

---

## Glossary

- **PDP** — Policy Decision Point (OPA). Answers "is this allowed?"
- **PAP** — Policy Administration Point (governance service). Owns and publishes
  the grants.
- **PEP** — Policy Enforcement Point (Polaris, Trino, the broker). Asks the PDP,
  then enforces.
- **Vending** — minting a short-lived, scoped storage credential (STS).
- **Metadata-visibility plane** — permission to *see a thing exists*.
- **Data-access plane** — permission to *read the bytes*.
</content>
</invoke>
