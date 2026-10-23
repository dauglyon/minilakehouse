# minilakehouse — handoff: groups, tenants and roles, 2026-10-22

For a coding agent with access to the `KBaseDataLakehouse` org. This records a design
discussion held without that access; the first task is to check its assumptions against the
real tenant code, then implement. Work is on `main` (fast-forwarded from
`identity-passthrough-grants-out-of-opa` on 2026-10-23). Other docs: `WHITEPAPER.md` (target design), `DESIGN.md` (the code),
`docs/HANDOFF-2026-10-20.md` (what is built and running), root `HANDOFF.md` (the BERDL/Gravitino
review).

## Goal

Make the group model match how the platform's **tenants** already work, and make it
self-serve, like GitHub orgs:

- Any user may create a group.
- A group has **members** and one role, **admin**. At least one admin at all times.
- A group that owns a root (`datasets/<name>/`, `<catalog>.<namespace>`) is a **tenant**.
  Its admins are what the source material calls **data stewards**: they register datasets
  under the root, change grants on them, and hand sub-roots to other groups.
- A group that owns no root is a plain consumer group (a grant target). Same kind of thing.
- Every user has a personal space, modelled as a group of one that owns their personal root.

"Steward" stops being a global capability and becomes "admin of a group that owns a root".

## What to verify first (needs org access)

Read, at `KBaseDataLakehouse/*` on `main`: `minio_manager_service`, `trino_access_control`,
`berdl_docs`, `spark_notebook` (`notebook_utils/.../spark/database.py`,
`create_namespace_if_not_exists`), and whatever holds tenant administration. The earlier review
(root `HANDOFF.md`) read these on 2026-10-19. Confirm or correct:

1. A tenant is one Iceberg catalog and one object-store prefix
   (`tenant-general-warehouse/<tenant>/`), and its members get read on the whole catalog.
2. There is a tenant-admin role, decided by the governance service. Who may create a tenant?
   Who may grant admin? Can a tenant have more than one admin?
3. Personal space is `my.u_<user>__<dataset>` (tables) and a per-user prefix (files). Who else
   can be given read on it, if anyone?
4. Whether any role exists between admin and member (e.g. writer). If so, record it; do not
   add it here yet.
5. The names actually used (tenant, admin, owner, steward, member) so the UI can use them.

Record findings at the top of this file before changing code.

## Changes to make

### Schema (`governance/app.py`)
- `group_members (grp, member)` gains `role text not null check (role in ('admin','member'))`.
- Drop `group_owners`. Migrate seed: `governance/registry.json` `group_owners` → the owning
  group's members become admins of the owned group. Seed should end with:
  `jgi-writers`: alice admin; `projw-team`: carol admin; `stewards`, `no-access`,
  `group-admins`: carol admin.
- Drop `register_grants` and the `stewards` group once rego no longer reads them.

### Rego
- `opa/groups.rego`: `allow_create` true for any authenticated subject. `allow_change`:
  caller is an admin of the group. Add `is_admin(subject, group)` for the other packages.
- `opa/blob.rego` / `opa/tables.rego`: `allow_register` = caller is admin of a group owning a
  root above the prefix/namespace (drop the `"stewards" in _groups` conjunct). `allow_change`
  for `share`/`write`/`delete`/`detach` = admin of an owning group (not any member).
  `describe`/`read` changes stay with `share` holders.
- `allow_change_root`: unchanged in shape; "owner of a root above" means admin of a group
  owning it. `group-admins` keeps top-level assignment.
- `opa/governance.rego`: fetch `/internal/groups/<subject>` with roles, or add
  `/internal/admin-of/<subject>`.
- Private-space exemption (`PROVENANCE.md` 9): in `opa/blob.rego` (`_reads`, `vend_write`)
  and `opa/tables.rego` (`readable`, `writable`), an entry under the subject's own personal
  root skips the sources check, unless one of the subject's groups is in a carried source's
  `revoked`. `revoked` is a new per-source set of groups beside the six grants, changed by the source's root owners as `share` and `detach`
  are, recorded and shown to its `share` holders like detaches; governance's lookups return it
  with each source's `read` and `share`.

### Governance API
- `POST /groups`: body `{name}`. Caller becomes the first admin and member. Owners/members in
  the body are ignored (or refused). Keep the name-in-use check (grants, roots, and now
  reserved names).
- `PATCH /groups/<name>`: `{members: {add, remove}, admins: {add, remove}}`. Refuse a change
  that leaves no admin. Admin implies member.
- Decide: does creating group `X` also assign it `datasets/X/` and `lakehouse.X`? If yes,
  do it in the same transaction and extend the name-in-use check to roots. If no,
  `group-admins` assigns top-level roots as today. Verification item 2 decides this.
- Reserved names: a list in `.env` or `registry.json` (`kbase`, `my`, `governance`, `u_*`,
  `datasets`, `warehouse`). Refuse creating a group with one.
- Personal space: on a person's first appearance (`POST /principals/me` already runs then),
  create group `u_<user>` with them as admin, owning `datasets/u_<user>/` and `my.u_<user>`,
  if that matches item 3.
- Default grants at registration: a dataset registered under a tenant's root defaults to
  `read: [<tenant>]`, `share: [<tenant>]`. Make this the default the caller may override in
  the request body, not a rego rule; the registry stays the only truth. Confirm against item 1.

### Read side (prerequisite for any UI; new)
Governance has no `GET` routes. Add, each narrowed by the same predicates as the writes:
- `GET /me` → groups with my role in each; roots those groups own; whether I am in
  `group-admins`.
- `GET /groups/<name>` → members with roles, roots owned. Visible to members.
- `GET /datasets/<id>`, `GET /tables/<id>` → the entry with declared grants, effective `read`
  after provenance narrowing, status. Visible if `describe` passes.
- `GET /roots/<kind>/<id>` → owning groups and immediate children. Visible to an admin of an
  owning group or one above.

### Docs and seed
- Update `README.md` sections "Changing groups", "Assigning roots", the `stewards` mentions,
  and the registration demo. Update `DESIGN.md` 4.4 and `WHITEPAPER.md` 4.2–4.4 where they
  say "each group has owners, which are groups".
- `seed/check-index-narrowing.py` and the README demos must still pass.

## Out of scope here
- On-behalf-of tokens for the ingest pipeline (Keycloak token exchange). Pipelines act as
  subjects in groups for now.
- A separate writer role between admin and member.
- The web UI itself. The read routes above are its only server-side prerequisite.

## Decisions already taken (do not reopen)
- `group-admins` stays a small human group: break-glass, reclaiming abandoned roots,
  top-level roots not named after a group.
- The governance API takes a person's token only. No service lane.
- One role (admin), not owner + steward. Split later if a need appears.

---

# Section 2 — namespace grants (inheritance)

## Why

In the platform's ingest (`kbase/data-lakehouse-ingest`) one dataset is a namespace with many
tables, created in one run. Today access there is per tenant (whole catalog). minilakehouse
grants per table, so a tenant with hundreds of tables would be registered and permissioned one
table at a time. Every comparable system (Unity Catalog, Polaris, Snowflake, Lake Formation,
Gravitino, Ranger) grants at a level of the hierarchy and inherits downward; the table is the
exception. Match that.

The rego stays almost untouched: every rule in `tables.rego` reads `e.read`, `e.describe`,
etc. off the entry governance hands it, so governance returns *effective* grants (the table's
own ∪ each ancestor namespace's) and `readable`, `viewable`, `writable`, `shares` and the
provenance narrowing work as they are. OPA still decides on one named resource; no
enumeration is added.

## Changes

### Schema (`governance/app.py`)
- `namespace_grants (namespace TEXT PRIMARY KEY, describe, read, share, write, delete, detach
  TEXT[])`, the same six sets as `table_entries` (`detach` was added after this section was
  first written). An empty `detach` lets any writer of a derived output detach the table
  (`PROVENANCE.md` 6.5), so inheriting it narrows: a namespace's `detach` restricts every table
  under it, and a table's effective `detach` is empty only when its own and every ancestor's
  are. `namespace` is `<catalog>` or
  `<catalog>.<namespace...>`.

### Internal lookups
- `/internal/tables` and `/internal/tables/<id>`: each set is the table's own ∪ every ancestor
  namespace's (`lakehouse.db.t1` gets `lakehouse.db` and `lakehouse`). Add `own` (the table's
  own sets) and `inherited_from` ({group: namespace} per set) beside them, for the read API
  and UI only; rules use the effective sets.
- `_own_grants` (`governance/app.py`), which supplies each carried source's `read` and `share`
  for provenance narrowing (`_with_sources`, `PROVENANCE.md` 6, rule 3), returns the same
  effective sets. Otherwise a source granted only through its namespace admits nobody to
  anything derived from it, though people can read the source itself.
- `_index_rows`: the candidate filter for `governance.datasets` must include namespace grants,
  or a table granted only through its namespace never reaches OPA and vanishes from the index.
  `seed/check-index-narrowing.py` must still pass; extend its seed with an inherited-only table.
- `/internal/namespaces` viewers: union in `namespace_grants` at and below the namespace.

### API
- `PATCH /permissions/namespace/<id>`: new kind. `describe`/`read` change for a group holding
  the namespace's `share`; `share`/`write`/`delete`/`detach` for an admin of a group owning
  the namespace or one above (section 1's role model).
- `POST /tables`: accept a list of entries in one request, all under one namespace, in one
  transaction. Grants on each are optional and default to empty (inherit only). Registering
  from an ingest config's table list is the intended use.

### OPA (`opa/tables.rego`)
- `allow_change` gains a clause for kind `namespace`, deciding on the `namespace_grants` row
  with the same `_may_change` split. Governance passes `kind` in the input.
- No other rule changes.

### Read API (section 1) additions
- `GET /namespaces/<id>`: its own grants, owners, tables under it with status and whether each
  has grants of its own. This is the steward's day-to-day page.
- `GET /tables/<id>`: returns `grants` (effective), `own`, `inherited_from`.

### Semantics to document
- Removing a group from a table's own grant does nothing while an ancestor namespace still
  grants it (as in Unity Catalog). The UI shows inherited grants as not editable on the table,
  with a link to the namespace that grants them.
- Tables created later under a namespace inherit at once (Snowflake's "future grants" for free).
- Provenance narrowing applies to effective `read`: a namespace grant does not let a group read
  a table derived from sources it may not read.

### Later, same shape
- Blobs: `root_grants` on `datasets/<root>/`, unioned into `/internal/datasets` the same way.
  Not needed for the first UI.

## Decided
- Inheritance is computed by governance when serving the entry, not by rego fetching parents
  and not by copying grants onto tables at registration. The registry's per-table rows stay
  the only place a table-specific grant lives.

---

# Section 3 — storage-first registration

Vocabulary follows the whitepaper: a **publisher** writes and then **registers** an entry;
**declaring** is the separate provenance act that names which candidate sources were used.
`describe` stays a grant name and is not used for anything else.

## Why

The design's rule is "storage owns existence, the registry owns meaning", and the registry
already reconciles against RGW events. But registration today is form-first: a dataset is
registered (`POST /datasets`, `allow_register`) before its bytes exist, and a table must be
registered `pending` before `CREATE TABLE` is allowed. Writing is gated on a registry entry
that describes nothing yet. Invert it: writing under a root you own is allowed by ownership
alone; registering what was written comes after.

## Model

- A **tenant admin** (section 1) may write anywhere under a root their group owns: a blob
  folder under `datasets/<root>/`, a table under `<catalog>.<ns>`.
- Whatever appears there is an entry at once, **unregistered**: no description, grants = those
  inherited from the root or namespace (section 2), nothing of its own. Readable by whoever
  the root's grants name — by default only the owning group.
- **Registering** it (description, own grants) is the publisher's act; declaring sources is
  the separate act it already is. The entry's `registered` flag replaces `pending`; `live`/`gone` stay as the storage truth.
- The cross-tenant guard moves, it does not go: writing needs an owned root; overlapping blob
  folders are refused at registration, which now follows the write.

## Changes

### Blobs
- `opa/blob.rego`: drop `allow_register`. `vend_write` takes `{subject, prefix}`, where
  `prefix` is one folder: exactly one level below a root (a new dataset), or inside an
  existing dataset's folder (that dataset). It allows an admin of a group owning a root above
  the folder, or the dataset's `write` grant, cut by its sources as now. A key directly under
  a root is never writable: a dataset is a folder (`WHITEPAPER.md` 10).
- `broker/app.py`: `POST /vend` with `mode: write` takes `prefix` instead of `dataset`.
  Governance derives the folder's dataset id as registration does (`derive_id`), and the
  broker logs the credential against that id before returning it, as now; the entry the
  first event creates has the same id. A credential is never for a whole root: a folder's
  files are matched to the write credentials logged against that dataset (`_CARRIED_SQL`),
  by time, so a root-wide credential would either carry nothing (logged against no dataset)
  or, matched by prefix, make every folder under the root carry its holder's reads while it
  was valid. S3 Access Grants' `privilege=Minimal`, a credential no wider than the requested
  target inside a wider grant, is the same shape.
- `governance/app.py` `/events`: a key under an owned root with no entry creates one. Its id
  is derived as now; its folder is the key's first path segment below the root (deeper
  structure stays inside the dataset). Log `EVENT ... created unregistered <id>` instead of
  "ungoverned". A key under no owned root stays ungoverned and logged.
- `POST /datasets` becomes `PATCH /datasets/<id>` on an unregistered entry: description and
  own grants. Sources are declared as today (`governance.derivations`). Allowed for an admin of a group owning a root above it. Keep the
  overlap check here (refuse registering a folder that overlaps a registered one).
- Schema: `datasets.registered BOOLEAN NOT NULL DEFAULT false`; `status` keeps `live|gone`.
  Drop `register_grants`.

### Tables
- `opa/tables.rego`: `allow_create` allows an admin of a group owning the namespace or one
  above (drop the `pending` entry requirement). Drop `allow_register`.
- `gate/app.py`: reports created tables as now; governance inserts the entry unregistered with
  status `live`. `POST /tables` goes away; `PATCH /tables/<id>` registers.
- `table_entries.registered` as for datasets; `pending` goes away.

### Read API (sections 1–2) additions
- `GET /groups/<name>` gains `unregistered`: entries under its roots with `registered = false`,
  each with writer (from the access log), first-seen time, object or row count, and, for a
  blob folder, the tables whose sessions read it (so an ingest pair shows side by side).
- `GET /datasets/<id>` / `GET /tables/<id>`: `registered`, and `writer`.

### Index
- `governance.datasets` lists unregistered entries only to groups that may read them (the
  owning group by default). A registered entry a group may describe but not read is visible by `describe` as now.

### Docs and seed
- README "Registry freshness & governed ingest", "Flow B" (the `t2` demo) and the whitepaper's
  register-at-ingest section change to: write, then register. `seed/ingest-demo.py` uploads
  with a root-scoped write credential, then registers.

## UI consequence
"Register" is not a form. It is an inbox on the group page: things in your roots nobody has
registered yet. Registering is the same grants panel as everywhere else plus a description;
declaring sources sits beside it, prefilled from the lineage candidates.

## Decided
- Writing under an owned root needs no prior registry entry.
- Unregistered data is readable only through root/namespace grants, never wider.
- `pending` is removed; `registered` is a flag on a live entry.
- No new vocabulary: register, declare, publisher, entry, as in `WHITEPAPER.md` and `PROVENANCE.md`.

---

# Section 4 — engine-drafted declarations

Vocabulary as above: a **declaration** is the publisher's signed insert into
`governance.derivations` (`PROVENANCE.md` 5.3). A **draft** is new: an engine's proposal for
one, which the publisher confirms. A draft is never a declaration.

## Why

Declaring today means reading `governance.lineage` for a target and giving every candidate a
`used` value (`PROVENANCE.md` 5.4). Candidates are every read of the session (4.2), so a
person who explored for a morning and then ran one `CREATE TABLE … AS SELECT` declares a
dozen sources by hand. The engine knows which tables that one statement read: Trino reports
inputs and output per query through its event listener, Spark through OpenLineage. Use that
to draft the declaration.

The trust model does not move. `PROVENANCE.md` 2 rejects engine-emitted provenance as truth
because the engine is not trusted, and that stands: a draft changes nothing about who may read
until the publisher inserts it, and that insert passes every existing check (OPA on each
source marked unused, the `detach` rules, the candidate check). The engine saves the
publisher the lookup; the publisher still signs.

## Model

- A draft is per target and per statement, written by the engine's service account. The
  engine knows more than what each statement read: it knows where every result went, into a
  table or back to the client. For each candidate of the target the draft says one of three
  things:
  - `used`: the engine read it in the writing statement;
  - `unused`: the engine read it in that session, not in the writing statement, and every
    read of it in the session wrote its rows into a table. The data never left the engine's
    custody, and where it went is a table the log already tracks;
  - nothing: the engine cannot vouch. It never saw the source (a broker read, another
    engine), or it returned the source's rows to the client at some point in the session,
    after which only the person knows whether they came back (`PROVENANCE.md` 8). Left blank
    for the publisher.
- A writing statement whose data comes from the client (`INSERT … VALUES`, or any statement
  with no table input) is a write of whatever the client holds: no candidate the client has
  received is prefilled on it.
- An engine may speak only about reads it made. A draft naming a source the access log does
  not show that engine reading for that person is refused.
- Over-attribution is the safe direction. Where a statement cannot be tied exactly to log
  rows (concurrent statements by one person), the draft marks more `used`, never more
  `unused`. Extra `used` costs the publisher an edit; a wrong `unused` they confirm without
  looking is a false declaration they signed.
- Confirming is one statement, the same insert as today with the draft as its source:

      INSERT INTO governance.derivations (source, source_type, target, used)
      SELECT source, source_type, target, used FROM governance.drafts
      WHERE target = 'lakehouse.db.joined';

  A blank candidate left out is refused as now (`not declared: projx/public`), which is the
  right prompt: the engine could not see it, so a person must say.

## Changes

### Trino
- Enable Trino's HTTP event listener (`event-listener.name=http`,
  `http-event-listener.connect-ingest-uri`, `log-completed=true`) pointed at governance.
  `QueryCompletedEvent` carries the user (`principal_name`), query id, start and end time,
  `queryType`, `ioMetadata.inputs` (catalog, schema, table per table read), `ioMetadata.output`
  (the table written, when the statement wrote one) and the statistics' output row count, so
  a statement that returned rows to the client is told apart from one that wrote a table.
  No Java to write. Verify: whether the listener can present a client
  certificate to the internal listener (port 8443); if not, a header secret as `/events`
  uses, since the listener supports custom headers.
- Ignore inputs in the `governance` namespace.

### Governance
- Table `drafts (target, engine, statement_id, person, source, source_type, used, at)`.
- `POST /internal/drafts`, from a certificate (or secret) named `trino`, confined to that
  route. Per event: the person is the event's user; the target is the output table; the
  statement's reads are its inputs. Validate against the access log: the person wrote the
  target in `[start, end]` (the gate logged the commit); every input is a table the person
  read, through the gate, in that session. Governance keeps, per session and engine, which
  table reads had rows returned to the client (from the same events). Candidates per
  `lineage` that are table reads, not inputs of this statement, and never returned to the
  client get `unused`; a candidate returned to the client, a `files` candidate, and a source
  that arrived through a read (`direct` false) get no row. An event whose output is not a registered
  entry the person wrote is dropped and logged.
- `governance.drafts`, read-only, served like `lineage`: the person's own drafts, columns of
  `derivations` plus `engine` and `statement_id`. Built from Postgres on each load as the
  other governance tables are. The gate answers the `governance` namespace itself and treats
  any name not in `INDEX_TABLES` (`gate/app.py`) as not found, so add `drafts` there; define
  its columns in `governance/index_table.py`. Inserts into it stay refused (`WRITABLE`).
- Spark: OpenLineage `RunEvent` has inputs and outputs in the same shape; a second parser on
  the same route, later.

### UI (section 3)
- The declare panel prefills from `drafts` instead of raw candidates. Blank candidates are
  the ones that need the person's attention; show them first.

## Decided
- A draft never changes who may read. Only the publisher's insert into `derivations` does.
- An engine drafts only for reads it made, and marks `unused` only what never left its
  custody. A source whose rows it returned to the client is never prefilled.
- Over-attribute, never under-attribute, when a statement and the log cannot be matched
  exactly.
- The engine does not sign declarations for its own reads. A deployment that wants that
  grants the engine's service account `detach` on the sources in question and widens the
  rule in `opa/derivations.rego`; it is a trust decision made in policy, not a code path.

## Out of scope
- Spark / OpenLineage parser (same endpoint; later).
- Out-of-band carry through the client: a person who reads `t1`, looks at the result, and
  types the numbers into `INSERT VALUES`. The engine saw `t1`'s rows go to the client, so
  `t1` stays blank on the draft and the person must say. Same limit as today
  (`PROVENANCE.md` 8); the draft never guesses `unused` for it.

## To verify
- Trino's HTTP event listener: TLS client certificate support; that `ioMetadata.inputs` lists
  base tables behind views and CTEs; that `ioMetadata.output` is set for `CREATE TABLE AS`
  and `INSERT`.
- Matching a statement to access-log rows by person and time window when the person runs
  statements concurrently.
