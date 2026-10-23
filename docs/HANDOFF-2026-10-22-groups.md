# minilakehouse — handoff: groups, tenants and roles, 2026-10-22

For a coding agent with access to the `KBaseDataLakehouse` org. This records a design
discussion held without that access; the first task is to check its assumptions against the
real tenant code, then implement. Work is on branch `identity-passthrough-grants-out-of-opa`
(head `8b909bb`). Other docs: `WHITEPAPER.md` (target design), `DESIGN.md` (the code),
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
- `namespace_grants (namespace TEXT PRIMARY KEY, describe, read, share, write, delete TEXT[])`,
  the same five sets as `table_entries`. `namespace` is `<catalog>` or
  `<catalog>.<namespace...>`.

### Internal lookups
- `/internal/tables` and `/internal/tables/<id>`: each set is the table's own ∪ every ancestor
  namespace's (`lakehouse.db.t1` gets `lakehouse.db` and `lakehouse`). Add `own` (the table's
  own sets) and `inherited_from` ({group: namespace} per set) beside them, for the read API
  and UI only; rules use the effective sets.
- `_index_rows`: the candidate filter for `governance.datasets` must include namespace grants,
  or a table granted only through its namespace never reaches OPA and vanishes from the index.
  `seed/check-index-narrowing.py` must still pass; extend its seed with an inherited-only table.
- `/internal/namespaces` viewers: union in `namespace_grants` at and below the namespace.

### API
- `PATCH /permissions/namespace/<id>`: new kind. `describe`/`read` change for a group holding
  the namespace's `share`; `share`/`write`/`delete` for an admin of a group owning the
  namespace or one above (section 1's role model).
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
