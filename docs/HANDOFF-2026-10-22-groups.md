# minilakehouse — handoff: groups, tenants and roles, 2026-10-22

For a coding agent with access to the `KBaseDataLakehouse` org. This records a design
discussion held without that access; the first task is to check its assumptions against the
real tenant code, then implement. Work is on `main` (fast-forwarded from
`identity-passthrough-grants-out-of-opa` on 2026-10-23). Other docs: `WHITEPAPER.md` (target design), `DESIGN.md` (the code),
`docs/HANDOFF-2026-10-20.md` (what is built and running), root `HANDOFF.md` (the BERDL/Gravitino
review).

## Findings (checked 2026-10-24 against minio_manager_service@d9ba718, trino_access_control@5f2af94, berdl_docs@2bae4d8, spark_notebook@e4741cd)

The `BERDataLakehouse` GitHub organization holds these repositories (this file called it
`KBaseDataLakehouse`). Citation roots: `MMS` = minio_manager_service, the governance service;
`TAC` = trino_access_control; `DOCS` = berdl_docs; `SN` = spark_notebook at origin/main e4741cd.
MMS at d9ba718 uses the MinIO-backed managers in `src/minio/managers/` (MMS
src/service/app_state.py:19-23); the Ceph copies in `src/s3/managers/` hold the same tenant
logic.

Polaris terms: a **catalog role** is a named set of privileges on one catalog; a **principal
role** is what a user is bound to and carries catalog roles; **CATALOG_MANAGE_CONTENT** is the
privilege MMS gives tenant writers, described in the BERDL docs as "create namespaces and
tables, write and delete data" (DOCS user_guides/requesting-tenant-access.md:121-126).

### 1. Tenant = one catalog + one prefix; members read the whole catalog — corrected in part

**What a tenant is.** Two storage groups, `<t>` (read-write) and `<t>ro` (read-only), created
together with the creating admin in both (MMS src/minio/managers/group_manager.py:358-378); one
Polaris catalog `tenant_<t>` (MMS src/polaris/constants.py:52-54); one Trino catalog `<t>` (MMS
src/routes/management.py:526-532); a metadata row and steward rows in the MMS database (MMS
migrations/versions/002_tenant_metadata.py:29-51).

**Two prefixes, not one.** Files under `tenant-general-warehouse/<t>/`; table data under
`tenant-sql-warehouse/<t>/iceberg/`, the catalog's storage location (MMS
src/polaris/managers/group_manager.py:42-46). Legacy Delta paths `tenant-sql-warehouse/<t>/<t>_*`
are read-only (MMS src/s3/core/policy_creator.py:72-79, 435-481; DOCS user_guides/s3_guide.md:153-155).

**Members read the whole catalog — confirmed.** The reader role `<t>_reader` holds
TABLE_READ_DATA, TABLE_LIST and NAMESPACE_LIST; the writer role `<t>_writer` holds
CATALOG_MANAGE_CONTENT; both are catalog-scoped (MMS src/polaris/polaris_service.py:491,
608-631). MMS makes no namespace- or table-scoped grant anywhere; the only callers of the grant
functions are polaris_service.py:611-629, src/polaris/managers/user_manager.py:79-97 and
src/polaris/managers/group_manager.py:127. On storage, `<t>ro` gets READ and `<t>` WRITE on the
whole general prefix (policy_creator.py:445-479). Trino lets every tenant in a user's
membership be read in full, whatever the access level (TAC
src/main/java/us/kbase/trino/BerdlSystemAccessControl.java:722-724, 889-896).

**Automatic membership.** Every user joins the read-write group `globalusers` when their
storage user is created, on their first `GET /credentials/` (MMS
src/minio/managers/user_manager.py:204-206; src/credentials/s3_service.py:87-93). There is no
`refdata` in the code: tenants joined because of a KBase role are set per deployment in
`MMS_ROLE_TENANTS` (MMS src/service/config.py:111-121), joined only on `GET /credentials/`
(src/routes/credentials.py:72-84, 116-118; src/minio/managers/tenant_manager.py:394-450).
Whether refdata is configured, and at which level, is unverified (deployment config).

### 2. Tenant-admin role decided by the governance service — corrected

**The per-tenant role is "steward", not "admin".** Stewards are rows in MMS's
`tenant_stewards`, keyed by (tenant, user) (002_tenant_metadata.py:42-51), checked against its
primary database (MMS src/service/dependencies.py:29-50).

**"Admin" is platform-wide only:** a user whose KBase token carries a role listed in
`KBASE_ADMIN_ROLES` (MMS src/service/kb_auth.py:153-158, 181-184); code default `KBASE_ADMIN`
(src/service/app_state.py:133), local compose `CDM_JUPYTERHUB_ADMIN` (MMS docker-compose.yml:56),
production unverified. Assigned in the KBase auth server by KBase sysadmins, not through MMS
(DOCS user_guides/admin_user_management_guide.md:213-220).

**Who may create a tenant:** platform admins only, `POST /management/groups/{name}`
(management.py:491-553). One call makes both groups, the catalog and its roles, the Trino
catalog and the metadata row; no steward is assigned. `POST /tenants/{name}` only adds metadata
to an existing group, also admin only (src/routes/tenants.py:374-390).

**Who may make someone a steward:** platform admins only (tenants.py:221-259). It also adds them
to the read-write group (tenant_manager.py:627-633). The docs and the notebook client say the
user must already be a member (DOCS admin_user_management_guide.md:190; SN
notebook_utils/berdl_notebook_utils/governance/tenant_management.py:374); the service does not
require it.

**How many:** any number of stewards, zero allowed; creation assigns none and removal has no
last-steward check (tenant_manager.py:648-657).

**What a steward can do:** edit the tenant's metadata; add members at `read_write` or
`read_only`; remove members other than themselves and other stewards (tenants.py:95, 153, 185;
tenant_manager.py:340-350). Their data access is a read-write member's, plus `root/` in tenants
with per-user write areas (item 4). They cannot assign stewards, create or delete tenants, or
switch the per-user write area (tenants.py:265-288).

**Joining:** a steward or platform admin adds the user; or the user asks through Slack and an
admin approves (DOCS user_guides/requesting-tenant-access.md:13, 44;
services/tenant-access-request-service.md:15-23); or by KBase role (item 1).

**Visibility:** any signed-in user can list every tenant with its metadata and stewards; member
lists go only to members, stewards and admins (tenants.py:40-52; tenant_manager.py:174-195).

### 3. Personal space `my.u_<user>__<dataset>` plus a per-user prefix — corrected

**Tables:** the personal catalog is Polaris `user_<u>` (MMS src/polaris/constants.py:39-41),
named `my` and `<u>` in Spark (SN notebook_utils/berdl_notebook_utils/setup_spark_session.py:57,
206-218) and `<u>` in Trino (TAC BerdlSystemAccessControl.java:110-118).
`create_namespace_if_not_exists` creates `my.<namespace>` (or `<tenant>.<namespace>`) with no
prefix, and `iceberg=False` raises (SN notebook_utils/berdl_notebook_utils/spark/database.py:42-77).
So personal tables are `my.<namespace>.<table>`. `u_<u>__` is the retired Delta/Hive database
prefix, read-only (policy_creator.py:72-79, 388-396; DOCS user_guides/data_sharing_guide.md:212),
though MMS still returns it from `GET /workspaces/me/namespace-prefix` (MMS
src/routes/workspaces.py:362-426; src/s3/utils/governance.py:16-35).

**Files:** `users-general-warehouse/<u>/` with read, write and delete; table data under
`users-sql-warehouse/<u>/iceberg/` (policy_creator.py:398-417).

**Personal space is not a group.** It is the user's own storage policies plus a catalog whose
only role, `catalog_admin` (CATALOG_MANAGE_CONTENT), is bound to the principal role `<u>_role`,
held by that user alone (MMS src/polaris/managers/user_manager.py:50-99).

**Who else can read it.** Tables: no one; MMS has no call granting another user anything on
`user_<u>`, and Trino shows a personal catalog only to its user (TAC
BerdlSystemAccessControl.java:116-118, 690-695). Files: the owner (the user whose home prefix
contains the path, MMS src/minio/managers/user_manager.py:344-359, 403-416) can still share them
through deprecated routes still served: `POST /sharing/share` gives named users or groups read
or write on a path (MMS src/routes/sharing.py:201-271; src/minio/managers/sharing_manager.py:151-199),
`/sharing/make-public` adds it to `globalusers`' policy (sharing.py:342-383;
sharing_manager.py:341-357); Delta paths are refused (sharing_manager.py:187-194); sharing the
`iceberg/` path gives the files, not the catalog. DOCS data_sharing_guide.md:163 says "There is
no per-table or per-path sharing".

### 4. A role between admin and member — found

Inside a tenant, below platform admins: steward, then member at one of two levels.
- **read_write:** group `<t>`, principal role `<t>_member`, catalog role `<t>_writer`:
  CATALOG_MANAGE_CONTENT on the whole catalog and WRITE on the general prefix.
- **read_only:** group `<t>ro`, principal role `<t>ro_member`, catalog role `<t>_reader`
  (MMS src/polaris/constants.py:57-74; polaris_service.py:608-631; policy_creator.py:445-479).

A per-tenant "per-user write area" flag, switched by platform admins (tenants.py:265-288):
with it on, the read-write group can no longer write the general prefix; each read-write member
writes `users/<self>/`, and `log/<self>/` while `TENANT_LOG_MEMBER_DIRECT_WRITE` is on; stewards
also write `root/` (MMS src/s3/core/tenant_write_area.py:82-146; src/tenant_write_area/manager.py:1-17).
Table writes are unaffected (tenant_write_area.py:128-131). In Trino both member levels are
read-only (TAC README.md:14).

### 5. Names actually used

- **tenant:** the `/tenants` routes and the docs; underneath, a pair of "groups" `<t>` and
  `<t>ro` (`/management/groups`). Names: lowercase letters and digits, starting with a letter,
  2-64 characters, no underscore or hyphen, not ending in `ro`; reserved: admin, root, system,
  all, everyone, public, default, minio, service, backup, warehouse (MMS
  src/s3/utils/validators.py:117-179, 182-205).
- **steward** ("data steward", MMS README.md:29-32): the per-tenant role.
- **admin:** platform-wide only; no per-tenant admin.
- **member:** `access_level` `read_write` or `read_only`; API flags `is_member`, `is_steward`
  (MMS src/s3/models/tenant.py:90-99, 124-136); the docs say "Read-only access" and "Read-write
  access" (DOCS requesting-tenant-access.md:10-11).
- **owner:** no tenant owner; the word appears only for the user whose home path is shared
  (sharing.py:209). Tenant metadata records `created_by` (002_tenant_metadata.py:35).
- **Display fields:** display_name, description, website, organization (s3/models/tenant.py:22-30).
- **Polaris role names:** `<t>_writer`, `<t>_reader`, `<t>_member`, `<t>ro_member`,
  `catalog_admin`, `<u>_role` (polaris/constants.py:33-74).

### Contradictions with sections 1-4

**Section 1.**
- Self-serve creation: only platform admins create tenants (management.py:491-501).
- "One role, admin, at least one": BERDL has 0..n stewards assigned only by platform admins,
  plus two member levels (items 2 and 4).
- Steward duties as written (register datasets, change grants on them, hand sub-roots to other
  groups): no BERDL code does these. MMS has no dataset object (the only "datasets" in its source
  is a marker folder, group_manager.py:718, 741), no per-dataset or per-namespace grants, and no
  route giving one tenant part of another's catalog or prefix.
- "A group that owns no root is a plain consumer group": every group made through MMS gets a
  catalog and prefixes (management.py:509-537); the `<t>ro` companions have none of their own
  (MMS src/polaris/managers/group_manager.py:80-97). Grants to other groups exist only in the
  deprecated path sharing.
- Personal space as a group of one, and `my.u_<user>`: neither matches (item 3).
- The "Decide" item: creating a tenant always provisions its catalog and prefixes in the same
  call, one step after another rather than as a transaction, with repair routes
  `/management/migrate/ensure-polaris-resources` and `/management/migrate/reconcile-trino-catalogs`
  (management.py:526-531, 1048-1063, 1204-1212).
- Reserved names: BERDL does not reserve `kbase`, `my`, `governance` or `datasets`; `kbase` is a
  tenant throughout the docs (DOCS data_sharing_guide.md:5, 156). `u_*` can never be a tenant
  name, since underscores are refused, and this repository's seed names (`jgi-writers`,
  `projw-team`, `no-access`, `group-admins`) would be refused for their hyphens
  (validators.py:145-158).
- `group-admins`: BERDL's platform admins are a KBase auth role, not a group (item 2).

**Section 2.**
- "Per tenant (whole catalog)": confirmed (item 1).
- "One dataset = one namespace": data-lakehouse-ingest at 543ad45 creates a namespace named
  after the config's `dataset` in the tenant's catalog
  (src/data_lakehouse_ingest/orchestrator/init_utils.py:82-117); whether that checkout is
  current was not confirmed.
- Namespace grants: the Trino plugin parses a `namespace_acl_tenants` field from
  `GET /polaris/effective-access/me` and allows exactly the named schema in that catalog, no
  other (TAC BerdlSystemAccessControl.java:198-227, 714-730, 885-924; TAC README.md:18-24), but
  MMS's response has no such field (MMS src/routes/polaris.py:74-81, 250-270): something reads
  them, nothing writes them.

**Section 3.**
- Who writes tenant data: every read-write member, anywhere in the tenant's prefix and catalog,
  not stewards only (policy_creator.py:445-479; polaris_service.py:608-619). The only
  steward-only write is `root/` in per-user-write tenants (tenant_write_area.py:100-106).
- "A key directly under a root is never writable": the read-write group can put objects directly
  under `tenant-general-warehouse/<t>/` (MMS src/s3/core/policy_builder.py:379-388;
  tenant_write_area.py:149-172), and MMS itself writes `README.txt` there (group_manager.py:747-748).
- How folders and tables come to exist: at tenant creation MMS writes `.s3keep` markers for the
  SQL root and for `shared/`, `datasets/` and `projects/`, plus a README (group_manager.py:710-748).
  Nothing else in MMS creates or records folders, and it has no bucket-event code; files appear
  by direct storage writes. In flagged tenants the first level is `users/`, `log/` and `root/`
  (tenant_write_area.py:100-106). Namespaces and tables are created through Spark with
  `CREATE NAMESPACE IF NOT EXISTS <catalog>.<ns>` (SN spark/database.py:70-73), the Polaris writer
  role being the only check; Trino refuses all creation (TAC BerdlSystemAccessControl.java:573-592).

**Section 4.**
- Trino in BERDL is read-only: it refuses INSERT, DELETE, CREATE TABLE (so CREATE TABLE AS) and
  views (TAC BerdlSystemAccessControl.java:72-80, 484-492, 584-592; TAC README.md:14). No BERDL
  Trino query writes a table; table writes go through Spark.
- BERDL already ships a Trino event listener, `berdl-query-log`, which reads `ioMetadata` inputs
  and output and writes JSON lines to stdout; it is off unless configured (TAC
  src/main/java/us/kbase/trino/querylog/QueryLogListener.java:115-117; TAC README.md:72-88).

### Not checked

- The tenant access request service's code is not on disk; who approves requests and which MMS
  route it calls come from docs only. SN's client docstring says approvers hold
  `CDM_JUPYTERHUB_ADMIN` (SN governance/operations.py:873-876).
- Production settings: `KBASE_ADMIN_ROLES`, `MMS_ROLE_TENANTS` (refdata, kind), which tenants
  have the per-user write area, whether the deprecated `/sharing` routes are used.
- Polaris's own definition of CATALOG_MANAGE_CONTENT (taken from BERDL docs).
- UI labels in tenant-data-browser and berdl_access_request_extension.
- No tests or code were run.

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
  after provenance narrowing, status. Visible if `describe` passes. For a caller who may
  describe it but not read it, why (decided 2026-10-23): the carried sources they may not read,
  each named only if they may describe it, and any release of it to them that was withdrawn.
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
- A group's root and namespace give its members `describe` and its admins `delete` by default
  (decided 2026-10-23). Sources narrow neither, so a dataset in a group space that rule 3 has
  closed, for instance after a release is withdrawn (`PROVENANCE.md` 6.7), stays listed for the
  group's members and removable by its admins.

### Later, same shape
- Blobs: `root_grants` on `datasets/<root>/`, unioned into `/internal/datasets` the same way.
  Needed for the default `describe` and `delete` above on a group's file datasets.

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
