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

Section 1 was rewritten on 2026-10-24 to follow these findings; the items below are what its
first version assumed.

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

# Section 1 — groups, tenants and spaces

Rewritten 2026-10-24 from the findings above. Prior art: Google Groups for owners, managers
(here admins) and members; BERDL for stewards appointed by platform admins and for read-only
members; Dataverse, where contributors deposit and curators publish, for separating work in a
space from publishing it; Google Drive's move from My Drive into a shared drive for transfers.

## Roles

Each role is held in one group. A person is an owner, admin, member or viewer of a group, and
can also be its steward.

| Role | May |
|---|---|
| Owner | everything an admin may; delete the group; add and remove owners and admins |
| Admin | add and remove members and viewers; delete in the group's space; see declarations that mark the space's folders unused |
| Steward | in a tenant: publish from its space, change grants there, add and remove members and viewers. Appointed and removed by platform admins only |
| Member | read and write the group's space; transfer folders and tables into it |
| Viewer | read the group's space |

- Owner includes admin, admin includes member, member includes viewer. A steward is a member
  or above.
- A group always has at least one owner; a change that would leave none is refused.
- A viewer never holds `write`. A grant naming a group gives `describe` and `read` to everyone
  in it, and every other grant to its members and above. Viewers are BERDL's read-only members.
- **Platform admins** hold no role in any group. They appoint and remove stewards, act for a
  tenant that has none, and act in emergencies. How a person is marked as one is open (below).

## Groups and tenants

- Any signed-in person may create a group, and becomes its owner.
- Names follow BERDL's rule (MMS src/s3/utils/validators.py:117-179): 2 to 64 lowercase letters
  and digits, starting with a letter. Reserved: BERDL's list (`admin`, `root`, `system`, `all`,
  `everyone`, `public`, `default`, `minio`, `service`, `backup`, `warehouse`) and `governance`,
  the namespace the gate answers itself (`gate/app.py:72`). BERDL's refusal of tenant names
  ending in `ro` (validators.py:182-205) is not adopted: it protects the `<t>ro` group BERDL
  creates for read-only members, which viewers replace.
- Every group has a space: the folder `datasets/<group>/` and the namespace
  `lakehouse.<group>`. Creating a group writes nothing to storage; a folder is tracked from its
  first write credential (section 3).
- A group with at least one steward is a **tenant**. A member asks; a platform admin appoints.
  Only stewards publish or change grants in a space, so a group without one cannot open its
  space to anyone outside it.
- When a tenant's last steward leaves, its published datasets stay published with their grants.
  Nothing is published and no grant changes until a platform admin appoints a steward or acts
  for the group. BERDL lets a tenant run with no steward the same way (tenant_manager.py:648-657).

## Default grants in a space

Grants name groups, and a role within a group as `<group>#<role>`, the notation Zanzibar and
SpiceDB use for the members of a relation. A space's defaults, which folder grants (section 3)
and publishing add to:

| Grant | Default |
|---|---|
| `describe`, `read` | `<g>`: viewers and above |
| `write` | `<g>`: members and above |
| `delete` | `<g>#admin` |
| `share` | `<g>#steward` |
| `detach` | empty |

Changing `share`, `write`, `delete`, `detach` or `revoked` anywhere in a space takes a steward of
its group; changing `describe` and `read` takes `share`, as now.

## Why a plain group's space reaches no one outside the group

- Nobody in it holds `share`, and changing its grants or publishing takes a steward.
- Rule 3 limits anything built from it, wherever written, to people who can read the folder it
  came from: the group's viewers and above.
- Who is in the group decides who reads it, and only owners and admins change that.
- What remains is what every dataset has (`PROVENANCE.md` 7 and 8): a member can download, or
  declare a read of the space unused, which the shipped policy accepts for a direct read
  (`PROVENANCE.md` 6.5). A declaration marking a source unused is shown to the source's `share`
  holders and, for a folder or table in a space, to its group's admins: a plain group's space
  has no `share` holders.

## Personal spaces

- On a person's first appearance (`POST /principals/me`), governance creates the group
  `u_<user>` with them as its only owner. No one else can be added, it can have no steward, and
  nothing in it is published or granted to anyone else. No created group can take the name: the
  name rule refuses underscores.
- The personal-space exemption and `revoked` (`PROVENANCE.md` 9) apply in personal spaces only.
- A person shares from their space by transferring a folder or table: to a group, for its
  members, or to a tenant, for a steward to publish.

## Transfers

A transfer moves a folder or a table from a personal space or a plain group's space into
another group's space. Its old path stops working.

- **Who.** For a personal folder or table, the person whose space it is; for a plain group's,
  an owner or admin of that group. The caller is a member or above of the receiving group.
- **Where.** The destination does not exist yet and is not inside a published dataset or
  namespace, so a transfer reaches no one beyond the receiving group; publishing it is a
  steward's separate act.
- **Files.** `POST /transfers {from, to}`. The broker copies each object with a server-side copy
  and deletes the original, under a session policy covering the old folder (get, list, delete)
  and the new one (put); governance keeps its read-only storage key. Ceph shares stored data
  between an object and its copy in the same bucket: measured 2026-10-24 on this stack, the copy
  of a 64 MiB object left the data pool at 64 MiB, and read back intact after the original was
  deleted and garbage collection forced (`radosgw-admin gc process --include-all`). The broker's
  credentials are logged as a read of the old folder and a write of the new one, in a session of
  the caller's own for the transfer, so the listing (`PROVENANCE.md` 6.2) attributes the copies
  to that session and rule 2 gives each copy everything the old folder carried. Every moved file
  therefore carries every source any file in the folder carried. Reading the moved folder brings
  in the same sources as reading the old one did; removing a source that only one file carried takes a declaration
  (`PROVENANCE.md` 6.4) instead of deleting that file.
- **Tables.** The caller copies the table with `CREATE TABLE <to> AS SELECT * FROM <from>`,
  posts `POST /transfers {from, to}`, and drops the original. The copy loses the original's
  version history and every setting the `CREATE` does not restate: partitioning, sort order,
  comments. It carries the original as a source, so without the record below only the
  original's readers could read it.
- **The record.** The old entry stays, with status `moved` and `moved_to` naming the new one.
  Governance's lookups follow `moved_to` for every carried source, so data built from the old
  folder or table, wherever it is, is checked against the new one's grants; the new one carrying
  the old as a source is then a dataset carrying itself, which changes nothing
  (`PROVENANCE.md` 6.1). The broker refuses a credential for a moved folder; the refusal names
  the new path to anyone who may describe it, and is the ordinary refusal for everyone else.
- A personal folder's transfer ends the personal-space exemption for its data.

## Changes

### Schema (`governance/app.py`)
- `groups (name PRIMARY KEY, created_by, created_at)`.
- `group_members (grp, member, role, steward)`: `role` in `owner`, `admin`, `member`, `viewer`;
  `steward` a boolean, changed by platform admins only, and only for a member or above.
- Drop `group_owners`, `register_grants`, `namespace_owners` and the `stewards` group: a
  group's space follows from its name.
- Entries gain status `moved` and `moved_to`. `transfers (id, kind, from_id, to_id, by, at)`.
- `revoked`: a per-source set of groups beside the six grants, changed by the source's
  stewards, recorded and shown to its `share` holders as detaches are; governance's lookups
  return it with each source's `read` and `share`.

### OPA
- `opa/governance.rego`: `/internal/groups/<subject>` returns the subject's groups with role
  and steward flag, as the names grants use (`<g>`, `<g>#admin`, `<g>#steward`) in two lists:
  those the subject reads through and those they write through, a viewer's groups left out of
  the second. `write` is checked against the second.
- `opa/groups.rego`: `allow_create` for any signed-in subject (governance checks the name).
  `allow_change`: owners change owners and admins; owners, admins and, in a tenant, stewards
  change members and viewers; platform admins change stewards.
- `opa/blob.rego`, `opa/tables.rego`: drop `allow_register`, `allow_change_root` and the
  `stewards` conjunct. The space defaults above join each entry's effective grants (sections 2,
  3 and 5). `allow_change` for `share`, `write`, `delete`, `detach` and `revoked`: a steward of
  the group whose space holds the entry. `allow_transfer {subject, from, to}` as above.
- Personal-space exemption (`PROVENANCE.md` 9): in `_reads` and `vend_write` (`opa/blob.rego`)
  and `readable` and `writable` (`opa/tables.rego`), an entry in the subject's own personal
  space skips the sources check, unless one of the subject's groups is in a carried source's
  `revoked`.

### Governance API
- `POST /groups {name}`: the caller becomes its owner. Refused for a name in use, reserved or
  outside the rule.
- `PATCH /groups/<name>`: `{owners, admins, members, viewers: {add, remove}}`. Refuse a change
  that leaves no owner.
- `PUT` and `DELETE /groups/<name>/stewards/<person>`: platform admins.
- `DELETE /groups/<name>`: owners.
- `POST /principals/me` also creates the personal group.
- `POST /transfers {from, to}`.
- `governance.derivations` shows a declaration marking a source unused to the admins of the
  group whose space holds the source, besides its `share` holders.

### Read side (prerequisite for any UI)
Governance has no `GET` routes. Add, each narrowed by the same predicates as the writes:
- `GET /me`: my groups with my role in each and whether I am its steward; whether each is a
  tenant; whether I am a platform admin.
- `GET /groups/<name>`: owners, admins, members, viewers and stewards; transfers in and out.
  Visible to its viewers and above.
- `GET /datasets/<id>`, `GET /tables/<id>`: the entry with declared grants, effective `read`
  after provenance narrowing, status. Visible if `describe` passes. For a caller who may
  describe it but not read it, why (decided 2026-10-23): the carried sources they may not read,
  each named only if they may describe it, and any release of it to them that was withdrawn.

### Docs and seed
- Seed: `jgi-writers` becomes `jgi` (alice owner and steward); `projw-team` becomes `projw`
  (carol owner and steward); `no-access` becomes `noaccess` (bob owner); `bob-only` becomes
  `bobonly`, with no members; `stewards` goes. Seed datasets and tables move into their group's
  space, `datasets/projy/secret/` into `bobonly`'s, so that it stays invisible to everyone.
- Update `README.md` sections "Changing groups", "Assigning roots", the `stewards` mentions and
  the registration demo; `DESIGN.md` 4.4 and `WHITEPAPER.md` 4.2-4.4 where they say "each group
  has owners, which are groups".
- `seed/check-index-narrowing.py` and the README demos must still pass.

## Open
- How platform admins are marked: the seed group `group-admins`, renamed under the name rule,
  or a Keycloak realm role, as BERDL uses a KBase auth role (findings, item 2).
- Deleting a group whose space holds data.

## Out of scope
- On-behalf-of tokens for the ingest pipeline (Keycloak token exchange). Pipelines act as
  subjects in groups for now.
- Transfers out of a tenant.
- The web UI itself. The read routes above are its only server-side prerequisite.

## Decided
- Roles: owner, admin, steward, member, viewer, held per group; platform admins outside groups.
- Anyone creates a group, and every group has a space; a steward appointed by a platform admin
  makes it a tenant, and only a tenant publishes.
- A tenant whose last steward leaves keeps its published datasets and grants, frozen until a
  platform admin acts.
- Personal spaces publish nothing and share only by transfer.
- Transfers move files by server-side copy and tables by `CREATE TABLE … AS SELECT`, keeping a
  record from the old entry to the new; only members and above of the receiving group transfer
  in.
- BERDL's name rule and reserved names, plus `governance`, without the `ro` rule.
- The governance API takes a person's token only. No service lane.

---

# Section 2 — namespace grants (inheritance)

Partly replaced on 2026-10-24 by sections 3 and 5: a table has no grants of its own, so its
grants are its namespace's and those above it, plus the collections that contain its namespace;
the table-level `own` sets below go.

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
  the namespace's `share`; `share`/`write`/`delete`/`detach` for a steward of the group whose
  space holds the namespace (section 1).
- `POST /tables`: accept a list of entries in one request, all under one namespace, in one
  transaction. Grants on each are optional and default to empty (inherit only). Registering
  from an ingest config's table list is the intended use.

### OPA (`opa/tables.rego`)
- `allow_change` gains a clause for kind `namespace`, deciding on the `namespace_grants` row
  with the same `_may_change` split. Governance passes `kind` in the input.
- No other rule changes.

### Read API (section 1) additions
- `GET /namespaces/<id>`: its own grants, the group whose space holds it, tables under it with status and whether each
  has grants of its own. This is the steward's day-to-day page.
- `GET /tables/<id>`: returns `grants` (effective), `own`, `inherited_from`.

### Semantics to document
- Removing a group from a table's own grant does nothing while an ancestor namespace still
  grants it (as in Unity Catalog). The UI shows inherited grants as not editable on the table,
  with a link to the namespace that grants them.
- Tables created later under a namespace inherit at once (Snowflake's "future grants" for free).
- Provenance narrowing applies to effective `read`: a namespace grant does not let a group read
  a table derived from sources it may not read.
- A group's space gives its viewers and above `describe` and its admins `delete` by default
  (decided 2026-10-23; section 1's defaults). Sources narrow neither, so a dataset in a group
  space that rule 3 has closed, for instance after a release is withdrawn (`PROVENANCE.md`
  6.7), stays listed for the group's viewers and above and removable by its admins.

### Later, same shape
- Blobs: `root_grants` on `datasets/<root>/`, unioned into `/internal/datasets` the same way.
  Needed for the default `describe` and `delete` above on a group's file datasets.

## Decided
- Inheritance is computed by governance when serving the entry, not by rego fetching parents
  and not by copying grants onto tables at registration. The registry's per-table rows stay
  the only place a table-specific grant lives.

---

# Section 3 — write first, publish later

Rewritten 2026-10-24. **Publishing** is the act this section's first version called
registering: giving a folder or a table a description and grants of its own. The docs that
describe today's code keep "register" for what the code does now, registering an entry before
anything is written, until this section is built. **Declaring** is the separate provenance
act that names which candidate sources were used. `describe` stays a grant name.

## Why

The design's rule is "storage owns existence, the registry owns meaning", and the registry
already reconciles against RGW events. But today a dataset is registered (`POST /datasets`,
`allow_register`) before its bytes exist, and a table must be registered `pending` before
`CREATE TABLE` is allowed: writing waits on an entry that describes nothing yet. Invert it:
writing in a space your group owns needs no entry first, and publishing what was written
comes after.

## Model

- **A folder becomes a dataset by being published.** Until then it is a folder. Any folder in
  a space can be published, at any depth, and nothing is copied or moved when it is.
- **Published datasets do not nest.** A published dataset can sit among other folders and
  loose files, but cannot contain, or sit inside, another published dataset. Governance
  already refuses a folder inside or containing a registered one; publishing keeps that check.
- **A folder is tracked from its first write credential.** The first time someone is given a
  credential to write a folder, the folder becomes an entry that is not published: no
  description, no grants of its own. Governance tracks its files from then on, as it tracks a
  dataset today. Folders nobody has written into are not tracked, and nothing scans the
  bucket (`DESIGN.md` 2: "neither enumerates the whole bucket").
- **Before publishing, a folder is reached through its space's grants** (section 1's
  defaults: the group's viewers and above read, its members write), and rule 3 restricts it by what its files were made from,
  as for any entry. Publishing gives it a description and grants of its own.
- **Grants on folders** (decided 2026-10-24). Grants can be set on any folder in a space and
  are inherited by every entry under it, published or not, as namespace grants are in section
  2: an entry's grants are its own, every folder's above it, and its space's. The group's stewards
  change them (section 1), and an inherited `detach` narrows as section 2 says.
  Section 2's "later, same shape" grants on file roots become grants on any folder.
- **Tables are published as namespaces** (decided 2026-10-24). Publishing a namespace makes it
  one dataset of its tables, with one description and one set of grants; a single table is not
  published and has no grants of its own, as a single file is not. This is how KBase's ingest
  treats a dataset (`tenant.dataset`, many tables) and how Kaggle, Dataverse and Hugging Face
  publish a dataset of several tables. Published namespaces do not contain or sit inside one
  another, as folders do not; a table that needs its own audience goes in a namespace of its
  own. Each table still has its own credential, so rule 3 can close one table built from a
  source a person may not read and leave the rest of its namespace open, which a folder of
  files cannot do. Collections (section 5) group datasets of either kind.

## Credentials

Agreed and tried against Ceph on 2026-10-24. No credential reaches into a published dataset
except that dataset's own; the broker keeps this by choosing what each credential covers,
not by moving data.

- **Recursive unless asked otherwise.** A request for a folder covers everything under it
  unless it says `"recursive": false`, the split the S3 tools make (`aws s3 ls` and
  `ls --recursive`, `cp -r`, `rm -r`); S3 itself lists non-recursively with `Delimiter=/`.
- **A folder with no published dataset under it:** one credential for the whole folder, as for
  a dataset now. Recursive commands (`aws s3 sync`, `cp --recursive`, `ls --recursive`) work.
- **A published dataset:** its own credential, under its own grants.
- **A folder with a published dataset under it:** no recursive credential covers it, since one
  would reach the dataset. Asked for one, the broker refuses with a short message, the same for
  any folder and naming nothing inside it:

      datasets/projw/ contains published datasets, so it can't be opened recursively.
      Open it with "recursive": false for the files directly in it, or open its subfolders
      and datasets separately.

- **A non-recursive credential**, for any folder, covers the files directly in it and nothing
  in its subfolders: it allows `<folder>*` and denies `<folder>*/*`, and lists only `<folder>`
  one level at a time (`s3:prefix` exactly the folder, `s3:delimiter` `/`). Its size is the
  same for every folder and every person. Tried: it read and wrote a file directly in the
  folder, was refused reading or writing inside a subfolder and listing below the folder, and
  listed the files directly in it and its subfolders' names.
- **Logged against what it covers.** A credential is logged against the entry of the folder
  or dataset it covers, so file attribution (`PROVENANCE.md` 6.2) works as it does now.
- **Rejected on the way:** a folder credential denying each published dataset inside it, with
  listing restricted to one level so dataset contents stay hidden (Ceph limits a credential's
  policy to about 2,048 characters: 19 short-named datasets fit, 13 with longer names,
  measured); a list of files to deny for each person (OPA would be deciding file by file, and
  a list of 50 was already refused); copying a folder's files to a separate area when it is
  published; and a whole-folder credential for people who may read every dataset under the
  folder, which would count every one of those datasets as read, so all their later outputs
  would carry them as sources.

## Seeing what is in a folder

Through `describe` and the dataset index: `governance.datasets` lists each folder a person may
describe, with whether it is published and whether they can read it. Files are listed a page
at a time by a read route (section 1's read API): the SQL index is rebuilt from Postgres on
every load and Trino cannot pass a folder filter through to it, which is fine for entries but
not for every file. No storage listing is needed for browsing.

## Changes

### Files
- `opa/blob.rego`: drop `allow_register`. `vend` and `vend_write` take `{subject, folder,
  recursive}`: a folder in a space, allowed by its effective grants (its own if it is an
  entry, every folder's above it, its space's), restricted by sources as now; a recursive
  request is refused for a folder with a published dataset under it.
- `broker/app.py`: `POST /vend` takes `folder` and `recursive` (default true) instead of
  `dataset`, returns the message above when refused for that reason, and builds the
  non-recursive policy. A write
  credential for a folder with no entry creates its entry (id from its path, as `derive_id`
  does now) before the credential is logged.
- `governance/app.py` `/events`: a key under a tracked folder is recorded for it; any other key
  stays ungoverned and logged. Publishing is `PATCH /datasets/<id>` on an entry: description
  and own grants, allowed for a steward of the group whose space holds it, refused for a folder inside
  or containing a published dataset. Sources are declared as today (`governance.derivations`).
- Schema: `datasets.published BOOLEAN NOT NULL DEFAULT false`; `status` keeps `live|gone`.
  Drop `register_grants`.
- Store each entry's sources, updated when its folder is listed or a declaration is accepted,
  rather than working them out on every decision (scale; today's per-decision cost too).

### Tables
- `opa/tables.rego`: `allow_create` allows a member or above of the group whose space holds
  the namespace (drop the `pending` entry requirement). Drop `allow_register`.
- `gate/app.py`: reports created tables as now; governance records the table under its
  namespace, with status `live`. `POST /tables` goes away; `PATCH /namespaces/<id>` publishes a
  namespace: description and grants, refused inside or around another published namespace.
- Grants move from `table_entries` to namespace entries: a table's grants are its namespace's
  and those of the namespaces above it, plus collections (section 5). Today `lakehouse.db` holds
  tables with different grants (`t1`, `t2`, …); each moves to a namespace of its own.

### Read API (sections 1–2) additions
- `GET /groups/<name>` gains `unpublished`: entries in its spaces not yet published, each with
  writer (from the access log), first-seen time, object or row count, and, for a folder, the
  tables whose sessions read it (so an ingest pair shows side by side).
- `GET /datasets/<id>` / `GET /tables/<id>`: `published`, and `writer`.
- A paged route listing one level of a folder: its files and subfolders, with published state.

### Index
- `governance.datasets` lists unpublished entries only to groups that may read them (the owning
  group by default), and published ones by `describe` as now.

### Docs and seed
- README "Registry freshness & governed ingest", "Flow B" (the `t2` demo) and the whitepaper's
  register-at-ingest section change to: write, then publish, using "publish" throughout.
  `seed/ingest-demo.py` uploads with a folder's write credential, then publishes.

## UI consequence
"Publish" is not a form. It is an inbox on the group page: folders and tables in your spaces
nobody has published yet. Publishing is the same grants panel as everywhere else plus a
description; declaring sources sits beside it, prefilled from the lineage candidates.

## Decided
- Writing in an owned space needs no prior entry; a folder is tracked from its first write
  credential.
- A folder becomes a dataset when published; published datasets do not contain or sit inside
  one another; nothing is copied.
- No credential reaches into a published dataset except its own; a folder with one under it is
  opened non-recursively (`"recursive": false`) plus its parts.
- Grants can be set on any folder and are inherited by every entry under it.
- Tables are published only as namespaces; single tables have no grants of their own.
- Unpublished data is readable only through its space's grants and those of the folders above
  it, never grants of its own.
- `pending` is removed; `published` is a flag on a live entry.
- "Publish" is the user-facing word (decided 2026-10-24).

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
  that arrived through a read (`direct` false) get no row. An event whose output is not an entry,
  published or not, that the person wrote is dropped and logged.
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

---

# Section 5 — collections

Decided 2026-10-24. Published datasets do not nest (section 3); collections give the nesting.
A dataset is a published folder of files or a published namespace of tables. A **collection**
groups datasets and other collections by reference. It holds no data, and no storage
credential is ever issued for one, so nothing about storage changes.

Prior art: Dataverse collections hold datasets and other collections, and nest; Hugging Face
Collections are curated lists of datasets and models; a Delta Sharing share is a set of tables
and schemas granted to recipients together.

Example: the collection `pangenome` holds the namespace `kbase.pangenome` (tables `genome`,
`gene`) and the folder `pangenome-raw/` holding the files they were loaded from; the collection
`kbase-reference` holds `pangenome` and `taxonomy`.

## Model

- A dataset or a collection can be in several collections. A collection cannot end up
  containing itself.
- A collection has a description and appears in the dataset index as one entry, its members
  under it.

## Grants

- A collection has `describe` (see it, its description, and the members the viewer may
  describe), `read` (read every member through it), `share` (change who may describe or read
  it), `write` (curate it: its description, adding and removing members) and `delete` (delete
  it; its members are untouched).
- `describe` and `read` flow down to members, through nested collections: `read` on
  `kbase-reference` reads `pangenome`'s namespace and folder. `share`, `write` and `delete` on a
  collection give no rights over its members.
- A dataset's effective `describe` and `read` are its own, those of the folders or namespaces
  above it, and those of every collection containing it directly or through other collections.
  Governance serves these effective sets, as section 2 does for namespaces, both for the entry
  and for each carried source's `read` and `share` in rule 3's lookups.
- Sources still apply. Reading a member through a collection is restricted by that member's
  sources as reading it directly is; only a release (`PROVENANCE.md` 6.7) gets past a source.
- The access log records the dataset read, never the collection, so lineage and declarations
  are unchanged.

## Membership

- Adding a dataset or a collection takes `write` on the receiving collection and `share` on what
  is added: its `share` holders decide whether it joins.
- Consent reaches through nesting: joining a collection trusts its `share` holders, including to
  place it inside larger collections, as the old design's chain of grants did. A dataset's
  `share` holders see every collection it reaches and can remove it from any collection that
  holds it directly.
- Removing takes `write` on the collection, or `share` on the member.

## Ownership

- A collection belongs to a group; that group's stewards hold `share` and its admins `delete`
  on it, as for datasets in its space (section 1). A collection can hold datasets from other
  groups' spaces when their `share` holders agree, which shares across tenants.

## Changes

- Governance: `collections (id, owner, description, describe, read, share, write, delete)` and
  `collection_members (collection, member, member_kind, added_by, added_at)`, with a cycle check
  on adding; `POST /collections`, `PATCH /collections/<id>` (description and grants),
  `POST` and `DELETE /collections/<id>/members/<member>`; `GET /collections/<id>` in the read API.
- OPA: `collections.allow_change` (`describe` and `read` by `share` holders; `share`, `write`
  and `delete` by the owning group's stewards), `allow_add` (`write` on the collection and `share`
  on the member) and `allow_remove`.
- Lookups: effective sets include collections, as above.
- Index: `governance.datasets` lists collections (kind `collection`) to their `describe`
  holders, with members under them.
