# minilakehouse: one grant model for every tool that touches a dataset

This document describes a target design. The repository implements an earlier iteration;
section 13 lists the differences. Everything else is written as the design, not the code.

## 1. Summary

A data platform has many tools that decide whether a person may use a dataset: the SQL
engine, the catalog it reads from, the service that hands out object-store credentials, the
portal that shows what exists, the workflow engine that stages inputs for a job, the API that
issues download links. Left alone, each grows its own copy of "who may do what," and the
copies drift.

This design holds one grant model, in one catalog, for every dataset of every kind, and makes
every tool either ask one policy engine about it or obey a credential that engine gated. The
model is small: six grants per dataset, and a rule that data built from other datasets may be
read only by people who may read those datasets too. Because the model is outside any one tool,
it can say things no single tool can: that a table and a folder of files have the same
audience, that narrowing a source narrows everything derived from it across both kinds, and
that a dataset exists without being readable.

The two consumers built so far are an Iceberg catalog, Polaris, and a credential broker for
folders of files. They are the first two, not the design. The design is the model and the
contract any further consumer meets.

Mechanically: OPA is the policy engine. A read decision is carried by a short-lived
object-store credential scoped to one dataset, enforced by the object store, so nothing on
the byte path re-decides, with one exception noted in section 5. The person's own identity
token reaches every decision; a query engine carries the token and cannot alter it.

## 2. Why this exists

**The problem is drift between permission stores, and it is proportional to how many tools
decide.** Object-store policy, catalog grants, an engine plugin, and per-service checks are
four places to express one fact. The internal stack this design descends from had all four.
Every product that governs data unifies some of them: AWS unifies tables under Lake Formation
and prefixes under S3 Access Grants and glues them with a catalog workflow; Unity Catalog and
Gravitino unify tables and files under one product's permission store. All of them stop at the
edge of the product. A compute service, a portal, or a download API that must decide about a
dataset either calls that product's API, if one exists for the question, or keeps a copy.

**The alternative chosen here is to make the model the product.** Grants live in a catalog
that holds every dataset regardless of kind; the policy engine evaluates them; any tool with a
request to gate asks the engine. The catalog and the engine are both generic. The only thing
specific to tables is the Polaris hook; the only thing specific to files is the broker. A
third consumer adds a policy check and nothing else.

**What that buys that no per-product model does.** Rules that span kinds and tools. The
derivation rule in section 4.3 is the worked example: a table joined from two file datasets
and a table has an audience computed from all three, and revoking a group on any of them
reaches the table at its next decision, whether the table is read through Trino, through
a notebook, or staged by a job. In a per-product model that rule has nowhere to live.

**What it costs.** A catalog to run, a policy engine to run, and one enforcement point per
tool. Where a tool cannot host a policy check, as Polaris cannot filter its own listings, the
enforcement point is a proxy in front of it. The design is worth that cost when the number of
deciding tools is more than two or when derivation chains are common. A platform with one
engine and one catalog and no derived data should use the catalog's own grants.

**The deployment target** is a scientific data platform on self-hosted Ceph RGW, where
datasets are mostly files, most datasets are derived from others, and access decisions are
made by several services beyond the query engine. In the stack this design descends from,
three services decide dataset access:

1. The object store (MinIO or Ceph RGW) enforces per-user IAM policies that the platform's
   governance service writes.
2. Polaris grants decide catalog read and write; a tenant's readers get read on the whole
   catalog. Catalogs are created without STS, so Spark reads table files with the user's
   static object-store key.
3. A Trino access-control plugin decides catalog and schema visibility by calling the
   governance service with the user's platform token. Trino reaches Polaris as one global
   principal.

The governance service also decides who may administer tenants. The platform's MCP server
and Spark Connect proxy have not been read; either may decide access itself.

## 3. Prior art

| System | What is taken | Where it stops |
|---|---|---|
| AWS Lake Formation | Decide once, vend a scoped credential, storage enforces. `DESCRIBE` without `SELECT` as visible-not-readable. | Glue tables on S3. Decisions available only to AWS engines. |
| AWS S3 Access Grants | Identity-or-group to prefix grant, temporary credentials on request. The broker is this shape. | Prefixes, not datasets. S3 only. |
| Amazon SageMaker Catalog | Publish, discover, subscribe over tables and S3 object collections. | Unifies at the workflow over two permission stores. The stores do not share a rule. |
| Apache Polaris 1.5 | Iceberg REST catalog that delegates each operation's decision to OPA and vends per-table credentials. | Tables only. One yes/no per operation; cannot filter a list, still so in 1.8.0. |
| Unity Catalog (open source) | A catalog holding tables and a file entity with vending for both. | Permission model is the product's; reachable only through the product's API. |
| Apache Gravitino | A catalog holding tables and filesets, with grants over both. Its Iceberg REST server filters list responses per entry before paginating. Its Trino connector reads a per-user token from the Trino extra credential section 6 uses. | The permissions API grants and revokes; it has no "may U do X on O" query, so decisions happen only inside Gravitino's own API. Filesets are governed by GVFS, a client filesystem library for Hadoop and fsspec clients that resolves a fileset to its location; storage enforces nothing unless credential vending is turned on, and it is off by default. A client attaching the Trino token itself is untested with Gravitino. |
| Immuta, Privacera | One policy, many platforms as enforcement points. The scope this design shares. | Immuta compiles policy into each platform's native controls; Privacera's Ranger lineage puts a plugin on the engine's query path. Both commercial. |
| SQL views with `WITH GRANT OPTION` | Invoker-rights views give declared-intersect-underlying; grant option is the `manage` right. | One database engine. |
| Envoy `ext_authz` and `ext_proc` with the OPA Envoy plugin | The enforcement-point pattern the gate in section 5 follows. | A mechanism, not a model. |
| Trino OPA system access control | Engine-side enforcement point over the same OPA data, with batched listing filters. | The Trino path only. |

The design is Immuta's scope with Lake Formation's mechanism, on Ceph, with the model in the
open rather than compiled into each product. The rule in section 4.3 is the invoker-rights
view rule with grant option, lifted out of any engine so it can span kinds.

## 4. Permission model

### 4.1 The dataset entry

Every governed thing is one entry in the catalog, a Postgres table owned by the governance
service.

| Field | Meaning |
|---|---|
| `id` | Tables: catalog, namespaces and table name joined by dots, `lakehouse.jgi.t1`; a table any of whose names contains a dot has no id and is refused, since its id would be ambiguous. Files: the folder's path under `datasets/`, `jgi/public`. Tables cannot be renamed (section 8); a table created again after a drop takes its old id back. |
| `kind` | `table` or `files`. Views are `table`. |
| `space` | The group whose space holds it: a folder's first name, a table's namespace after the catalog. Every group has a space, `datasets/<group>/` and `<catalog>.<group>`, and a person's personal group `u_<user>` too. |
| `published` | Whether a steward has published it: a folder, or a namespace at or above a table. A folder becomes an entry at its first credential, unpublished. |
| `location` | Folder in the bucket. A property, not the identity. For a table, learned from Polaris when the table is created. |
| `description`, `contact` | Human metadata. Contact carries no authority. |
| `describe`, `read`, `manage`, `write`, `delete`, `detach` | Six sets of groups, and `revoked` beside them (section 4.3, `PROVENANCE.md` 9). Each is a union of layers: a published folder's own, those set on the folder or namespace and on every one above it, its space's defaults, and the `describe` and `read` of every collection holding it (section 10); a table has none of its own. See 4.2. |
| sources | Not stored in the entry: the datasets its stored files were built from, worked out from the access log and a listing of its folder. See 4.3. |
| releases | Per source, the groups that source's `manage` holders let read this dataset although they may not read the source. See 4.3. |
| `status` | `live`, `gone`, `moved` with `moved_to`. See section 9. |

### 4.2 Six grants

Each grant is a set of groups, or of roles in a group: `<g>#member`, `<g>#admin`, `<g>#owner` and
`<g>#steward`, the notation Zanzibar and SpiceDB use. Governance holds the groups beside the
grants: each person in a group is its owner, admin, member or viewer, and a member or above can
also be its steward. Keycloak only proves who a person is; its realm role `platform-admin` marks
platform admins, who hold no role in any group. A grant naming a group gives `describe` and
`read` to everyone in it and every other grant to its members and above, so a viewer never
writes. Section 4.4 says who changes membership. A membership change applies at the person's
next request, since every rule looks the person's groups up at decision time.

- **describe**: the dataset appears in listings for this group. For a table, in Polaris's listing
  through the gate, and its metadata can be loaded: whether it exists, its columns, and its
  storage location; for every dataset, in the catalog's listing.
- **read**: for a table, obtaining a read credential for its files, which returns its
  metadata too; for a
  file dataset, a read credential for its folder. Listing a file dataset's objects is part of
  read.
- **manage**: this group may change who sees and reads this dataset, and may release
  datasets built from it to groups that may not read it (4.3).
- **write**: for a file dataset, a write credential for its folder, which permits put and
  delete and not get; for a table, creating it and performing DDL and data writes on it.
  Writing is narrowed by what a dataset was built from exactly as reading is, so no one writes
  into a dataset they may not read.
- **delete**: for a table, dropping it, which also removes its files. Writing a table does
  not include dropping it. For a file dataset, a credential that lists and deletes in its
  folder and cannot get or put, used with ordinary S3 tools (`aws s3 rm --recursive`); the
  listing shows file names, sizes, times and ETags, which for a single-part upload are an MD5
  of its contents. Neither kind is narrowed by what a dataset was built from, so data nobody
  may read can still be removed.
- **detach**: this group's members may declare that data built from this dataset no longer
  holds its data, so this dataset stops counting as a source of that data (4.3). While the
  grant is empty, anyone who wrote that data may.

Two grants imply others, and no more: `read` implies `describe`, so a dataset a group may read is
listed for it; and for tables, `write` implies `read`, because writing an Iceberg table
requires reading its metadata and the credential Polaris vends for writing is read-write. A
dataset whose `describe` includes a group and whose `read` does
not is visible-not-readable: it appears in a listing with its name and description, a
table's metadata can be loaded, and its contents cannot be read. Trino requests a credential
with every table load, and Polaris refuses the whole load when neither credential check
passes, so the gate repeats a refused load once without the credential request: a describe-only
table can be described through Trino, and reading it fails because Trino gets no credential for its files. A load that hands out no
credential carries the table's columns, partitioning, properties and current version; the gate
removes earlier versions and schemas, column statistics, and the row and file counts and
writer names in version summaries, all of which describe the contents. OPA's `load` rule
decides whether a person gets the whole metadata and which properties such a load keeps; the
shipped rules give a table's whole metadata to nobody on a load without a credential and keep
every property. A view's metadata is its query text, its columns, and its earlier versions. A
view never comes with a credential, so `load` says who gets all of it: the shipped rules give
it to those who may read or write the view, as for a table, and anyone who may only describe
it gets the current version and its query text. A view runs with the rights of whoever queries
it, and the gate refuses one that would run with its owner's rights: its tables would be read
as the owner without the owner's token. So `read` on a view shows its earlier versions, and
reading data through it still takes `read` on the tables it uses.

### 4.3 Derived datasets

Data built from other datasets carries them as sources, and only people who may read every
source may read it. `PROVENANCE.md` 6 holds the design and what was run to test it; this
section states the rule.

A **source** of some data is a dataset whose own `read` limits who may read that data. Sources
are tracked per stored file, the way Apache Atlas propagates a classification to everything
derived from a dataset and Palantir Foundry's markings follow data along lineage.

1. **Reading brings sources in.** A read of a dataset brings in the dataset and every source
   its files carry. Every credential is logged before it is handed out, so this holds for
   every read made through the platform.
2. **A file carries what its writers brought in.** A stored file is matched by its time to
   the write credentials valid for its folder, and carries everything their holders had
   brought in by then, minus what a declaration of theirs marks unused.
3. **Who may read**: a person in the dataset's `read` who, for every source its files carry,
   is in that source's `read` or in a group a release lets past it. `write` is narrowed the
   same way, so no one writes into a dataset they could not read back. `describe` and `delete`
   are not narrowed: a derived dataset can be listed for people who cannot read its sources,
   and data nobody may read can still be removed. Nor is `manage`: changing who may see and
   read a dataset takes `manage` on that dataset alone, and rule 3 still applies to whoever is
   added.

Governance returns each dataset's sources with their grants, and OPA applies rule 3 at
decision time, so a grant change on a source reaches everything built from it at the next
decision with nothing recomputed.

Two acts change what a dataset carries:

- **Declaring.** A writer names which of the datasets they read were used. Until they do,
  everything they read counts.
- **Detaching.** Marking unused a source that arrived through another dataset states that the
  data no longer holds it. Nobody can check that, so the source's `detach` grant says who may,
  and each detach is recorded where the source's `manage` holders see it and can put the source
  back (`PROVENANCE.md` 6.5).

A **release** lets a group read a dataset built from a source although the group may not read
the source. A `manage` holder of the dataset asks, once the group is in its `read`; a
`manage` holder of each such source approves. Data built from the released dataset carries the
release. Withdrawing it closes the dataset to the group again at the next decision
(`PROVENANCE.md` 6.7). US classified-information handling has the same step for
originator-controlled material: a derivative product keeps the marking, and further
dissemination needs the originator's permission.

Consequences, stated so they are not surprises:

- Narrowing `read` on a source narrows every dataset built from it, except for groups a
  release covers.
- A dataset built from many sources has a small audience: its readers may read everything it
  was built from.
- A `gone` source still constrains data built from it. Grants are independent of status.
- Which of a writer's reads were used is declared and trusted; that the list of candidates is
  complete is enforced, for data that came through the platform (section 11).

### 4.4 Changing grants

Changes to the grant model are governance operations, decided by OPA like every other request.
For each change governance locks what it changes, a dataset's row or a folder's or namespace's
grants, asks OPA with the caller's subject and the id and the change, and on allow writes. OPA
fetches the entry from governance like any other rule; every writer takes the same lock, so the
grants OPA reads are the ones the write replaces.

- `describe` and `read` of a published dataset, a folder or a namespace d: callers holding
  `manage` on d.
- `manage`, `write`, `delete`, `detach` and `revoked` of d: stewards of the group whose space
  holds d. Who added a group to `revoked` is recorded and shown to d's `manage` holders.
- Publishing a folder or a namespace: stewards of the group whose space holds it, never inside
  or around another published one. Nothing in a personal space is published or granted.
- Releasing d past source s to group x: asked by callers holding `manage` on d, once x is in
  d's `read` and d's declarations mark s used; approved, declined or withdrawn by callers
  holding `manage` on s.
- Putting back a source detached from d: callers holding `manage` on the source.
- A group's people, decided under a lock on that group: its owners change owners and admins;
  its owners, admins and stewards change members and viewers. A change leaving a group without
  an owner is refused, and so is one leaving a steward a viewer or out of the group.
- A group's stewards: platform admins, choosing among its members and above. A group with a
  steward is a tenant.
- Creating a group: anyone signed in, who becomes its owner. Names follow BERDL's rule, 2 to
  64 lowercase letters and digits starting with a letter, and its reserved names plus
  `governance`. A name any grant already uses, or whose space has entries, is refused, since
  the new group's owner would hold those grants.
- Deleting a group: its owners, while its space holds no data.
- Creating a collection: members and above of a group other than a personal one, which owns
  none. A collection's `describe` and `read`: callers holding its `manage`; its `manage`, `write`
  and `delete`: stewards of the group it belongs to. Its description and members: callers
  holding its `write`, with `manage` on each member added; a member's `manage` holders may
  also remove it from any collection holding it directly.
- Moving a folder or a table into another group's space: the person whose personal space holds
  it, or an owner or admin of the plain group whose space does, into a group they are a member
  or above of, at a path that does not exist and is not inside a published dataset.
- Platform admins pass every check on a group's people, stewards and deletion, every check that
  asks for a steward (publishing; changing `manage`, `write`, `delete`, `detach` and `revoked`;
  changing a collection's `manage`, `write` and `delete`), and creating a collection. A check on
  a grant or role they would have to hold, such as a credential, a move or a change to
  `describe` or `read`, they pass only by adding themselves to a group that holds it. None of
  this reaches into a personal space, whose group takes no one else and in which nothing is
  published or granted, whoever asks.

## 5. Components and trust

| Component | Role | Trusted for |
|---|---|---|
| Keycloak | Identity provider. Issues every token the system accepts, one audience per service. | Who the person is. |
| governance | Owns the catalog, the only copy of any grant, and group membership. Serves entries to OPA. Lists datasets as a per-person table whose files it builds and serves, tracks a folder from its first credential, accepts publishing, grant changes, group changes and transfers, receives lifecycle events. | The grant model and its administration. Availability of every decision: a governance outage denies every read. |
| OPA | Holds policy and no grants. Each rule fetches the entries it needs from governance at decision time. Returns a decision document. Reachable only by its callers: its API evaluates any query it is sent, including one that reads its own credentials. | Every access decision. |
| gate | A proxy in front of Polaris. Verifies the token, checks table creation against the catalog through OPA, trims list responses to what the person may see, maps denied named operations to not-found, and reports table create and drop to governance. Answers for the dataset index table itself. | The same custody of every current user's Polaris token that Trino has; the table lifecycle (section 9); correctness of list trimming. Polaris must be reachable only through it. |
| Polaris | Iceberg REST catalog. Delegates every operation's decision to OPA. Vends a per-table credential on allow. Holds a long-lived storage credential able to assume the vending role. | Relaying the decision into a credential; custody of that storage credential. |
| broker | Verifies a person's token, asks OPA about the named folder, and on allow assumes a role with a session policy scoped to the folder in OPA's decision. Moves folders between spaces by server-side copy. | Relaying the decision into a credential, for files. |
| Ceph RGW | S3 and STS. Enforces every credential. Emits bucket notifications. | Enforcement. |
| Trino | Query engine. Authenticates users with their Keycloak token, carries that token to Polaris, reads with the credential Polaris vends. | Custody of every current user's Polaris-audience token. Not trusted to name a user: Polaris decides on the token, not on Trino's word. |
| Postgres | Polaris metastore and the catalog. | Durability. |

The gate is structured as Envoy's `ext_authz` and `ext_proc` filters: a request check that
asks OPA, and a response processor that rewrites list bodies. The prototype implements both
in one process; a deployment that already runs Envoy replaces the request check with
configuration and keeps the response processor as a service. Governance and the broker verify
tokens themselves; placing the gate in front of them is optional.

Every caller of OPA sends the person's subject and groups and the ids it names, never
grants; OPA fetches entries from governance. The entry lookup returns any dataset's grants,
including datasets the person cannot see, so it is reachable only by OPA, which governance
knows by its TLS client certificate. An unknown id has
no entry and is denied exactly as a dataset the person has no grant on. A file entry is its
folder, and a table's folder is fixed at creation (set-location is root-only, section 8), so
the folder in OPA's decision is the folder the grants were written for.

No long-lived service holds a storage admin key. A one-shot setup step configures bucket
policy and notifications with admin rights and exits. Polaris authenticates to storage as a
user whose only right is assuming the vending role, and its own reads and writes of a table's
metadata use a credential from that role scoped to the table's locations, as a vended one is.

Polaris through 1.8 refuses a token whose name has no stored principal, and writes the
token to its log when it does. So before a person's first request reaches Polaris, the gate
has governance create their principal: governance verifies the person's own token and
creates a principal with that name and nothing else, logging in as a Polaris principal that
OPA allows to create principals and to do nothing more. The principal holds no grants or
roles; it exists because Polaris looks the name up on every request. Polaris's main branch
adds an `external` credential mode (PR #5119) that takes the name from the token and stores
nothing; once a release includes it, the realm switches to that mode and this step is
removed. The gate refuses a token naming one of Polaris's own principals (`root`,
`provisioner`).

## 6. Identity path

Keycloak is the only token issuer. Each service verifies tokens against Keycloak's published
keys and checks issuer, expiry, login client, and its own audience. A token issued for
Polaris is rejected by the broker and by governance, and the reverse. Every service derives
the subject from the same claim.

**Files.** The client presents a broker-audience token to the broker. End to end, no engine.

**Tables through Trino.** The person authenticates to Trino with a Polaris-audience Keycloak
token, through Trino's JWT authenticator validating against Keycloak's keys, and attaches
the same token as a Trino extra credential under the key `token`. Trino's Iceberg REST
connector copies a session's extra credentials into the per-user catalog session it creates
(`TrinoRestCatalog.convert`). The Iceberg REST client Trino bundles
(`OAuth2Manager.maybeCreateChildSession`) uses a credential named `token` directly as the
bearer for that session, before any exchange. Polaris, behind the gate, therefore receives
the person's own token on every request Trino makes for them. Both facts were verified by
reading the sources of Trino 476 with Iceberg 1.9.1 and Trino 484 with Iceberg 1.12.0. Extra
credentials are not a field of Trino's serialized session (`SessionRepresentation`), so the
token stays out of query info, where the username appears. The deployment pins Trino 484 for
the cache key below.

Conditions on the Trino configuration:

- Trino's system access control is `default`, which Trino's 476 documentation states
  permits all operations except user impersonation. This stops a person authenticated as
  alice from naming bob as the user and attaching alice's token to bob's session.
- The catalog session cache key is the Trino username, the query id, and the client source
  in Trino 484; in 476 it is the username and the source. The token is read only when a
  session is created, so in 484 every query opens a session with the token attached to that
  query. With Trino authenticating, the username is the token's subject, so no one rides
  another's session.
- The Iceberg client refreshes each session's token at nine tenths of its lifetime
  (`OAuth2Util.AuthSession.scheduleTokenRefresh`), by token exchange against Keycloak. Its
  first attempt authenticates with the session's own bearer, which Keycloak rejects
  (`client_not_found`); after five retries it falls back to the engine's client credential,
  which Keycloak's standard token exchange accepts once enabled for the `trino` client. The
  engine cannot originate a token for anyone, since the exchange requires the user's
  still-valid token. What it does keep alive is wider than a running query: a session stays
  cached until an hour after its last use (`iceberg.rest-catalog.session-timeout`, default
  1h; Iceberg's `AuthSessionCache` expires after access) and refreshes on schedule until
  evicted, or until Keycloak refuses the exchange. Keycloak refuses it once the person's
  Keycloak login session has gone idle (realm SSO session idle, default 30 minutes): an
  exchange is not activity on that session, while the person's own client refreshing their
  login is. Measured with 60-second tokens and a 90-second idle limit: every refresh 54
  seconds after a query succeeded, and every later one failed with `subject_token validation
  failure`. A query therefore stays alive while its person's login session does, up to the
  realm's session maximum (default 10 hours), and fails at its next Polaris call after
  that.
- Jobs and service connections with no person authenticate as Keycloak service accounts
  placed in groups. They are subjects like any other.

Run against the prototype (Trino 484, Polaris 1.5.0, Keycloak 26.6.1): a query authenticated
with a person's token and carrying it as the `token` extra credential reaches OPA with that
person as `input.actor.principal`; a query naming another user is refused as impersonation;
a query without the extra credential fails, because the Iceberg client falls back to a token
exchange Keycloak refuses. Trino's CLI sends an access token only over TLS, so Trino serves
HTTPS. Polaris accepts Keycloak as its issuer, takes the principal name from a
`principal_name` claim, and names that principal in its OPA input. That name is all OPA
needs: it fetches the person's groups from governance, as every rule does, so Polaris's
input carrying no groups does not matter.

**Tables through any other client.** The client presents a Polaris-audience token to the gate
as the catalog bearer. Same decision as through Trino.

Trino's own non-user calls use a client-credentials login to Keycloak as the engine's service
account, which holds no grants.

## 7. Flows

### Reader

1. **Find tables in SQL.** Any SQL tool lists namespaces and tables through the gate and sees
   only what its person may see.
2. **Find datasets.** Query the table `governance.datasets` from any engine connected to the
   catalog. It returns every dataset, table or file, that the person may describe or read (4.2,
   4.3), with name and description and whether the person may read it. The table's files are
   built by governance for the person reading them and served by governance; no copy of the
   list is stored.
3. **Read a table in Trino.** Log in. Connect to Trino with the token, attach it as the extra
   credential. Query.
4. **Read a table elsewhere.** Log in. Point the client at the gate with the token as bearer.
5. **Read files.** Log in. Ask the broker for a credential naming the folder, for everything
   under it or, with `"recursive": false`, the files directly in it. Read with any S3 client.

Every read decision fetches the dataset's entry from governance, so a governance outage
denies every read.

### Publisher

6. **Publish a source dataset.** Log in. Write it into the group's space: for files, ask the
   broker for a write credential, granted on `write` (the space's members by default), then
   upload; the first credential makes the folder an entry and storage events do the rest. For
   tables, create them through Polaris in a namespace of the space; the gate admits the
   creation on `write` and reports the location back. Then a steward of the group publishes the
   folder or the namespace: description and grants of its own.
7. **Publish a derived dataset.** As 6. Build the output with any tool, as themselves; its
   files carry everything they read (4.3). Declare which reads were used, in
   `governance.derivations`, and ask for a release past any source some intended readers may
   not read.
8. **Delete.** Delete the objects or drop the table. The delete events, or the gate's drop
   report, set `gone`.
9. **Change grants.** Log in. Call governance naming the dataset, folder or namespace and the
   change. Governance applies 4.4.
10. **Move work into a group.** From a personal space or a plain group's space: a folder through
    the broker, a table by copying it and recording the move with governance. The old entry is
    `moved` to the new one.

### Operator

11. **People and groups.** People in Keycloak; groups in governance, created by anyone and
    changed by their owners, admins and stewards (4.4). Platform admins, a Keycloak realm role,
    appoint stewards, which makes a group a tenant. Each person's personal group and Polaris
    principal are created on first use (section 5).

## 8. What OPA decides

Every rule takes the person's subject, verified by the caller, plus the id of the named
resource, fetches the person's groups and that resource's entry from governance, and returns a
decision. Where the enforcement needs more than yes or no, the
decision carries it. OPA never lists storage. Any operation not named here is denied for
everyone but root.

| Rule | Caller | Input | Decision |
|---|---|---|---|
| `visible` | governance, for its listing; gate, for a Polaris listing | candidate ids | which ids have a caller group in `describe`, or the caller may read (4.3) |
| `vend` (read) | broker | folder id, recursive or not | the caller may read it (4.3); allow, plus the entry's folder for the read session policy. Refused for a moved folder, one inside a published dataset, and recursively for one holding a published dataset, each with a refusal naming the way round to those it is otherwise open to |
| `vend_write` | broker | folder id, recursive or not | the caller may write it (4.3); allow, plus the entry's folder for the write session policy, refused as `vend` is |
| `vend_delete` | broker | folder id, recursive or not | a caller group in `delete`; allow, plus the entry's folder for the delete session policy, refused as `vend` is |
| `allow_transfer` | broker, governance | old and new folder or table ids | the rules of 4.4 for moving |
| `load` | gate, once Polaris has answered a table or view load | table id, kind, whether a credential was handed out, property keys | whether that credential can write; whether a load without one keeps every version; which properties it keeps (4.2) |
| `derivations.allowed` | governance, for a declaration | target and the sources it marks unused | which may be marked unused: a direct read always, a detach by `detach` (4.3) |
| `derivations.may_release`, `may_reattach` | governance | source ids | which sources' releases and putting back the caller decides: a caller group in the source's `manage` |
| `allow_create` | gate, from the create-table request body | table id | the caller may write the table it would be (4.3): `write` on its namespace, which the space gives its members |
| `allow_publish` | governance | folder or namespace id, whether the caller is a platform admin | a steward of the group whose space holds it, or a platform admin |
| `allow_change` | governance | dataset, folder or namespace id and the requested change | the rules of 4.4 |
| `groups.allow_create` | governance | | the caller is signed in; governance checks the name |
| `groups.allow_change` | governance | group name, the roles the change touches | the rules of 4.4 for each role |
| `groups.allow_steward` | governance | group name | the caller is a platform admin |
| Polaris: list namespaces, list tables, list views | Polaris | namespace | allowed for any authenticated person; the gate trims the response by `visible` |
| Polaris: namespace exists, load namespace metadata | Polaris | namespace | a caller group holds `describe`, `read` or `write` on it or on a namespace under it |
| Polaris: create table, create view, commit a staged create | Polaris | namespace | the caller may view the namespace; the gate has already decided per table with `allow_create`, since Polaris names only the namespace |
| Polaris: table exists, view exists, load table or view metadata | Polaris | table id | group in `describe`, or the caller may read it |
| Polaris: load with a read credential | Polaris | table id | the caller may read it (4.3); `write` implies `read` for tables |
| Polaris: load with a read-write credential | Polaris | table id | the caller may write it (4.3). Trino asks for this on every load; when denied, Polaris checks for a read credential instead |
| Polaris: update, commit table or view | Polaris | table id | the caller may write it |
| Polaris: drop table or view, with or without purging its files | Polaris | table id | group in `delete` |
| Polaris: rename table or view, register table, set table location | Polaris | | root only. Rename would orphan the entry's id; register and set-location would let a table alias another table's folder |
| Polaris: create namespace | Polaris | namespace | any authenticated person; the gate has decided with `write` on it |
| Polaris: drop namespace, update namespace properties | Polaris | namespace | `delete` on it; `write` on it |
| Polaris: admin operations | Polaris | | root only |

Grant changes are decided while governance holds the lock on what they change (4.4), so the
decision and the write see the same grants.

The gate trims a list response in three steps: fetch every upstream page, filter once, then
paginate the result with its own page tokens, so page size and tokens reveal nothing about
hidden entries. This is the order Gravitino's Iceberg REST list handler uses. The filter is
one `visible` decision over the candidate ids. A namespace is visible to those holding
`describe`, `read` or `write` on it or on one under it, so a person granted a namespace deep in
another group's space can reach it; the gate trims namespace listings by that rule. Every denied operation that names a table or namespace is mapped to not-found,
including create and rename conflicts against names the caller cannot see. A table created
with an explicit location is subject to Polaris's location confinement: the location must lie
under the namespace's base location and must not overlap another table's. Polaris has feature
flags for both; their defaults in 1.5 are unverified and must be pinned.

OPA holds policy only. Every rule that needs a grant fetches entries from governance with
OPA's `http.send`, once per decision; a decision over several ids fetches them in one
request, and a failed fetch denies. This is the one path for every caller because it is the
only one Polaris can use: Polaris builds its own input (actor, action, resource) and cannot
attach an entry. It is the shape of a Zanzibar-style check API such as OpenFGA's: the caller
names the user, the permission, and the object, and the authorization service looks up the
grants. Polaris 1.5 makes one synchronous OPA call per authorization check, with no decision
cache; checks that need no grant fetch nothing. In the prototype, a `SELECT` on one table
made two checks, loading the table with a credential and reporting read metrics, and one
governance read; a denied load made two, because Polaris retries a denied write-credential
load as a read-credential load. Rejected: callers that can build OPA's input passing the
entry in it, which leaves Polaris on a second path; and keeping grants in OPA, which is a
second copy that lags governance.

## 9. Lifecycle

A folder becomes an entry at the first credential anyone is given for it, read or write; a
table at its creation. Status changes only in response to an event about that entry, and the
event triggers a check of that one entry:

- A folder's first credential checks it once.
- Files: a creation or deletion event under a tracked folder, delivered by Ceph bucket
  notifications, triggers a listing of every tracked folder the key falls under, which also
  records each file's time for attributing it to its writers (`PROVENANCE.md` 6.2). Non-empty
  sets `live`, empty sets `gone`. An event under a table's folder triggers the same listing; a
  table's status comes from the gate.
- Tables: the gate reports table creation, with its location, and table drop. Creation sets
  `live`, and a table created again after a drop is `live` again at its new folder; drop sets
  `gone`.
- A transfer sets the old entry `moved`, naming the new one, and the old entry stays `moved`
  whatever storage or a drop later says.
- There is no periodic sweep. Notifications are delivered through Ceph persistent topics with
  retry. A lost event leaves a stale status until the next event for that entry: a lost
  deletion leaves a `gone` dataset listed, a lost creation leaves a `live` dataset hidden
  while its grants already allow reading it. Both are the accepted price of having no sweep.
- The events endpoint authenticates the sender with a shared secret that RGW adds to every
  event it sends (the notification topic's opaque data); a secret in the push URL would land
  in the endpoint's request log. A forged event can only trigger a check, never set a status
  directly.

Grants are independent of status, but for `moved`: a moved folder gets no credential, and a
moved table is read and written only at its new id. Listings show `live` entries only.

## 10. Limitations by design

- **Granularity is the dataset.** No row filters, no column masks. A credential cannot
  express either, and nothing on the byte path could apply them. A narrower audience for part
  of a dataset is a separate dataset.
- **A dataset is one unit, as a repository is.** Every file in a dataset's folder shares its
  grants and the sources its files carry, as every file in a GitHub or GitLab repository shares
  the repository's permissions; no file has grants of its own. Folders and namespaces nest and
  hold datasets, as GitLab groups and subgroups hold projects. A dataset is a published folder
  of files or a published namespace of tables; a single file or table is not published.
  Published datasets do not nest: a folder inside one is part of it, and one can sit among
  other folders and files but not inside another, because no credential may reach into a
  published dataset except its own. Collections give nesting instead: a collection groups
  datasets and other collections by reference, holds no data, and passes `describe` and `read`
  to its members. This differs from Google Drive, where any file or folder can be shared on
  its own.
- **No per-person dynamic filtering.** "Rows where owner is the current user" is not a
  dataset.
- **Revocation lag.** A grant or group membership change reaches the next decision and
  reaches data when outstanding credentials expire.
- **No request workflow.** A person can see a dataset they cannot read and has no in-system
  way to ask for it. Listings return a contact.
- **Declarations are trusted.** Every read through the platform is recorded, so the list of
  candidate sources is complete; which of them were used is the writer's declaration, and
  data brought in from outside the platform is invisible to it (`PROVENANCE.md` 7, 8). Content
  is never checked.
- **A space reveals names to its group.** Everyone in a group may list what its space holds
  before it is published. Accepted: they share the space.
- **The gate is a component you run** in front of a catalog you do not control. A Polaris
  release that changes list response shapes requires a gate change.

## 11. Enforced, decided, declared

**Enforced by storage.** A credential opens one folder, or the files directly in it, and
nothing else. The session policy is built by Polaris or the broker after OPA's decision, from
the entry's folder, never by the client.

**Enforced by the gate.** What appears in a Polaris listing, and that a table or namespace is
created only by someone holding `write` on the namespace it goes in.

**Enforced by governance.** Every credential is logged before the broker or the gate hands it
out, so the candidate sources of anything written through the platform are complete.

**Decided by OPA.** Every decision in section 8, including publishing, transfers, changes to
the grants and rule 3 (4.3), over the entry governance holds at the time of the decision.

**Declared and trusted.** Which candidates were used. Data from outside the platform. The
content of any dataset.

## 12. Decisions

Decided: governance holds the only copy of every grant and of group membership,
callers send OPA only who is asking and the ids they name, and every rule fetches the groups
and entries it needs with `http.send`; table names are
confidential, so `describe` is enforced per table and the gate trims listings; the engine may extend an active user's token by exchange, bounded by
Keycloak's session maximum; the catalog lists both kinds; rename, register-table, and
set-location are root-only; every group has a space where its members write first and its
stewards publish after; platform admins, a Keycloak realm role and not a group, appoint
stewards; a table has no grants of its own; `read` implies `describe`.

## 13. Status against the repository

Implemented today: the catalog with `describe`, `read`, `manage`, `write`, `delete` and
`detach`, and `revoked`, layered from published folders' own grants, folders' and namespaces'
grants and each space's defaults; the file listing; the dataset index as a per-person table,
`governance.datasets`, listing both kinds with whether each is published; the broker, scoping
read, write and delete credentials to the folder in OPA's decision, recursively or to the
files directly in it, and moving folders between spaces by server-side copy; Polaris delegating
to OPA with per-table credentials, viewing a table gated on `describe` or `read` and read-write
credentials on `write`, drops on `delete`; OPA holding policy and no grants, every rule fetching
what it needs from governance with `http.send`; Trino authenticating people by their Keycloak
token over HTTPS and forwarding it to Polaris as the `token` extra credential, with nested
namespaces; the gate as the only way to Polaris, verifying the token, trimming listings (every
upstream page, one filter, its own page tokens), answering not-found for a refused name the
person may not view, repeating a refused credentialed load without the credential request and
cutting that load to the current version, refusing views that would run with their owner's
rights, deciding table and namespace creation on `write`, and reporting table creates and
drops; groups with each person's role, stewards appointed by platform admins, and a space each,
personal groups included; writing first and publishing after, by stewards, with published
datasets never nesting; transfers into another group's space; grant changes through governance,
decided by OPA under a lock as in 4.4; the read routes `GET /me`, `GET /groups/<name>`,
`GET /datasets/<id>` and `GET /tables/<id>`; each person's Polaris principal created on first
use; a login proxy that keeps a client session past the token's 5-minute life by holding the
refresh token and forwarding a fresh token to Trino; OPA reachable only by its callers;
persistent storage events, each checking the folders it falls under, and no sweep. Derivation
as in 4.3 (`PROVENANCE.md` sections 6 and 10): the access log and sessions, switched by an
insert into `governance.sessions` or `POST /sessions`, `governance.lineage`, declarations in
`governance.derivations` or `POST /declarations`, sources carried per stored file and stored
per entry until what they come from changes, rule 3 in OPA for reading and writing files and
tables, the personal-space exemption and `revoked`, detaching and putting back, releases
(`POST /releases`, `governance.releases`), and `governance.grants`. Collections, nesting, whose
`describe` and `read` reach their members and those members' rule 3 lookups, listed in
`governance.datasets` and `governance.collection_members`.

Differs from this document: tables are entries in their own registry, not in the catalog
with files; events are checked as each delivery arrives rather than coalesced per folder.

## 14. Questions for the reviewer

Judge the composition, not the remainder after subtracting its parts. The claim is that one
grant model outside any product, with a policy engine in front of it, yields properties no
per-product model has, at a cost that is justified when several tools decide about datasets
or when derivation is common.

1. Is that claim true? Name a per-product model that can express the derivation rule across
   a table and a file dataset, or enforce one audience across a query engine, a file broker,
   and a third service such as a job scheduler.
2. Is the cost stated honestly? A catalog, a policy engine, one enforcement point per tool,
   and a proxy where a tool cannot host a check. What is missing from that bill?
3. Section 2 says the design pays off above two deciding tools or with common derivation. Is
   that threshold right, and is the deployment described above it?
4. Is the gate a reasonable enforcement point for a catalog that cannot filter its own
   responses, or a sign the wrong catalog was chosen?
5. Is the derivation rule in 4.3 sound as now written?
6. Which unverified items in sections 6, 8, and 9 would, if false, change the design rather
   than a configuration value?
