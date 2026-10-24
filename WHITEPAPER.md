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
model is small: five grants per dataset, and a rule that a dataset built from other datasets
inherits read permission from its inputs. Because the model is outside any one tool, it can
say things no single tool can: that a table and a folder of files have the same audience,
that narrowing a source narrows everything derived from it across both kinds, and that a
dataset exists without being readable.

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
| SQL views with `WITH GRANT OPTION` | Invoker-rights views give declared-intersect-underlying; grant option is the share right. | One database engine. |
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
| `id` | Tables: catalog, namespaces and table name joined by dots, `lakehouse.db.t1`; a table any of whose names contains a dot has no id and is refused, since its id would be ambiguous. Files: the tenant-qualified folder name, `projx/public`. Never reused. Tables cannot be renamed (section 8). |
| `kind` | `table` or `blob`. Views are `table`. |
| `location` | Folder in the bucket. A property, not the identity. For a table, learned from Polaris when the table is created. |
| `description`, `contact` | Human metadata. Contact carries no authority. |
| `describe`, `read`, `share`, `write`, `delete` | Five sets of groups. See 4.2. |
| `inputs` | Ids of datasets this one was built from. Set at registration, immutable. Every input must already exist and ids are never reused, so the input graph is acyclic. |
| `releases` | Per grant, groups the dataset was released to past the inputs' intersection, each with the covering groups and inputs that justified it. See 4.3. |
| `status` | `pending`, `live`, `gone`. See section 9. |

### 4.2 Five grants

Each grant is a set of groups. Governance holds the groups and who belongs to each, beside the
grants; Keycloak only proves who a person is. Each group has owners, which are groups, and
section 4.4 says who changes membership. A membership change applies at the person's next
request, since every rule looks the person's groups up at decision time.

- **describe**: the dataset appears in listings for this group. For a table, in Polaris's listing
  through the gate, and its metadata can be loaded: whether it exists, its columns, and its
  storage location; for every dataset, in the catalog's listing.
- **read**: for a table, obtaining a read credential for its files, which returns its
  metadata too; for a
  file dataset, a read credential for its folder. Listing a file dataset's objects is part of
  read.
- **share**: this group may change who sees and reads this dataset, and may release
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

An entry with a non-empty `inputs` list is derived. `read` and `share` are inherited; `describe`
and `write` are declared only.

    base(d, g)       = declared(d, g) ∩ ⋂ { effective(i, g) : i ∈ inputs(d) }    g ∈ {read, share}
    effective(d, g)  = base(d, g) ∪ { x ∈ releases(d, g) : covered(d, g, x) }
    covered(d, g, x) = ∀ i ∈ inputs(d) with x ∉ effective(i, g):
                           ∃ c ∈ covers(d, g, x, i) : c ∈ effective(i, share)
    effective(d, g)  = declared(d, g)                                              g ∈ {describe, write}

A release adds group `x` to grant `g` on `d` past what the inputs allow, with their owners'
consent: data built from a source stays restricted by it, and the source's `share` holders
approve an additional audience for a particular derived dataset. (US classified-information
handling has the same step for originator-controlled material: a derivative product keeps the
marking, and further dissemination needs the originator's permission.) To release `d` to `x`
for `g`, the caller must hold `share` on every input whose effective `g` lacks `x`. For each such input the caller's groups holding `share` on it are
recorded as `covers(d, g, x, i)`. An input that granted `x` at release time has no cover
recorded; if it later stops granting `x`, there is no cover for it and the release is
uncovered until someone with `share` on that input re-adds it. That is the conservative
reading and it is the intended one.

Direct inputs suffice: every group in `effective(i, share)` either inherited it from `i`'s
own inputs or was placed there by a release that someone with `share` on those inputs made,
so authority over `i` is authority over everything upstream of `i`, by induction on the
input graph.

Governance recomputes effective sets on every grant change and stores them in the entry.
OPA receives only effective sets and never sees `inputs` or `releases`.

Consequences, stated so they are not surprises:

- Narrowing `read` on a source narrows every derived dataset except where a release is
  still covered. A share holder on the source can re-add the removed group downstream; that
  is what `share` means.
- A dataset with many transitive inputs has a small effective `read`. The output's readers
  are allowed to read everything it was built from.
- `describe` does not inherit. A derived dataset can be listed for people who cannot see its
  inputs. Its `inputs` field is shown only for inputs the viewer may see, and the count of
  hidden inputs is not shown.
- A `gone` input still constrains its outputs. Grants are independent of status.
- A group given `share` on a derived dataset by a release can release further downstream. This
  is grant-option chaining, and it began with someone who held `share` on the inputs.
- The `inputs` list is declared by the publisher and trusted. The control is who may register
  (section 8), not verification of content.

### 4.4 Changing grants

Changes to the grant model are governance operations, decided by OPA like every other
request. For each change governance locks the dataset's row, asks OPA with the caller's
subject and groups, the dataset id, and the change, and on allow recomputes effective sets
and writes. OPA fetches the entry from governance like any other rule; every writer of a
row takes its lock, so the entry OPA reads is the one the write replaces.

- `describe` and `read` of dataset d: callers holding effective `share` on d.
- `share`, `write` and `delete` of d: callers in a group owning the folder root (a file
  dataset) or namespace (a table) that d sits under.
- Releasing d to group x for grant g: callers holding effective `share` on every
  input of d whose effective g lacks x. Removing one: callers holding effective `share` on d.
- `inputs`: never.
- A group's members and owners: callers in one of the group's owners, decided under a lock
  on that group. A change leaving a group without an owner is refused.
- Creating a group: callers in `group-admins`, who name its first owners. A name any grant or
  ownership already uses is refused, since whoever joined the new group would hold those
  grants.
- Owners of a folder root or namespace: callers in `group-admins` for a top-level one, and
  callers in a group owning it or one above it. A group owning a root owns everything under
  it, so an owner can hand part of its tree to another group and can always take it back;
  nothing records who delegated what.

## 5. Components and trust

| Component | Role | Trusted for |
|---|---|---|
| Keycloak | Identity provider. Issues every token the system accepts, one audience per service. | Who the person is. |
| governance | Owns the catalog, the only copy of any grant, and group membership. Serves entries to OPA. Lists datasets as a per-person table whose files it builds and serves, accepts registration, grant changes and group changes, receives lifecycle events. | The grant model and its administration. Availability of every decision: a governance outage denies every read. |
| OPA | Holds policy and no grants. Each rule fetches the entries it needs from governance at decision time. Returns a decision document. Reachable only by its callers: its API evaluates any query it is sent, including one that reads its own credentials. | Every access decision. |
| gate | A proxy in front of Polaris. Verifies the token, checks table creation against the catalog through OPA, trims list responses to what the person may see, maps denied named operations to not-found, and reports table create and drop to governance. Answers for the dataset index table itself. | The same custody of every current user's Polaris token that Trino has; the table lifecycle (section 9); correctness of list trimming. Polaris must be reachable only through it. |
| Polaris | Iceberg REST catalog. Delegates every operation's decision to OPA. Vends a per-table credential on allow. Holds a long-lived storage credential able to assume the vending role. | Relaying the decision into a credential; custody of that storage credential. |
| broker | Verifies a person's token, asks OPA about the named dataset, and on allow assumes a role with a session policy scoped to the folder in OPA's decision. | Relaying the decision into a credential, for files. |
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
no entry and is denied exactly as a dataset the person has no grant on. A dataset's folder is
fixed at registration, as a table's is (set-location is root-only, section 8), so the folder
in OPA's decision is the folder the grants were written for.

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
   catalog. It returns every dataset, table or file, whose effective `describe` includes one of the person's groups, with name and
   description and whether the person may read it. The table's files are built by governance
   for the person reading them and served by governance; no copy of the list is stored.
3. **Read a table in Trino.** Log in. Connect to Trino with the token, attach it as the
   extra credential. Query.
4. **Read a table elsewhere.** Log in. Point the client at the gate with the token as bearer.
5. **Read files.** Log in. Ask the broker for a credential naming the dataset. Read the folder
   with any S3 client.

Every read decision fetches the dataset's entry from governance, so a governance outage
denies every read.

### Publisher

6. **Publish a source dataset.** Log in. Register: id or folder, description, the grant
   sets. Governance checks the person is a steward and a group of theirs owns that folder's
   root. Entry is `pending`; governance checks the folder once and sets `live` if it already
   has objects. For files, ask the broker for a write credential, granted on `write`, then
   upload; storage events do the rest. For tables, create the table through Polaris; the
   gate admits the creation because the entry exists and the caller is in its `write`, and
   reports the location back.
7. **Publish a derived dataset.** As 6, plus `inputs` and any releases. Governance
   additionally checks the person may read every input and holds `share` on every input they
   release past. Build the output with any tool, as themselves.
8. **Delete.** Delete the objects or drop the table. The delete events, or the gate's drop
   report, set `gone`.
9. **Change grants.** Log in. Call governance naming the dataset and the change. Governance
   applies 4.4 and recomputes.

### Operator

10. **People and groups.** People in Keycloak; groups in governance, created by
    `group-admins` and changed by each group's owners (4.4). Each person's Polaris principal
    is created on first use (section 5).
11. **Which groups own which folder roots and namespaces.** `group-admins` assign top-level
    ones; their owners delegate below them (4.4).

## 8. What OPA decides

Every rule takes the person's subject, verified by the caller, plus the id of the named
resource, fetches the person's groups and that resource's entry from governance, and returns a
decision. Where the enforcement needs more than yes or no, the
decision carries it. OPA never lists storage. Any operation not named here is denied for
everyone but root.

| Rule | Caller | Input | Decision |
|---|---|---|---|
| `visible` | governance, for its listing; gate, for a Polaris listing | candidate ids | which ids have a caller group in effective `describe` or `read` |
| `vend` (read) | broker | dataset id | allow, plus the entry's folder for the read session policy |
| `vend_write` | broker | dataset id | allow, plus the entry's folder for the write session policy |
| `allow_create` | gate, from the create-table request body | table id | an entry with that id exists, is `pending`, and a caller group is in its `write`; unregistered names are refused |
| `allow_register` | governance | requested folder | the caller is a steward and a caller group owns a root above the folder |
| `allow_change` | governance | dataset id and the requested change | the rules of 4.4 |
| `groups.allow_create` | governance | | the caller is in `group-admins` |
| `groups.allow_change` | governance | group name | a caller group is among the group's owners |
| `allow_change_root` | governance | folder root or namespace | the caller is in `group-admins` and it is top-level, or a caller group owns it or one above it |
| Polaris: list namespaces, list tables, list views | Polaris | namespace | allowed for any authenticated person; the gate trims the response by `visible` |
| Polaris: namespace exists, load namespace metadata | Polaris | namespace | a caller group owns the namespace or one above it, or any table in it is visible to the caller |
| Polaris: create table, create view, commit a staged create | Polaris | namespace | the caller may view the namespace; the gate has already decided per table with `allow_create`, since Polaris names only the namespace |
| Polaris: table exists, view exists, load table or view metadata | Polaris | table id | group in effective `describe` or `read` |
| Polaris: load with a read credential | Polaris | table id | group in effective `read`; `write` implies `read` for tables |
| Polaris: load with a read-write credential | Polaris | table id | group in effective `write`. Trino asks for this on every load; when denied, Polaris checks for a read credential instead |
| Polaris: update, commit table or view | Polaris | table id | group in effective `write` |
| Polaris: drop table or view, with or without purging its files | Polaris | table id | group in `delete` |
| Polaris: rename table or view, register table, set table location | Polaris | | root only. Rename would orphan the entry's id; register and set-location would let a table alias another table's folder |
| Polaris: create or drop namespace, update namespace properties | Polaris | namespace | a caller group owns the namespace or one above it |
| Polaris: admin operations | Polaris | | root only |

Grant changes are decided while governance holds the dataset's row lock (4.4), so the
decision and the write see the same entry.

The gate trims a list response in three steps: fetch every upstream page, filter once, then
paginate the result with its own page tokens, so page size and tokens reveal nothing about
hidden entries. This is the order Gravitino's Iceberg REST list handler uses. The filter is
one `visible` decision over the candidate ids. A namespace is visible to its root owners always, and to
others when any table in it is visible to them; the gate trims namespace listings by that
rule. Every denied operation that names a table or namespace is mapped to not-found,
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

An entry exists only through registration. Status changes only in response to an event about
that entry, and the event triggers a check of that one entry:

- Registration creates `pending` and checks the folder once.
- Files: a creation or deletion event under the folder, delivered by Ceph bucket
  notifications, triggers an existence check of that folder, a listing capped at one object.
  Non-empty sets `live`; empty after having been `live` sets `gone`. Events are coalesced per
  folder so a bulk upload costs one check. Events under table folders are ignored.
- Tables: the gate reports table creation, with its location, and table drop. Creation sets
  `live`; drop sets `gone`. A drop report for an unknown id is logged and ignored; a create
  for an unknown id cannot occur because the gate refuses it.
- There is no periodic sweep. Notifications are delivered through Ceph persistent topics with
  retry. A lost event leaves a stale status until the next event for that entry: a lost
  deletion leaves a `gone` dataset listed, a lost creation leaves a `live` dataset hidden
  while its grants already allow reading it. Both are the accepted price of having no sweep.
- The events endpoint authenticates the sender with a shared secret that RGW adds to every
  event it sends (the notification topic's opaque data); a secret in the push URL would land
  in the endpoint's request log. A forged event can only trigger a check, never set a status
  directly.

Grants are independent of status. Listings show `live` entries only.

## 10. Limitations by design

- **Granularity is the dataset.** No row filters, no column masks. A credential cannot
  express either, and nothing on the byte path could apply them. A narrower audience for part
  of a dataset is a separate dataset.
- **A dataset is one unit, as a repository is.** Every file in a dataset's folder shares its
  grants and the sources its files carry, as every file in a GitHub or GitLab repository shares
  the repository's permissions; no file has grants of its own. Roots and namespaces nest and
  hold datasets, as GitLab groups and subgroups hold projects. Datasets do not nest: a folder
  inside a dataset is part of it, because a write credential for the dataset reaches every
  file under its prefix. This differs from Google Drive, where any file or folder can be
  shared on its own.
- **No per-person dynamic filtering.** "Rows where owner is the current user" is not a
  dataset.
- **Revocation lag.** A grant or group membership change reaches the next decision and
  reaches data when outstanding credentials expire.
- **No request workflow.** A person can see a dataset they cannot read and has no in-system
  way to ask for it. Listings return a contact.
- **Inputs are trusted.** A publisher who omits an input defeats the derivation rule. The
  control is who may register. Verifying inputs would require engine lineage, which requires
  trusting the engine, which this design does not.
- **Registration reveals names within a tenant.** Registering an id that exists fails, so
  co-owners of a root can learn each other's names. Accepted: they share a root.
- **The gate is a component you run** in front of a catalog you do not control. A Polaris
  release that changes list response shapes requires a gate change.

## 11. Enforced, decided, declared

**Enforced by storage.** A credential opens one dataset's folder and nothing else. The
session policy is built by Polaris or the broker after OPA's decision, from the registered
folder, never by the client.

**Enforced by the gate.** What appears in a Polaris listing, and that a table is created only
under a registered entry by someone in its `write`.

**Decided by OPA.** Every decision in section 8, including registration and changes to the
grants, over the entry governance holds at the time of the decision.

**Declared and trusted.** The `inputs` list of a derived dataset. The content of any dataset.

## 12. Decisions

Decided: governance holds the only copy of every grant and of group membership,
callers send OPA only who is asking and the ids they name, and every rule fetches the groups
and entries it needs with `http.send`; table names are
confidential, so `describe` is enforced per table and the gate trims listings; the engine may extend an active user's token by exchange, bounded by
Keycloak's session maximum; the catalog lists both kinds; rename, register-table, and
set-location are root-only; `group-admins` assign top-level folder roots and namespaces, and
their owners delegate below them; `read` implies `describe`.

## 13. Status against the repository

Implemented today: the catalog with `describe`, `read` and `share` for file datasets; the file
listing; the dataset index as a per-person table, `governance.datasets`, listing both kinds;
the broker, scoping credentials to the folder in OPA's decision; Polaris delegating to OPA
with per-table credentials, viewing a table gated on `describe` or `read` and read-write
credentials on `write`, drops on `delete`; registration gated by `stewards` and root
ownership; OPA holding policy and no grants, every rule fetching what it needs from
governance with `http.send`; Trino authenticating people by their Keycloak token over HTTPS
and forwarding it to Polaris as the `token` extra credential; the gate as the only way to
Polaris, verifying the token, trimming listings (every upstream page, one filter, its own
page tokens), answering not-found for a refused name the person may not view, and repeating
a refused credentialed load without the credential request, deciding table and namespace
creation, and reporting table creates and drops; tables registered as entries with `describe`,
`read`, `share`, `write` and `delete` by group; `write` for file datasets, a broker
credential that puts and deletes in the folder; grant changes through governance, decided by
OPA under the entry's row lock as in 4.4; group membership and owners, and root ownership,
in governance, changed through it as in 4.4; each person's Polaris principal created on
first use; a login proxy that keeps a client session past the token's 5-minute life by
holding the refresh token and forwarding a fresh token to Trino; OPA reachable only by its
callers; persistent storage events, each checking one folder with a listing capped at one
object, and no sweep.

Differs from this document: tables are entries in their own registry, not in the catalog
with files; `share` is only the right to change grants, since there are no derived datasets
to release; no derived datasets, no releases; events are checked as each delivery arrives
rather than coalesced per folder.

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
