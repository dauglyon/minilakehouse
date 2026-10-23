# Provenance transactions: server-bounded inputs, attested use

Build step 1 and the first part of step 2 (section 10) are implemented; the rest is design.
Section 10 lists what was run against the stack on 2026-10-22 and what each run showed. The
document extends `WHITEPAPER.md` and replaces its derivation rule (section 4.3), which limits a
dataset by a list of `inputs`, with sources that travel with the stored data (section 6).

## 1. Purpose

The whitepaper takes a derived dataset's `inputs` from the publisher and trusts them
(`WHITEPAPER.md` 4.3, 10, 11). A publisher who omits an input defeats the derivation rule, and
the only control is who may register. Section 10 rejects verifying inputs because that would
require engine lineage, which requires trusting the engine.

This design is the third option. The server records every dataset a person's work obtained a
credential for, and before an output is listed for others the publisher declares, per
candidate, whether it was used. The publisher can subtract from a list the server built and can add
things the platform never saw; the publisher cannot shorten the list silently. Every read in
this stack is a credential issued after a policy decision, and nothing on the byte path is
readable without one, so the server's list is complete for everything that came through the
platform.

What it is not: verification of content. A declaration of "unused" is a signed claim by an
identified person, recorded against a list the server holds. The design makes omission a
lie rather than a gap.

## 2. Prior art

| System | What is taken | Where it differs |
|---|---|---|
| in-toto link metadata | A step has materials and products, signed by whoever ran it. The record here has the same shape. | in-toto trusts the signer to list materials. Here the server lists them. |
| Trusted research environments (OpenSAFELY and similar airlocks) | Nothing leaves until the researcher accounts for what an output derives from; the check happens at the exit, where the researcher's attention is. | Those environments also prevent the researcher from holding the data at all. This design does not; see section 8. |
| W3C PROV | The record's terms: a declared derivation (`wasDerivedFrom`) and whether a source was `used`. | A vocabulary, not a mechanism. |
| Unity Catalog's `system.access.table_lineage` | The shape of `governance.lineage` (5.2): a row per source and target, an empty target for a read that wrote nothing, an empty source for a write that read nothing. | Unity's rows come from the engine, one statement at a time. These come from credentials and commits, one session at a time, so a target is paired with everything its session read before writing it, which the declaration narrows. |
| Apache Atlas classification propagation; Palantir Foundry markings | A restriction travels from a dataset to everything derived from it (section 6); in Foundry, removing a marking takes a permission. | Here the restriction is the source dataset's own `read` grant, it is tracked per stored file, and it is enforced by computing who may read. |
| SLSA provenance, OpenLineage | Inputs recorded per output. | Emitted by a trusted builder or engine. Rejected by the whitepaper and here. |
| Database triggers | A write to a table runs server logic. Section 5 moves this to the catalog so it works from any Iceberg client. | |

## 3. Sessions

A session is a unit of work a person names. A person has one until they ask for another.

- Governance holds a `sessions` table: person, name, started, last used. Names are unique per
  person. A person with no session gets one named `default` at their first credential.
- Every login carries a current-session pointer, held by governance and keyed by the login's
  `sid`. Keycloak puts a `sid`, the login session id, in every access token this realm issues
  (checked 2026-10-22 on a token for alice; a refreshed token keeps it). Nothing is minted.
- One lever: inserting a name into `governance.sessions` (section 5). A name the person has
  not used starts a session and points the login at it; a name they have used points the
  login at that session. There is no close, join, or link.
- A new login's pointer defaults to the person's most recently used session, so a re-login
  after an idle timeout continues the same work with no action.
- Every credential record is stamped with the pointer's value at the moment governance writes
  it (section 4). The stamp never changes. No clock enters the mapping.

Jobs and service connections are Keycloak service accounts, subjects like any other
(`WHITEPAPER.md` section 6). A client-credentials token carries no `sid` (checked 2026-10-22
on `service-account-trino`), so every token of one service account is one login with one
pointer, keyed by the account. An orchestrator that wants each agent's work in its own
session therefore gives each agent its own service account, or a login that has a `sid`, and
inserts a session name as each agent's first statement; agents sharing one account share a
pointer, and an insert by one moves it for all.

Keycloak's login lifetime settings affect convenience only. A login that outlives Keycloak's
session maximum forces a re-login mid-work, and the new login's pointer continues the same
session. Setting the maximum to an environment's intended lifetime removes the interruption.
Unverified: whether an offline session (a long-lived refresh token) keeps a stable `sid`.

What a session is not: an environment or a login. Two environments can work in one session;
one environment can move through several. Data that stays in an environment across a session
boundary is out-of-band carry-over, section 8, the same as a download.

## 4. Capture

### 4.1 The access log

Governance holds one row per credential issued and per table write (`accesses` in
`governance/app.py`): person, Keycloak subject, `sid`, session, dataset id, kind, `read` or
`write`, time, expires. Two writers, each calling governance's internal listener with its own
client certificate:

- The broker, for every file vend (`broker/app.py`, `vend`).
- The gate (`gate/app.py`, `proxy`), for every response that hands out a storage credential,
  whatever its path: a load or a refresh from the credentials endpoint Polaris advertises as
  `client.refresh-credentials-endpoint` is a read, a create (staged or not) a write of the
  new table, and a credential on a path that names no table is refused. A 304 to a
  credentialed load is a read too, since the engine reuses a credential it already holds.
  And for every table create and commit it forwards.

Both record before they return the credential, and the gate records a write before it
forwards the create or commit, so a failed record stops the write before the catalog sees
it. A failed record refuses the request. A lost record would silently shorten a candidate
list, which is the one failure the design exists to prevent, so the record is synchronous
and fail-closed. OPA decision logs were
considered and rejected: they are buffered and best-effort. Side effects inside Rego were
rejected: a rule may evaluate more than once per decision.

Each read decision already calls governance (`WHITEPAPER.md` section 8), so this adds one
more call on a path that is already coupled to governance's availability.

### 4.2 Which session wrote an output

An output's candidates are the reads of the sessions that wrote it, so every write must be
attributed to a session, and to a time that bounds which of its reads it may have used.

**Tables.** Exact. Every create and commit passes through the gate with the person's token,
and the gate logs it with the token's `sid` before forwarding it. The write happens at the
commit.

**Files.** Governance never sees a file write: the person puts objects straight into Ceph
with a credential from the broker. It does see the credential, which the broker logs with its
session, dataset and expiry (4.1). Any write made with it falls between its issue and its
expiry, so a file write credential counts as a write by its session that lasts until the
credential expires. The cost is extra candidates, never a missing one: a credential never
used to write still makes its session a writer, and reads made after the last real write
but before expiry are candidates. With 15-minute credentials the second is at most 15
minutes of reads.

This bounds the candidates a person declares. Which sources each stored file carries is
worked out per file, from the time it was written (6.2).

A credential outlives a session switch: issued in session A, it still writes after the login
points at B. So a file write credential may also have used every read its own login made
while the credential was valid, whatever session that read was stamped with. Reads by
another login of the same person are not included; a credential carried to another login is
out-of-band carry-over (section 8), as a download is. Including every read by the person
would cover that too, but it would pair each agent's writes with every other agent's reads
when an orchestrator runs many agents as one person in separate sessions.

Rejected: naming the writer in Ceph's storage event. The event could name the person only if
the broker vended write credentials with `AssumeRoleWithWebIdentity` (with `AssumeRole` the
event names the broker), with a role and an OIDC provider that belong to no RGW account and a
trust condition naming a token audience only the broker could obtain, since RGW's STS
endpoint is open to every client (section 10, items 1 and 2). It is not needed: the session
comes from the write credentials valid when the object was written, so the object's time is
all that matters, and a listing of the folder gives it (6.2).

## 5. The tables

Three Iceberg tables in the `governance` namespace, which the gate already answers for
itself (`gate/app.py`, `index_answer`; `governance/index_table.py`). A load returns a table
governance builds in memory for the person, with a credential for governance's own S3-style
endpoint, which serves the files. Nothing is written to storage. Every client that speaks
the Iceberg REST catalog, Trino, Spark, pyiceberg, sees the same tables, so the catalog is
the whole interface and there is no governance API for the person. A table's rows cannot
depend on a query's `WHERE`: no filter reaches the catalog (section 10, item 6), so each
table holds all of the person's rows and a filter is an ordinary one.

### 5.1 `governance.sessions`

| column | meaning |
|---|---|
| `name` | the session's name |
| `started`, `last_used` | timestamps |
| `current` | true for the session this login points at |

`SELECT` lists the person's sessions. `INSERT` of a name is the lever of section 3.

### 5.2 `governance.lineage`

Read only. The shape of Unity Catalog's `system.access.table_lineage`, computed from the
person's access log at each load.

| column | meaning |
|---|---|
| `source`, `source_type` | a dataset read; `table` or `files` |
| `target`, `target_type` | a dataset written after that read; `table` or `files` |
| `session` | the session the read, or the write, was stamped with |
| `event_time` | when the latest event of the row happened |

Two rules make the rows:

- Every read is a row with an empty target, in the read's session.
- Every write is a row for each read it may have used (4.2), in the write's session, or one
  row with an empty source when there is none. A dataset is never paired with itself, so a
  table read in order to append to it is not its own candidate.

Repeated events of one shape are one row. The person sees only their own sessions' rows.
Design, not built: a column `direct`, false on rows for a source that arrived through a read
(section 6) rather than being read, so a person sees what a declaration may drop.

An output's candidates are the sources of the rows whose target is the output, across every
session that wrote it: `WHERE target = '<id>'`. That is how a later session declares
something built earlier, and how an output written in two sessions gets the reads of both. A
session's reads are `WHERE session = '<name>' AND target IS NULL`.

### 5.3 `governance.derivations`

Insert only, with `lineage`'s column names, so a declaration copies candidates column for
column.

| column | meaning |
|---|---|
| `source` | a candidate's id, or a hash of an input from outside the platform |
| `source_type` | `table`, `files`, or `external`; may be left out for a candidate |
| `target` | id of a pending dataset the caller may write |
| `used` | boolean |

One `INSERT` is one commit is one attestation. Governance applies one rule to the commit as a
whole: for every target it names, the caller must have written it, a caller group must be in
its `write`, and the rows must give each of the caller's own candidates of that target a
`used` value; every `external` row's source is a hash. Under section 6 (not built), a
declaration covers only the caller's files in the target that no earlier declaration of
theirs covered, and may also name a source that arrived through one of their reads, to mark
it unused (6.3). A source named twice with the same `used` counts once; named with
both values, the commit is refused. A source that is not a candidate is refused unless its
`source_type` is `external`, so a mistyped id is never recorded as an outside input. A row
with an empty source, which a target with no candidates has in `lineage`, names no input. On
success governance stores the rows and signs the record: a DSSE envelope, the envelope in-toto
attestations use, over the person, the target, the time, the person's candidates and the
declared sources, signed with governance's Ed25519 key (`signing.key`, made by
`governance/pki.py`). Otherwise the commit is refused with an Iceberg error and nothing is
stored; the person sees the reason as the statement's error.

Each person who wrote a target declares their own candidates, and the target goes `live` once
everyone who wrote it has declared. A person's `lineage` holds only their own sessions, and
only the person who made a read can say whether they used it. This is in-toto's model: each
functionary signs the link for the step they ran, and a product verifies only with every
step's link. Rejected: one person declaring for every writer, which would show them the
other writers' reads (some naming datasets they may not see) and have them vouch for reads
they did not make; and one writer per output, which stops a group working on a shared output.
Setting `live` and the grant recomputation below are build step 2's second part, not built.

Who may then read the target follows section 6: a source marked unused is not carried by
the files the declaration covers. `external` rows are recorded and shown and limit no one,
since they have no grants. Until a person declares, their files carry every source they
brought in, so declaring can only widen who may read.

### 5.4 Examples

All examples assume `lineage` pairs `lakehouse.db.joined` with `lakehouse.db.t1` (table),
`projx/public` (files) and `lakehouse.db.weather` (table).

Start or resume a session:

```sql
INSERT INTO governance.sessions (name) VALUES ('run7');
```

The candidates:

```sql
SELECT source, source_type, session FROM governance.lineage
WHERE target = 'lakehouse.db.joined';
```

Everything was used:

```sql
INSERT INTO governance.derivations
SELECT DISTINCT source, source_type, target, true
FROM governance.lineage WHERE target = 'lakehouse.db.joined';
```

One dataset was not used:

```sql
INSERT INTO governance.derivations
SELECT DISTINCT source, source_type, target, source <> 'lakehouse.db.weather'
FROM governance.lineage WHERE target = 'lakehouse.db.joined';
```

The same, plus a file from a collaborator:

```sql
INSERT INTO governance.derivations
SELECT DISTINCT source, source_type, target, source <> 'lakehouse.db.weather'
FROM governance.lineage WHERE target = 'lakehouse.db.joined'
UNION ALL
VALUES ('sha256:9f3c…', 'external', 'lakehouse.db.joined', true);
```

Refused:

```
Query failed: Failed to commit: lakehouse.db.joined: not declared: projx/public, lakehouse.db.weather
Query failed: Failed to commit: lakehouse.db.other: not a pending dataset in your write grant
```

Looking back:

```sql
SELECT source, source_type, used FROM governance.derivations
WHERE target = 'lakehouse.db.joined';
```

Cleaning (section 6.4; not built). `lakehouse.db.joined`'s files carry `lakehouse.db.weather`,
and its rows from `weather` have been deleted, the files rewritten, and old versions removed.
The rewrite read `joined`, which brought in `joined` and, through it, `weather`:

```sql
INSERT INTO governance.derivations VALUES
  ('lakehouse.db.joined',  'table', 'lakehouse.db.joined', true),   -- read directly
  ('lakehouse.db.weather', 'table', 'lakehouse.db.joined', false);  -- arrived through it; dropped
```

### 5.5 How an INSERT becomes the call

An Iceberg write from any client is three catalog steps. The gate sees all three for the
`governance` namespace:

1. Load the table with a credential. Governance builds the person's current table in memory,
   as `index_table.build` does for the index, and returns its metadata and a credential that
   reads the person's prefix on governance's endpoint and puts new files under their own
   governance tables.
2. Put the data file (Parquet), a manifest and a manifest list (Avro), and Trino's statistics
   file under the table's location. Docker DNS sends that bucket's host name,
   `governance-index.storage.internal`, to governance, whose S3-style endpoint checks the
   signature and keeps the bytes in memory (`governance/app.py`, `index_write`). It accepts
   PutObject, multipart uploads and DeleteObjects; it refuses a put to a key that already
   holds a file, since engines write every file once under a new name and governance's own
   files must stay as built; it caps a person's uploads, open multipart parts included, at
   64 MiB and eight open multipart uploads; and it parses XML bodies with defusedxml, which
   refuses document type declarations.
3. Commit: requirements, such as the branch still pointing at the loaded snapshot, and
   updates: `add-snapshot` naming the manifest list, `set-snapshot-ref`, and Trino's
   `set-statistics`. Governance checks the requirements against the table the person last
   loaded, so a commit against a changed table is refused the standard way, applies the
   updates with pyiceberg, follows the new snapshot's manifests to the data files it added,
   refusing any file outside the person's own table, since the in-memory store holds every
   person's files and a refusal's message would echo rows read from another's, reads their
   rows with pyarrow, validates them as section 5.3 says, and in one Postgres
   transaction stores the record. Anything but appended rows is refused, so a `DELETE` or
   `UPDATE` fails. The response is the committed metadata, the engine's own snapshot
   included; the next load rebuilds the table from Postgres.

Nothing durable comes from the in-memory table. Postgres is the record; the Iceberg table is
a view of it that accepts writes. Other tables in the namespace accept the upload and refuse
the commit, so the person's error names the table rather than a failed file write.

## 6. Sources travel with the data

Agreed 2026-10-22; not built. A *source* of some data is a dataset whose own `read` grant
limits who may read that data. Sources are tracked per stored file, the way Apache Atlas
propagates a classification to everything derived from a dataset and Palantir Foundry's
markings follow data along lineage. Three rules:

1. **Reading brings sources in.** A read credential for dataset X brings in X and every source
   carried by a file in X's folder at that moment. The access log keeps that set with the
   read, so cleaning X later does not change what an earlier read of it brought in.
2. **A file carries what its writers brought in.** A stored file belongs to everyone who held
   a write credential for its folder when it was last modified (6.2). It carries every source
   they brought in before that time, through their session's reads and their login's reads
   while the credential was valid (4.2), minus the sources a declaration of theirs covering
   the file marked unused (6.3).
3. **Who may read a dataset** is its own `read` grant, cut down by the own `read` grant of
   every source carried by any file in its folder. `share` follows the same rule, as
   `WHITEPAPER.md` 4.3 has both inherit.

This replaces `WHITEPAPER.md` 4.3's per-dataset `inputs`. A file's sources already include
everything upstream of it, so rule 3 needs no chain of inputs-of-inputs: it looks up each
source's own grant at decision time, and a grant change takes effect at the next decision
with nothing to recompute.

### 6.1 What follows

- **A write to a live dataset** carries everything its writer brought in until they declare.
  The dataset stays listed, and who may read it is cut down at once; a declaration marking a
  source unused gives the access back.
- **A copy** reads the original, so its files carry the original and every source the
  original's files carry, each separately. Either the copy or the original can be cleaned
  later.
- **A rewrite of a table**, a delete or a compaction, reads the table, so the new files carry
  the same sources. Compaction cannot quietly drop one.
- **A dataset written from itself** carries itself as a source, which changes nothing: its own
  grant applies anyway.

### 6.2 Which files a write produced

Governance lists the dataset's folder. Each object has a last-modified time, which governance
matches to the write credentials valid for that folder at that time, with a tolerance for
clock skew: the broker's write credentials for a file dataset, and for a table the credential
Polaris hands someone in its `write`, which can write (the gate logs those as writes too). A
file matching several credentials carries all of their sources. An object no write
credential matches, such as data seeded by an administrator, carries none.

Storage decides. Governance stops counting a source for a dataset only after a listing shows
no file carrying it; Ceph's notifications tell it when to list again.

### 6.3 What a declaration covers

A person's declaration of a target covers their files in it that no earlier declaration of
theirs covered. It gives a `used` value to each dataset they read directly before those
files, as `lineage` lists them, and may name a source that arrived through one of those reads
to mark it unused. The files it covers do not carry a source it marks unused. Who may mark an
arrived-through source unused is open (section 9).

### 6.4 Cleaning a dataset

To remove a source from a dataset:

1. To keep the data as it is, copy it first: `CREATE TABLE … AS SELECT * FROM …`. The copy
   carries the same sources (6.1), and the person chooses which of the two to clean.
2. Delete the data that came from the source: `DELETE FROM … WHERE …`.
3. Get the old files out of storage. Iceberg keeps deleted rows in their files, marking them
   deleted, and keeps every earlier version (section 10, item 10), and a read credential
   reaches every file in the folder. `ALTER TABLE … EXECUTE optimize` rewrites the files
   without the deleted rows; `expire_snapshots` and `remove_orphan_files` remove old versions
   and files nothing uses. A file dataset's objects are deleted or replaced directly.
4. Declare the rewrite, marking the source unused (6.3; example in 5.4).

A declaration that marks an arrived-through source unused is refused while files carrying it,
other than the ones the declaration covers, remain in the folder; the refusal names step 3's
statements. Once it is accepted, no file carries the source and rule 3 stops counting it.

### 6.5 Lifecycle of an output

- Registered `pending`, created as today: the gate admits a create for a registered pending
  table whose caller is in its `write`; a file dataset gets a write credential on `write`.
- Written in one or more sessions, by one or more people.
- Declared by each person who wrote it, from any session.
- `live` once every writer's files are covered by a declaration of theirs: listed, and
  readable under rule 3.
- An output never declared stays `pending`: listed for no one, readable under rule 3.
- Later writes keep it `live`; their files carry their sources until declared (6.1).

## 7. What this enforces, decides, declares

Extending `WHITEPAPER.md` section 11:

**Enforced.** The candidate list is a superset of every input that came through the
platform: no credential without a record. An output is not `live` until declared. A
declaration covers the list exactly.

**Decided by OPA.** Registration, grants and vends as before, with who may read a dataset
given by section 6's rule 3.

**Declared and trusted.** Which candidates were used. External inputs. The content of any
dataset.

## 8. Limitations

- **Data outside the platform is invisible.** A file from a collaborator, a download from
  last month, or data left in an environment across a session boundary. The external row is
  the only cover, and omitting it is a false declaration by an identified person. Research
  environments that hold the data server-side close this; the platforms this design is
  meant for mostly will, not all.
- **File writes are counted by credential.** A session that got a file write credential
  counts as writing its dataset until the credential expires, whether or not it wrote, and
  its reads up to that expiry are candidates (4.2). Extra candidates, never a missing one.
- **A file belongs to every writer whose credential was valid when it was written** (6.2).
  When several people could write a folder at once, each of their files carries all of
  their sources.
- **Rule 3 needs each file's time.** Governance lists a dataset's folder when a source might
  stop counting; a large table is a long listing.
- **A credential carried to another login is not followed.** The reads of the login it was
  issued to are paired with it; another login's are out-of-band carry-over.
- **Lineage grows with a person's history.** Each load of `governance.lineage` computes it
  from every event the person has logged.
- **A silent re-login after a timeout continues the last session.** Right when the
  environment is the same, wrong when a person starts unrelated work without inserting a
  session name. The cost is a longer list, never a shorter one.
- **A person who never names a session has one list that grows forever.** Long, not wrong.
- **Content is never checked.** Comparing an output's objects or rows against candidates
  declared unused would catch copies; it is out of scope.
- **Every write and read now calls governance.** A governance outage already denies every
  read; it now also denies every write.

## 9. Open

**Project folders.** Decided 2026-10-22: a project folder is scratch, not a dataset, and a file
written into it is not a registered output. Section 6 applies to scratch files like any
other: a scratch file carries what its writer had read, and reading it brings that in, which
closes the path from one session to another through scratch. Work in scratch becomes a
dataset by being written into a registered dataset's own folder, and those files carry what
the scratch files carried. No dataset sits inside another or inside a project folder:
nesting was rejected because a parent's write credential reaches the child's files, and
reading one's own project folder would make the whole project a source of the child.

Open: whether a scratch folder's own read grant is cut down by what its files carry (rule 3).
That keeps a project member from reading data derived from something they may not read, but
locks them out of the shared folder; the alternative is a scratch folder per person.

**Who may drop a source that arrived through a read** (6.3): anyone who wrote the data, as
with any declaration, or only someone holding `share` on that source, as Foundry requires a
permission to remove a marking.


## 10. Evidence and build order

Run on the stack on 2026-10-22. Items 1 and 2 used a throwaway notification topic pointed at
a sink container, all artefacts removed afterwards; they bear on the rejected event
attribution (4.2).

1. An object put with a credential from `AssumeRole` on `blob-writer`, session name
   `probe-session-42`: the event's `userIdentity.principalId` was `blob-broker`. Confirmed in
   Ceph v20.2.1 source: `rgw_notify.cc` sets the event user from the request owner;
   `rgw_auth.cc` `RoleApplier::load_acct_info` loads the user from the token's `user_id`, the
   assumer. Nothing else in the record names the session.
2. `AssumeRoleWithWebIdentity` with alice's broker-audience token, Keycloak registered as an
   OIDC provider over plain http with the JWKS certificate's SHA-1 thumbprint. Under the
   admin's RGW account, with role and provider created through the IAM API: the event named
   the account, `RGW62588371164537598`. With role and provider created by a user in no
   account: the event named `$oidc$997d4829-…`, alice's Keycloak subject. A provider created
   under an account is not found by an account-less role: `Couldn't get oidc provider info`.
3. alice's access token carries `sid`.
4. A client-credentials token for `service-account-trino` carries no `sid`.
5. Trino 484 loads a table through the gate on every query: two runs of one `SELECT` made two
   loads, both answered 200 with a storage credential. Polaris also sends an `ETag`; a
   credentialed load sent with `If-None-Match` got 304, which the gate logs as a read.
6. Trino 484 never sends a query's filter to the catalog. Iceberg 1.12, which it bundles,
   plans a scan on the server when a load's config sets `scan-planning-mode=server`
   (`RESTSessionCatalog.restTableForScanPlanning` returns a `RESTTable`), but
   `TrinoRestCatalog.loadTable` wraps every loaded table in a new `BaseTable` built from its
   operations, which plans on the client. Read from the bytecode of the jars in the running
   Trino image.
7. Build step 1, run on the stack. As alice: a Trino read of `db.t1` and a broker read
   credential for `projx/public` were logged in session `default`, and `governance.sessions`
   showed `default` as current, though each command used a new login. A CTAS into a registered pending table logged two writes: Polaris hands out a
   credential on Trino's staged create, and the completing commit is the second. bob's refused read logged nothing. With the
   log's address made unreachable, a gate given a credentialed load answered 503, a gate
   given a commit answered 503 and Polaris logged no request for the table, a load without a
   credential still answered 200, and the broker answered 503. On the internal listener, the
   `opa` certificate is refused on the log, and `broker` is refused everywhere else.
8. `governance.lineage`, run on the stack. A CTAS of `db.p3` from `db.t1` gave rows for the
   reads of `t1` and `p3` with no target and one row pairing `t1` with `p3`. Then, on one
   login, a write credential for `projz` in `default`; the login pointed at a new session
   `run2`; a read credential for `projx/public` there. `lineage` showed the read in `run2`
   with no target, and `projx/public` paired with `projz` in `default`, with the earlier
   reads of `default`.
9. Build step 2, first part, through Trino as alice, whose `lineage` paired `t2` with `t1`.
   `INSERT INTO governance.derivations SELECT DISTINCT source, source_type, target, true FROM
   governance.lineage WHERE target = 'lakehouse.db.t2'` was accepted, and a `SELECT` read
   the row back. Trino accepted the commit response, which holds its own snapshot, and a
   refusal reached the person as "Failed to commit the transaction during insert: Malformed
   request: lakehouse.db.t2: not declared: lakehouse.db.t1" (400 is Malformed request, 403
   Forbidden). Refused as they should be: a missing candidate, a source that is not a
   candidate, a target alice never wrote, any target for bob, an insert into
   `governance.lineage`, and a `DELETE` from `derivations`. Accepted: `t1` unused plus an
   outside input by hash. Every stored envelope verified against `signing.pub`, and an altered
   payload did not. With boto3 on a credential from a load: a multipart upload read back
   whole, DeleteObjects removed the object, and puts over an existing file, under bob's
   prefix, and outside the governance tables were refused.
10. What a delete leaves in a table. A test table with rows `keep` and `secret`, then
    `DELETE … WHERE note = 'secret'`: the current version's data file still held both rows
    (`$files`: one data file of 2 records, one file marking 1 row deleted), both versions
    were kept (`$snapshots`: append, delete), and `FOR VERSION AS OF` the first one returned
    the `secret` row. alice's read credential for `t1` listed every file in its folder.

Gotchas recorded on the way: pyiceberg 0.10's `SetStatisticsUpdate` reads its `statistics`
field as an object before validating it, so one parsed from JSON fails; governance builds that
update itself (`index_table._update`). RGW merges a put of the bucket notification configuration into
the existing one rather than replacing it, so removing an entry needs
`radosgw-admin notification rm`; roles and policies are removed with `role delete` and
`role-policy delete`.

Build order, each step usable on its own:

1. Built. The access log and the session pointer in governance; the broker and the gate
   recording fail-closed; `governance.sessions` and `governance.lineage` served read-only.
2. `governance.derivations`, in two parts. First, built: uploads to governance's endpoint,
   commit parsing and validation, the signed record. Second, section 6: the sources each read
   brings in kept with it; writer table credentials logged as writes; files attributed by a
   listing; who may read from rule 3 in governance's lookups for OPA; declarations covering
   only undeclared files and naming arrived-through sources; `lineage`'s `direct` rows; a
   target `live` once every writer has declared. Waits on who may drop an arrived-through
   source (section 9).
3. The `sessions` lever as an insert.

Section 13 of `WHITEPAPER.md` and the "inputs are trusted" statements in its sections 4.3,
10 and 11 change when step 2 lands.
