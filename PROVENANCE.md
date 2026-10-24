# Provenance transactions: server-bounded inputs, attested use

Build steps 1 and 2 (section 10) are implemented; step 3 is design.
Section 10 lists what was run against the stack on 2026-10-22 and what each run showed. The
document extends `WHITEPAPER.md` and replaces its derivation rule (section 4.3), which limits a
dataset by a list of `inputs`, with sources that travel with the stored data (section 6).

## 1. Purpose

The whitepaper takes a derived dataset's `inputs` from the publisher and trusts them
(`WHITEPAPER.md` 4.3, 10, 11). A publisher who omits an input defeats the derivation rule, and
the only control is who may register. Section 10 rejects verifying inputs because that would
require engine lineage, which requires trusting the engine.

This design is the third option. The server records every dataset a person's work obtained a
credential for, and until the publisher declares, per candidate, whether it was used, everything
that could be in an output limits who may read it. The publisher can subtract from a list the
server built and can add things the platform never saw; the publisher cannot shorten the list
silently. A write needs no declaration: declaring is how a publisher widens who may read. Every read in
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
A column `direct` is false on rows for a source that arrived through a read (section 6)
rather than being read, so a person sees what a declaration may detach.

An output's candidates are the sources of the rows whose target is the output, across every
session that wrote it: `WHERE target = '<id>'`. That is how a later session declares
something built earlier, and how an output written in two sessions gets the reads of both. A
session's reads are `WHERE session = '<name>' AND target IS NULL`.

### 5.3 `governance.derivations`

Insert only, with `lineage`'s column names, so a declaration copies candidates column for
column. An insert names the four columns it fills; governance fills in the other two.

| column | meaning |
|---|---|
| `source` | a candidate's id, or a hash of an input from outside the platform |
| `source_type` | `table`, `files`, or `external`; may be left out for a candidate |
| `target` | id of a pending dataset the caller may write |
| `used` | boolean |
| `declared_by` | the person who declared, filled in by governance |
| `declared_at` | when, filled in by governance |

A person sees their own declarations, every detach and every putting back of a source whose
own `share` names one of their groups, and every putting back on a target they declared
(6.5).

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

Each person who wrote a target declares their own candidates; until they do, their files carry
everything they brought in. A person's `lineage` holds only their own sessions, and only the
person who made a read can say whether they used it. This is in-toto's model: each
functionary signs the link for the step they ran, and a product verifies only with every
step's link. Rejected: one person declaring for every writer, which would show them the
other writers' reads (some naming datasets they may not see) and have them vouch for reads
they did not make; and one writer per output, which stops a group working on a shared output.

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
INSERT INTO governance.derivations (source, source_type, target, used)
SELECT DISTINCT source, source_type, target, true
FROM governance.lineage WHERE target = 'lakehouse.db.joined';
```

One dataset was not used:

```sql
INSERT INTO governance.derivations (source, source_type, target, used)
SELECT DISTINCT source, source_type, target, source <> 'lakehouse.db.weather'
FROM governance.lineage WHERE target = 'lakehouse.db.joined';
```

The same, plus a file from a collaborator:

```sql
INSERT INTO governance.derivations (source, source_type, target, used)
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
INSERT INTO governance.derivations (source, source_type, target, used) VALUES
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

Agreed 2026-10-22 and built (section 10, items 11 to 13): rules 1 to 3, declarations naming an
arrived-through source, the `detach` grant and OPA's rules (`opa/derivations.rego`), detaches
shown to the source's `share` holders, and putting a source back. A *source* of some data is a dataset whose own `read` grant
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
3. **Who may read a dataset**: a person in its own `read` grant who is also in the own `read`
   grant of every source carried by any file in its folder, through any of their groups.
   `share` follows the same rule, as `WHITEPAPER.md` 4.3 has both inherit, and so does
   `write`, for files as for tables (decided 2026-10-23): a file write credential cannot get
   or list, so without the cut someone who may not read a source would overwrite or delete
   files they cannot see and could not read back their own. A release past a source (6.7)
   counts as its `read` here.

This replaces `WHITEPAPER.md` 4.3's per-dataset `inputs`. A file's sources already include
everything upstream of it, so rule 3 needs no chain of inputs-of-inputs: it looks up each
source's own grant at decision time, and a grant change takes effect at the next decision
with nothing to recompute.

OPA applies rule 3, not governance (decided 2026-10-22). Governance's lookups return a
dataset's own grants and its carried sources, each with that source's own `read` and `share`
and whether a declaration says it was used (`declared`) or it is there because a writer has
not declared yet. The rules in `opa/tables.rego` (`readable`, `writable`, `shares`) and
`opa/blob.rego` (`_reads`) do the cut, so how undeclared data is treated is policy: the shipped
rules treat an undeclared source like a declared one, and a deployment can, for example,
require `declared` for someone who may describe a table but not read it. This reverses
`WHITEPAPER.md` 4.3's "OPA receives only effective sets", whose reason, keeping the chain of
inputs out of Rego, is gone. The rule checks people, not groups: the whitepaper's formula
intersects group sets, which would refuse someone who reaches the dataset and a source
through different groups.

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
no file carrying it; Ceph's notifications, for `datasets/` and `warehouse/`, tell it when to
list again.

A commit or create the gate logged since the last listing counts as having written a file at
its time, since the gate logs it before Polaris sees it. A credential that can write, from the
broker or from Polaris, counts only for files a listing finds from its time, and governance
lists the folder again when it expires, in case a notification was lost. Counting a valid
credential as writing now was built first and dropped: it held a dataset to everything its
writer read for as long as the credential lasted, up to an hour for Polaris's, cleaning
included, and it protected only the seconds before the listing a write's notification
triggers. Anyone holding a credential reads new files in the folder until it expires whatever
governance knows, as with any grant change.

A table write counts only where it can write (decided 2026-10-24). The gate logs each table
credential with the folder it is scoped to, and a staged create's commit with the location it
sets; a write counts toward a table if it names no location, the table's folder, or a location
a commit the gate logged for the table names. Creating a table with `CREATE TABLE … AS SELECT`
stages it at a new folder each attempt, and an attempt refused before its commit leaves a
credential for a folder the table is never created at: counted, it held the table to that
attempt's session for the credential's hour and refused every later attempt. A table whose
creation report the gate failed to deliver has no folder in its entry; its creating commit's
location still counts, so attribution stays closed. A create is therefore not refused for the
sources its own attempt brings in: the table is created, and rule 3 cuts it once a listing
finds its files.

### 6.3 What a declaration covers

A person's declaration of a target covers their files in it that no earlier declaration of
theirs covered. It gives a `used` value to each dataset they read directly before those
files, as `lineage` lists them, and may name a source that arrived through one of those reads
to mark it unused. The files it covers do not carry a source it marks unused. Marking an
arrived-through source unused detaches it (6.5).

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

Trino refuses to expire versions younger than its catalog's minimum, seven days by default;
`trino/etc/catalog/iceberg.properties` sets `iceberg.expire-snapshots.min-retention` and
`iceberg.remove-orphan-files.min-retention` to `0s`. The restriction lifts as soon as the
declaration is stored, the old files being gone.

Once the declaration is accepted, the files it covers no longer carry the source and rule 3
stops counting it. Planned and dropped: refusing the declaration while files from the source
remain, with a message naming step 3's statements. A file is attributed by when it was
written, and both the cleaner's old files and the rewrite come after they read the dataset,
so the time cannot tell them apart; a declaration made before the old files are gone is
accepted, and if they still hold the source's data it is a false claim by its declarer.

### 6.5 Detaching a source

Decided 2026-10-22. Detaching states that the data a declaration covers no longer holds a
source's data. Nobody can check that, and a false one lets data derived from the source reach
people outside its `read` grant, so it is controlled by authority given ahead of time and by
a record, not by approval each time.

- **A sixth grant, `detach`,** on every dataset: the groups whose members may detach it from
  data derived from it. The name was chosen over `purge`, which Polaris and Spark already use
  for dropping a table with its files.
- **OPA decides every source a declaration marks unused,** with one rule that receives each
  source and whether it was read directly or arrived through a read. The shipped policy is
  permissive: a direct read may always be marked unused, and an arrived-through source may be
  detached by anyone who wrote the data while the source's `detach` is empty, and by its
  members once the source's owners fill it. A deployment tightens this by editing the rule,
  with no change to governance: strict everywhere, only a `curators` group, never for sources
  under a given root, or the declarer also holding `share` on the target.
- **Recorded and visible.** A detach is stored with its declarer and signed, as every
  declaration is, and everyone holding `share` on the source sees, in
  `governance.derivations`, every declaration by anyone that detaches it, including the
  target's id.
- **Reversible.** A `share` holder of the source can put it back by inserting a row that marks
  it used for that target; governance accepts that from them for a target the source was
  detached from, OPA deciding who holds `share` (`may_reattach`), and from then on the
  target's files carry it again. A putting back overrides every detach of that source from
  that target made before it; a detach made after it overrides it in turn, so a source's
  owners who want it to stay attached fill its `detach` grant. Data read in between has
  gone out, and the record names who said the data was clean.

Rejected: holding each detach until someone with `share` on the source approves it. The
approver cannot check the claim, which is about data they may not be allowed to read; the
data stays restricted until people outside the work respond; and a dataset carrying many
sources needs as many approvals. Authority given ahead of time is how Palantir Foundry handles
markings, whose administrators choose who may remove them, and how declassification
authority is delegated for classified documents.

### 6.6 Lifecycle of an output

Decided 2026-10-22: a write needs no declaration, and status does not wait for one.

- Registered `pending`, created as today: the gate admits a create for a registered pending
  table whose caller is in its `write`; a file dataset gets a write credential on `write`.
- `live` when it exists, as before: a table once the gate reports its creation, a file
  dataset once its folder holds a file. Listed under its `describe` grant, which no source
  cuts down, as `WHITEPAPER.md` 4.3 lets a derived dataset be listed for people who cannot see
  its inputs.
- Readable under rule 3 from its first write: until each writer declares, everything that
  writer brought in limits who may read it, so declaring is how a writer widens its readers.
- Rejected: holding an output `pending` until every writer has declared. Status decides only
  listing, so it would have hidden the dataset from the index and nothing more; making it
  decide reads too would add a step to every write, where rule 3 already limits who may read
  everything that could be in it.

### 6.7 Releasing a dataset past a source

Decided 2026-10-23. A release lets a group read a dataset built from a source although the
group may not read the source: the source's `share` holders approve that audience for that
dataset. Detaching says the source's data is not in the dataset; a release says it is, and the
source's owners consent. US handling of originator-controlled material has the same step: a
derivative product keeps the marking, and further dissemination needs the originator's
permission. A release is the second half of `share` (`WHITEPAPER.md` 4.2).

- **Two decisions, by different people.** The target's `share` holders choose who may see
  and read it, holding `share` on the target alone. A group they add that may not read a
  source stays blocked by rule 3 until that source's `share` holders release the target to
  it. This replaces the rule under which changing a dataset's `describe` or `read` also took
  `share` on every source.
- **Asking.** A release is requested for a target, a source and a group, by a `share` holder
  of the target, once the group is in the target's `read`, and only for a source the target's
  declarations mark used. Until its writers declare, a dataset carries everything they read,
  and owners of sources it never used would be asked.
- **Approving.** A `share` holder of the source approves or declines, shown the target's
  description, declared sources and writers. Each source consents separately: a target built
  from two sources the group may not read needs a release from each.
- **What it covers.** Under rule 3 the group passes that source's check on the target.
  Reading the target brings in the source marked with the release, so data built from the
  target carries the mark and the group may read that too. Data that took the source by
  another path is not covered and still needs the source's `read`.
- **It grants no `write`.** Write permission comes only from `write` grants. Rule 3 also checks
  sources when someone writes a dataset they hold `write` on, so that no one writes blind
  (rule 3 above), and there a release counts as it does for reading: a member of the group
  can write their own table built from the target although it carries the source. The group
  cannot release the target further.
- **Recorded, visible, withdrawable.** A release is stored with who requested and approved it
  and when, shown to the source's `share` holders, and withdrawn by any of them. A release
  stays when its approver later loses `share` on the source.
- **Withdrawing** works as losing `read` on the source does. At the next decision the target
  closes to the group, and so does everything built from it that people read only through
  the release, except a person's own copies in their private space (section 9), which stay
  theirs unless the source's owners add them to its `revoked`.
- **How it is carried.** A read records, for each source it brings in, the datasets the source
  arrived through on each path. Governance's lookups give OPA, for each source a dataset
  carries, the groups released past it on each path: releases on the dataset itself or on any
  dataset the path passed through. Rule 3 admits a person who may read the source or is in
  such a group on every path, so a release approved after a read still covers what that read
  produced.
- **Calls and tables.** `POST /releases {target, source, group}` asks,
  `POST /releases/<id>/approve` or `/decline` decides, `DELETE /releases/<id>` withdraws (a
  pending request also by whoever asked); grant changes are HTTP too (`PATCH /permissions`),
  as Trino's Iceberg connector refuses `GRANT`. `governance.releases` shows a person the
  releases they asked for and those on targets or past sources whose `share` they hold, and
  `governance.grants` the grants on every entry `governance.datasets` shows them, in Unity
  Catalog's column names. A declaration can also be posted as `POST /declarations`, checked by
  the same code as the insert.

## 7. What this enforces, decides, declares

Extending `WHITEPAPER.md` section 11:

**Enforced.** The candidate list is a superset of every input that came through the
platform: no credential without a record. Until declared, everything on that list limits who
may read the output. A declaration covers the list exactly.

**Decided by OPA.** Registration, grants and vends as before, and section 6's rule 3, from
the sources governance reports with each dataset.

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
- **Rule 3 needs each file's time.** Governance lists a dataset's folder on every storage
  notification for it and when a write credential for it expires; a large table is a long
  listing, and a bulk upload lists the folder once per object.
- **A file written with a credential counts once listed.** In the seconds between the write
  and the listing its notification triggers, a newly decided reader can be handed a
  credential to it, as anyone already holding one can read it until expiry.
- **A declaration covers a file from two seconds after it was written.** A listing gives
  last-modified times in whole seconds, rounded down, so governance leans the safe way: a
  read up to two seconds after a file's listed time counts toward it, and a declaration made
  sooner than two seconds after it covers it only at the person's next declaration.
- **A table file belongs to everyone who could write the table when it was written**,
  including a writer who only read the table then.
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

Decided 2026-10-23: scratch is per person. Each person has a default group with themselves
as its only member, which owns their private space (the personal space in
`docs/HANDOFF-2026-10-22-groups.md` section 1; its name in a UI is not settled, "My Data" is a
candidate). Each folder in it that the person writes into is an entry of its own, published
or not (the handoff's section 3), so what follows applies folder by folder.

- The person's own reads and writes in their private space are not cut by rule 3. They could
  read every source their files carry when they wrote them; losing `read` on a source later
  leaves them their own copies, as a download would. Everyone else is cut there as anywhere:
  whoever the person shares a folder with is held to its sources unless a release (6.7) covers
  them.
- A source's root owners can take a person's own copies back. Each source has `revoked`, a
  set of groups; for anyone in one of them the exemption does not apply to
  anything carrying that source, private space included. One person is named through their
  group of one. Additions are recorded with who made them and when, shown to the source's
  `share` holders, and reversible, as detaches are (6.5). Credentials already handed out last
  until they expire, and files the person downloaded are out of reach (section 8).
- The exemption is a rule in OPA. A deployment that wants losing `read` on a source to reach
  every copy derived from it, as Palantir Foundry's markings do, turns it off.

A shared folder would lock out any member who may not read a source another member's files
carry, which is why scratch is not shared.



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
11. Rules 1 to 3, run on the stack. `lakehouse.db.r1` registered readable by `jgi-writers` and
    `projw-team`; alice, in a fresh session, created it from literal values, and carol
    (`projw-team`) read it. Alice appended rows from `t1`, which only `jgi-writers` may read;
    `r1`'s files then carried `t1` and carol's `SELECT` answered "does not exist", while the
    lookup OPA gets showed `read` and `write` cut to `jgi-writers`. Cleaning: `DELETE` of the
    `t1` rows, `optimize`, `expire_snapshots` and `remove_orphan_files` left one data file
    and one version; alice declared `t1` unused. `r1` still carried `t1` through the write
    credential Polaris had handed alice at the create, valid for another 57 minutes, under a
    timing rule since dropped (6.2); with that credential marked expired in the access log
    (a test shortcut), carol read the one remaining row. Under the current rule, a table
    `z1` written after alice read `t1` was hidden from carol, and she read it right after
    alice declared `t1` unused, with alice's create credential still valid. A first version of the timing rule that also counted a writer's load
    credential before any listing made `t1` carry what alice read after loading it.
12. Detaching, run on the stack. alice appended `t1` rows to `r1` again, then in a new session
    copied it: `CREATE TABLE c1 AS SELECT * FROM r1`. `c1`'s lineage showed `r1` read
    directly and `t1` with `direct` false, and carol could not read `c1`. After the `t1` rows
    were deleted from `c1` and its old versions removed, a declaration marking `r1` used and
    `t1` unused was refused while `t1`'s `detach` named only `group-admins` ("you may not
    detach it: lakehouse.db.t1") and accepted once it also named `jgi-writers`, and before
    that while it was empty. With alice's write credentials for `c1` marked expired (the test
    shortcut), `c1` carried only `r1` and carol read it, while `r1` still carried `t1` and
    stayed hidden from her. `detach` is changed by root owners, as `share` is.
13. Showing and putting back detaches, run on the stack. alice copied `t1` into `x2`, then in
    another session `x2` into `y2`, and declared `y2` with `x2` used and `t1` detached.
    carol, given `share` on `t1`, saw that row in `governance.derivations` with
    `declared_by` alice; bob's putting back was refused ("you have not written it"), carol's
    was accepted, alice then saw carol's row on `y2`, and `y2` carried `t1` again. An insert
    naming `declared_by` was refused. The run found that listings round last-modified times
    down to the second: `y2`'s files, written a third of a second after alice's read of
    `x2`, looked older than the read, so `y2` carried nothing once the commit's own window
    passed. Comparisons now lean two seconds the safe way (section 8).
14. Rule 3 in OPA, run on the stack. alice, in a fresh session, read `t1` and created `z2`,
    readable by `jgi-writers` and `projw-team`. The lookup OPA gets showed `z2`'s own `read`
    with `t1` among its sources, `declared` false, and carol was refused; after alice declared
    `t1` used, `declared` was true and carol still refused; after she declared it unused,
    `z2` carried nothing and carol read it. alice's read of `t1`, `SHOW TABLES`, carol's
    index, a broker vend and `seed/check-index-narrowing.py` were as before. A syntax error
    in the lookup's query denied every read during the change, which is the fail-closed path
    working.
15. Releases, run on the stack 2026-10-24. alice built `rel1` from `t1`, readable by
    `jgi-writers` and `projw-team`; carol (`projw-team`) was refused it. A release request
    before declaring was refused ("declare lakehouse.db.rel1's sources first"); alice declared
    over `POST /declarations` and asked; carol could not decide it (no `share` on `t1`), alice
    approved, and carol read `rel1`. In a fresh session carol built `rel4` from `rel1` and read
    it. `rel3`, built by alice from `rel1` and from `t1` directly, stayed closed to carol, and
    the lookup showed `t1` on two paths, one released and one not. Holding `share` on `rel1`
    alone, carol added a group to its `read` and asked for a release for it. alice withdrew
    the release; carol lost `rel1` and `rel4`, alice kept `rel1`. carol could drop `rel4`,
    whose `delete` she held, only after giving her group `describe` on it, since Trino loads a
    table before dropping it. Found on the way: rule 3 must admit a release for writing as for
    reading, or carol could not build anything from what she was allowed to read; and test
    entries deleted from the registry instead of marked `gone` left reads that named them,
    and a source with no entry admits no one, so alice could not write until they were put
    back as `gone`.
16. Writes counted where they can write, run on the stack 2026-10-24. A credential planted for
    `relx1` at a folder no commit names, in carol's session that had read `t1` directly, still
    valid, no longer stopped carol creating `relx1` from a fresh session, and `relx1` carried
    nothing that session had read. The creating commit was logged with its location. With
    `relx1`'s folder blanked in its entry, as after a lost creation report, it carried the same
    sources. alice's `relx2` built from `t1` stayed closed to carol, and lineage paired it with
    `t1`.
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
   only undeclared files and naming arrived-through sources; the `detach` grant, OPA's rule for
   sources marked unused, detaches shown to the source's `share` holders and their putting a
   source back (6.5); `lineage`'s `direct` rows. All built: the sources each read brings in, writer credentials flagged by
   the gate, files attributed by listing, rule 3 in governance's lookups, notifications and
   listing extended to table folders, the `detach` grant and OPA's rule, declarations naming
   arrived-through sources, `lineage`'s `direct` column, the `declared_by` and `declared_at`
   columns with detaches shown to the source's `share` holders, and putting a source back.
3. The `sessions` lever as an insert.
4. Releases (6.7). Built 2026-10-24.

Section 13 of `WHITEPAPER.md`, the "inputs are trusted" statements in its sections 4.3, 10
and 11, and its section 4.2's list of grants, which gains `detach`, change when step 2 lands.
