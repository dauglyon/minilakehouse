# Provenance transactions: server-bounded inputs, attested use

This document describes a design that is not implemented. Section 10 lists what was run
against the stack on 2026-10-22 and what each run showed; everything else is design. It
extends `WHITEPAPER.md`, whose derivation rule (section 4.3) consumes each dataset's `inputs`.

## 1. Purpose

The whitepaper takes a derived dataset's `inputs` from the publisher and trusts them
(`WHITEPAPER.md` 4.3, 10, 11). A publisher who omits an input defeats the derivation rule, and
the only control is who may register. Section 10 rejects verifying inputs because that would
require engine lineage, which requires trusting the engine.

This design is the third option. The server records every dataset a person's work obtained a
credential for, and before an output is published the publisher declares, per candidate,
whether it was used. The publisher can subtract from a list the server built and can add
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
| W3C PROV | `used`, `wasGeneratedBy`, `wasDerivedFrom` are the record's vocabulary. The table names in section 5 follow it. | A vocabulary, not a mechanism. |
| SLSA provenance, OpenLineage, Unity Catalog lineage | Inputs recorded per output. | Emitted by a trusted builder or engine. Rejected by the whitepaper and here. |
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
(`WHITEPAPER.md` section 6). An orchestrator that starts many agents gives each its own login
and inserts a session name as each agent's first statement, so each agent's work is its own
session. Whether Keycloak gives each client-credentials grant its own `sid` is unverified.

What a session is not: an environment or a login. Two environments can work in one session;
one environment can move through several. Data that stays in an environment across a session
boundary is out-of-band carry-over, section 8, the same as a download.

## 4. Capture

### 4.1 The vend log

Governance holds one row per credential issued: person, Keycloak subject, `sid`, session,
dataset id, kind, `read` or `write`, issued, expires. Two writers:

- The broker, for every file vend (`broker/app.py`, `vend`).
- The gate, for every table load answered with a storage credential, and for every table
  create and commit it forwards (`gate/app.py`, `proxy`).

Both record before they return the credential, and a failed record refuses the request. A
lost record would silently shorten a candidate list, which is the one failure the design
exists to prevent, so the record is synchronous and fail-closed. OPA decision logs were
considered and rejected: they are buffered and best-effort. Side effects inside Rego were
rejected: a rule may evaluate more than once per decision.

Each read decision already calls governance (`WHITEPAPER.md` section 8), so this adds one
more call on a path that is already coupled to governance's availability.

### 4.2 Which session wrote an object

An output's candidates come from the sessions that wrote it, so every write must be
attributed to a session.

**Tables.** Exact. Every create and commit passes through the gate with the person's token,
and the gate records it with the token's `sid`.

**Files.** A file write credential covers a folder, and governance never sees the bytes. It
learns that an object exists from the bucket notification, which carries the key, the time
to the microsecond, and a user identity. Two findings from the stack decide how that
identity is used (section 10):

- With the broker's current `AssumeRole`, the event names the broker. Ceph sets the event's
  user to the request owner, and for an assumed-role session the owner is the user that
  called `AssumeRole`. The role session name is kept only for policy conditions. This is
  Ceph's design, not configuration, and AWS differs.
- With `AssumeRoleWithWebIdentity`, the event names the person: `$oidc$<subject>`, the
  Keycloak subject. This holds only when the vending role and the registered OIDC provider
  belong to no RGW account; under an account the event names the account instead. RGW looks
  the provider up under the role's account, so an account-less role needs a provider created
  by an account-less user.

So the broker vends write credentials with `AssumeRoleWithWebIdentity`, passing a token for
the person, and governance attributes an object by joining the event's subject and time
against that person's write vends whose folder covers the key and whose issued-to-expires
window contains the event time, with a few seconds' tolerance for clock skew. One session
almost always. When two of a person's sessions held write credentials on the same folder at
that moment, both are attributed, which is a superset and still sound.

**The trust condition must name something only the broker can present.** RGW's STS endpoint
is the S3 endpoint, reachable by every client. If `blob-writer` trusted any token with the
broker's audience, a person could assume it directly with their own session policy, which
narrows only from the role's folder-wide rights, and write anywhere under `datasets/` with no
OPA decision. The broker therefore exchanges the person's token at Keycloak for one with an
audience only the broker's client may request, and the role's trust condition names that
audience. The subject is unchanged by the exchange, so the event still names the person.
Unverified: that Keycloak's standard token exchange, already enabled for the `trino` client
(`WHITEPAPER.md` section 6), can be restricted to the broker's client for that audience.

Read vends need no attribution and can stay on `AssumeRole`.

## 5. The tables

Three Iceberg tables in the `governance` namespace, which the gate already answers for
itself (`gate/app.py`, `index_answer`; `governance/index_table.py`). A load returns a table
governance builds in memory for the person, with a credential for governance's own S3-style
endpoint, which serves the files. Nothing is written to storage. Every client that speaks
the Iceberg REST catalog, Trino, Spark, pyiceberg, sees the same tables, so the catalog is
the whole interface and there is no governance API for the person.

### 5.1 `governance.sessions`

| column | meaning |
|---|---|
| `name` | the session's name |
| `started`, `last_used` | timestamps |
| `current` | true for the session this login points at |

`SELECT` lists the person's sessions. `INSERT` of a name is the lever of section 3.

### 5.2 `governance.accessed`

Read only. One row per dataset per session.

| column | meaning |
|---|---|
| `dataset` | the governed id, `lakehouse.db.t1` or `projx/public` |
| `kind` | `table` or `files` |
| `session` | the session the credential was stamped with |
| `first_access`, `last_access` | when credentials were issued |

With no filter, the rows of the current session. With `WHERE output = <id>`, the candidates
for that output: the rows of every session that wrote it, each cut at that session's last
write to it. That is how a later session declares something built earlier, and how an
output touched in two sessions gets both. An output is not its own candidate; a sibling
output of the same session is.

### 5.3 `governance.derivations`

Insert only. One row per output per candidate.

| column | meaning |
|---|---|
| `output` | id of a pending dataset the caller may write |
| `dataset` | a candidate's id, `*` for every candidate, or a hash for an external input |
| `kind` | `session` or `external`; optional, see below |
| `used` | boolean |

One `INSERT` is one commit is one attestation. Governance applies one rule to the commit as a
whole: for every output it names, the `session` rows must cover that output's candidates
exactly once, each marked used or unused; every `external` row carries a hash; the output is
`pending` and a caller group is in its `write`. On success governance stores the rows, signs
the record, and sets the output `live`. Otherwise the commit is refused with an Iceberg error
and nothing is stored; the person sees the reason as the statement's error.

`kind` left out means `session` for an id among the candidates and an error for anything
else, so a mistyped id is refused rather than recorded as an external input. A `*` row is
expanded to every candidate not named by another row, and the expansion is what is stored,
so the record is always explicit.

Governance recomputes the output's grants from the record as `WHITEPAPER.md` 4.3 specifies:
its `inputs` are the `session` rows marked used. `external` rows are recorded and shown and
take no part in the grant rule, since they have no entry. Until an output is declared it is
governed as if every candidate were an input, so its effective read is the intersection over
all of them; declaring can only widen.

### 5.4 Examples

All examples assume the current session's `accessed` holds `lakehouse.db.t1` (table),
`projx/public` (files) and `lakehouse.db.weather` (table).

Start or resume a session:

```sql
INSERT INTO governance.sessions (name) VALUES ('run7');
```

Everything was used:

```sql
INSERT INTO governance.derivations (output, dataset, used)
VALUES ('lakehouse.db.joined', '*', true);
```

One dataset was not used, written from the list:

```sql
INSERT INTO governance.derivations (output, dataset, used)
SELECT 'lakehouse.db.joined', dataset, dataset <> 'lakehouse.db.weather'
FROM governance.accessed;
```

The same, plus a file from a collaborator:

```sql
INSERT INTO governance.derivations (output, dataset, kind, used) VALUES
  ('lakehouse.db.joined', '*',                    'session',  true),
  ('lakehouse.db.joined', 'lakehouse.db.weather', 'session',  false),
  ('lakehouse.db.joined', 'sha256:9f3c…',         'external', true);
```

An output made in an earlier session, declared from this one:

```sql
SELECT dataset, kind, session FROM governance.accessed WHERE output = 'lakehouse.db.joined';
INSERT INTO governance.derivations (output, dataset, used)
SELECT 'lakehouse.db.joined', dataset, true
FROM governance.accessed WHERE output = 'lakehouse.db.joined';
```

Refused:

```
Query failed: Failed to commit: lakehouse.db.joined: not declared: projx/public, lakehouse.db.weather
Query failed: Failed to commit: lakehouse.db.other: not a pending dataset in your write grant
```

Looking back:

```sql
SELECT output, dataset, used FROM governance.derivations WHERE output = 'lakehouse.db.joined';
```

### 5.5 How an INSERT becomes the call

An Iceberg write from any client is three catalog steps. The gate sees all three for the
`governance` namespace:

1. Load the table with a write credential. Governance builds the person's current table in
   memory, as `index_table.build` does for the index, and returns its metadata and a
   credential bound to the person's prefix on governance's endpoint.
2. Put the data file, a manifest and a manifest list under the table's location. Trino's
   security mapping routes that bucket to governance (`trino/etc/s3-security-mapping.json`),
   whose S3 shim checks the signature and keeps the bytes in memory. The shim serves `GET`
   and `HEAD` today (`governance/app.py`, `index_object`) and must accept `PUT` and multipart
   uploads, since the engine decides how to write and a file grows with the list.
3. Commit: a requirement that the branch still points at the loaded snapshot, an
   `add-snapshot` naming the manifest list, a `set-snapshot-ref`. Governance follows the
   manifest list to the data files it holds, reads the rows with pyarrow, checks the
   requirement so a concurrent commit is refused the standard way, validates the rows as
   section 5.3 says, and in one Postgres transaction stores the record. The response is the
   person's table rebuilt from Postgres, so the next `SELECT` shows what was stored.

Nothing durable comes from the in-memory table. Postgres is the record; the Iceberg table is
a view of it that accepts writes.

Unverified: whether Trino's REST commit path accepts a response whose metadata does not
contain the snapshot it proposed. If it insists, governance appends the validated rows as that
snapshot instead of rebuilding. Also unverified: that a commit error body from the gate
surfaces its message through Trino's "Failed to commit" wrapper the way create refusals
already surface through "Failed to create transaction".

## 6. Lifecycle of an output

- Registered `pending`, created as today: the gate admits a create for a registered pending
  table whose caller is in its `write`; a file dataset gets a write credential on `write`.
- Written in one or more sessions. Each write is recorded with its session (4.2).
- Declared, from any session, by an `INSERT` into `derivations` naming it. Candidates come
  from its writing sessions, never from the declaring one.
- `live` on a successful declaration. Listed and readable per its recomputed grants.
- An output never declared stays `pending`: readable by its steward, listed for no one else.
- A later write to a live output by a new session adds that session's reads to the
  candidates; the next declaration must cover them. Whether a live output may be written
  without a fresh declaration is open (section 9).

## 7. What this enforces, decides, declares

Extending `WHITEPAPER.md` section 11:

**Enforced.** The candidate list is a superset of every input that came through the
platform: no credential without a record. An output is not `live` until declared. A
declaration covers the list exactly.

**Decided by OPA.** Nothing new. Registration, grants and vends are decided as before; the
recomputed grants of a declared output follow the whitepaper's rule.

**Declared and trusted.** Which candidates were used. External inputs. The content of any
dataset.

## 8. Limitations

- **Data outside the platform is invisible.** A file from a collaborator, a download from
  last month, or data left in an environment across a session boundary. The external row is
  the only cover, and omitting it is a false declaration by an identified person. Research
  environments that hold the data server-side close this; the platforms this design is
  meant for mostly will, not all.
- **Attribution of file writes is to a person, not a session.** The session comes from the
  time join. Two of a person's sessions writing one folder at once are both attributed.
- **A silent re-login after a timeout continues the last session.** Right when the
  environment is the same, wrong when a person starts unrelated work without inserting a
  session name. The cost is a longer list, never a shorter one.
- **A person who never names a session has one list that grows forever.** Long, not wrong.
- **Content is never checked.** Comparing an output's objects or rows against candidates
  declared unused would catch copies; it is out of scope.
- **Every write and read now calls governance.** A governance outage already denies every
  read; it now also denies every write.

## 9. Open

**Project folders.** A file written into a project folder is not a registered output, and
sharing it means it must become a dataset. Conclusions offered on 2026-10-22, not accepted:
a project folder is scratch, not a dataset; writing into it is not a share and reading it is
not an input, since the project group is the trust boundary; a scratch object's provenance is
its writing session's; publishing moves the objects into a new dataset's own folder, done by
governance, so no dataset is ever nested in another. Nesting was analysed and rejected: a
child's audience must stay a superset of its parent's forever, which the derivation rule can
break by narrowing; parent write credentials reach the child's bytes; reading one's own project
folder makes the project an input and caps the child's audience at the project's. Costs of
the move: governance needs a credential that copies within `datasets/*` and deletes under
scratch, and a publish of many objects can half-fail, which `pending` already expresses.

**Writes to a live output.** Whether a declared output may be written again without
returning to `pending`, and if so how the new session's reads reach a future declaration.

**Session lifetime settings.** With sessions decoupled from logins these are convenience: a
login that outlives Keycloak's session maximum forces a re-login mid-work, which the default
pointer absorbs. Setting the maximum to an environment's intended lifetime removes the
interruption. Whether offline sessions keep a stable `sid` is unverified.

**Service-account logins.** Whether each client-credentials grant carries its own `sid`.

**The broker's exchange audience.** Section 4.2's trust condition depends on Keycloak
restricting one audience to the broker's client.

## 10. Evidence and build order

Run on the stack on 2026-10-22, with a throwaway notification topic pointed at a sink
container, all artefacts removed afterwards:

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

Gotchas recorded on the way: RGW merges a put of the bucket notification configuration into
the existing one rather than replacing it, so removing an entry needs
`radosgw-admin notification rm`; roles and policies are removed with `role delete` and
`role-policy delete`.

Build order, each step usable on its own:

1. The vend log and the session pointer in governance; the broker and the gate recording
   fail-closed; `governance.sessions` and `governance.accessed` served read-only.
2. Write attribution: the OIDC provider registered in `ceph/sts-bootstrap.sh` by an
   account-less setup user; the broker's exchanged audience; `blob-writer` trusting it; the
   broker's write vend on `AssumeRoleWithWebIdentity`; the event join in governance.
3. `governance.derivations`: the S3 shim's `PUT` and multipart; commit parsing and
   validation; the recomputed grants; `pending` to `live` on declaration.
4. The `sessions` lever as an insert.

Section 13 of `WHITEPAPER.md` and the "inputs are trusted" statements in its sections 4.3,
10 and 11 change when step 3 lands.
