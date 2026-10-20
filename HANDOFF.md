# Handoff — 2026-10-19

Outcome of a review comparing minilakehouse with BERDL (the stack it descends from) and Apache
Gravitino. `WHITEPAPER.md` is the target design; `DESIGN.md` describes the code. Nothing below
was run against the stack. Sources read:

- BERDL: `KBaseDataLakehouse/*` at origin `main` on 2026-10-19 (`minio_manager_service`,
  `trino_access_control`, `berdl_docs`, `spark_notebook`, and others).
- Apache Gravitino: `main` docs and source, checked against release v1.3.1.
- Apache Polaris 1.5.0 source (the version pinned in `.env`; the latest release is 1.8.0).
- Trino 476 and 484 source; Apache Iceberg 1.9.1 and 1.12.0 source (the versions those Trinos
  bundle).

## Working tree

Updated later on 2026-10-19: the decisions below are implemented and run, uncommitted. The
June validating-shim work was discarded (a copy is at `/tmp/minilakehouse-june-shim.patch`
on the machine that did it). `idp-shim/` and `opa/config.yaml` are deleted; `seed/user_token.py`
is new. Run with `docker compose up -d --build --wait`; on a host where 18181 is taken, an
override remapping OPA's host port is needed.

## Decided

**Grants leave OPA's bundle.** Governance's Postgres holds the only copy. OPA receives the
dataset's entry as input and evaluates rules over it.

- Revised after implementation: callers send OPA only ids, and every rule, files included,
  fetches entries from governance with `http.send` (`opa/governance.rego`). Callers passing
  the entry was built first and dropped because Polaris cannot, which left tables on a
  second path.
- Registration and grant changes: governance locks the dataset's row, asks OPA, and writes. `WHITEPAPER.md:321` makes these governance-evaluated decisions; the only
  reason was that OPA's copy lags governance by a bundle poll (`:168`), and that copy no
  longer exists.
- A dataset's folder is fixed at registration, as a table's already is (set-location is
  root-only, §8). OPA's `vend` decision returns the registered folder; the broker builds the session policy from it.

Consequences:

- A grant change takes effect at the next decision. The remaining lag is credential lifetime.
- Every read calls governance, so `WHITEPAPER.md:273` ("Reading never calls governance")
  becomes false, and a governance outage denies every read.
- The bundle, its authenticated pull, and its bearer token are removed.
- Commit `6eb63dd` removed `GET /datasets/<name>` because it revealed which datasets exist,
  and made the broker derive the folder from the id to avoid a governance call. The new entry
  lookup must be reachable only by the broker, OPA, and governance, and the broker must give
  the same answer for an unknown dataset as for a denied one.

## Decided later: tables

**Tables: OPA fetches the entry from governance with `http.send`.** Implemented:
`opa/policy.rego` fetches `/internal/tables/<fqn>` and `/internal/table-writers`. Polaris builds OPA's input
itself (actor, action, resource) and cannot attach an entry. Polaris makes one synchronous OPA
call per authorization check with no decision cache
(`extensions/auth/opa/impl/.../OpaPolarisAuthorizer.java:202-231`); only checks whose rule
needs a grant fetch, and a one-table `SELECT` made one such check. The alternative, keeping table
grants in OPA, splits the grant store by kind.

**List trimming.** Trimming a listing needs the grants of every candidate. With grants out of
OPA, governance trims the list itself (written into `WHITEPAPER.md` §8; the gate is unbuilt).

## Identity through Trino

`WHITEPAPER.md` §6 already specifies the path: Trino authenticates the user's Keycloak JWT,
the user attaches the same token as the extra credential `token`, and Trino's Iceberg client
sends it to Polaris as the bearer with no token exchange. Confirmed from source for both Trino
versions:

- Trino copies every extra credential into the Iceberg catalog session
  (`plugin/trino-iceberg/.../rest/TrinoRestCatalog.java`, `convert`).
- Iceberg sends a `token` credential directly as the bearer
  (`core/.../rest/auth/OAuth2Manager.java`, `maybeCreateChildSession`).
- Extra credentials are not a field of Trino's serialized session
  (`core/trino-main/.../SessionRepresentation.java`), so they stay out of query info, where
  `--user` appears.

Corrections to §6:

- The catalog session cache key in 476 is user name plus source, not user name.
- In 484 the key also includes the query id, so each query opens a session with the user's
  current token. For queries shorter than the token's lifetime, §6's refresh-by-exchange is
  unnecessary. That refresh is §6's main unverified mechanism and the means by which the
  engine could keep a token alive. Pin 484.

Gravitino's Trino connector reads the same extra credential
(`trino-connector/.../GravitinoConnector.java:272`). Its docs say open-source Trino cannot
forward user tokens; that describes the coordinator populating the credential. A client
attaching it, as BERDL's Trino plugin already requires for `kbase_auth_token`, is untested
with Gravitino.

Tested on the stack: alice's query reaches OPA as `principal: alice`, bob's as `bob`; naming
another user is refused as impersonation; a query without the extra credential fails at a
Keycloak exchange (`client_not_found`). Trino's CLI refuses to send a token over plain HTTP,
so Trino now serves HTTPS on 8443 (host 18443) from a keystore the container generates.
Polaris 1.5 accepts Keycloak as issuer. Polaris's OPA input carries `roles: []`: the token's
groups do not reach table rules (`WHITEPAPER.md` §6, open decision §12.4).

## List filtering

Polaris 1.5 sends one decision per list operation and has no per-entry filter, which is why
the gate exists. Gravitino filters because it is the catalog: its Iceberg REST list handler
reads the whole namespace from its backend, filters each entry in-process, then paginates
(`iceberg/iceberg-rest-server/.../IcebergTableOperations.java:145-158, 747-767`). The gate can
use that order in place of §8's refill loop (`WHITEPAPER.md:324-327`): fetch every upstream
page, filter in one call, paginate with its own tokens. Whether Polaris 1.6–1.8 added
per-entry list filtering is unchecked; if one did, the gate shrinks.

## Polaris cost per table load

Read from 1.5.0 source; not measured. A JDBC catalog has the engine read the pointer from
Postgres and `metadata.json` from storage itself. Polaris adds, per table per query plan:

1. Bearer token validation.
2. Catalog, namespace and table resolution from Postgres. An entity cache exists
   (`polaris-core/.../InMemoryEntityCache.java`); whether it is on by default is unchecked.
3. One OPA HTTP call per authorization check (above).
4. Polaris reads `metadata.json` itself and returns it over HTTP
   (`runtime/service/.../IcebergCatalog.java:1480-1492`).
5. STS `AssumeRole` on a credential-cache miss. The key is catalog, locations and actions,
   not the user (`StorageCredentialCacheKey.java`;
   `INCLUDE_PRINCIPAL_NAME_IN_SUBSCOPED_CREDENTIAL` defaults to false), so users reading one
   table share a credential. An entry lives half the credential's lifetime, capped at 30
   minutes (`StorageCredentialCache.java:62-72`).

Data bytes move directly between engine and storage, so the cost is planning latency, not
throughput. It matters for many small queries or queries over many tables. Measured after
implementing `http.send`: a `SELECT` on one table made two OPA checks and one governance read.

## Comparison with Gravitino

Gaps that are unbuilt, not design: filtered listings, grant administration, write credentials
for files, production readiness (TLS, authenticated events, persistent notifications).

Where minilakehouse is ahead:

- A decision point any service can ask. Gravitino decides only inside its own API; its
  permissions API (`docs/open-api/permissions.yaml`) grants and revokes but has no
  "may U do X on O" endpoint.
- File access enforced by storage with unmodified S3 clients. Gravitino governs files through
  GVFS, a client filesystem library that resolves a fileset name to its location and
  optionally fetches vended credentials. The check runs in the client and enforces nothing
  unless vending is on (`fs.gravitino.enableCredentialVending` defaults to false), and only
  Hadoop and fsspec clients use it.
- Visible-but-not-readable files (built). No see-only privilege appears in the parts of
  Gravitino's privilege tables read; not ruled out.
- Grants inherited through derived datasets (`WHITEPAPER.md` §4.3; unbuilt). Gravitino's
  lineage docs cover capture only.

## BERDL facts for `WHITEPAPER.md` §2

§2 (`:60-63`) leaves the list of services that decide dataset access unwritten. In BERDL:

1. The object store (MinIO or Ceph RGW) enforces per-user IAM policies written by the
   governance service (`minio_manager_service`).
2. Polaris grants decide catalog read and write; tenant readers get read on the whole catalog
   (`src/polaris/polaris_service.py:590-632`). Catalogs are created with `stsUnavailable`, so
   Spark reads table files with the user's static key.
3. The Trino plugin (`trino_access_control`) decides catalog and schema visibility by calling
   governance with the user's KBase token. Trino reaches Polaris as one global principal.

The governance service also decides who may administer tenants. Unread: `datalake-mcp-server`
and `spark_connect_proxy`, either of which may decide access itself.

## Next steps

Done: every design and code step listed here before; the gate (listings, not-found,
isolation, creation checks, create/drop reports); group membership moved from Keycloak to
governance, with tables registered as entries granted `see`/`read`/`write`/`delete` by group;
a `delete` grant for drops. Open:

1. Polaris accounts: built, created on first use (governance `POST /principals/me`, as the
   create-only `provisioner`; the gate calls it before a person's first request). Planned:
   when a Polaris release includes the `external` credential mode (PR #5119, merged on main
   2026-09-24, not in 1.8.0), set `polaris.authentication.credential-mode=external`, pin that
   release, and remove the provisioner, the endpoint and the gate's call.
2. Client sessions past the 5-minute token: a login proxy in front of Trino that speaks
   Trino's external-authentication protocol and keeps each person's refresh token. Chosen,
   unbuilt.
3. Long queries: Trino's refresh works only while the user's Keycloak login session is
   active (idle 30 min by default; exchanges don't renew it), measured (`WHITEPAPER.md` §6).
4. No API to change group membership or grants; both change only in governance's database.

To check:

- Polaris 1.6–1.8 release notes for per-entry list filtering.
- `DESIGN.md:234-237` calls Polaris "the one open catalog" that hands the vend decision to an
  external policy; Lakekeeper's authorizer is pluggable and has not been checked.
- BERDL's MCP server and Spark Connect proxy.
