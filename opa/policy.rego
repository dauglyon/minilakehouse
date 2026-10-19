package polaris.authz

# Deny by default; five allow lanes:
#
#  1. root            — the internal admin principal (bootstrap, principal/grant mgmt).
#                       An external token's principal_name also lands here, so Keycloak
#                       must have no user named `root`.
#  2. read vend       — LOAD_TABLE_WITH_READ_DELEGATION hands out a read-only STS credential
#                       for a table's files; gated on a per-table read grant keyed by the
#                       real end-user principal.
#  3. view            — whether a table or view exists, and its metadata (columns,
#                       snapshots, storage location); gated on see or read for it, so a
#                       table can be viewed without being read. Writers may view any table.
#  4. catalog reads   — catalog, namespace and listing operations; any authenticated
#                       principal. Listings are not trimmed (the gate doesn't trim them
#                       yet), so table names are visible to everyone.
#  5. write / DDL ops — create/update/drop of tables, namespaces, views, and every
#                       write-delegation vend (a read-write credential) → "writers"
#                       only. Admin ops (principal/role/grant/catalog/policy/credential
#                       management) are in NO lane → root-only by default.
#
# Anything not named in a lane is denied for non-root (so bob — no grants, not a writer
# — cannot view or read a table, nor drop the catalog, nor create principals). Lanes 2, 3
# and 5 fetch their grants from governance per check (lakehouse.governance); the others
# fetch nothing.

import data.lakehouse.governance
import future.keywords.if
import future.keywords.in

default allow := false

# Lane 1 — internal admin.
allow if {
	input.actor.principal == "root"
}

# Lane 2 — read-credential vend, gated on a read grant for the target table.
allow if {
	input.action in _delegation_ops
	some t in input.resource.targets
	t.type == "TABLE_LIKE"
	input.actor.principal in governance.get(concat("/", ["/internal/tables", _fqn(t)])).read
}

# Lane 3 — view a table, gated on see or read for it, or on being a writer.
allow if {
	input.action in _view_ops
	some t in input.resource.targets
	t.type == "TABLE_LIKE"
	g := governance.get(concat("/", ["/internal/tables", _fqn(t)]))
	input.actor.principal in array.concat(g.see, g.read)
}

allow if {
	input.action in _view_ops
	input.actor.principal in governance.get("/internal/table-writers").writers
}

# Lane 4 — catalog-level reads.
allow if {
	input.action in _read_ops
}

# Lane 5 — data writes / DDL, for writers only.
allow if {
	input.action in _write_ops
	input.actor.principal in governance.get("/internal/table-writers").writers
}

# Loading an EXISTING table with a read-only credential is gated on that table's grant
# (lane 2). Write delegation vends a credential that can also put and delete the table's
# files, so it is a write (lane 5). Trino requests write delegation even for a SELECT;
# when that check denies, Polaris checks read delegation and vends a read-only credential.
_delegation_ops := {"LOAD_TABLE_WITH_READ_DELEGATION"}

_view_ops := {"LOAD_TABLE", "TABLE_EXISTS", "LOAD_VIEW", "VIEW_EXISTS"}

_read_ops := {
	"LIST_CATALOGS", "GET_CATALOG",
	"LIST_NAMESPACES", "LOAD_NAMESPACE_METADATA", "NAMESPACE_EXISTS",
	"LIST_TABLES", "LIST_VIEWS",
	"LIST_POLICY", "LOAD_POLICY",
	"GET_APPLICABLE_POLICIES_ON_CATALOG",
	"GET_APPLICABLE_POLICIES_ON_NAMESPACE",
	"GET_APPLICABLE_POLICIES_ON_TABLE",
	"REPORT_READ_METRICS", "REPORT_WRITE_METRICS",
}

# Table/namespace/view mutations and write-delegation vends (NOT principal/role/grant/
# catalog/policy/credential admin ops — those are root-only). CREATE_TABLE_*_WITH_WRITE_
# DELEGATION targets the NAMESPACE (the table doesn't exist yet), so it is a namespace write.
_write_ops := {
	"LOAD_TABLE_WITH_WRITE_DELEGATION",
	"CREATE_NAMESPACE", "DROP_NAMESPACE", "UPDATE_NAMESPACE_PROPERTIES",
	"CREATE_TABLE_DIRECT", "CREATE_TABLE_STAGED", "REGISTER_TABLE",
	"CREATE_TABLE_DIRECT_WITH_WRITE_DELEGATION", "CREATE_TABLE_STAGED_WITH_WRITE_DELEGATION",
	"DROP_TABLE_WITHOUT_PURGE", "DROP_TABLE_WITH_PURGE", "RENAME_TABLE",
	"UPDATE_TABLE", "UPDATE_TABLE_FOR_STAGED_CREATE", "COMMIT_TRANSACTION",
	"SET_TABLE_STATISTICS", "SET_TABLE_PROPERTIES", "SET_TABLE_LOCATION",
	"SET_TABLE_CURRENT_SCHEMA", "SET_TABLE_DEFAULT_SORT_ORDER", "SET_TABLE_SNAPSHOT_REF",
	"ADD_TABLE_SCHEMA", "ADD_TABLE_SNAPSHOT", "ADD_TABLE_PARTITION_SPEC", "ADD_TABLE_SORT_ORDER",
	"REMOVE_TABLE_PROPERTIES", "REMOVE_TABLE_SNAPSHOTS", "REMOVE_TABLE_SNAPSHOT_REF",
	"REMOVE_TABLE_STATISTICS", "REMOVE_TABLE_PARTITION_SPECS",
	"ASSIGN_TABLE_UUID", "UPGRADE_TABLE_FORMAT_VERSION",
	"CREATE_VIEW", "DROP_VIEW", "REPLACE_VIEW", "RENAME_VIEW",
}

# Table FQN "<ns...>.<table>", from the resource hierarchy Polaris sends. Built from ALL
# namespace levels in order, so a nested namespace (a.db.t1) yields one deterministic key —
# not multiple values, which would make this function conflict (eval error) at the vend.
_fqn(t) := concat(".", array.concat(
	[p.name | some p in t.parents; p.type == "NAMESPACE"],
	[t.name],
))
