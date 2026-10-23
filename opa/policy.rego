package polaris.authz

# Deny by default. Polaris sends the principal's name, the action and its targets; every rule
# but 1 and 5 fetches the principal's groups and the target's grants from governance
# (lakehouse.tables, lakehouse.governance). Lanes:
#
#  1. root            — the internal admin principal (bootstrap, principal/grant mgmt).
#                       `provisioner`, governance's internal principal, may create principals
#                       and nothing else. The gate refuses a Keycloak token naming either.
#  2. read vend       — LOAD_TABLE_WITH_READ_DELEGATION, a read-only STS credential for a
#                       table's files: read or write on it.
#  3. table view      — whether a table or view exists, and its metadata (columns, snapshots,
#                       storage location): describe, read or write on it, so a table can be viewed
#                       without being read.
#  4. namespace view  — whether a namespace exists, and its properties: its owners, and
#                       anyone who may view a table under it.
#  5. catalog reads   — the catalog, listings and metrics reports; any authenticated
#                       principal. The gate (gate/app.py) trims every listing with
#                       lakehouse.tables, so a listing shows only what lanes 3 and 4 allow.
#  6. create          — creating a table or view, and committing a staged create. Polaris
#                       names only the namespace, so the gate decides the name first
#                       (lakehouse.tables.allow_create); here the person must be able to view
#                       the namespace. Creating a namespace names only the catalog, so the gate
#                       decides it (allow_namespace) and any authenticated principal passes.
#  7. table writes    — updates and commits, and every write-delegation vend (a read-write
#                       credential): write on every target.
#  8. drop            — dropping a table or view, with or without purging its files: delete on
#                       it. Not implied by any other grant.
#  9. namespace admin — dropping a namespace or changing its properties: its owners.
#
# Anything not named in a lane is root-only: admin operations (principals, roles, grants,
# catalogs, policies, credentials), and renaming, registering or relocating a table, since
# each would let a table take another table's id or folder.

import data.lakehouse.governance
import data.lakehouse.tables
import future.keywords.every
import future.keywords.if
import future.keywords.in

default allow := false

# `provisioner` passes no lane: it may create principals and nothing else.
allow if {
	input.actor.principal != "provisioner"
	_allow
}

allow if {
	input.actor.principal == "provisioner"
	input.action == "CREATE_PRINCIPAL"
}

# Lane 1 — internal admin.
_allow if {
	input.actor.principal == "root"
}

# Lane 2 — read-credential vend.
_allow if {
	input.action == "LOAD_TABLE_WITH_READ_DELEGATION"
	_tables_pass("read")
}

# Lane 3 — view a table or view.
_allow if {
	input.action in _view_ops
	_tables_pass("view")
}

# Lane 4 — view a namespace.
_allow if {
	input.action in _namespace_view_ops
	_namespaces_pass("view")
}

# Lane 5 — catalog-level reads.
_allow if {
	input.action in _read_ops
}

# Lane 6 — create; the gate has decided the name.
_allow if {
	input.action in _create_ops
	_namespaces_pass("view")
}

_allow if {
	input.action == "CREATE_NAMESPACE"
}

# Lane 7 — table writes.
_allow if {
	input.action in _write_ops
	_tables_pass("write")
}

# Lane 8 — drop.
_allow if {
	input.action in _drop_ops
	_tables_pass("delete")
}

# Lane 9 — namespace admin.
_allow if {
	input.action in _namespace_admin_ops
	_namespaces_pass("own")
}

# Every target is a table or view, and the principal's groups hold `grant` on its entry. An
# unregistered table has no entry, so nothing passes.
_tables_pass(grant) if {
	gs := governance.groups(input.actor.principal)
	count(input.resource.targets) > 0
	every t in input.resource.targets {
		t.type == "TABLE_LIKE"
		_table_holds(grant, gs, tables.table(_id(t)))
	}
}

_table_holds("read", gs, e) if tables.readable(gs, e)

_table_holds("view", gs, e) if tables.viewable(gs, e)

_table_holds("write", gs, e) if tables.writable(gs, e)

_table_holds("delete", gs, e) if tables.droppable(gs, e)

_namespaces_pass(grant) if {
	gs := governance.groups(input.actor.principal)
	count(input.resource.targets) > 0
	every t in input.resource.targets {
		t.type == "NAMESPACE"
		_namespace_holds(grant, gs, tables.namespace(_id(t)))
	}
}

_namespace_holds("view", gs, e) if tables.namespace_viewable(gs, e)

_namespace_holds("own", gs, e) if tables.namespace_owned(gs, e)

_view_ops := {"LOAD_TABLE", "TABLE_EXISTS", "LOAD_VIEW", "VIEW_EXISTS"}

_namespace_view_ops := {"LOAD_NAMESPACE_METADATA", "NAMESPACE_EXISTS"}

_read_ops := {
	"LIST_CATALOGS", "GET_CATALOG",
	"LIST_NAMESPACES", "LIST_TABLES", "LIST_VIEWS",
	"LIST_POLICY", "LOAD_POLICY",
	"GET_APPLICABLE_POLICIES_ON_CATALOG",
	"GET_APPLICABLE_POLICIES_ON_NAMESPACE",
	"GET_APPLICABLE_POLICIES_ON_TABLE",
	"REPORT_READ_METRICS", "REPORT_WRITE_METRICS",
}

# Polaris authorizes these against the NAMESPACE: the table does not exist yet.
_create_ops := {
	"CREATE_TABLE_DIRECT", "CREATE_TABLE_STAGED",
	"CREATE_TABLE_DIRECT_WITH_WRITE_DELEGATION", "CREATE_TABLE_STAGED_WITH_WRITE_DELEGATION",
	"UPDATE_TABLE_FOR_STAGED_CREATE", "CREATE_VIEW",
}

# Trino requests write delegation even for a SELECT; when that check denies, Polaris checks
# read delegation (lane 2) and vends a read-only credential.
_write_ops := {
	"LOAD_TABLE_WITH_WRITE_DELEGATION",
	"UPDATE_TABLE", "COMMIT_TRANSACTION",
	"SET_TABLE_STATISTICS", "SET_TABLE_PROPERTIES",
	"SET_TABLE_CURRENT_SCHEMA", "SET_TABLE_DEFAULT_SORT_ORDER", "SET_TABLE_SNAPSHOT_REF",
	"ADD_TABLE_SCHEMA", "ADD_TABLE_SNAPSHOT", "ADD_TABLE_PARTITION_SPEC", "ADD_TABLE_SORT_ORDER",
	"REMOVE_TABLE_PROPERTIES", "REMOVE_TABLE_SNAPSHOTS", "REMOVE_TABLE_SNAPSHOT_REF",
	"REMOVE_TABLE_STATISTICS", "REMOVE_TABLE_PARTITION_SPECS",
	"ASSIGN_TABLE_UUID", "UPGRADE_TABLE_FORMAT_VERSION",
	"REPLACE_VIEW",
}

_drop_ops := {"DROP_TABLE_WITHOUT_PURGE", "DROP_TABLE_WITH_PURGE", "DROP_VIEW"}

_namespace_admin_ops := {"DROP_NAMESPACE", "UPDATE_NAMESPACE_PROPERTIES"}

# Table or namespace id "<catalog>.<ns...>[.<table>]", from the resource hierarchy Polaris
# sends: the catalog and every namespace level, in order. A target whose catalog, namespace
# or own name contains "." has no id and is denied, since otherwise one level named "a.b" and
# two levels "a", "b" would share an id. gate/app.py builds the same ids.
_id(t) := id if {
	parts := array.concat(
		[p.name | some p in t.parents; p.type in {"CATALOG", "NAMESPACE"}],
		[t.name],
	)
	every p in parts { not contains(p, ".") }
	id := concat(".", parts)
}
