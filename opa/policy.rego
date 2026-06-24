package polaris.authz

# Phase 0 policy (Stage C + M1 hardening). Deny by default; four allow lanes:
#
#  1. root            — the internal admin principal (bootstrap, principal/grant mgmt).
#                       NOT assertable via the engine (the idp-shim refuses sub=root).
#  2. credential vend — LOAD/CREATE table WITH_*_DELEGATION hands out an STS credential
#                       for a table's files; gated on a per-table grant keyed by the
#                       real end-user principal.
#  3. read-only ops   — metadata/listing; expose no bytes → any authenticated principal.
#  4. write / DDL ops — create/update/drop of tables, namespaces, views → "writers"
#                       only. Admin ops (principal/role/grant/catalog/policy/credential
#                       management) are in NO lane → root-only by default.
#
# Anything not named in a lane is denied for non-root (so bob — no grants, not a writer
# — cannot read data, nor drop the catalog, nor create principals). Grants + writers
# live in data (opa/data.json), published by governance, never copied into Polaris.

import future.keywords.if
import future.keywords.in

default allow := false

# Lane 1 — internal admin.
allow if {
	input.actor.principal == "root"
}

# Lane 2 — credential vend, gated on a read grant for the target table.
allow if {
	input.action in _delegation_ops
	some t in input.resource.targets
	t.type == "TABLE_LIKE"
	_granted(input.actor.principal, _fqn(t))
}

# Lane 3 — read-only / metadata operations.
allow if {
	input.action in _read_ops
}

# Lane 4 — data writes / DDL, for writers only.
allow if {
	input.action in _write_ops
	input.actor.principal in data.writers
}

# Loading an EXISTING table with a credential is gated on that table's grant (lane 2).
# Note CREATE_TABLE_*_WITH_WRITE_DELEGATION is NOT here: at create time the table does
# not exist yet, so Polaris's authz target is the NAMESPACE, not the table — there's no
# table grant to check. Creating-and-vending is a namespace write, so it lives in the
# writer lane (lane 4) below.
_delegation_ops := {"LOAD_TABLE_WITH_READ_DELEGATION", "LOAD_TABLE_WITH_WRITE_DELEGATION"}

_read_ops := {
	"LIST_CATALOGS", "GET_CATALOG",
	"LIST_NAMESPACES", "LOAD_NAMESPACE_METADATA", "NAMESPACE_EXISTS",
	"LIST_TABLES", "LOAD_TABLE", "TABLE_EXISTS",
	"LIST_VIEWS", "LOAD_VIEW", "VIEW_EXISTS",
	"LIST_POLICY", "LOAD_POLICY",
	"GET_APPLICABLE_POLICIES_ON_CATALOG",
	"GET_APPLICABLE_POLICIES_ON_NAMESPACE",
	"GET_APPLICABLE_POLICIES_ON_TABLE",
	"REPORT_READ_METRICS", "REPORT_WRITE_METRICS",
}

# Table/namespace/view mutations (NOT the *_WITH_*_DELEGATION ops — those are lane 2 —
# and NOT principal/role/grant/catalog/policy/credential admin ops — those are root-only).
_write_ops := {
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

# Table FQN = "<namespace>.<table>", read from the resource hierarchy Polaris sends.
_fqn(t) := sprintf("%s.%s", [ns, t.name]) if {
	some p in t.parents
	p.type == "NAMESPACE"
	ns := p.name
}

_granted(principal, tbl) if {
	tbl in object.get(data.grants, [principal, "read"], [])
}
