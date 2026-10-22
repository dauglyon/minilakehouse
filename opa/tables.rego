package lakehouse.tables

# Table and namespace rules, by group. Polaris's checks (polaris.authz) and the gate both decide
# with these, so a listing shows exactly what a load would allow. A person's groups and every
# table's grants come from governance (lakehouse.governance); Polaris sends only a name.
#
# An id is "<catalog>.<namespace...>" for a namespace and "<catalog>.<namespace...>.<table>"
# for a table. polaris.authz._id builds it from Polaris's input and gate/app.py from the URL,
# request bodies and list responses; a name containing "." has no id and nothing allows it.
#
#   decide           input {subject, tables: [id], namespaces: [id]}
#                    gate: {tables: [id], namespaces: [id]}, the ones the subject may view
#   allow_create     input {subject, id}   gate: may create this table or view now
#   allow_namespace  input {subject, id}   gate: may create this namespace
#   allow_register   input {subject, id}   governance: may register this table
#   allow_change     input {subject, id, grants: [grant]}
#                                          governance: may change these grants on this table
#   allow_change_root  input {subject, id}  governance: may change who owns this namespace

import data.lakehouse.governance
import data.lakehouse.groups
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

decide := {"tables": tables, "namespaces": namespaces}

tables contains id if {
	gs := governance.groups(input.subject)
	some id, e in governance.post("/internal/tables", {"ids": input.tables}).entries
	viewable(gs, e)
}

namespaces contains id if {
	gs := governance.groups(input.subject)
	some id, e in governance.post("/internal/namespaces", {"ids": input.namespaces}).entries
	namespace_viewable(gs, e)
}

# Creating a table or view needs its entry registered first, still pending, with one of the
# person's groups in its write grant. Ids are never reused, so a dropped table stays gone.
default allow_create := false

allow_create if {
	e := table(input.id)
	e.status == "pending"
	writable(governance.groups(input.subject), e)
}

default allow_namespace := false

allow_namespace if {
	namespace_owned(governance.groups(input.subject), namespace(input.id))
}

default allow_register := false

allow_register if {
	gs := governance.groups(input.subject)
	"stewards" in gs
	namespace_owned(gs, namespace(_parent(input.id)))
}

# Changing grants (WHITEPAPER 4.4): `see` and `read` by a group holding `share` on the table;
# `share`, `write` and `delete` by a group owning its namespace, the ownership registration
# checks.
default allow_change := false

allow_change if {
	e := table(input.id)
	gs := governance.groups(input.subject)
	count(input.grants) > 0
	every g in input.grants {
		_may_change(gs, e, g)
	}
}

_may_change(gs, e, g) if {
	g in {"see", "read"}
	some x in gs
	x in e.share
}

_may_change(gs, _, g) if {
	g in {"share", "write", "delete"}
	namespace_owned(gs, namespace(_parent(input.id)))
}

# Changing who owns a namespace: `group-admins` for a top-level one (<catalog>.<namespace>),
# and anyone whose group owns that namespace or one above it, as for prefix roots (blob.rego).
default allow_change_root := false

allow_change_root if {
	groups.admin(input.subject)
	count(split(input.id, ".")) == 2
}

allow_change_root if namespace_owned(governance.groups(input.subject), namespace(input.id))

# The namespace holding a table: its id without the last name.
_parent(id) := concat(".", array.slice(parts, 0, count(parts) - 1)) if {
	parts := split(id, ".")
	count(parts) >= 3
}

# A table's grants. For tables, write implies read: writing an Iceberg table reads its
# metadata, and the credential Polaris vends for writing can read the files.
readable(groups, e) if {
	some g in groups
	g in array.concat(e.read, e.write)
}

viewable(groups, e) if {
	some g in groups
	g in array.concat(e.see, array.concat(e.read, e.write))
}

writable(groups, e) if {
	some g in groups
	g in e.write
}

droppable(groups, e) if {
	some g in groups
	g in e.delete
}

# A namespace: its owners, and anyone who may view some table under it.
namespace_viewable(groups, e) if {
	some g in groups
	g in array.concat(e.owners, e.viewers)
}

namespace_owned(groups, e) if {
	some g in groups
	g in e.owners
}

table(id) := governance.get(concat("/", ["/internal/tables", urlquery.encode(id)]))

namespace(id) := governance.post("/internal/namespaces", {"ids": [id]}).entries[id]
