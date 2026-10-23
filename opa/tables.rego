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
#                    gate, governance: {tables: [id], namespaces: [id]}, the ones the subject
#                    may view, and readable: [id], the tables they may read
#   allow_create     input {subject, id}   gate: may create this table or view now
#   allow_write      input {subject, id}   governance: may declare what this table was derived
#                                          from (PROVENANCE.md 5.3)
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

decide := {"tables": tables, "namespaces": namespaces, "readable": readable_tables}

tables contains id if {
	gs := governance.groups(input.subject)
	some id, e in governance.post("/internal/tables", {"ids": input.tables}).entries
	viewable(gs, e)
}

readable_tables contains id if {
	gs := governance.groups(input.subject)
	some id, e in governance.post("/internal/tables", {"ids": input.tables}).entries
	readable(gs, e)
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

# Declaring what a table was derived from needs a group in its write grant.
default allow_write := false

allow_write if writable(governance.groups(input.subject), table(input.id))

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

# Changing grants (WHITEPAPER 4.4): `describe` and `read` by a group holding `share` on the table;
# `share`, `write`, `delete` and `detach` by a group owning its namespace, the ownership
# registration checks: `detach` decides how far the table's protection follows its data
# (PROVENANCE.md 6.5), as `share` does.
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
	g in {"describe", "read"}
	shares(gs, e)
}

_may_change(gs, _, g) if {
	g in {"share", "write", "delete", "detach"}
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

# A table's grants, and the sources its files carry (PROVENANCE.md 6, rule 3). Governance's
# entry lists each source with its own `read` and `share` grants and whether a declaration says
# it was used (`declared`), or it is there because a writer has not declared yet. The shipped
# rules treat both alike: a person may read or write the table only if they may also read every
# source, through any of their groups. A deployment changes how undeclared data is treated
# here, for example by requiring `s.declared` in viewable's describe clause. For tables, write
# implies read: writing an Iceberg table reads its metadata, and the credential Polaris vends
# for writing can read the files.
readable(groups, e) if {
	_holds(groups, array.concat(e.read, e.write))
	sources_allow(groups, e)
}

# Governance's dataset index offers OPA only tables whose describe, read or write names one of the
# person's groups (governance/app.py _index_rows); a change to what makes a table viewable
# changes that too. `describe` is not cut by sources (WHITEPAPER 4.3).
viewable(groups, e) if readable(groups, e)

viewable(groups, e) if _holds(groups, e.describe)

writable(groups, e) if {
	_holds(groups, e.write)
	sources_allow(groups, e)
}

shares(groups, e) if {
	_holds(groups, e.share)
	every s in object.get(e, "sources", []) {
		_holds(groups, s.share)
	}
}

sources_allow(groups, e) if {
	every s in object.get(e, "sources", []) {
		_holds(groups, s.read)
	}
}

_holds(groups, grant) if {
	some g in groups
	g in grant
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
