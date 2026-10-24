package lakehouse.tables

# Table and namespace rules, by group. Polaris's checks (polaris.authz) and the gate both decide
# with these, so a listing shows exactly what a load would allow. The names a person holds grants
# through and every table's grants come from governance (lakehouse.governance holder: `read` for
# describe and read, `write` for every other grant); Polaris sends only a name. Rules that
# governance asks about registering and changing grants also get input.platform_admin, which
# passes wherever a steward does.
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
#   load             input {subject, id, kind: table | view, credential, properties: {key: value}}
#                    gate, once per table request that hands out a credential or loads the
#                    metadata without one, and per view load or commit:
#                    {write, history, properties: [key]}
#   allow_namespace  input {subject, id}   gate: may create this namespace
#   allow_register   input {subject, id, platform_admin}   governance: may register this table
#   allow_change     input {subject, id, grants: [grant], platform_admin}
#                                          governance: may change these grants on this table
#   allow_change_root  input {subject, id, platform_admin}
#                                          governance: may change who owns this namespace
#   blocking         input {subject, id}   governance's read API: the sources that refuse the
#                                          subject this table
#   effective_read   input {id, holders: {name: [name]}}
#                                          governance's read API: the names in the table's read or
#                                          write all of whose holders pass every source

import data.lakehouse.governance
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

decide := {"tables": tables, "namespaces": namespaces, "readable": readable_tables}

tables contains id if {
	h := governance.holder(input.subject)
	some id, e in governance.post("/internal/tables", {"ids": input.tables}).entries
	viewable(h, e)
}

readable_tables contains id if {
	h := governance.holder(input.subject)
	some id, e in governance.post("/internal/tables", {"ids": input.tables}).entries
	readable(h, e)
}

namespaces contains id if {
	h := governance.holder(input.subject)
	some id, e in governance.post("/internal/namespaces", {"ids": input.namespaces}).entries
	namespace_viewable(h, e)
}

# Creating a table or view needs its entry registered first, still pending, with one of the
# person's groups in its write grant. Ids are never reused, so a dropped table stays gone.
default allow_create := false

allow_create if {
	e := table(input.id)
	e.status == "pending"
	writable(governance.holder(input.subject), e)
}

# Declaring what a table was derived from needs a group in its write grant.
default allow_write := false

allow_write if writable(governance.holder(input.subject), table(input.id))

# The gate's one decision on a table or view request, asked once Polaris has answered:
#   write       the credential handed out can write the table, so the access log counts its
#               lifetime as a time the person could have written files (PROVENANCE.md 6.2)
#   history     a load that hands out no credential, which is how a person with `describe`
#               but not `read` loads a table, returns the whole metadata. Otherwise it carries
#               the current version without its counts (gate/app.py current_only): the metadata
#               also holds every version with its time, row and file counts and Trino's name for
#               the writer, earlier schemas, and column statistics. A view (`kind` "view")
#               never comes with a credential, so for a view this decides who sees its earlier
#               versions, each with its query text (current_view_only).
#   properties  the property keys such a load keeps. Properties are whatever the table's writers
#               set: engine settings and a `comment` mostly, and also labels such as an owner's
#               name or a data-quality figure.
# The shipped rules give a view's history to those who may read or write it, as a table's
# readers and writers get its history with the credential they are handed, show a table's to
# nobody on a load without a credential, and keep every property. A deployment adds a
# `_load_history` clause, for example `readable(governance.holder(input.subject),
# table(input.id))` to show a table's history to readers whose client asked for no credential,
# or replaces `_load_properties`'s clause, for example with one keeping only keys that start
# with `write.`.
load := {"write": _load_write, "history": _load_history, "properties": _load_properties}

default _load_write := false

_load_write if {
	input.credential
	writable(governance.holder(input.subject), table(input.id))
}

default _load_history := false

_load_history if {
	input.kind == "view"
	readable(governance.holder(input.subject), table(input.id))
}

_load_properties contains k if some k, _ in input.properties

# A member or above of a group owning the namespace or one above it.
default allow_namespace := false

allow_namespace if {
	namespace_owned(governance.holder(input.subject).write, namespace(input.id))
}

# Registering a table: a steward of a group owning its namespace or one above it.
default allow_register := false

allow_register if _steward(namespace(_parent(input.id)).owners)

# Changing grants (WHITEPAPER 4.4): `describe` and `read` by a group holding `manage` on the table
# itself; a group added that may not read a source stays blocked by rule 3 until the source's
# `manage` holders release the table to it (PROVENANCE.md 6.7). `manage`, `write`, `delete` and
# `detach` by a steward of a group owning its namespace, the ownership registration checks:
# `detach` decides how far the table's protection follows its data (6.5), as `manage` does.
default allow_change := false

allow_change if {
	e := table(input.id)
	h := governance.holder(input.subject)
	count(input.grants) > 0
	every g in input.grants {
		_may_change(h, e, g)
	}
}

_may_change(h, e, g) if {
	g in {"describe", "read"}
	_holds(h.write, e.manage)
}

_may_change(_, _, g) if {
	g in {"manage", "write", "delete", "detach"}
	_steward(namespace(_parent(input.id)).owners)
}

# Changing who owns a namespace: a steward of a group owning it or one above it, as for prefix
# roots (blob.rego). Owning a namespace owns everything under it, so an owner can hand part of
# its tree to another group and can't be shut out of it. Platform admins assign top-level ones.
default allow_change_root := false

allow_change_root if _steward(namespace(input.id).owners)

# A steward of one of these groups, or a platform admin.
_steward(_) if input.platform_admin == true

_steward(owners) if {
	some g in owners
	concat("#", [g, "steward"]) in governance.groups(input.subject)
}

# The read API (governance GET /tables/<id>): the sources that refuse the subject this table,
# and which names in its read and write pass every source with all their holders.
blocking contains s.id if {
	h := governance.holder(input.subject)
	some s in object.get(table(input.id), "sources", [])
	not source_admits(h.read, s)
}

effective_read contains n if {
	e := table(input.id)
	some n, names in input.holders
	sources_allow(names, e)
}

# The namespace holding a table: its id without the last name.
_parent(id) := concat(".", array.slice(parts, 0, count(parts) - 1)) if {
	parts := split(id, ".")
	count(parts) >= 3
}

# A table's grants, and the sources its files carry (PROVENANCE.md 6, rule 3). Governance's
# entry lists each source with its own `read` grant, whether a declaration says it
# was used (`declared`) or it is there because a writer has not declared yet, and `released`:
# for each path the source arrived by, the groups a release lets past it (6.7). The shipped
# rules treat declared and undeclared alike: a person may read or write the table only if, for
# every source, they may read it or a release covers them on every path; writing needs it
# because a writer who could not read the table's data would be writing blind. A deployment
# changes how undeclared data
# is treated here, for example by requiring `s.declared` in viewable's describe clause. For
# tables, write implies read: writing an Iceberg table reads its metadata, and the credential
# Polaris vends for writing can read the files. A viewer of a group in `write` does not hold it,
# so does not read through it. `h` is governance.holder: `read` and `write` name lists.
readable(h, e) if {
	_holds(h.read, e.read)
	sources_allow(h.read, e)
}

readable(h, e) if {
	_holds(h.write, e.write)
	sources_allow(h.read, e)
}

# Governance's dataset index offers OPA only tables whose describe, read or write names one of the
# person's groups (governance/app.py _index_rows); a change to what makes a table viewable
# changes that too. `describe` is not cut by sources (WHITEPAPER 4.3).
viewable(h, e) if readable(h, e)

viewable(h, e) if _holds(h.read, e.describe)

writable(h, e) if {
	_holds(h.write, e.write)
	sources_allow(h.read, e)
}

sources_allow(groups, e) if {
	every s in object.get(e, "sources", []) {
		source_admits(groups, s)
	}
}

source_admits(groups, s) if _holds(groups, s.read)

source_admits(groups, s) if {
	released := object.get(s, "released", [])
	count(released) > 0
	every path in released {
		_holds(groups, path)
	}
}

_holds(groups, grant) if {
	some g in groups
	g in grant
}

droppable(h, e) if _holds(h.write, e.delete)

# A namespace: its owners, and anyone who may view some table under it.
namespace_viewable(h, e) if {
	some g in h.read
	g in array.concat(e.owners, e.viewers)
}

namespace_owned(groups, e) if {
	some g in groups
	g in e.owners
}

table(id) := governance.get(concat("/", ["/internal/tables", urlquery.encode(id)]))

namespace(id) := governance.post("/internal/namespaces", {"ids": [id]}).entries[id]
