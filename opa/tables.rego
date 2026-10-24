package lakehouse.tables

# Table and namespace rules, by group. Polaris's checks (polaris.authz) and the gate both decide
# with these, so a listing shows exactly what a load would allow. The names a person holds grants
# through and every table's grants come from governance (lakehouse.governance holder: `read` for
# describe and read, `write` for every other grant); Polaris sends only a name. Rules that
# governance asks about publishing and changing grants also get input.platform_admin, which
# passes wherever a steward does.
#
# A table has no grants of its own (docs/HANDOFF-2026-10-22-groups.md section 3): its entry's
# grants are the union of its namespace's, those of the namespaces above it and its space's
# defaults (the space of group g is the namespace <catalog>.g). A namespace published is one
# dataset of its tables; `published` on a table says one at or above it is.
#
# An id is "<catalog>.<namespace...>" for a namespace and "<catalog>.<namespace...>.<table>"
# for a table. polaris.authz._id builds it from Polaris's input and gate/app.py from the URL,
# request bodies and list responses; a name containing "." has no id and nothing allows it.
#
#   decide           input {subject, tables: [id], namespaces: [id]}
#                    gate, governance: {tables: [id], namespaces: [id]}, the ones the subject
#                    may view, and readable: [id], the tables they may read
#   allow_create     input {subject, id}   gate: may create this table or view
#   allow_write      input {subject, id}   governance: may declare what this table was derived
#                                          from (PROVENANCE.md 5.3)
#   load             input {subject, id, kind: table | view, credential, properties: {key: value}}
#                    gate, once per table request that hands out a credential or loads the
#                    metadata without one, and per view load or commit:
#                    {write, history, properties: [key]}
#   allow_namespace  input {subject, id}   gate: may create this namespace
#   allow_publish    input {subject, id, platform_admin}   governance: may publish this namespace
#   allow_transfer   input {subject, from: id, to: id}  governance: may record this table's move
#   allow_change     input {subject, id, grants: [grant], platform_admin}
#                                          governance: may change these grants on this namespace
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

# Creating a table or view: `write` on the namespace it goes in, which governance's entry for a
# table not created yet carries (status null), cut by rule 3 like any write.
default allow_create := false

allow_create if writable(governance.holder(input.subject), table(input.id))

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

# Creating a namespace: `write` on it, which the namespaces above it and its space grant.
default allow_namespace := false

allow_namespace if _holds(governance.holder(input.subject).write, namespace(input.id).write)

# Recording a table's move, as blob.rego's allow_transfer for folders: out of the subject's
# own personal space, or a plain group's space by its owners and admins, into the space of a
# group they are a member or above of, outside every published namespace.
default allow_transfer := false

allow_transfer if {
	h := governance.holder(input.subject)
	f := table(input.from)
	t := table(input.to)
	f.status == "live"
	t.status == "live"
	_may_send(h, f)
	t.space != f.space
	not startswith(t.space, "u_")
	concat("#", [t.space, "member"]) in h.write
	not t.published
}

_may_send(h, f) if f.space == h.personal

_may_send(h, f) if {
	not f.tenant
	concat("#", [f.space, "admin"]) in h.write
}

# Publishing a namespace: a steward of the group whose space holds it.
default allow_publish := false

allow_publish if _steward(namespace(input.id).space)

# Changing a namespace's grants (WHITEPAPER 4.4): `describe` and `read` by a group holding its
# `manage`; a group added that may not read a source of a table stays blocked by rule 3 until the
# source's `manage` holders release the table to it (PROVENANCE.md 6.7). `manage`, `write`,
# `delete` and `detach` by a steward of the group whose space holds it: `detach` decides how
# far its tables' protection follows their data (6.5), as `manage` does.
default allow_change := false

allow_change if {
	e := namespace(input.id)
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

_may_change(_, e, g) if {
	g in {"manage", "write", "delete", "detach", "revoked"}
	_steward(e.space)
}

# A steward of the space's group, or a platform admin.
_steward(_) if input.platform_admin == true

_steward(space) if concat("#", [space, "steward"]) in governance.groups(input.subject)

# The read API (governance GET /tables/<id>): the sources that refuse the subject this table,
# and which names in its read and write pass every source with all their holders.
blocking contains s.id if {
	h := governance.holder(input.subject)
	e := table(input.id)
	not sources_ok(h, e)
	some s in object.get(e, "sources", [])
	not source_admits(h.read, s)
}

effective_read contains n if {
	e := table(input.id)
	some n, names in input.holders
	sources_allow(names, e)
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
	sources_ok(h, e)
}

readable(h, e) if {
	_holds(h.write, e.write)
	sources_ok(h, e)
}

# Governance's dataset index offers OPA only tables some layer of whose describe, read or write
# names one of the person's groups (governance/app.py _index_rows); a change to what makes a
# table viewable changes that too. `describe` is not cut by sources (WHITEPAPER 4.3). A table in
# no published namespace is viewable only by those holding its `read` or `write`, whatever its
# `describe`, and by them even when rule 3 closes it (handoff section 3).
viewable(h, e) if readable(h, e)

viewable(h, e) if {
	e.published
	_holds(h.read, e.describe)
}

viewable(h, e) if {
	not e.published
	_holds(h.read, e.read)
}

viewable(h, e) if {
	not e.published
	_holds(h.write, e.write)
}

writable(h, e) if {
	_holds(h.write, e.write)
	sources_ok(h, e)
}

# Rule 3, and the personal-space exemption (PROVENANCE.md 9): a person's own reads and writes in
# their personal space are not cut by the sources its data carries, as their own downloads would
# not be, unless one of their groups is in a carried source's `revoked`. A deployment that wants
# losing `read` on a source to reach every copy derived from it drops the second clause. An
# entry that moved passes neither: it is read and written at its new id, and stays viewable and
# droppable, so the original of a moved table can be dropped.
sources_ok(h, e) if {
	object.get(e, "status", "") != "moved"
	sources_allow(h.read, e)
}

sources_ok(h, e) if {
	object.get(e, "status", "") != "moved"
	h.personal != ""
	e.space == h.personal
	not revoked(h, e)
}

revoked(h, e) if {
	some s in object.get(e, "sources", [])
	_holds(h.read, object.get(s, "revoked", []))
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

# A namespace: anyone holding describe, read or write on it, or on a namespace under it, so a
# person can reach what they were granted deeper down.
namespace_viewable(h, e) if _holds(h.read, array.concat(array.concat(e.describe, e.read), e.below))

namespace_viewable(h, e) if _holds(h.write, e.write)

namespace_writable(h, e) if _holds(h.write, e.write)

namespace_droppable(h, e) if _holds(h.write, e.delete)

table(id) := governance.get(concat("/", ["/internal/tables", urlquery.encode(id)]))

namespace(id) := governance.post("/internal/namespaces", {"ids": [id]}).entries[id]
