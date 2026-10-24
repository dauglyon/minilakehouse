package lakehouse.blob

# Blob-plane rules (Flows A and C, and registration). Callers send the person's subject and
# the dataset ids or prefix they name; the rules fetch the names the person holds grants through
# (lakehouse.governance holder), the entries and ownership from governance. Rules governance
# asks about registering and changing also get input.platform_admin, which passes wherever a
# steward does.
#
#   vend            input {subject, dataset: id}       broker: {allow, prefix} to read one dataset
#   vend_write      input {subject, dataset: id}       broker: {allow, prefix} to write one dataset
#   vend_delete     input {subject, dataset: id}       broker: {allow, prefix} to delete in one dataset
#   discover        input {subject, datasets: [id]}    governance: {visible: [id], readable: [id]}
#   allow_register  input {subject, prefix, platform_admin}
#                                                      governance: may register at prefix
#   allow_change    input {subject, dataset: id, grants: [grant], platform_admin}
#                                                      governance: may change these grants
#   allow_change_root  input {subject, prefix, platform_admin}
#                                                      governance: may change who owns this root
#   blocking        input {subject, dataset: id}       governance's read API: the sources that
#                                                      refuse the subject this dataset
#   effective_read  input {dataset: id, holders: {name: [name]}}
#                                                      governance's read API: the names in its
#                                                      read all of whose holders pass every source
#
# An entry is {id, prefix, describe, access, manage, write, detach, delete: [group], sources}. A dataset can be
# visible-but-not-readable: in `visible` and not in `readable`. An unknown id has no entry,
# so it is denied exactly as a dataset the caller has no grant on.

import data.lakehouse.governance
import data.lakehouse.tables
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# The broker scopes its session policy to the returned prefix: the folder the dataset was
# registered with, which is the folder its grants were written for.
default vend := {"allow": false}

vend := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_reads(e)
}

# Writing (WHITEPAPER 4.2): put and delete in the dataset's folder, granted by `write`; it
# implies neither `describe` nor `read`. Rule 3 cuts it as it cuts reading, as for tables: the
# credential cannot get or list, so someone who may not read a source the folder's files carry
# would otherwise overwrite or delete files they cannot see, and could not read back their own.
# A release past a source admits its group here as it does for reading (PROVENANCE.md 6.7).
default vend_write := {"allow": false}

vend_write := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_holds(_holder.write, e.write)
	every s in object.get(e, "sources", []) {
		tables.source_admits(_holder.read, s)
	}
}

# Deleting (WHITEPAPER 4.2): list and delete in the dataset's folder, granted by `delete` and,
# like a table's `delete`, not cut by the sources its files carry. The credential reads and
# writes nothing, so data that has become unreadable to everyone can still be removed. Listing
# shows names, sizes, times and ETags (an MD5 of a single-part upload's contents).
default vend_delete := {"allow": false}

vend_delete := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_holds(_holder.write, e.delete)
}

discover := {"visible": visible, "readable": readable}

# `read` implies `describe`: a dataset a group may read is listed for it. Governance's dataset index
# offers OPA only entries whose describe or access names one of the person's groups
# (governance/app.py _index_rows); a change to what makes a dataset visible changes that too.
visible contains id if {
	some id, e in _entries
	_holds(_holder.read, e.describe)
}

visible contains id if {
	some id, e in _entries
	_reads(e)
}

readable contains id if {
	some id, e in _entries
	_reads(e)
}

# Governed ingest: a steward of a group owning a root above the prefix ({group: [prefix root]}),
# so a steward can't claim another tenant's folders.
default allow_register := false

allow_register if _steward_over(input.prefix)

# Changing grants (WHITEPAPER 4.4): `describe` and `read` by a group holding `manage` on the dataset
# itself, sources being the business of releases (PROVENANCE.md 6.7);
# `manage`, `write`, `detach` and `delete` by a steward of a group owning a root above its
# prefix, the ownership registration checks: `detach` decides how far the dataset's protection
# follows its data (PROVENANCE.md 6.5), as `manage` does.
default allow_change := false

allow_change if {
	e := _entries[input.dataset]
	count(input.grants) > 0
	every g in input.grants {
		_may_change(e, g)
	}
}

_may_change(e, g) if {
	g in {"describe", "read"}
	_holds(_holder.write, e.manage)
}

_may_change(e, g) if {
	g in {"manage", "write", "detach", "delete"}
	_steward_over(e.prefix)
}

# Changing who owns a prefix root: a steward of a group owning that root or one above it.
# Owning a root owns everything under it, so an owner can delegate part of its tree and can't
# be shut out of it. Platform admins assign top-level roots (datasets/<name>/).
default allow_change_root := false

allow_change_root if _steward_over(input.prefix)

_steward_over(_) if input.platform_admin == true

_steward_over(prefix) if {
	some g, roots in governance.get("/internal/register-grants")
	some root in roots
	startswith(prefix, root)
	concat("#", [g, "steward"]) in _holder.read
}

# The read API (governance GET /datasets/<id>): the sources that refuse the subject this
# dataset, and which names in its read pass every source with all their holders.
blocking contains s.id if {
	some s in object.get(_entries[input.dataset], "sources", [])
	not tables.source_admits(_holder.read, s)
}

effective_read contains n if {
	e := _entries[input.dataset]
	some n, names in input.holders
	every s in object.get(e, "sources", []) {
		tables.source_admits(names, s)
	}
}

_ids := input.datasets if input.datasets
else := [input.dataset]

# {id: entry} for the ids named in the input that exist.
_entries := governance.post("/internal/datasets", {"ids": _ids}).entries

_holder := governance.holder(input.subject)

# A dataset's `read` (stored as access), and every source its files carry (PROVENANCE.md 6,
# rule 3): governance lists each with its own grants, whether a declaration says it was used,
# and the groups releases let past it on each path it arrived by; the shipped rule treats an
# undeclared source like a declared one, as tables.rego does.
_reads(e) if {
	_holds(_holder.read, e.access)
	every s in object.get(e, "sources", []) {
		tables.source_admits(_holder.read, s)
	}
}

_holds(names, grant) if {
	some g in names
	g in grant
}
