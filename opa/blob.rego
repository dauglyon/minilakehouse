package lakehouse.blob

# Blob-plane rules (Flows A and C, publishing and grant changes). Callers send the person's
# subject and the dataset or folder ids they name; the rules fetch the names the person holds
# grants through (lakehouse.governance holder) and the entries from governance. Rules governance
# asks about publishing and changing also get input.platform_admin, which passes wherever a
# steward does.
#
#   vend            input {subject, dataset: id}       broker: {allow, prefix} to read one folder
#   vend_write      input {subject, dataset: id}       broker: {allow, prefix} to write one folder
#   vend_delete     input {subject, dataset: id}       broker: {allow, prefix} to delete in one folder
#   discover        input {subject, datasets: [id]}    governance: {visible: [id], readable: [id]}
#   allow_publish   input {subject, dataset: id, platform_admin}
#                                                      governance: may publish this folder
#   allow_change    input {subject, dataset: id, grants: [grant], platform_admin}
#                                                      governance: may change these grants of a
#                                                      published dataset
#   allow_change_folder  input {subject, folder: id, grants: [grant], platform_admin}
#                                                      governance: may change these grants of a folder
#   blocking        input {subject, dataset: id}       governance's read API: the sources that
#                                                      refuse the subject this dataset
#   effective_read  input {dataset: id, holders: {name: [name]}}
#                                                      governance's read API: the names in its
#                                                      read all of whose holders pass every source
#
# An entry is a folder in a group's space (docs/HANDOFF-2026-10-22-groups.md sections 1 to 3):
# {id, prefix, tracked, published, space, inside_published, contains_published, sources, and
# describe, access (read), manage, write, detach, delete: [name]}, each grant the union of the
# folder's own when it is published, the folders' above it and its space's defaults. Governance
# answers for an untracked folder in a space too, which its first credential makes an entry. A
# dataset can be visible-but-not-readable: in `visible` and not in `readable`. An id with no
# entry is denied exactly as a dataset the caller has no grant on.

import data.lakehouse.governance
import data.lakehouse.tables
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# The broker scopes its session policy to the returned prefix: the entry's folder, which is the
# folder its grants were decided for. No credential reaches into a published dataset but its
# own, so a folder inside one or containing one gets none.
default vend := {"allow": false}

vend := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_reaches_no_other(e)
	_reads(e)
}

# Writing (WHITEPAPER 4.2): put and delete in the folder, granted by `write`; it implies neither
# `describe` nor `read`. Rule 3 cuts it as it cuts reading, as for tables: the credential cannot
# get or list, so someone who may not read a source the folder's files carry would otherwise
# overwrite or delete files they cannot see, and could not read back their own. A release past
# a source admits its group here as it does for reading (PROVENANCE.md 6.7).
default vend_write := {"allow": false}

vend_write := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_reaches_no_other(e)
	_holds(_holder.write, e.write)
	every s in object.get(e, "sources", []) {
		tables.source_admits(_holder.read, s)
	}
}

# Deleting (WHITEPAPER 4.2): list and delete in the folder, granted by `delete` and, like a
# table's `delete`, not cut by the sources its files carry. The credential reads and writes
# nothing, so data that has become unreadable to everyone can still be removed. Listing shows
# names, sizes, times and ETags (an MD5 of a single-part upload's contents).
default vend_delete := {"allow": false}

vend_delete := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_reaches_no_other(e)
	_holds(_holder.write, e.delete)
}

_reaches_no_other(e) if {
	count(e.inside_published) == 0
	count(e.contains_published) == 0
}

discover := {"visible": visible, "readable": readable}

# `read` implies `describe`: a dataset a group may read is listed for it. A folder not yet
# published is listed only to those holding its `read`, whatever its `describe` (handoff
# section 3), and to them even when rule 3 closes it. Governance's dataset index offers OPA
# only entries some layer of whose describe or read names one of the person's groups
# (governance/app.py _index_rows); a change to what makes a dataset visible changes that too.
visible contains id if {
	some id, e in _entries
	e.published
	_holds(_holder.read, e.describe)
}

visible contains id if {
	some id, e in _entries
	not e.published
	_holds(_holder.read, e.access)
}

visible contains id if {
	some id, e in _entries
	_reads(e)
}

readable contains id if {
	some id, e in _entries
	_reads(e)
}

# Publishing a folder: a steward of the group whose space holds it.
default allow_publish := false

allow_publish if _steward(_entries[input.dataset].space)

# Changing grants (WHITEPAPER 4.4): `describe` and `read` by a group holding `manage` on the
# dataset itself, sources being the business of releases (PROVENANCE.md 6.7); `manage`,
# `write`, `detach` and `delete` by a steward of the group whose space holds it: `detach` decides
# how far the dataset's protection follows its data (PROVENANCE.md 6.5), as `manage` does. A
# folder's grants are changed the same way, `manage` being the folder's and those above it.
default allow_change := false

allow_change if {
	e := _entries[input.dataset]
	count(input.grants) > 0
	every g in input.grants {
		_may_change(e, g)
	}
}

default allow_change_folder := false

allow_change_folder if {
	f := governance.post("/internal/folders", {"ids": [input.folder]}).entries[input.folder]
	count(input.grants) > 0
	every g in input.grants {
		_may_change(f, g)
	}
}

_may_change(e, g) if {
	g in {"describe", "read"}
	_holds(_holder.write, e.manage)
}

_may_change(e, g) if {
	g in {"manage", "write", "detach", "delete"}
	_steward(e.space)
}

# A steward of the space's group, or a platform admin.
_steward(_) if input.platform_admin == true

_steward(space) if concat("#", [space, "steward"]) in _holder.read

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

# {id: entry} for the ids named in the input that have one.
_entries := governance.post("/internal/datasets", {"ids": _ids}).entries

_holder := governance.holder(input.subject)

# A dataset's `read` (stored as access), and every source its files carry (PROVENANCE.md 6,
# rule 3): governance lists each with its effective `read`, whether a declaration says it was
# used, and the groups releases let past it on each path it arrived by; the shipped rule treats
# an undeclared source like a declared one, as tables.rego does.
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
