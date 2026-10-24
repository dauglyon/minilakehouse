package lakehouse.blob

# Blob-plane rules (Flows A and C, publishing and grant changes). Callers send the person's
# subject and the dataset or folder ids they name; the rules fetch the names the person holds
# grants through (lakehouse.governance holder) and the entries from governance. Rules governance
# asks about publishing and changing also get input.platform_admin, which passes wherever a
# steward does.
#
#   vend            input {subject, dataset: id, recursive}   broker: {allow, prefix} to read a folder
#   vend_write      input {subject, dataset: id, recursive}   broker: {allow, prefix} to write a folder
#   vend_delete     input {subject, dataset: id, recursive}   broker: {allow, prefix} to delete in a folder
#   discover        input {subject, datasets: [id]}    governance: {visible: [id], readable: [id]}
#   allow_publish   input {subject, dataset: id, platform_admin}
#                                                      governance: may publish this folder
#   allow_change    input {subject, dataset: id, grants: [grant], platform_admin}
#                                                      governance: may change these grants of a
#                                                      published dataset
#   allow_change_folder  input {subject, folder: id, grants: [grant], platform_admin}
#                                                      governance: may change these grants of a folder
#   allow_transfer  input {subject, from: id, to: id}  broker: may move this folder there
#   blocking        input {subject, dataset: id}       governance's read API: the sources that
#                                                      refuse the subject this dataset
#   effective_read  input {dataset: id, holders: {name: [name]}}
#                                                      governance's read API: the names in its
#                                                      read all of whose holders pass every source
#
# An entry is a folder in a group's space (docs/HANDOFF-2026-10-22-groups.md sections 1 to 3):
# {id, prefix, tracked, published, space, inside_published, contains_published, sources, and
# describe, access (read), manage, write, detach, delete: [name]}, each grant the union of the
# folder's own when it is published, those set on it and on the folders above it, and its
# space's defaults. Governance
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
# folder its grants were decided for. A credential covers everything under the folder unless
# `recursive` is false, when it covers the files directly in it, and the sources checked are
# those its files carry. No credential reaches into a published dataset but its own, so a folder
# inside one gets none and a folder containing one gets only a credential for its direct files;
# asked for a recursive one, someone the folder is otherwise open to is told so
# (recursive_refused), and the broker names the way round.
default vend := {"allow": false}

vend := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_reaches_no_other(e)
	_reads(e)
}

vend := {"allow": false, "recursive_refused": true} if {
	e := _entries[input.dataset]
	_only_recursion_refused(e)
	_reads(e)
}

# A folder that moved gets no credential (docs/HANDOFF-2026-10-22-groups.md section 1); the
# refusal names where it went to anyone who may describe the new entry, and is the ordinary
# refusal for everyone else.
vend := {"allow": false, "moved_to": e.moved_to} if {
	e := _entries[input.dataset]
	e.status == "moved"
	_describes(governance.post("/internal/datasets", {"ids": [e.moved_to]}).entries[e.moved_to])
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
	_writes(e)
}

vend_write := {"allow": false, "recursive_refused": true} if {
	e := _entries[input.dataset]
	_only_recursion_refused(e)
	_writes(e)
}

_writes(e) if {
	_holds(_holder.write, e.write)
	tables.sources_ok(_holder, e)
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

vend_delete := {"allow": false, "recursive_refused": true} if {
	e := _entries[input.dataset]
	_only_recursion_refused(e)
	_holds(_holder.write, e.delete)
}

_recursive := object.get(input, "recursive", true)

_reaches_no_other(e) if {
	_not_moved(e)
	count(e.inside_published) == 0
	not _recursive
}

_reaches_no_other(e) if {
	_not_moved(e)
	count(e.inside_published) == 0
	count(e.contains_published) == 0
}

_only_recursion_refused(e) if {
	_not_moved(e)
	count(e.inside_published) == 0
	_recursive
	count(e.contains_published) > 0
}

# A moved folder's old path, and every folder under it, stop working.
_not_moved(e) if {
	e.status != "moved"
	count(e.inside_moved) == 0
}

discover := {"visible": visible, "readable": readable}

# `read` implies `describe`: a dataset a group may read is listed for it. A folder not yet
# published is listed only to those holding its `read`, whatever its `describe` (handoff
# section 3), and to them even when rule 3 closes it. Governance's dataset index offers OPA
# only entries some layer of whose describe or read names one of the person's groups
# (governance/app.py _index_rows); a change to what makes a dataset visible changes that too.
visible contains id if {
	some id, e in _entries
	_describes(e)
}

_describes(e) if {
	e.published
	_holds(_holder.read, e.describe)
}

_describes(e) if {
	not e.published
	_holds(_holder.read, e.access)
}

_describes(e) if _reads(e)

readable contains id if {
	some id, e in _entries
	_reads(e)
}

# Moving a folder (docs/HANDOFF-2026-10-22-groups.md section 1): an unpublished folder, neither
# in nor holding a published dataset, so the move's credential reaches into none, out of the
# subject's own personal space, or out of a plain group's space by one of its owners or admins, into the
# space of a group the subject is a member or above of, other than a personal one, at a folder
# that is not published and neither sits in nor holds a published dataset: a move reaches no one
# beyond the receiving group, and publishing is a steward's act. Governance checks that the
# destination holds nothing yet.
default allow_transfer := false

allow_transfer if {
	f := _pair[input.from]
	t := _pair[input.to]
	f.tracked
	_not_moved(f)
	not f.published
	count(f.inside_published) == 0
	count(f.contains_published) == 0
	_may_send(f)
	t.space != f.space
	not startswith(t.space, "u_")
	concat("#", [t.space, "member"]) in _holder.write
	not t.published
	count(t.inside_published) == 0
	count(t.contains_published) == 0
}

_may_send(f) if f.space == _holder.personal

_may_send(f) if {
	not f.tenant
	concat("#", [f.space, "admin"]) in _holder.write
}

_pair := governance.post("/internal/datasets", {"ids": [input.from, input.to]}).entries

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
	g in {"manage", "write", "detach", "delete", "revoked"}
	_steward(e.space)
}

# A steward of the space's group, or a platform admin.
_steward(_) if input.platform_admin == true

_steward(space) if concat("#", [space, "steward"]) in _holder.read

# The read API (governance GET /datasets/<id>): the sources that refuse the subject this
# dataset, and which names in its read pass every source with all their holders.
blocking contains s.id if {
	e := _entries[input.dataset]
	not tables.sources_ok(_holder, e)
	some s in object.get(e, "sources", [])
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

# {id: entry} for the ids named in the input that have one, each with the sources of what a
# credential of the requested reach covers.
_entries := governance.post("/internal/datasets", {"ids": _ids, "recursive": _recursive}).entries

_holder := governance.holder(input.subject)

# A dataset's `read` (stored as access), and every source its files carry (PROVENANCE.md 6,
# rule 3): governance lists each with its effective `read` and `revoked`, whether a declaration
# says it was used, and the groups releases let past it on each path it arrived by; the shipped
# rule treats an undeclared source like a declared one, and exempts the person's own personal
# space, as tables.rego does (sources_ok).
_reads(e) if {
	_holds(_holder.read, e.access)
	tables.sources_ok(_holder, e)
}

_holds(names, grant) if {
	some g in names
	g in grant
}
