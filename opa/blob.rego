package lakehouse.blob

# Blob-plane rules (Flows A and C, and registration). Callers send the person's subject and
# the dataset ids or prefix they name; the rules fetch the person's groups, the entries and
# ownership from governance (lakehouse.governance).
#
#   vend            input {subject, dataset: id}       broker: {allow, prefix} to read one dataset
#   vend_write      input {subject, dataset: id}       broker: {allow, prefix} to write one dataset
#   vend_delete     input {subject, dataset: id}       broker: {allow, prefix} to delete in one dataset
#   discover        input {subject, datasets: [id]}    governance: {visible: [id], readable: [id]}
#   allow_register  input {subject, prefix}            governance: may register at prefix
#   allow_change    input {subject, dataset: id, grants: [grant]}
#                                                      governance: may change these grants
#   allow_change_root  input {subject, prefix}         governance: may change who owns this root
#
# An entry is {id, prefix, describe, access, share, write, detach, delete: [group], sources}. A dataset can be
# visible-but-not-readable: in `visible` and not in `readable`. An unknown id has no entry,
# so it is denied exactly as a dataset the caller has no grant on.

import data.lakehouse.governance
import data.lakehouse.groups
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
default vend_write := {"allow": false}

vend_write := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_holds(e.write)
	every s in object.get(e, "sources", []) {
		_holds(s.read)
	}
}

# Deleting (WHITEPAPER 4.2): list and delete in the dataset's folder, granted by `delete` and,
# like a table's `delete`, not cut by the sources its files carry. The credential reads and
# writes nothing, so data that has become unreadable to everyone can still be removed. Listing
# shows names, sizes, times and ETags (an MD5 of a single-part upload's contents).
default vend_delete := {"allow": false}

vend_delete := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_holds(e.delete)
}

discover := {"visible": visible, "readable": readable}

# `read` implies `describe`: a dataset a group may read is listed for it. Governance's dataset index
# offers OPA only entries whose describe or access names one of the person's groups
# (governance/app.py _index_rows); a change to what makes a dataset visible changes that too.
visible contains id if {
	some id, e in _entries
	_holds(e.describe)
}

visible contains id if {
	some id, e in _entries
	_reads(e)
}

readable contains id if {
	some id, e in _entries
	_reads(e)
}

# Governed ingest. The `stewards` group is the capability to register at all; ownership
# ({group: [prefix root]}) scopes where — the prefix must sit under a root one of the caller's
# groups owns, so a steward can't claim another tenant's namespace.
default allow_register := false

allow_register if {
	"stewards" in _groups
	_owns_root(input.prefix)
}

# Changing grants (WHITEPAPER 4.4): `describe` and `read` by a group holding `share` on the dataset;
# `share`, `write`, `detach` and `delete` by a group owning a root above its prefix, the
# ownership registration checks: `detach` decides how far the dataset's protection follows its
# data (PROVENANCE.md 6.5), as `share` does.
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
	_holds(e.share)
	every s in object.get(e, "sources", []) {
		_holds(s.share)
	}
}

_may_change(e, g) if {
	g in {"share", "write", "detach", "delete"}
	_owns_root(e.prefix)
}

# Changing who owns a prefix root: `group-admins` for a top-level root (datasets/<name>/), and
# anyone whose group owns that root or one above it. Owning a root owns everything under it,
# so an owner can delegate part of its tree and can't be shut out of it.
default allow_change_root := false

allow_change_root if {
	groups.admin(input.subject)
	count(split(trim_suffix(input.prefix, "/"), "/")) == 2
}

allow_change_root if _owns_root(input.prefix)

_owns_root(prefix) if {
	owned := governance.get("/internal/register-grants")
	some g in _groups
	some root in object.get(owned, g, [])
	startswith(prefix, root)
}

_ids := input.datasets if input.datasets
else := [input.dataset]

# {id: entry} for the ids named in the input that exist.
_entries := governance.post("/internal/datasets", {"ids": _ids}).entries

_groups := governance.groups(input.subject)

# A dataset's `read` (stored as access), and every source its files carry (PROVENANCE.md 6,
# rule 3): governance lists each with its own grants and whether a declaration says it was
# used; the shipped rule treats an undeclared source like a declared one.
_reads(e) if {
	_holds(e.access)
	every s in object.get(e, "sources", []) {
		_holds(s.read)
	}
}

_holds(grant) if {
	some g in _groups
	g in grant
}
