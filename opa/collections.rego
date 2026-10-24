package lakehouse.collections

# Collections (docs/HANDOFF-2026-10-22-groups.md section 5): published datasets and other
# collections, held by reference by a collection that belongs to a group. Its `describe` and
# `read` reach every member through nested collections; governance folds them into each
# member's grants, so the dataset rules decide about members unchanged. These rules decide
# about the collection itself. Rules governance asks about changes also get
# input.platform_admin, which passes wherever a steward does.
#
#   allow_create   input {subject, group, platform_admin}              may create one owned by this group
#   allow_write    input {subject, collection, platform_admin}         may change its description
#   allow_change   input {subject, collection, grants: [grant], platform_admin}
#                                                                      may change these grants
#   allow_add      input {subject, collection, member, kind, platform_admin}
#                                                                      may add this member
#   allow_remove   input {subject, collection, member, kind, platform_admin}
#                                                                      may remove this member
#   allow_delete   input {subject, collection}                         may delete it
#   discover       input {subject, collections: [id]}                  {visible: [id], readable: [id]}

import data.lakehouse.governance
import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

# A member or above of the group it will belong to.
default allow_create := false

allow_create if concat("#", [input.group, "member"]) in _holder.write

allow_create if input.platform_admin == true

# Curating it, its description and members: `write` on it.
default allow_write := false

allow_write if _holds(_holder.write, _collection.write)

# `describe` and `read` by its `manage` holders; `manage`, `write` and `delete` by the owning
# group's stewards.
default allow_change := false

allow_change if {
	count(input.grants) > 0
	every g in input.grants {
		_may_change(g)
	}
}

_may_change(g) if {
	g in {"describe", "read"}
	_holds(_holder.write, _collection.manage)
}

_may_change(g) if {
	g in {"manage", "write", "delete"}
	_steward(_collection.owner)
}

_steward(_) if input.platform_admin == true

_steward(group) if concat("#", [group, "steward"]) in _holder.read

# Adding: `write` on the collection and `manage` on what is added, whose holders so consent to
# it joining, and to the collection's own `manage` holders placing it in larger ones. Removing:
# either, so a member's `manage` holders can always take it out.
default allow_add := false

allow_add if {
	_holds(_holder.write, _collection.write)
	_manages_member
}

default allow_remove := false

allow_remove if _holds(_holder.write, _collection.write)

allow_remove if _manages_member

_manages_member if _holds(_holder.write, _member.manage)

_member := governance.post("/internal/datasets", {"ids": [input.member]}).entries[input.member] if input.kind == "files"

_member := governance.post("/internal/namespaces", {"ids": [input.member]}).entries[input.member] if input.kind == "namespace"

_member := governance.post("/internal/collections", {"ids": [input.member]}).entries[input.member] if input.kind == "collection"

default allow_delete := false

allow_delete if _holds(_holder.write, _collection.delete)

# `read` implies `describe`, as for datasets.
discover := {"visible": visible, "readable": readable}

visible contains id if {
	some id, e in _entries
	_holds(_holder.read, array.concat(e.describe, e.read))
}

readable contains id if {
	some id, e in _entries
	_holds(_holder.read, e.read)
}

_entries := governance.post("/internal/collections", {"ids": input.collections}).entries

_collection := governance.post("/internal/collections", {"ids": [input.collection]}).entries[input.collection]

_holder := governance.holder(input.subject)

_holds(names, grant) if {
	some g in names
	g in grant
}
