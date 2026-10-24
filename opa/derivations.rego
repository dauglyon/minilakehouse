package lakehouse.derivations

# Marking a source unused in a declaration (PROVENANCE.md 6.3, 6.5). Governance asks once per
# target with every source the declaration marks unused, whether the declarer read it directly
# or it arrived through one of their reads:
#
#   allowed   input {subject, target, sources: [{id, direct}]}   the ids that may be marked unused
#
# The shipped policy is permissive. A direct read may always be marked unused. A source that
# arrived through a read is detached, which its `detach` grant controls: anyone may detach it
# while the grant is empty, and only its members once the source's owners fill it. A deployment
# tightens either case here, with no change to governance. A source with no entry is refused.

import data.lakehouse.governance
import future.keywords.contains
import future.keywords.if
import future.keywords.in

allowed contains s.id if {
	some s in input.sources
	s.direct == true
}

allowed contains s.id if {
	some s in input.sources
	s.direct == false
	count(_entry(s.id).detach) == 0
}

allowed contains s.id if {
	some s in input.sources
	s.direct == false
	some g in governance.groups(input.subject)
	g in _entry(s.id).detach
}

# Putting back a detached source (6.5): a holder of the source's `share`.
#
#   may_reattach   input {subject, target, sources: [{id}]}   the ids the subject may put back
may_reattach contains s.id if {
	some s in input.sources
	some g in governance.groups(input.subject)
	g in _entry(s.id).share
}

# Approving, declining or withdrawing a release past a source (6.7): a holder of the source's
# `share`, as for putting a source back.
#
#   may_release   input {subject, sources: [{id}]}   the ids whose releases the subject decides
may_release contains s.id if {
	some s in input.sources
	some g in governance.groups(input.subject)
	g in _entry(s.id).share
}

_ids := [s.id | some s in input.sources]

_tables := governance.post("/internal/tables", {"ids": _ids}).entries

_datasets := governance.post("/internal/datasets", {"ids": _ids}).entries

_entry(id) := _tables[id]

_entry(id) := _datasets[id] if not _tables[id]
