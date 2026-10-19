package lakehouse.blob

# Blob-plane rules (Flows A and C, and registration). Callers send the person's subject and
# groups and the dataset ids or prefix they name; the rules fetch entries and ownership from
# governance (lakehouse.governance), once per decision.
#
#   vend            input {subject, groups, dataset: id}       broker: {allow, prefix} for one dataset
#   discover        input {subject, groups, datasets: [id]}    governance: {visible: [id], readable: [id]}
#   allow_register  input {subject, groups, prefix}            governance: may register at prefix
#
# An entry is {id, prefix, visibility: [group], access: [group]}. A dataset can be
# visible-but-not-readable: in `visible` and not in `readable`. An unknown id has no entry,
# so it is denied exactly as a dataset the caller has no grant on.

import data.lakehouse.governance
import future.keywords.contains
import future.keywords.if
import future.keywords.in

# The broker scopes its session policy to the returned prefix: the folder the dataset was
# registered with, which is the folder its grants were written for.
default vend := {"allow": false}

vend := {"allow": true, "prefix": e.prefix} if {
	e := _entries[input.dataset]
	_reads(e)
}

discover := {"visible": visible, "readable": readable}

visible contains id if {
	some id, e in _entries
	some g in input.groups
	g in e.visibility
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
	"stewards" in input.groups
	owned := governance.get("/internal/register-grants")
	some g in input.groups
	some root in object.get(owned, g, [])
	startswith(input.prefix, root)
}

_ids := input.datasets if input.datasets
else := [input.dataset]

# {id: entry} for the ids named in the input that exist.
_entries := governance.post("/internal/datasets", {"ids": _ids}).entries

_reads(e) if {
	some g in input.groups
	g in e.access
}
