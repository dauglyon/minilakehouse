package lakehouse.blob

# Blob-plane access predicate (Flow C: blob datasets). The broker asks ONLY "may this subject
# read this named dataset?" → yes/no. There is NO path logic here: OPA is a predicate,
# never an enumerator. The broker resolves the dataset→prefix mapping (from governance) and
# binds the prefix into the vended credential's session policy itself.
#
# Input:  {subject, groups, action, dataset: "<name>"}
# Output: allow = true|false
#
# Grants are group-based and published by governance in data.dataset_grants.groups (the
# broker passes the user's REAL groups, since the client presented its own token).

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
	some g in input.groups
	input.dataset in object.get(data.dataset_grants.groups, g, [])
}

# --- Metadata-visibility plane (Flow A: discovery): "may S SEE this dataset exists?" ---
# A SEPARATE predicate over visibility_grants. A dataset can be visible-but-not-readable
# (visible == true, allow == false) — the see-but-not-read model. Discovery (governance)
# calls this per registry entry; OPA never enumerates.
default visible := false

visible if {
	some g in input.groups
	input.dataset in object.get(data.visibility_grants.groups, g, [])
}

# --- Governed ingest: "may S register a new dataset at input.prefix?" ---
# Two-part, single-sourced in OPA: the `stewards` group is the CAPABILITY to register at
# all, and register_grants.groups scopes WHERE — the prefix must sit under a root one of the
# caller's groups owns. So a steward can't claim another tenant's namespace.
default allow_register := false

allow_register if {
	"stewards" in input.groups
	some g in input.groups
	some root in object.get(data.register_grants.groups, g, [])
	startswith(input.prefix, root)
}
