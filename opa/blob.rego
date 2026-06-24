package lakehouse.blob

# Blob-plane access predicate (Phase 1, Flow C). The broker asks ONLY "may this subject
# read this named dataset?" → yes/no. There is NO path logic here: OPA is a predicate,
# never an enumerator. The broker already holds the dataset→prefix mapping (its registry)
# and binds the prefix into the vended credential's session policy itself.
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

# --- Metadata-visibility plane (Phase 2, Flow A): "may S SEE this dataset exists?" ---
# A SEPARATE predicate over visibility_grants. A dataset can be visible-but-not-readable
# (visible == true, allow == false) — the see-but-not-read model. Discovery (governance)
# calls this per registry entry; OPA never enumerates.
default visible := false

visible if {
	some g in input.groups
	input.dataset in object.get(data.visibility_grants.groups, g, [])
}

# --- Governed ingest (Phase 3): "may S register a new dataset?" ---
# Register-at-ingest is authorized by OPA too (single-sourced policy), not hardcoded in
# governance. The steward CAPABILITY is group membership; the per-dataset `steward` field
# (who owns it) is recorded separately by governance. A stricter model would scope which
# prefixes a steward may claim — here any member of `stewards` may register.
default allow_register := false

allow_register if {
	"stewards" in input.groups
}
