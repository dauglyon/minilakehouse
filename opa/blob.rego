package lakehouse.blob

# Blob-plane access predicate (Phase 1, Flow C). The broker asks ONLY "may this subject
# read this named dataset?" → yes/no. There is NO path logic here: OPA is a predicate,
# never an enumerator. The broker already holds the dataset→prefix mapping (its registry)
# and binds the prefix into the vended credential's session policy itself.
#
# Input:  {subject, groups, action: "read", dataset: "<name>"}
# Output: allow = true|false
#
# Grants live in data.dataset_grants (opa/blob-data.json), published by governance.

import future.keywords.if
import future.keywords.in

default allow := false

# Granted directly to the subject.
allow if {
	input.dataset in object.get(data.dataset_grants.users, input.subject, [])
}

# Granted to one of the subject's groups. The broker can pass the user's REAL groups
# here because the client presented its own token (unlike the Polaris path, where Polaris
# filtered token groups against its grants).
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
	input.dataset in object.get(data.visibility_grants.users, input.subject, [])
}

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
	some g in input.groups
	g == "stewards"
}
