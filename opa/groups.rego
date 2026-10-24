package lakehouse.groups

# Group administration (docs/HANDOFF-2026-10-22-groups.md section 1). A person holds one role in
# a group, owner, admin, member or viewer, and may also be its steward; the names they hold
# (`<g>#owner`, `<g>#admin`, `<g>#steward`) come from governance. Platform admins hold no role
# in any group: governance reads the Keycloak realm role `platform-admin` from the verified token
# and passes it as input.platform_admin, and they pass every check here.
#
#   allow_create   input {subject}                               may create a group
#   allow_change   input {subject, group, roles: [role], platform_admin}
#                                                                may add or remove people in these roles
#   allow_steward  input {subject, group, platform_admin}        may appoint or remove its stewards
#   allow_delete   input {subject, group, platform_admin}        may delete it
#   allow_view     input {subject, group, platform_admin}        may see its people

import data.lakehouse.governance
import future.keywords.every
import future.keywords.if
import future.keywords.in

# Anyone signed in; governance checks the name.
default allow_create := false

allow_create if is_string(input.subject)

# Owners change owners and admins; owners, admins and stewards change members and viewers.
default allow_change := false

allow_change if {
	count(input.roles) > 0
	every r in input.roles {
		_may_change(r)
	}
}

_may_change(r) if {
	r in {"owner", "admin"}
	_is("owner")
}

_may_change(r) if {
	r in {"member", "viewer"}
	some role in {"admin", "steward"}
	_is(role)
}

_may_change(_) if input.platform_admin == true

default allow_steward := false

allow_steward if input.platform_admin == true

default allow_delete := false

allow_delete if _is("owner")

allow_delete if input.platform_admin == true

# Its viewers and above: everyone in it holds the bare name.
default allow_view := false

allow_view if input.group in governance.groups(input.subject)

allow_view if input.platform_admin == true

# An owner also holds `<g>#admin`, so _is("admin") passes for owners too.
_is(role) if concat("#", [input.group, role]) in governance.groups(input.subject)
