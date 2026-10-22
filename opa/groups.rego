package lakehouse.groups

# Group administration. A group's owners are groups; anyone in one of them may change the
# group's members and owners. Creating a group is reserved to `group-admins`, who name its
# first owners and assign top-level roots (blob.rego, tables.rego). Members, owners and the
# caller's groups come from governance.
#
#   allow_create  input {subject}         governance: may create a group
#   allow_change  input {subject, group}  governance: may change this group's members and owners

import data.lakehouse.governance
import future.keywords.if
import future.keywords.in

default allow_create := false

allow_create if admin(input.subject)

admin(subject) if "group-admins" in governance.groups(subject)

default allow_change := false

allow_change if {
	owners := governance.get(concat("/", ["/internal/group-owners", urlquery.encode(input.group)])).owners
	some g in governance.groups(input.subject)
	g in owners
}
