package lakehouse.governance

# The one way any rule gets grants or group membership. OPA holds neither; every rule that
# needs one fetches it from governance's /internal lookups here, at decision time, so a grant
# or membership change applies at the next decision. Callers send only who is asking and what
# they name.
#
# The result is the response body, or undefined on any failure (raise_error=false turns a
# transport error into a status code), so a rule that depends on it denies. Governance serves
# these lookups only to OPA's client certificate (governance/pki.py), read from files: unlike an
# environment variable, a file cannot be read back through OPA's query API.

import future.keywords.if

get(path) := _send({"method": "GET", "url": _url(path)})

# The names a person (subject or Polaris principal name) holds grants through: each group they
# are in, `<g>`, and their roles in it, `<g>#member`, `<g>#admin`, `<g>#owner`, `<g>#steward`
# (governance/app.py _group_names). `read` holds every name, for `describe` and `read`; `write`
# holds those of the groups they are more than a viewer in, for every other grant.
holder(subject) := {"read": r.groups, "write": r.write_groups} if {
	r := get(concat("/", ["/internal/groups", urlquery.encode(subject)]))
}

groups(subject) := holder(subject).read

# http.send serializes `body` as JSON but sets no Content-Type; governance needs it to parse.
post(path, body) := _send({
	"method": "POST", "url": _url(path), "body": body,
	"headers": {"Content-Type": "application/json"},
})

_url(path) := concat("", [opa.runtime().env.GOVERNANCE_URL, path])


_send(req) := resp.body if {
	resp := http.send(object.union(req, {
		"timeout": "2s", "raise_error": false,
		"tls_ca_cert_file": "/pki/ca.crt",
		"tls_client_cert_file": "/pki/client.crt",
		"tls_client_key_file": "/pki/client.key",
	}))
	resp.status_code == 200
}
