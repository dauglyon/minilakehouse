package lakehouse.governance

# The one way any rule gets grants. OPA holds none; every rule that needs a grant fetches it
# from governance's /internal lookups here, at decision time, so a grant change applies at
# the next decision. Callers send only who is asking and what they name.
#
# The result is the response body, or undefined on any failure (raise_error=false turns a
# transport error into a status code), so a rule that depends on it denies.

import future.keywords.if

get(path) := _send({"method": "GET", "url": _url(path), "headers": _auth})

# http.send serializes `body` as JSON but sets no Content-Type; governance needs it to parse.
post(path, body) := _send({
	"method": "POST", "url": _url(path), "body": body,
	"headers": object.union(_auth, {"Content-Type": "application/json"}),
})

_url(path) := concat("", [opa.runtime().env.GOVERNANCE_URL, path])

_auth := {"Authorization": concat(" ", ["Bearer", opa.runtime().env.ENTRY_TOKEN])}

_send(req) := resp.body if {
	resp := http.send(object.union(req, {"timeout": "2s", "raise_error": false}))
	resp.status_code == 200
}
