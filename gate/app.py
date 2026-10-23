"""
gate — the proxy in front of Polaris (WHITEPAPER.md §5). Polaris is reachable only through it.

1. It verifies the caller's Keycloak token (signature, issuer, expiry, audience) and reads the
   subject from it. Groups and grants live in governance; OPA fetches them.
2. Listings. Polaris authorizes a listing as one operation and returns every entry, so the
   gate fetches every upstream page, keeps the entries OPA's lakehouse.tables says the caller
   may view (one decision per listing), and pages the result with its own page tokens, so
   page sizes and tokens say nothing about hidden entries.
3. A refusal naming a table, view or namespace the caller may not view becomes not-found, so
   a refusal does not confirm that the name exists.
4. Trino asks for a storage credential on every table load, and Polaris refuses the whole
   load when neither credential check passes, so the gate repeats such a refused load once
   without the credential request. A person who may view a table but not read it can then
   DESCRIBE it; reading it fails at storage. A load that hands out no credential keeps only
   the current version, with no counts in it, and the properties OPA's lakehouse.tables.load
   keeps, unless that decision allows the whole metadata (current_only).
5. Creation. Polaris's own check for creating a table, committing a staged create, or creating
   a namespace names only the parent, so the gate decides the name: a table or view must be
   registered in governance, still pending, with the person in its write grant; a namespace
   must lie under one the person's group owns. It reports each table created or dropped to
   governance, which marks the entry live or gone. Registering and renaming tables are refused
   (root-only in Polaris too).
6. The governance namespace. The gate answers for one namespace itself, `governance`, holding
   `datasets` (the dataset index), `sessions`, `lineage` and `derivations`. A load of one
   returns governance's per-person table (governance/index_table.py), whose files governance
   serves; a commit to `derivations` goes to governance, which accepts it only as a valid
   declaration (PROVENANCE.md 5.3). Polaris holds none of them.
7. The access log (PROVENANCE.md 4.1). Before it passes on any response that hands out a
   storage credential, the gate has governance log it: a read of the table the path names, or
   on a create a write of the new table; before it forwards a table create or commit, the
   write. When the log refuses or is unreachable, the gate refuses the request.
8. Accounts. Polaris 1.5 refuses a token whose name has no stored principal, and logs the
   token when it does. Before a person's first request reaches Polaris, the gate has
   governance create their principal (governance verifies the person's own token). A token
   naming one of Polaris's own principals is refused.

The gate holds no permissions. Everything it forwards carries the caller's own token and is
decided by Polaris and OPA; the gate's own decisions only refuse, remove entries, or turn a
refusal into not-found.
"""
import base64
import json
import logging
import os
import threading
from urllib.parse import unquote

import jwt
import requests
from flask import Flask, Response, jsonify, request

POLARIS = os.environ.get("POLARIS_URL", "http://polaris:8181")
OPA = os.environ["OPA_URL"]  # .../v1/data/lakehouse/tables
GOVERNANCE = os.environ["GOVERNANCE_URL"]
# Table create/drop reports go to governance's internal listener, which knows the gate by its
# client certificate (governance/pki.py).
GOVERNANCE_INTERNAL = os.environ["GOVERNANCE_INTERNAL_URL"]
PKI = os.environ.get("PKI_DIR", "/pki")
KEYCLOAK_JWKS = os.environ["KEYCLOAK_JWKS"]
KEYCLOAK_ISS = os.environ["KEYCLOAK_ISS"]
AUDIENCE = os.environ["POLARIS_AUDIENCE"]
RESERVED = {"root", "provisioner"}  # Polaris's own principals
DELEGATION = "x-iceberg-access-delegation"
SEP = "\x1f"  # Iceberg REST separator between namespace levels in a URL
MAX_PAGES = 1000
INDEX_NS, INDEX_TABLES = "governance", ("datasets", "sessions", "lineage", "derivations")
# Hop-by-hop headers, and ones requests recomputes after decoding the body.
DROP = {"host", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
        "proxy-authorization", "proxy-authenticate", "content-length", "content-encoding"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app = Flask(__name__)
app.logger.setLevel(logging.INFO)
_http = requests.Session()
_jwks = jwt.PyJWKClient(KEYCLOAK_JWKS)
# People whose Polaris principal this process has had governance create (or confirm).
_provisioned = set()
_provisioned_lock = threading.Lock()


def caller():
    """The claims of the request's verified Keycloak token, or None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        token = auth[7:]
        return jwt.decode(token, _jwks.get_signing_key_from_jwt(token).key, algorithms=["RS256"],
                          issuer=KEYCLOAK_ISS, audience=AUDIENCE)
    except Exception as e:  # noqa: BLE001
        app.logger.info("token refused: %s", e)
        return None


def ident(parts):
    """A table or namespace id as opa/tables.rego defines it, or None when a name contains
    "." (or is empty): such a name has no id and nobody may view it."""
    if not parts or any(not p or "." in p for p in parts):
        return None
    return ".".join(parts)


def route(segments):
    """What a catalog path names: (kind, catalog, namespace levels, name), where kind is
    namespaces | namespace | tables | table | views | view; None for anything else."""
    if segments[:3] != ["api", "catalog", "v1"] or len(segments) < 5 or segments[4] != "namespaces":
        return None
    catalog, rest = segments[3], segments[5:]
    if not rest:
        return "namespaces", catalog, [], None
    levels = rest[0].split(SEP)
    if len(rest) == 1 or rest[1] in ("properties", "register"):
        return "namespace", catalog, levels, None
    if rest[1] in ("tables", "views"):
        if len(rest) == 2:
            return rest[1], catalog, levels, None
        return rest[1][:-1], catalog, levels, rest[2]
    return None


def opa(rule, inp):
    r = _http.post(f"{OPA}/{rule}", json={"input": inp}, timeout=10)
    r.raise_for_status()
    return r.json().get("result")


def visible(subject, tables=(), namespaces=()):
    """(table ids, namespace ids) among the candidates that the subject may view."""
    result = opa("decide", {"subject": subject, "tables": [t for t in tables if t],
                            "namespaces": [n for n in namespaces if n]}) or {}
    return set(result.get("tables", [])), set(result.get("namespaces", []))


def may_view(subject, kind, catalog, levels, name):
    if kind in ("table", "view"):
        i = ident([catalog, *levels, name])
        return i is not None and i in visible(subject, tables=[i])[0]
    i = ident([catalog, *levels])
    return i is not None and i in visible(subject, namespaces=[i])[1]


def index_answer(named, segments):
    """The gate's own answer for the governance namespace and its tables, or None for any other
    path."""
    if not named or named[2] != [INDEX_NS]:
        return None
    kind, name = named[0], named[3]
    if request.method == "HEAD" and (kind == "namespace" or (kind == "table" and name in INDEX_TABLES)):
        return "", 204
    if request.method == "GET" and kind == "namespace" and segments[-1] == INDEX_NS:
        return jsonify({"namespace": [INDEX_NS], "properties": {}})
    if request.method == "GET" and kind in ("tables", "views"):
        ids = [{"namespace": [INDEX_NS], "name": t} for t in INDEX_TABLES] if kind == "tables" else []
        return jsonify({"identifiers": ids})
    if kind == "table" and name in INDEX_TABLES:
        if request.method == "GET" and segments[-1] == name:
            r = _http.post(f"{GOVERNANCE}/index/load", timeout=60, json={"table": name},
                           headers={"Authorization": request.headers["Authorization"]})
            return relay(r)
        if request.method == "POST" and segments[-1] == name:
            r = _http.post(f"{GOVERNANCE}/index/commit", timeout=60,
                           json={"table": name, "commit": request.get_json(silent=True) or {}},
                           headers={"Authorization": request.headers["Authorization"]})
            return relay(r)
        if request.method == "POST" and segments[-1] == "metrics":
            return "", 204
    if kind in ("table", "view"):
        return not_found(kind, named[2], name)
    return forbidden("the governance namespace is governance's own; "
                     "only governance.derivations takes inserted rows")


def forbidden(message):
    return jsonify({"error": {"message": message, "type": "ForbiddenException", "code": 403}}), 403


def creates(segments, body):
    """The table ids and namespace ids a POST would create, read from its path and body:
    ([table id], [namespace id]). A name with no id is None, which nothing allows."""
    if segments[:3] != ["api", "catalog", "v1"] or len(segments) < 5:
        return [], []
    catalog, rest = segments[3], segments[4:]
    if rest == ["namespaces"]:
        return [], [ident([catalog, *(body.get("namespace") or [])])]
    if len(rest) == 3 and rest[0] == "namespaces" and rest[2] in ("tables", "views"):
        return [ident([catalog, *rest[1].split(SEP), body.get("name") or ""])], []
    # A commit that asserts the table does not exist yet is a staged create being completed.
    if len(rest) == 4 and rest[0] == "namespaces" and rest[2] == "tables":
        if any(q.get("type") == "assert-create" for q in body.get("requirements") or []):
            return [ident([catalog, *rest[1].split(SEP), rest[3]])], []
    if rest == ["transactions", "commit"]:
        return [ident([catalog, *(c.get("identifier") or {}).get("namespace", []),
                       (c.get("identifier") or {}).get("name") or ""])
                for c in body.get("table-changes") or []
                if any(q.get("type") == "assert-create" for q in c.get("requirements") or [])], []
    return [], []


def writes(segments, body):
    """The table ids a POST commits to: a create that is not staged, a commit to one table
    (completing a staged create included), or each table of a multi-table commit. A name with
    no id is None."""
    if segments[:3] != ["api", "catalog", "v1"] or len(segments) < 5:
        return []
    catalog, rest = segments[3], segments[4:]
    if len(rest) == 3 and rest[0] == "namespaces" and rest[2] == "tables":
        return [] if body.get("stage-create") else [ident([catalog, *rest[1].split(SEP), body.get("name") or ""])]
    if len(rest) == 4 and rest[0] == "namespaces" and rest[2] == "tables":
        return [ident([catalog, *rest[1].split(SEP), rest[3]])]
    if rest == ["transactions", "commit"]:
        return [ident([catalog, *(c.get("identifier") or {}).get("namespace", []),
                       (c.get("identifier") or {}).get("name") or ""])
                for c in body.get("table-changes") or []]
    return []


def vended(r):
    """(whether this catalog response hands out a storage credential, its expiry in epoch ms or
    None)."""
    if not 200 <= r.status_code < 300:
        return False, None
    try:
        body = r.json()
    except ValueError:
        return False, None
    configs = [c.get("config") or {} for c in body.get("storage-credentials") or []]
    configs += [body.get("config") or {}]
    creds = [c for c in configs if "s3.access-key-id" in c]
    if not creds and not body.get("storage-credentials"):
        return False, None
    expiry = next((c["s3.session-token-expires-at-ms"] for c in creds
                   if str(c.get("s3.session-token-expires-at-ms", "")).isdigit()), None)
    return True, int(expiry) if expiry is not None else None


def current_only(r, keep):
    """A table load response cut to the current version. Removed: earlier versions, the
    snapshot and metadata logs, refs other than `main`, column statistics, earlier schemas,
    partition specs and sort orders, every snapshot summary entry but `operation` (row and
    file counts, the writer's name and query id), and the properties whose keys are not in
    `keep`. The current snapshot stays: without it the
    metadata would describe an empty table. The ETag goes too: Polaris issues one
    per metadata file, and a client revalidating a cut response with it would be answered 304
    after gaining read. The metadata is rebuilt from the fields named here, so one they do not
    name is dropped. Format v3's `next-row-id` is the number of rows ever written, and Iceberg
    refuses v3 metadata without it, so it is 0."""
    body = r.json()
    m = body["metadata"]
    current = m.get("current-snapshot-id")
    snaps = [{**{k: s[k] for k in ("snapshot-id", "sequence-number", "timestamp-ms",
                                   "manifest-list", "schema-id") if k in s},
              "summary": {"operation": (s.get("summary") or {}).get("operation", "append")}}
             for s in m.get("snapshots") or [] if s.get("snapshot-id") == current]
    schema_ids = {m.get("current-schema-id"), *(s.get("schema-id") for s in snaps)}
    body["metadata"] = {
        **{k: m[k] for k in ("format-version", "table-uuid", "location", "last-updated-ms",
                             "last-column-id", "current-schema-id", "default-spec-id",
                             "last-partition-id", "default-sort-order-id") if k in m},
        "properties": {k: v for k, v in (m.get("properties") or {}).items() if k in keep},
        **({"current-snapshot-id": current} if snaps else {}),
        **({"next-row-id": 0} if m.get("format-version", 0) >= 3 else {}),
        "last-sequence-number": snaps[0].get("sequence-number", 0) if snaps else 0,
        "snapshots": snaps,
        "snapshot-log": [e for e in m.get("snapshot-log") or [] if e.get("snapshot-id") == current][-1:],
        "metadata-log": [],
        "refs": {"main": {"snapshot-id": current, "type": "branch"}} if snaps else {},
        "statistics": [], "partition-statistics": [],
        "schemas": [s for s in m.get("schemas") or [] if s.get("schema-id") in schema_ids],
        "partition-specs": [s for s in m.get("partition-specs") or []
                            if s.get("spec-id") == m.get("default-spec-id")],
        "sort-orders": [s for s in m.get("sort-orders") or []
                        if s.get("order-id") == m.get("default-sort-order-id")],
    }
    return Response(json.dumps(body), status=r.status_code, content_type="application/json",
                    headers=[(k, v) for k, v in r.headers.items()
                             if k.lower() not in DROP | {"etag", "content-type"}])


def log_access(claims, entries):
    """Have governance log these accesses for the caller (PROVENANCE.md 4.1). Raises when the
    log refuses or cannot be reached, and the request is then refused: an access that is not
    logged would be missing from what the person's outputs may derive from."""
    if any(e["dataset"] is None for e in entries):
        raise requests.RequestException("an access to a name with no id cannot be logged")
    _http.post(f"{GOVERNANCE_INTERNAL}/internal/accesses", timeout=5,
               cert=(f"{PKI}/client.crt", f"{PKI}/client.key"), verify=f"{PKI}/ca.crt",
               json={"person": claims["principal_name"], "sub": claims.get("sub") or "",
                     "sid": claims.get("sid") or "", "entries": entries}).raise_for_status()


def report(table_id, event, location=None):
    """Tell governance a table was created or dropped. Best effort: a lost report leaves the
    entry's status stale, never its grants."""
    try:
        _http.post(f"{GOVERNANCE_INTERNAL}/internal/table-events", timeout=5,
                   cert=(f"{PKI}/client.crt", f"{PKI}/client.key"), verify=f"{PKI}/ca.crt",
                   json={"id": table_id, "event": event, "location": location}).raise_for_status()
    except requests.RequestException as e:
        app.logger.warning("could not report %s %s: %s", event, table_id, e)


def not_found(kind, levels, name):
    if request.method == "HEAD":
        return Response(status=404)
    typ = {"table": "NoSuchTableException", "view": "NoSuchViewException"}.get(
        kind, "NoSuchNamespaceException")
    what = ".".join(levels + ([name] if name else []))
    return jsonify({"error": {"message": f"{kind.capitalize()} does not exist: {what}",
                              "type": typ, "code": 404}}), 404


def provision(subject, force=False):
    """Have governance create the subject's Polaris principal, once per process. Governance
    authenticates the person's own token, which this request carries."""
    with _provisioned_lock:
        if subject in _provisioned and not force:
            return True
    try:
        r = _http.post(f"{GOVERNANCE}/principals/me", timeout=10,
                       headers={"Authorization": request.headers.get("Authorization", "")})
        r.raise_for_status()
    except requests.RequestException as e:
        app.logger.warning("could not provision %s: %s", subject, e)
        return False
    with _provisioned_lock:
        _provisioned.add(subject)
    return True


def forward(path, headers, params=None):
    def send(h):
        return _http.request(request.method, f"{POLARIS}/{path}",
                             params=request.args if params is None else params,
                             headers=h, data=request.get_data(), timeout=30,
                             allow_redirects=False)
    r = send(headers)
    # A principal deleted since this process provisioned it: create it again, retry once.
    if r.status_code == 401 and provision(request.environ["gate.subject"], force=True):
        r = send(headers)
    return r


def relay(r):
    return Response(r.content, status=r.status_code,
                    headers=[(k, v) for k, v in r.headers.items() if k.lower() not in DROP])


def listing(path, headers, kind, catalog, levels, subject):
    """Every page of an upstream listing, trimmed to what the subject may view, then paged
    with the gate's own tokens (an offset into the trimmed list)."""
    if kind != "namespaces" or "parent" in request.args:
        parent = request.args["parent"].split(SEP) if kind == "namespaces" else levels
        if not may_view(subject, "namespace", catalog, parent, None):
            return not_found("namespace", parent, None)
    key = "namespaces" if kind == "namespaces" else "identifiers"
    params = {k: v for k, v in request.args.items() if k not in ("pageToken", "pageSize")}
    items, token = [], ""
    for _ in range(MAX_PAGES):
        r = forward(path, headers, {**params, "pageToken": token})
        if r.status_code != 200:
            return relay(r)
        body = r.json()
        items += body.get(key) or []
        if not (token := body.get("next-page-token")):
            break
    if kind == "namespaces":
        ids = [ident([catalog, *ns]) for ns in items]
        keep = visible(subject, namespaces=ids)[1]
    else:
        ids = [ident([catalog, *it["namespace"], it["name"]]) for it in items]
        keep = visible(subject, tables=ids)[0]
    items = [it for it, i in zip(items, ids) if i in keep]
    if kind == "namespaces" and "parent" not in request.args and [INDEX_NS] not in items:
        items.append([INDEX_NS])

    if "pageToken" not in request.args and "pageSize" not in request.args:
        return jsonify({key: items})
    try:
        tok = request.args.get("pageToken") or ""
        start = int(base64.urlsafe_b64decode(tok).decode().removeprefix("gate:")) if tok else 0
        size = int(request.args["pageSize"]) if "pageSize" in request.args else len(items)
    except ValueError:
        return jsonify({"error": {"message": "invalid page token or size",
                                  "type": "BadRequestException", "code": 400}}), 400
    end = start + max(size, 1)
    nxt = base64.urlsafe_b64encode(f"gate:{end}".encode()).decode() if end < len(items) else None
    return jsonify({key: items[start:end], "next-page-token": nxt})


@app.get("/healthz")
def health():
    return {"ok": True}


@app.route("/<path:_>", methods=["GET", "HEAD", "POST", "PUT", "DELETE"])
def proxy(_):
    claims = caller() or {}
    # The claim Polaris names the principal by (polaris.oidc.principal-mapper).
    subject = claims.get("principal_name")
    if subject is None or subject in RESERVED:
        return jsonify({"error": {"message": "invalid or missing token",
                                  "type": "NotAuthorizedException", "code": 401}}), 401
    request.environ["gate.subject"] = subject
    # The path as sent, so an encoded namespace separator in a name survives.
    raw = (request.environ.get("RAW_URI") or request.path).split("?", 1)[0].lstrip("/")
    segments = [unquote(s) for s in raw.split("/")]
    # Before matching a route, Polaris (and the HTTP client forwarding to it) resolves "." and
    # ".." segments and drops ";" parameters, so "x/../namespaces" or "namespaces;x" reaches
    # the namespace listing while route() sees something else and the listing goes untrimmed.
    # Any path that such a rewrite could change is refused; so is a "/" or "\" inside a name.
    if any(s in ("", ".", "..") or any(c in s for c in "/\\;") for s in segments):
        return jsonify({"error": {"message": "path not in canonical form",
                                  "type": "BadRequestException", "code": 400}}), 400
    named = route(segments)
    if (answer := index_answer(named, segments)) is not None:
        return answer
    headers = {k: v for k, v in request.headers if k.lower() not in DROP}
    if request.method == "POST" and (segments[-1:] == ["register"] or segments[-1:] == ["rename"]):
        return forbidden("registering and renaming tables and views are root-only")

    try:
        if not provision(subject):
            return jsonify({"error": {"message": "could not create your catalog account",
                                      "type": "ServiceUnavailableException", "code": 503}}), 503
        if named and request.method == "GET" and named[0] in ("namespaces", "tables", "views"):
            return listing(raw, headers, *named[:3], subject)

        body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
        new_tables, new_namespaces = creates(segments, body) if request.method == "POST" else ([], [])
        for n in new_namespaces:
            if n is not None and n.split(".")[1:2] == [INDEX_NS]:
                return forbidden("the governance namespace is governance's own")
            if n is None or opa("allow_namespace", {"subject": subject, "id": n}) is not True:
                return forbidden(f"none of your groups owns {n} or a namespace above it")
        for t in new_tables:
            if t is None or opa("allow_create", {"subject": subject, "id": t}) is not True:
                if named and named[2] and not may_view(subject, "namespace", named[1], named[2], None):
                    return not_found("namespace", named[2], None)
                return forbidden(f"{t} is not registered for creation, or you are not in its write grant")

        written = writes(segments, body) if request.method == "POST" else []
        if written:
            log_access(claims, [{"dataset": t, "kind": "table", "mode": "write", "expires": None}
                                for t in written])
        delegated = any(k.lower() == DELEGATION for k in headers)
        r = forward(raw, headers)
        if r.ok:
            created = new_tables if not body.get("stage-create") else []
            location = None
            if created and r.content:
                try:
                    location = (r.json().get("metadata") or {}).get("location")
                except ValueError:
                    pass
            for t in created:
                report(t, "created", location)
            if request.method == "DELETE" and named and named[0] in ("table", "view"):
                if dropped := ident([named[1], *named[2], named[3]]):
                    report(dropped, "dropped")
        if (r.status_code == 403 and request.method == "GET" and named and named[0] == "table"
                and any(k.lower() == DELEGATION for k in headers)):
            app.logger.info("credential refused for %s; loading without one", raw)
            delegated = False
            r = forward(raw, {k: v for k, v in headers.items() if k.lower() != DELEGATION})
        # No storage credential leaves the gate unlogged, whatever the path: one on a create
        # (staged or not) is a write of the new table, any other a read of the table the path
        # names, and one on a path naming no table is refused, having nothing to be logged as.
        # A 304 to a credentialed load means the engine reuses the credential it was given with
        # this table earlier, possibly in another session.
        issued, expires = vended(r)
        credentialed = issued or (request.method == "GET" and r.status_code == 304 and delegated)
        table = ident([named[1], *named[2], named[3]]) if named and named[0] == "table" else None
        loaded = (r.json() if table and request.method == "GET" and r.status_code == 200
                  and not issued and r.content else {})
        # The gate's one decision on a table request (opa/tables.rego load), asked once Polaris
        # has answered: only then are the credential and the table's properties known.
        load = (opa("load", {"subject": subject, "id": table, "credential": credentialed,
                             "properties": (loaded.get("metadata") or {}).get("properties") or {}})
                or {}) if table and (credentialed or "metadata" in loaded) else {}
        if credentialed:
            if table:
                held, mode = table, "read"
            elif named and named[0] == "tables" and request.method == "POST":
                held, mode = (new_tables or [None])[0], "write"
            else:
                held, mode = None, "read"
            if not (mode == "write" and held in written):
                # A credential handed to someone who may write the table can write it, so its
                # time is a time they could have written files (PROVENANCE.md 6.2).
                can_write = mode == "read" and load.get("write") is True
                log_access(claims, [{"dataset": held, "kind": "table", "mode": mode,
                                     "expires": expires, "can_write": can_write}])
        if "metadata" in loaded and load.get("history") is not True:
            return current_only(r, set(load.get("properties") or []))
        if r.status_code == 403 and named and named[2]:
            kind, catalog, levels, name = named
            # A create, or anything else on a table or view collection, names its namespace.
            if name is None:
                kind = "namespace"
            if not may_view(subject, kind, catalog, levels, name):
                return not_found(kind, levels, name)
        return relay(r)
    except requests.RequestException as e:
        app.logger.warning("upstream or OPA failure on %s: %s", raw, e)
        return jsonify({"error": {"message": "service unavailable",
                                  "type": "ServiceUnavailableException", "code": 503}}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8182, threaded=True, use_reloader=False)
