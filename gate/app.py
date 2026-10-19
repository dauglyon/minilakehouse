"""
gate — the proxy in front of Polaris (WHITEPAPER.md §5). Built so far: one behaviour.

Trino asks for a storage credential on every table load (X-Iceberg-Access-Delegation), and
Polaris refuses the whole load when neither credential check passes, so a person who may
view a table but not read it could not even DESCRIBE it. When Polaris refuses such a load
(403), the gate repeats it once without the credential request; Polaris then checks only
whether the person may view the table, and returns its metadata without a credential.

The gate holds no permissions and decides nothing: both attempts carry the caller's own
token and are decided by Polaris and OPA. Everything else is forwarded unchanged.
"""
import logging
import os
import re

import requests
from flask import Flask, Response, request

POLARIS = os.environ.get("POLARIS_URL", "http://polaris:8181")
DELEGATION = "X-Iceberg-Access-Delegation"
# GET {prefix}/namespaces/{ns}/tables/{table} — a table load (not /credentials, /metrics).
TABLE_LOAD = re.compile(r"^api/catalog/v1/[^/]+/namespaces/[^/]+/tables/[^/]+$")
# Hop-by-hop headers, and ones requests recomputes after decoding the body.
DROP = {"host", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
        "proxy-authorization", "proxy-authenticate", "content-length", "content-encoding"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app = Flask(__name__)
app.logger.setLevel(logging.INFO)
_http = requests.Session()


def forward(path, headers):
    return _http.request(request.method, f"{POLARIS}/{path}", params=request.args,
                         headers=headers, data=request.get_data(), timeout=30,
                         allow_redirects=False)


@app.get("/healthz")
def health():
    return {"ok": True}


@app.route("/<path:path>", methods=["GET", "HEAD", "POST", "PUT", "DELETE"])
def proxy(path):
    headers = {k: v for k, v in request.headers if k.lower() not in DROP}
    r = forward(path, headers)
    if (r.status_code == 403 and request.method == "GET" and TABLE_LOAD.match(path)
            and any(k.lower() == DELEGATION.lower() for k in headers)):
        app.logger.info("credential refused for %s; loading without one", path)
        r = forward(path, {k: v for k, v in headers.items() if k.lower() != DELEGATION.lower()})
    return Response(r.content, status=r.status_code,
                    headers=[(k, v) for k, v in r.headers.items() if k.lower() not in DROP])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8182, threaded=True, use_reloader=False)
