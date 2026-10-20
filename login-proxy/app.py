"""
login-proxy — keeps a person's Trino session alive past their 5-minute Keycloak token.

A Keycloak access token lasts 5 minutes, and Trino's CLI and JDBC driver send whatever token
they started with on every request, so a session dies when the token expires. Trino's own
browser login (OAuth2 external authentication) refreshes tokens, but the identity it builds
carries no token, so Polaris — which decides on the person's token — would receive none
(Trino issue #27197). This proxy sits in front of Trino and gives both: it speaks Trino's
external-authentication protocol to the client and holds each person's refresh token, and it
forwards the person's current token to Trino as the bearer and as the `token` extra
credential, so Polaris keeps deciding on a live token.

Toward the client (Trino's protocol):
  - A request with no live session gets 401 with
    `WWW-Authenticate: Bearer x_redirect_server=.../initiate, x_token_server=.../token, ...`.
  - The client opens the redirect URL; the proxy sends the browser to Keycloak
    (authorization-code, the `trino` client, so the token's audience is `polaris` and its azp
    is `trino`), takes the code at its callback, and exchanges it for access + refresh tokens.
  - The client polls the token URL with a secret poll token (not the browser-facing auth id):
    `{"nextUri": url}` until ready, then `{"token": session}`, an opaque id the proxy maps to
    that person's tokens. On refresh failure the proxy re-challenges and the client logs in
    again.

The browser leg is bound so knowing the (disclosed) auth id is not enough to complete a login
for someone else: the callback must echo an HttpOnly nonce cookie set at initiate, the code is
bound by PKCE (a verifier the browser never sees), the session is yielded only by the separate
poll token, and initiate and callback are each single-use (a replay is refused). Pending logins
expire (LOGIN_TTL); at the cap (MAX_PENDING) a new challenge sheds only logins no browser has
started, else returns 503, so a flood can't evict a login in progress or exhaust memory. The
login maps are guarded by a lock. Not done: a browser confirmation page naming the client.

Toward Trino (plain JWT, unchanged): every forwarded request carries the person's current
access token, refreshed from the stored refresh token when it is within REFRESH_SKEW of
expiry, as `Authorization: Bearer` and `X-Trino-Extra-Credential: token=`. Trino's nextUris
point back here via X-Forwarded-* (Trino sets http-server.process-forwarded=true).

Sessions live in memory: a restart ends every session, and the client logs in again. A
deployment would store them in Redis or similar. The refresh token is never sent to the
client; the client holds only the opaque session id.
"""
import base64
import datetime
import hashlib
import hmac
import logging
import os
import secrets
import ssl
import threading
import time
from urllib.parse import urlencode

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, Response, jsonify, redirect, request

TRINO_URL = os.environ["TRINO_URL"]  # https://trino:8443
KC_AUTH = os.environ["KC_AUTH"]      # http://keycloak:8080/realms/lakehouse/protocol/openid-connect/auth
KC_TOKEN = os.environ["KC_TOKEN"]    # .../token
CLIENT_ID = os.environ["TRINO_CLIENT_ID"]
CLIENT_SECRET = os.environ["TRINO_CLIENT_SECRET"]
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")  # how the client reaches this proxy (https://host:port)
TRINO_CA = os.environ["TRINO_CA"]                  # where to pin and read Trino's cert
TRINO_PIN_HOST = os.environ["TRINO_PIN_HOST"]      # host:port to pin that cert from at startup
PROXY_CRT, PROXY_KEY = "/tmp/proxy-tls.crt", "/tmp/proxy-tls.key"
SCOPE = "openid"
# Refresh the access token when it is within this many seconds of expiring, so a forwarded
# request never carries an about-to-expire token. Set very high to refresh on every request.
REFRESH_SKEW = int(os.environ.get("REFRESH_SKEW", "30"))
# Hop-by-hop headers, and ones requests recomputes after reading the body.
DROP = {"host", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
        "proxy-authorization", "proxy-authenticate", "content-length", "content-encoding",
        "authorization", "x-trino-extra-credential"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app = Flask(__name__)
app.logger.setLevel(logging.INFO)
_http = requests.Session()
_verify = TRINO_CA or True

# A pending login holds three unlinkable ids so knowing one does not grant the others:
#   auth_id    — in x_redirect_server, so it reaches the browser and the IdP; locates the record
#   poll_token — in x_token_server, a secret the initiating client keeps; yields the session
#   state/nonce/verifier — bind the browser leg (OAuth state + cookie + PKCE)
# auth_id -> {poll_token, status, created, nonce, verifier, session?, error?}.
_logins = {}
_by_poll = {}  # poll_token -> auth_id
# The dev server serves requests on threads; guard the login maps (not the per-request session
# refresh, which does network I/O and must not serialize behind one lock).
_lock = threading.Lock()
# A challenge is unauthenticated, so bound how many pending logins can pile up, and drop stale.
LOGIN_TTL = 300
MAX_PENDING = 1000
# session id -> {"subject", "access", "refresh", "access_exp"} after login.
_sessions = {}


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def _store(subject, tokens):
    """Record a person's tokens under a fresh opaque session id and return the id."""
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {"subject": subject, "access": tokens["access_token"],
                      "refresh": tokens["refresh_token"],
                      "access_exp": _claims(tokens["access_token"])["exp"]}
    return sid


def _fresh_token(sid):
    """The session's access token, refreshed if it is near expiry. None if the session is
    unknown or its refresh token no longer works (Keycloak login session ended)."""
    s = _sessions.get(sid)
    if s is None:
        return None
    if s["access_exp"] - time.time() > REFRESH_SKEW:
        return s["access"]
    r = _http.post(KC_TOKEN, timeout=10, data={
        "grant_type": "refresh_token", "refresh_token": s["refresh"],
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})
    if r.status_code != 200:
        app.logger.info("refresh failed for %s: %s", s["subject"], r.text[:120])
        _sessions.pop(sid, None)
        return None
    t = r.json()
    s["access"] = t["access_token"]
    s["access_exp"] = _claims(t["access_token"])["exp"]
    # Keycloak rotates refresh tokens; keep the new one or the next refresh fails.
    if "refresh_token" in t:
        s["refresh"] = t["refresh_token"]
    app.logger.info("REFRESH subject=%s", s["subject"])
    return s["access"]


def _drop_login(auth_id):  # call under _lock
    login = _logins.pop(auth_id, None)
    if login:
        _by_poll.pop(login["poll_token"], None)


def _purge_logins():  # call under _lock
    cutoff = time.time() - LOGIN_TTL
    for auth_id in [a for a, l in _logins.items() if l["created"] < cutoff]:
        _drop_login(auth_id)


def challenge(refresh_only_sid=None):
    """Trino's 401 bearer challenge. With a session whose refresh failed, offer only the token
    server (the client re-polls); otherwise the full redirect-and-token challenge, or 503 when
    too many logins are already in flight."""
    if refresh_only_sid:
        hdr = f'Bearer x_token_server="{PUBLIC_URL}/auth/token/{refresh_only_sid}"'
        return Response('{"error":"authentication required"}', status=401,
                        headers={"WWW-Authenticate": hdr}, content_type="application/json")
    with _lock:
        _purge_logins()
        # A challenge needs no credential. At the cap, shed only logins no browser has started
        # (no nonce yet), oldest first; never one mid-login. If even those don't free room, all
        # pending logins are in flight, so refuse the new one rather than evict a real one.
        while len(_logins) >= MAX_PENDING:
            spare = [a for a, l in _logins.items() if l["nonce"] is None]
            if not spare:
                return Response('{"error":"login capacity reached; retry shortly"}', status=503,
                                content_type="application/json")
            _drop_login(min(spare, key=lambda a: _logins[a]["created"]))
        auth_id = secrets.token_urlsafe(24)       # reaches the browser/IdP; locates the record
        poll_token = secrets.token_urlsafe(32)    # secret the client keeps; yields the session
        _logins[auth_id] = {"poll_token": poll_token, "status": "pending",
                            "created": time.time(), "nonce": None, "verifier": None}
        _by_poll[poll_token] = auth_id
    hdr = (f'Bearer x_redirect_server="{PUBLIC_URL}/auth/initiate/{auth_id}", '
           f'x_token_server="{PUBLIC_URL}/auth/token/{poll_token}", '
           f'x_token_endpoint="{KC_TOKEN}", scope="{SCOPE}"')
    return Response('{"error":"authentication required"}', status=401,
                    headers={"WWW-Authenticate": hdr}, content_type="application/json")


@app.get("/auth/initiate/<auth_id>")
def initiate(auth_id):
    # The browser landed here from x_redirect_server; send it to Keycloak. Bind this leg to this
    # browser: a nonce in an HttpOnly cookie the callback must echo, and a PKCE verifier the
    # browser never sees. Allowed once: a second initiate (nonce already set, or past pending)
    # is refused, so a login can't be restarted onto another browser.
    with _lock:
        _purge_logins()
        login = _logins.get(auth_id)
        if login is None:
            return "unknown or expired login", 404
        if login["status"] != "pending" or login["nonce"] is not None:
            return "login already started", 409
        nonce = login["nonce"] = secrets.token_urlsafe(16)
        verifier = login["verifier"] = secrets.token_urlsafe(48)
    chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    resp = app.make_response(redirect(f"{KC_AUTH}?" + urlencode({
        "response_type": "code", "client_id": CLIENT_ID, "scope": SCOPE,
        "redirect_uri": f"{PUBLIC_URL}/auth/callback", "state": auth_id,
        "code_challenge": chal, "code_challenge_method": "S256"})))
    resp.set_cookie("login_nonce", nonce, max_age=LOGIN_TTL, httponly=True,
                    secure=True, samesite="Lax", path="/auth/callback")
    return resp


@app.get("/auth/callback")
def callback():
    state = request.args.get("state", "")
    # Validate and consume the login atomically, so a replayed or forged callback can't reuse
    # the nonce or code; the Keycloak exchange then runs outside the lock.
    with _lock:
        _purge_logins()
        login = _logins.get(state)
        if login is None:
            return "unknown or expired login", 404
        if login["status"] != "pending":
            return "login already completed", 400
        if not login["nonce"] or not hmac.compare_digest(
                request.cookies.get("login_nonce", ""), login["nonce"]):
            return "login not recognised for this browser", 400
        if "error" in request.args or "code" not in request.args:
            login.update(status="error", error=request.args.get("error", "no code"))
            return "login failed; return to your client", 400
        login["status"] = "exchanging"
        verifier, login["nonce"], login["verifier"] = login["verifier"], None, None
        code = request.args["code"]
    r = _http.post(KC_TOKEN, timeout=10, data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": f"{PUBLIC_URL}/auth/callback", "code_verifier": verifier,
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})
    with _lock:
        login = _logins.get(state)
        if login is None:
            return "login expired", 400
        if r.status_code != 200:
            login.update(status="error", error="token exchange failed")
            return "login failed; return to your client", 400
        subject = _claims(r.json()["access_token"]).get("principal_name", "?")
        login.update(status="ready", session=_store(subject, r.json()))
    app.logger.info("LOGIN subject=%s", subject)
    return "login complete; return to your client", 200


@app.get("/auth/token/<key>")
def token_poll(key):
    # Two callers hit this. A session id (refresh): refresh and hand the same id back, or
    # 401-challenge if the refresh token lapsed. A pending login's poll_token: nextUri while the
    # browser finishes, then the session id. An auth_id is not accepted here — only poll_token.
    if key in _sessions:
        return (jsonify({"token": key}) if _fresh_token(key) else challenge())
    with _lock:
        _purge_logins()
        auth_id = _by_poll.get(key)
        login = _logins.get(auth_id) if auth_id else None
        if login is None:
            return jsonify({"error": "unknown or expired login"}), 404
        if login["status"] in ("pending", "exchanging"):
            return jsonify({"nextUri": f"{PUBLIC_URL}/auth/token/{key}"})
        if login["status"] == "error":
            err = login.get("error", "login failed")
            _drop_login(auth_id)
            return jsonify({"error": err})
        session = login["session"]
        _drop_login(auth_id)
    return jsonify({"token": session})


@app.get("/healthz")
def health():
    return {"ok": True}


@app.route("/<path:path>", methods=["GET", "HEAD", "POST", "PUT", "DELETE"])
def proxy(path):
    auth = request.headers.get("Authorization", "")
    sid = auth[7:] if auth.startswith("Bearer ") else ""
    if not sid or sid not in _sessions:
        return challenge()
    token = _fresh_token(sid)
    if token is None:
        return challenge(refresh_only_sid=sid)

    headers = {k: v for k, v in request.headers if k.lower() not in DROP}
    headers["Authorization"] = f"Bearer {token}"
    # The person's live token, forwarded to Polaris by Trino's Iceberg connector.
    headers["X-Trino-Extra-Credential"] = f"token={token}"
    # So Trino builds nextUris that point back at this proxy, not at itself.
    headers["X-Forwarded-Proto"] = "https"
    headers["X-Forwarded-Host"] = PUBLIC_URL.split("://", 1)[-1]
    r = _http.request(request.method, f"{TRINO_URL}/{path}", params=request.args,
                      headers=headers, data=request.get_data(), timeout=600,
                      allow_redirects=False, verify=_verify)
    return Response(r.content, status=r.status_code,
                    headers=[(k, v) for k, v in r.headers.items() if k.lower() not in DROP])


def _self_signed(crt_path, key_path):
    """A self-signed cert for the client-facing HTTPS (Trino refuses to send a token over
    plain HTTP). SANs cover the proxy's service name and localhost; the client trusts it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "loginproxy")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("loginproxy"), x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _pin_trino_cert():
    """Pin Trino's self-signed cert once, from TRINO_PIN_HOST, then verify every forwarded
    request against it. Trust-on-first-connect for a dev internal cert — stricter than not
    verifying, which a shared engine on the token path must never do."""
    host, port = TRINO_PIN_HOST.rsplit(":", 1)
    pem = ssl.get_server_certificate((host, int(port)))
    with open(TRINO_CA, "w") as f:
        f.write(pem)


if __name__ == "__main__":
    _self_signed(PROXY_CRT, PROXY_KEY)
    _pin_trino_cert()
    app.run(host="0.0.0.0", port=9200, threaded=True, use_reloader=False,
            ssl_context=(PROXY_CRT, PROXY_KEY))
