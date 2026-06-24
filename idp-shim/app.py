"""
idp-shim — the trusted identity layer between Trino and Polaris.

The problem it solves: Trino multiplexes many users over one connection and can
only *assert* the end user with an unsigned, self-issued JWT ("subject: alice") —
which Keycloak refuses to trust. So a real per-user identity can never reach Polaris
through Trino directly.

This shim sits where Trino fetches OAuth tokens (Trino's `oauth2.server-uri` points
here). It is the ONE place where "we trust our Trino" lives:

  - client_credentials  -> Trino getting its base identity. Mint a token for the
                           service principal (trino_svc). Used for metadata/config
                           calls that read no data.
  - token-exchange      -> Trino says (unsigned) "this request is alice's". We trust
                           our Trino, read the asserted subject, look up the user's
                           groups from Keycloak, and mint a REAL signed token that
                           says principal_name=alice, principal_roles=[groups].

Trino then presents that signed token to Polaris. Polaris validates it against this
shim's JWKS (the shim is Polaris's OIDC issuer) and OPA decides on the real user.
Polaris and OPA never see Trino's flimsy unsigned note; the bare trino_svc principal
is granted nothing in OPA, so even an open Polaris API has no skeleton key.

NOTE (hardening TODO): this prototype trusts any caller presenting the trino client
secret. Production must bind that trust to the engine (mTLS / network policy).
"""
import base64
import hashlib
import logging
import os
import time

import jwt  # PyJWT (with cryptography for RS256)
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

ISSUER = os.environ["SHIM_ISSUER"]
TRINO_CLIENT_ID = os.environ.get("TRINO_CLIENT_ID", "trino")
TRINO_CLIENT_SECRET = os.environ.get("TRINO_CLIENT_SECRET", "trino-secret")
SERVICE_PRINCIPAL = os.environ.get("SERVICE_PRINCIPAL", "trino_svc")
AUDIENCE = os.environ.get("AUDIENCE", "polaris")
KC_BASE = os.environ.get("KC_BASE", "")
KC_REALM = os.environ.get("KC_REALM", "lakehouse")
KC_ADMIN = os.environ.get("KC_ADMIN", "admin")
KC_ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "admin")
SHIM_TTL = int(os.environ.get("SHIM_TTL", "3600"))  # minted-token lifetime (seconds)
KEY_PATH = os.environ.get("SHIM_KEY_PATH", "/keys/shim-key.pem")

logging.basicConfig(level=logging.INFO)

# Principals the engine may NOT assert via token-exchange. The engine is trusted to
# speak for end users, never to escalate to the internal admin or its own service
# identity. (trino_svc == SERVICE_PRINCIPAL below.)
RESERVED_PRINCIPALS = {"root", "trino_svc"}

def _load_or_create_key_pem() -> bytes:
    """Load the signing key from disk; generate + persist it on first run. The key MUST
    survive a shim restart — otherwise every token Trino already holds (and Polaris's
    cached JWKS) is invalidated, silently breaking the whole table plane until both
    refresh. (Dev: the key lives in a plaintext volume; production would source it from a
    secret manager / KMS.)"""
    try:
        with open(KEY_PATH, "rb") as f:
            return f.read()
    except FileNotFoundError:
        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
        with open(KEY_PATH, "wb") as f:
            f.write(pem)
        return pem


# Persistent signing key (stable across restarts).
_priv_pem = _load_or_create_key_pem()
_key = serialization.load_pem_private_key(_priv_pem, password=None)
_pub_pem = _key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
# kid derived from the public key — now STABLE across restarts, so Polaris's cached JWKS
# stays valid and Trino's existing tokens keep verifying. (A genuine key change still
# yields a new kid, so Polaris would refetch.)
_kid = hashlib.sha256(_pub_pem).hexdigest()[:16]


def _b64u_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


_nums = _key.public_key().public_numbers()
_JWK = {
    "kty": "RSA",
    "kid": _kid,
    "use": "sig",
    "alg": "RS256",
    "n": _b64u_uint(_nums.n),
    "e": _b64u_uint(_nums.e),
}

app = Flask(__name__)


def lookup_groups(username: str) -> list:
    """Best-effort: read the user's group names from Keycloak (the IdP owns membership)."""
    if not KC_BASE:
        return []
    try:
        tok = requests.post(
            f"{KC_BASE}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KC_ADMIN,
                "password": KC_ADMIN_PASSWORD,
            },
            timeout=5,
        ).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        users = requests.get(
            f"{KC_BASE}/admin/realms/{KC_REALM}/users",
            params={"username": username, "exact": "true"},
            headers=h,
            timeout=5,
        ).json()
        if not users:
            return []
        groups = requests.get(
            f"{KC_BASE}/admin/realms/{KC_REALM}/users/{users[0]['id']}/groups",
            headers=h,
            timeout=5,
        ).json()
        return [g["name"] for g in groups]
    except Exception as e:  # noqa: BLE001 - best effort
        app.logger.warning("group lookup failed for %s: %s", username, e)
        return []


def mint(principal_name: str, roles: list) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": principal_name,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + SHIM_TTL,
        "principal_name": principal_name,
        "principal_roles": roles,
    }
    return jwt.encode(claims, _priv_pem, algorithm="RS256", headers={"kid": _kid})


def _token_response(access_token: str):
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": SHIM_TTL,  # match the minted token's actual lifetime
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    })


def _client_ok() -> bool:
    cid = request.form.get("client_id")
    csec = request.form.get("client_secret")
    if not cid and request.authorization:
        cid = request.authorization.username
        csec = request.authorization.password
    return cid == TRINO_CLIENT_ID and csec == TRINO_CLIENT_SECRET


def _valid_service_bearer() -> bool:
    """True if the request carries a shim-issued service token (proof the caller
    already authenticated with the client secret to obtain it). Full validation —
    signature, issuer, audience, AND expiry — an expired token is not valid proof."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    try:
        claims = jwt.decode(
            auth[7:], _pub_pem, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER
        )
    except Exception:
        return False
    return claims.get("principal_name") == SERVICE_PRINCIPAL


def _caller_is_trusted_engine() -> bool:
    # Either the client secret, or a valid service token the shim itself issued.
    return _client_ok() or _valid_service_bearer()


@app.get("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer": ISSUER,
        "jwks_uri": f"{ISSUER}/certs",
        "token_endpoint": f"{ISSUER}/token",
        "authorization_endpoint": f"{ISSUER}/auth",
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": [
            "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
    })


@app.get("/certs")
def certs():
    return jsonify({"keys": [_JWK]})


@app.post("/token")
def token():
    grant = request.form.get("grant_type", "")
    has_secret = _client_ok()
    has_bearer = _valid_service_bearer()
    app.logger.info(
        "token grant=%s client_secret=%s service_bearer=%s form_keys=%s",
        grant, has_secret, has_bearer, list(request.form.keys()),
    )

    # client_credentials = the engine's initial login: it MUST present the client secret.
    if grant == "client_credentials":
        if not has_secret:
            app.logger.warning("client_credentials rejected: bad/absent client secret")
            return jsonify({"error": "invalid_client"}), 401
        return _token_response(mint(SERVICE_PRINCIPAL, []))

    # token-exchange = the engine relaying an end user. The caller MUST prove it is our
    # engine (client secret, or a service token the shim already issued — which itself
    # required the secret). Then we trust the asserted subject, EXCEPT we never let the
    # engine escalate to a reserved/privileged principal.
    if grant.endswith("token-exchange"):
        if not (has_secret or has_bearer):
            app.logger.warning("token-exchange rejected: caller is not the trusted engine")
            return jsonify({"error": "invalid_client"}), 401
        subject_token = request.form.get("subject_token", "")
        user = None
        if subject_token:
            try:
                user = jwt.decode(subject_token, options={"verify_signature": False}).get("sub")
            except Exception as e:  # noqa: BLE001
                app.logger.warning("could not decode subject_token: %s", e)
        if not user:
            return jsonify({"error": "invalid_request", "error_description": "no subject"}), 400
        if user in RESERVED_PRINCIPALS or user == SERVICE_PRINCIPAL:
            app.logger.warning("refusing to mint reserved principal via exchange: %s", user)
            return jsonify({"error": "invalid_request", "error_description": "subject not allowed"}), 403
        roles = lookup_groups(user)
        app.logger.info("minting user token principal=%s roles=%s", user, roles)
        return _token_response(mint(user, roles))

    return jsonify({"error": "unsupported_grant_type"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
