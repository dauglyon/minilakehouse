"""
keycloak/setup.py — one-shot: one token audience per service (WHITEPAPER 6).

Each service accepts only tokens issued for it: Trino, the gate and Polaris take audience
`polaris`, the broker `broker`, governance `governance`. A client asks for the audience it needs
with the optional client scope aud-<service> on the `trino` login client, for example
`scope=openid aud-broker`; a token that asks for none carries none of them. The scopes are made
here rather than in the realm file because a realm file that lists any client scopes replaces
Keycloak's built-in ones. Safe to rerun.
"""
import os

import requests

KC = os.environ.get("KC_URL", "http://keycloak:8080")
REALM = os.environ["KC_REALM"]
CLIENT = os.environ.get("LOGIN_CLIENT_ID", "trino")
AUDIENCES = ("polaris", "broker", "governance")


def main():
    t = requests.post(f"{KC}/realms/master/protocol/openid-connect/token", timeout=10, data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": os.environ["KC_ADMIN"], "password": os.environ["KC_ADMIN_PASSWORD"]})
    t.raise_for_status()
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {t.json()['access_token']}"
    base = f"{KC}/admin/realms/{REALM}"

    existing = {c["name"] for c in s.get(f"{base}/client-scopes").json()}
    for aud in AUDIENCES:
        if f"aud-{aud}" in existing:
            continue
        s.post(f"{base}/client-scopes", json={
            "name": f"aud-{aud}", "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
            "protocolMappers": [{
                "name": f"{aud}-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": aud, "access.token.claim": "true",
                           "id.token.claim": "false", "introspection.token.claim": "true"}}],
        }).raise_for_status()
    scope_ids = {c["name"]: c["id"] for c in s.get(f"{base}/client-scopes").json()}

    client = s.get(f"{base}/clients", params={"clientId": CLIENT}).json()[0]
    for aud in AUDIENCES:
        s.put(f"{base}/clients/{client['id']}/optional-client-scopes/{scope_ids[f'aud-{aud}']}"
              ).raise_for_status()
    # A realm imported before this step fixed `polaris` on every token from the client.
    for m in client.get("protocolMappers", []):
        if m["protocolMapper"] == "oidc-audience-mapper":
            s.delete(f"{base}/clients/{client['id']}/protocol-mappers/models/{m['id']}"
                     ).raise_for_status()
    print(f"keycloak: audience scopes {', '.join('aud-' + a for a in AUDIENCES)} on {CLIENT}")


if __name__ == "__main__":
    main()
