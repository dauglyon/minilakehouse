"""
seed/user_token.py — print a demo user's Keycloak access token (password grant; the password
is the username) for one service's audience: polaris (Trino and the catalog, the default),
broker, or governance. Run in-network so the issuer matches what the services validate:

    TOKEN=$(docker compose exec -T governance python /seed/user_token.py alice)
    TOKEN=$(docker compose exec -T governance python /seed/user_token.py alice governance)
"""
import sys

import requests

KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"

user = sys.argv[1]
audience = sys.argv[2] if len(sys.argv) > 2 else "polaris"
r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                            "client_secret": "trino-secret", "username": user, "password": user,
                            "scope": f"openid aud-{audience}"})
r.raise_for_status()
print(r.json()["access_token"])
