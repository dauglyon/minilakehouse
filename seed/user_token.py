"""
seed/user_token.py — print a demo user's Keycloak access token (password grant; the password
is the username). Run in-network so the issuer matches what Trino, Polaris, and the services
validate:

    TOKEN=$(docker compose exec -T governance python /seed/user_token.py alice)
"""
import sys

import requests

KC = "http://keycloak:8080/realms/lakehouse/protocol/openid-connect/token"

user = sys.argv[1]
r = requests.post(KC, data={"grant_type": "password", "client_id": "trino",
                            "client_secret": "trino-secret", "username": user, "password": user})
r.raise_for_status()
print(r.json()["access_token"])
