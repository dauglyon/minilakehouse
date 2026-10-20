"""
proxy_login.py — log in to the login-proxy and print a session token, no browser.

Runs the browser steps of Trino's external-authentication flow as plain HTTP so a session can
be obtained in a script: read the proxy's 401 challenge, follow the redirect to Keycloak, post
the login form, let Keycloak redirect back to the proxy's callback, then poll for the session
token. The printed token is used as the Trino CLI's --access-token against the proxy; it stays
valid as the person's Keycloak login session does, across many commands.

  proxy_login.py <user>            (password defaults to the username, as the demo realm seeds)
"""
import re
import sys

import requests

PROXY = "https://loginproxy:9200"
user = sys.argv[1]
password = sys.argv[2] if len(sys.argv) > 2 else user
s = requests.Session()
s.verify = False
requests.packages.urllib3.disable_warnings()  # the proxy's dev cert is self-signed

# 1. No session yet: read the challenge's redirect and token URLs.
chal = s.get(f"{PROXY}/v1/statement", allow_redirects=False).headers["WWW-Authenticate"]
redirect_url = re.search(r'x_redirect_server="([^"]+)"', chal).group(1)
token_url = re.search(r'x_token_server="([^"]+)"', chal).group(1)

# 2. Follow the redirect to Keycloak; it returns the login form.
form = s.get(redirect_url).text
action = re.search(r'<form[^>]+action="([^"]+)"', form).group(1).replace("&amp;", "&")

# 3. Post credentials. Keycloak redirects to the proxy callback with a code; the proxy
#    exchanges it and stores the session. The session cookies carry the Keycloak login.
s.post(action, data={"username": user, "password": password}, allow_redirects=True)

# 4. Poll the token endpoint for the opaque session token.
for _ in range(10):
    body = s.get(token_url).json()
    if "token" in body:
        print(body["token"])
        break
    if "error" in body:
        sys.exit(f"login failed: {body['error']}")
else:
    sys.exit("login did not complete")
