import requests
import webbrowser
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import jwt
import base64

# CONFIGURATION
KEYCLOAK_BASE_URL = "http://localhost:8080"
REALM = "filippo"
CLIENT_ID = "python"
CLIENT_SECRET = "rf4Qv7vr5NZ5YJpVxxC58Dfh3v72qMRe"  # optional if public client
REDIRECT_URI = "http://localhost:8081/callback"
USERNAME = "fvalle"
PASSWORD = "fvalle"

def introspect_token(access_token):
    introspect_url = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/protocol/openid-connect/token/introspect"
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "token": access_token,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }

    response = requests.post(introspect_url, headers=headers, data=data)

    if response.status_code == 200:
        result = response.json()
        if result.get("active"):
            print("[+] Token is valid:")
        else:
            print("[-] Token is invalid or expired.")
        print(result)
        return {"access_token": result}
    else:
        print("[-] Introspection failed:")
        print(f"Status Code: {response.status_code}")
        print(response.text)


def verify_token(token_response):
    oidc_config = requests.get(
        f"{KEYCLOAK_BASE_URL}/realms/{REALM}/.well-known/openid-configuration"
    ).json()
    signing_algos = oidc_config["id_token_signing_alg_values_supported"]

    # setup a PyJWKClient to get the appropriate signing key
    jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])


    # data from the login flow
    # see: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
    id_token = token_response["id_token"]
    access_token = token_response["access_token"]

    # get signing_key from id_token
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    # now, decode_complete to get payload + header
    data = jwt.decode_complete(
        id_token,
        key=signing_key,
        audience=CLIENT_ID,
        algorithms=signing_algos
        
        )
    payload, header = data["payload"], data["header"]

    # get the pyjwt algorithm object
    alg_obj = jwt.get_algorithm_by_name(header["alg"])

    # compute at_hash, then validate / assert
    digest = alg_obj.compute_hash_digest(access_token.encode("utf-8"))
    at_hash = base64.urlsafe_b64encode(digest[: (len(digest) // 2)]).decode('utf-8').rstrip('=')
    assert at_hash == payload["at_hash"]

def login_with_password_grant():
    token_url = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/protocol/openid-connect/token"
    
    data = {
        'grant_type': 'acces',
        'client_id': CLIENT_ID,
        'username': USERNAME,
        'password': PASSWORD,
    }

    # Only include client_secret if the client is confidential
    if CLIENT_SECRET:
        data['client_secret'] = CLIENT_SECRET

    response = requests.post(token_url, data=data)

    if response.status_code == 200:
        tokens = response.json()
        print("[+] Access token acquired:")
        print(tokens['access_token'])
        return tokens
    else:
        print("[-] Login failed:")
        print(response.status_code, response.text)
        return None

class OAuthHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.auth_code = None

# Local HTTP handler to capture the code
class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [None])[0]

        self.server.auth_code = code

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Authorization code received. You can close this window.")

    def log_message(self, format, *args):
        return  # Suppress logging

def start_local_server():
    server = OAuthHTTPServer(("localhost", 8081), OAuthCallbackHandler)
    server.handle_request()  # waits for exactly one request
    return server.auth_code

def standard_flow():
    auth_url = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/protocol/openid-connect/auth"
    token_url = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/protocol/openid-connect/token"

    # Build authorization URL
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": REDIRECT_URI,
    }
    url = f"{auth_url}?{urllib.parse.urlencode(params)}"

    print(f"[+] Opening browser to authenticate: {url}")
    webbrowser.open(url)

    # Start local server to get auth code
    auth_code = start_local_server()

    if not auth_code:
        print("[-] No auth code received.")
        return

    print(f"[+] Auth code: {auth_code}")

    # Exchange code for tokens
    data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
    }

    response = requests.post(token_url, data=data)

    if response.status_code == 200:
        tokens = response.json()
        print("[+] Tokens acquired:")
        print(tokens)
        return tokens
    else:
        print("[-] Token exchange failed:")
        print(response.status_code, response.text)
        return None

if __name__ == "__main__":
    # token = login_with_password_grant()
    token = standard_flow()
    introspect_token(token["access_token"])
    try:
        verify_token(token)
    except Exception as e:
        print(f"[-] Token verification failed: {e}")
        print("[-] Token verification failed.")