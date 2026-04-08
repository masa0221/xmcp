"""Obtain an OAuth2 refresh token for the X API via Authorization Code + PKCE.

Usage:
    1. Set X_CLIENT_ID and X_CLIENT_SECRET in .env
    2. Run: python generate_token.py
    3. A browser opens for authorization
    4. After consent, the refresh token is printed and optionally saved

The redirect URI defaults to http://127.0.0.1:8976/oauth2/callback.
Register this URL in your X Developer App settings.
"""

import base64
import hashlib
import http.server
import os
import secrets
import socketserver
import threading
import urllib.parse
import webbrowser

import httpx
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except ImportError:
    pass

AUTHORIZE_URL = "https://x.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"

DEFAULT_SCOPES = (
    "tweet.read tweet.write tweet.moderate.write "
    "users.read follows.read follows.write "
    "like.read like.write bookmark.read bookmark.write "
    "list.read list.write block.read block.write "
    "mute.read mute.write space.read "
    "offline.access"
)


def generate_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def wait_for_code(host: str, port: int, path: str, timeout: int) -> str:
    result: dict[str, str | None] = {"code": None}
    event = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != path:
                self.send_response(404)
                self.end_headers()
                return
            query = urllib.parse.parse_qs(parsed.query)
            result["code"] = (query.get("code") or [None])[0]
            event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authorization complete. You may close this tab.")

        def log_message(self, *args: object) -> None:
            pass

    class Server(socketserver.TCPServer):
        allow_reuse_address = True

    server = Server((host, port), Handler)
    server.timeout = 1

    import time

    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            server.handle_request()
            if event.is_set():
                break
    finally:
        server.server_close()

    code = result.get("code")
    if not code:
        raise TimeoutError("Authorization callback not received.")
    return code


def main() -> None:
    client_id = os.getenv("X_CLIENT_ID", "").strip()
    client_secret = os.getenv("X_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        print("Error: Set X_CLIENT_ID and X_CLIENT_SECRET in .env")
        return

    callback_host = os.getenv("X_OAUTH_CALLBACK_HOST", "127.0.0.1")
    callback_port = int(os.getenv("X_OAUTH_CALLBACK_PORT", "8976"))
    callback_path = "/oauth2/callback"
    redirect_uri = f"http://{callback_host}:{callback_port}{callback_path}"
    scopes = os.getenv("X_OAUTH2_SCOPES", DEFAULT_SCOPES)

    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    print(f"Opening browser for authorization...")
    print(f"Redirect URI: {redirect_uri}")
    print(f"(Register this URL in your X Developer App settings)\n")
    webbrowser.open(auth_url)

    code = wait_for_code(callback_host, callback_port, callback_path, timeout=300)
    print("Authorization code received. Exchanging for tokens...\n")

    with httpx.Client() as http_client:
        response = http_client.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            },
            auth=(client_id, client_secret),
        )
        if response.status_code != 200:
            print(f"Token exchange failed ({response.status_code}): {response.text}")
            return
        data = response.json()

    refresh_token = data.get("refresh_token", "")
    access_token = data.get("access_token", "")
    expires_in = data.get("expires_in", "?")

    print("=== Tokens ===")
    print(f"Access token (expires in {expires_in}s):")
    print(f"  {access_token}\n")
    print(f"Refresh token (save this):")
    print(f"  {refresh_token}\n")

    token_file = os.getenv("X_TOKEN_FILE", "").strip()
    if token_file:
        import json

        Path(token_file).write_text(
            json.dumps({"refresh_token": refresh_token}), encoding="utf-8"
        )
        print(f"Saved refresh token to {token_file}")
    else:
        print("Add to your .env:")
        print(f"  X_REFRESH_TOKEN={refresh_token}")


if __name__ == "__main__":
    main()
