"""Mock OpenID Connect provider for the contract suite.

Stands in for Microsoft Entra ID. It generates an RSA key at start-up with
`openssl genrsa` (deleted on exit), serves discovery and JWKS, and signs
RS256 ID tokens. No real tenant, app registration or secret is involved.

Codes are handed out by the test, not by a sign-in page:
  POST /_test/code {"oid","tid","email","name","groups","nonce"} -> {"code"}
Token exchange checks client_id, client_secret, redirect_uri and the PKCE
verifier against the challenge the authorise request sent (S256).

Usage (from suite.py): MockOidc().start() then .stop().
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class MockOidc:
    client_id = "tawny-contract-client"
    client_secret = "mock-client-secret-not-real"
    tid = "11111111-2222-4333-8444-555555555555"

    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="tawny-mock-oidc-")
        self.pem = os.path.join(self.dir, "key.pem")
        subprocess.run(["openssl", "genrsa", "-out", self.pem, "2048"], check=True, capture_output=True)
        modulus = subprocess.run(
            ["openssl", "rsa", "-in", self.pem, "-noout", "-modulus"], check=True, capture_output=True
        ).stdout.decode().strip().split("=", 1)[1]
        self.n = b64url(bytes.fromhex(modulus))
        self.kid = "mock-" + secrets.token_hex(4)
        self.codes: dict[str, dict] = {}
        self.pending: dict[str, dict] = {}
        self.token_overrides: dict[str, dict] = {}
        self.server: ThreadingHTTPServer | None = None
        self.base = ""

    @property
    def issuer(self) -> str:
        return f"{self.base}/{self.tid}/v2.0"

    def sign(self, claims: dict, kid: str | None = None) -> str:
        header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid or self.kid}, separators=(",", ":")).encode())
        payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode()
        sig = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.pem], input=signing_input, check=True, capture_output=True
        ).stdout
        return f"{header}.{payload}.{b64url(sig)}"

    def issue_code(self, *, oid: str, email: str, groups: list[str], nonce: str, challenge: str, name: str = "Mock User", overrides: dict | None = None) -> str:
        code = secrets.token_urlsafe(24)
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "tid": self.tid,
            "oid": oid,
            "email": email,
            "name": name,
            "groups": groups,
            "nonce": nonce,
            "iat": now,
            "nbf": now - 5,
            "exp": now + 600,
        }
        claims.update(overrides or {})
        self.codes[code] = {"claims": claims, "challenge": challenge}
        return code

    def start(self) -> "MockOidc":
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:  # quiet
                return

            def _json(self, code: int, body: object) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                path = urllib.parse.urlparse(self.path).path
                if path == f"/{mock.tid}/v2.0/.well-known/openid-configuration":
                    return self._json(200, {
                        "issuer": mock.issuer,
                        "authorization_endpoint": f"{mock.base}/{mock.tid}/oauth2/v2.0/authorize",
                        "token_endpoint": f"{mock.base}/{mock.tid}/oauth2/v2.0/token",
                        "jwks_uri": f"{mock.base}/{mock.tid}/discovery/v2.0/keys",
                        "id_token_signing_alg_values_supported": ["RS256"],
                    })
                if path == f"/{mock.tid}/discovery/v2.0/keys":
                    return self._json(200, {"keys": [{"kty": "RSA", "use": "sig", "kid": mock.kid, "n": mock.n, "e": "AQAB"}]})
                return self._json(404, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode()
                path = urllib.parse.urlparse(self.path).path
                if path != f"/{mock.tid}/oauth2/v2.0/token":
                    return self._json(404, {"error": "not_found"})
                form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
                if form.get("grant_type") != "authorization_code":
                    return self._json(400, {"error": "unsupported_grant_type"})
                if form.get("client_id") != mock.client_id or form.get("client_secret") != mock.client_secret:
                    return self._json(401, {"error": "invalid_client"})
                entry = mock.codes.pop(form.get("code", ""), None)
                if entry is None:
                    return self._json(400, {"error": "invalid_grant"})
                verifier = form.get("code_verifier", "")
                if b64url(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
                    return self._json(400, {"error": "invalid_grant", "error_description": "PKCE"})
                return self._json(200, {"token_type": "Bearer", "id_token": mock.sign(entry["claims"]), "access_token": "unused"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
        shutil.rmtree(self.dir, ignore_errors=True)
