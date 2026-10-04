#!/usr/bin/env python3
"""Black-box HTTP contract suite. Stdlib only. See README.md."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("TAWNY_BASE_URL", "http://127.0.0.1:5080").rstrip("/")
AUTH = os.environ.get("TAWNY_CONTRACT_AUTH", "hmac").strip().lower()
HMAC_SECRET = os.environ.get("TAWNY_HMAC_SECRET", "test-hmac-secret")
TENANT = os.environ.get("TAWNY_TENANT_ID", "00000000-0000-0000-0000-000000000001")
ADMIN_ID = os.environ.get("TAWNY_ADMIN_USER_ID", "00000000-0000-0000-0000-0000000000aa")
SESSION_COOKIE = os.environ.get("TAWNY_SESSION_COOKIE", "")
SESSION_BEARER = os.environ.get("TAWNY_SESSION_BEARER", "")
CSRF = os.environ.get("TAWNY_CSRF_TOKEN", "")

if AUTH not in ("hmac", "session"):
    raise SystemExit(f"TAWNY_CONTRACT_AUTH must be hmac or session, got {AUTH!r}")

# Enroll limiter is 10/minute/IP and runs before the action, including 400s.
# Full-suite posts before the rate-limit test: windows, linux, routine, revoke,
# other-agent A, other-agent B, and 3 rejected identities (9).
_enroll_posts = 0
_rate_limit_phase = False
_windows: dict | None = None


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="-_.~")


def canonical_query(path_and_query: str) -> str:
    q = path_and_query.find("?")
    if q < 0 or q == len(path_and_query) - 1:
        return ""
    pairs: list[tuple[str, str]] = []
    for part in path_and_query[q + 1 :].split("&"):
        if part == "":
            continue
        if "=" not in part:
            key, value = urllib.parse.unquote_plus(part), ""
        else:
            raw_key, raw_value = part.split("=", 1)
            key = urllib.parse.unquote_plus(raw_key)
            value = urllib.parse.unquote_plus(raw_value)
        pairs.append((key, value))
    pairs.sort(key=lambda item: (item[0], item[1]))
    return "&".join(f"{_quote(key)}={_quote(value)}" for key, value in pairs)


def path_only(path_and_query: str) -> str:
    q = path_and_query.find("?")
    return path_and_query if q < 0 else path_and_query[:q]


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign(secret: str, canonical: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def dumps(obj: object) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def uniq(prefix: str) -> str:
    return f"ct-{prefix}-{uuid.uuid4().hex[:10]}"


def now_s() -> int:
    return int(time.time())


def call(
    method: str,
    path: str,
    body: dict | list | bytes | None = None,
    *,
    auth: str = "web",
    bearer: str | None = None,
    role: str = "Admin",
    sign_role: str | None = None,
    user_id: str | None = None,
    tenant: str | None = None,
    secret: str | None = None,
    unix_ts: int | None = None,
    nonce: str | None = None,
    sign_path: str | None = None,
    sign_body: bytes | None = None,
    session_cookie: str | None = None,
    csrf_token: str | None = None,
    omit_csrf: bool = False,
) -> tuple[int, object | None, str]:
    raw: bytes | None
    if isinstance(body, (dict, list)):
        raw = dumps(body)
        content_type = "application/json"
    elif isinstance(body, bytes):
        raw = body
        content_type = "application/json"
    else:
        raw = None
        content_type = ""

    signed_bytes = sign_body if sign_body is not None else (raw or b"")
    headers: dict[str, str] = {}
    if content_type:
        headers["Content-Type"] = content_type

    if auth == "web":
        if AUTH == "session":
            ensure_session()
        uid = user_id or ADMIN_ID
        tid = tenant or TENANT
        sent_role = role
        signed_role = sign_role or role
        if AUTH == "hmac":
            ts = str(unix_ts if unix_ts is not None else now_s())
            nonce_value = nonce or secrets.token_hex(16)
            signed_path = sign_path or path
            canonical = "\n".join(
                [
                    "v2",
                    method.upper(),
                    path_only(signed_path),
                    canonical_query(signed_path),
                    sha256_hex(signed_bytes),
                    content_type,
                    uid,
                    signed_role,
                    tid,
                    ts,
                    nonce_value,
                ]
            )
            headers["X-User-Id"] = uid
            headers["X-User-Role"] = sent_role
            headers["X-Tenant-Id"] = tid
            headers["X-Timestamp"] = ts
            headers["X-Nonce"] = nonce_value
            headers["X-Signature"] = sign(secret if secret is not None else HMAC_SECRET, canonical)
        else:
            headers["X-User-Id"] = uid
            headers["X-User-Role"] = sent_role
            headers["X-Tenant-Id"] = tid
            cookie = session_cookie if session_cookie is not None else SESSION_COOKIE
            csrf_value = "" if omit_csrf else (csrf_token if csrf_token is not None else CSRF)
            if cookie:
                headers["Cookie"] = cookie
            if SESSION_BEARER and session_cookie is None:
                headers["Authorization"] = f"Bearer {SESSION_BEARER}"
            if csrf_value and method.upper() not in ("GET", "HEAD"):
                headers["X-CSRF-Token"] = csrf_value
    elif auth in ("agent", "api"):
        if not bearer:
            raise AssertionError(f"{auth} call missing bearer")
        headers["Authorization"] = f"Bearer {bearer}"

    req = urllib.request.Request(
        BASE + path,
        data=raw,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            code = resp.status
            payload = resp.read()
    except urllib.error.HTTPError as err:
        code = err.code
        payload = err.read()
    except urllib.error.URLError as err:
        raise AssertionError(f"{method} {path} failed: {err}") from err

    text = payload.decode("utf-8", errors="replace")
    parsed: object | None = None
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return code, parsed, text


def ensure_session() -> None:
    """Session mode logs in once. HMAC mode never calls this."""
    global SESSION_COOKIE, CSRF
    if SESSION_COOKIE and CSRF:
        return
    email = os.environ.get("TAWNY_CONTRACT_EMAIL", "admin@tawny.local")
    password = os.environ.get("TAWNY_CONTRACT_PASSWORD", "contract-password")
    req = urllib.request.Request(
        BASE + "/api/auth/login",
        data=dumps({"email": email, "password": password}),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            set_cookie = resp.headers.get("Set-Cookie") or ""
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        raise AssertionError(f"session login failed: {err.code} {body[:500]}") from err
    parsed = json.loads(payload.decode("utf-8"))
    token = parsed.get("csrf_token")
    if not isinstance(token, str) or not token:
        raise AssertionError(f"session login missing csrf_token: {payload[:300]!r}")
    name = "tawny_session="
    if not set_cookie.startswith(name):
        raise AssertionError(f"session login missing cookie: {set_cookie!r}")
    raw_cookie = set_cookie.split(";", 1)[0]
    SESSION_COOKIE = raw_cookie
    CSRF = token


def note_enroll() -> None:
    global _enroll_posts
    if not _rate_limit_phase and _enroll_posts >= 10:
        raise AssertionError("enroll budget exceeded before rate-limit test")
    _enroll_posts += 1


def create_enrollment_token() -> str:
    code, parsed, raw = call("POST", "/api/enrollment-tokens", {"lifetime_hours": 1})
    if code != 200 or not isinstance(parsed, dict) or "token" not in parsed:
        raise AssertionError(f"enrollment token {code}: {raw[:500]}")
    return str(parsed["token"])


def enroll_host(
    prefix: str,
    os_name: str,
    os_version: str,
    arch: str,
    *,
    device_public_key: str | None = None,
    agent_version: str = "0.1.0",
) -> dict:
    hostname = uniq(prefix)
    token = create_enrollment_token()
    body: dict = {
        "enrollment_token": token,
        "hostname": hostname,
        "os": os_name,
        "os_version": os_version,
        "arch": arch,
        "agent_version": agent_version,
    }
    if device_public_key is not None:
        body["device_public_key"] = device_public_key
    note_enroll()
    code, parsed, raw = call("POST", "/api/agents/enroll", body, auth="none")
    if code != 200 or not isinstance(parsed, dict):
        raise AssertionError(f"enroll {hostname} {code}: {raw[:500]}")
    for key in ("agent_id", "jwt", "jwt_expires_at", "config"):
        if key not in parsed:
            raise AssertionError(f"enroll missing {key}: {raw[:500]}")
    agent_id = parsed["agent_id"]
    gcode, summary, graw = call("GET", f"/api/agents/{agent_id}")
    if gcode != 200 or not isinstance(summary, dict):
        raise AssertionError(f"get agent {gcode}: {graw[:500]}")
    return {
        "agent_id": agent_id,
        "jwt": parsed["jwt"],
        "hostname": hostname,
        "config": parsed["config"],
        "summary": summary,
    }


def windows_agent() -> dict:
    global _windows
    if _windows is None:
        _windows = enroll_host("win", "windows", "11", "x64")
    return _windows


def post_events(agent: dict, events: list[dict], *, batch_id: str | None = None) -> tuple[int, object | None, str]:
    body: dict = {"events": events}
    if batch_id is not None:
        body["batch_id"] = batch_id
    return call("POST", "/api/agents/events", body, auth="agent", bearer=agent["jwt"])


def event(event_type: str, payload: dict, **extra: object) -> dict:
    row = {
        "type": event_type,
        "occurred_at": now_s(),
        "payload": payload,
    }
    row.update(extra)
    return row


def wait_alerts(pred, count: int = 1, timeout: float = 8.0) -> list[dict]:
    deadline = time.time() + timeout
    last: object = None
    while True:
        code, rows, raw = call("GET", "/api/alerts?limit=100")
        if code != 200 or not isinstance(rows, list):
            raise AssertionError(f"alerts {code}: {raw[:500]}")
        found = [row for row in rows if isinstance(row, dict) and pred(row)]
        last = found
        if len(found) >= count:
            return found
        if time.time() >= deadline:
            raise AssertionError(f"wanted {count} alerts, saw {len(found)}: {last}")
        time.sleep(0.25)


def login_session(email: str, password: str) -> tuple[str, str, dict]:
    req = urllib.request.Request(
        BASE + "/api/auth/login",
        data=dumps({"email": email, "password": password}),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            set_cookie = resp.headers.get("Set-Cookie") or ""
            code = resp.status
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        raise AssertionError(f"login {email} failed: {err.code} {body[:500]}") from err
    parsed = json.loads(payload.decode("utf-8"))
    if code != 200 or not isinstance(parsed, dict):
        raise AssertionError(f"login {email} {code}: {payload[:300]!r}")
    token = parsed.get("csrf_token")
    if not isinstance(token, str) or not token:
        raise AssertionError(f"login missing csrf_token: {payload[:300]!r}")
    if not set_cookie.startswith("tawny_session="):
        raise AssertionError(f"login missing session cookie: {set_cookie!r}")
    return set_cookie.split(";", 1)[0], token, parsed


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def open_no_redirect(method: str, path: str, *, cookie: str | None = None) -> tuple[int, str, str, str]:
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(BASE + path, headers=headers, method=method.upper())
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, resp.headers.get("Location") or "", resp.headers.get("Set-Cookie") or "", body
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        location = err.headers.get("Location") if err.headers else ""
        set_cookie = err.headers.get("Set-Cookie") if err.headers else ""
        return err.code, location or "", set_cookie or "", body


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_rs256(pem_path: str, signing_input: bytes) -> str:
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", pem_path],
        input=signing_input,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr.decode("utf-8", errors="replace")[:500])
    return b64url(proc.stdout)


def require_hmac(test: unittest.TestCase) -> None:
    if AUTH != "hmac":
        test.skipTest("HMAC signature check; session mode does not sign")


def assert_snake_id(test: unittest.TestCase, row: dict) -> None:
    test.assertIn("agent_id", row)
    test.assertNotIn("agentId", row)


class ContractTests(unittest.TestCase):
    def test_health_anonymous(self) -> None:
        code, parsed, raw = call("GET", "/api/health", auth="none")
        self.assertEqual(code, 200, raw[:500])
        self.assertIsInstance(parsed, dict)
        assert isinstance(parsed, dict)
        self.assertEqual(parsed.get("status"), "ok")
        self.assertIn("time", parsed)

    def test_signed_request_accepted(self) -> None:
        require_hmac(self)
        code, parsed, raw = call("GET", "/api/agents")
        self.assertEqual(code, 200, raw[:500])
        self.assertIsInstance(parsed, list)

    def test_bad_signature_rejected(self) -> None:
        require_hmac(self)
        code, _parsed, raw = call(
            "GET",
            "/api/agents",
            secret="wrong-secret-that-is-long-enough-32b!",
        )
        self.assertEqual(code, 401, raw[:500])

    def test_stale_timestamp_rejected(self) -> None:
        require_hmac(self)
        code, _parsed, raw = call("GET", "/api/agents", unix_ts=now_s() - 300)
        self.assertEqual(code, 401, raw[:500])

    def test_body_tamper_rejected(self) -> None:
        require_hmac(self)
        signed = b'{"lifetime_hours":24}'
        sent = b'{"lifetime_hours":1}'
        code, _parsed, raw = call(
            "POST",
            "/api/enrollment-tokens",
            sent,
            sign_body=signed,
        )
        self.assertEqual(code, 401, raw[:500])

    def test_query_tamper_rejected(self) -> None:
        require_hmac(self)
        code, _parsed, raw = call(
            "GET",
            "/api/agents?limit=999",
            sign_path="/api/agents?limit=1",
        )
        self.assertEqual(code, 401, raw[:500])

    def test_nonce_replay_rejected(self) -> None:
        require_hmac(self)
        nonce = secrets.token_hex(16)
        first, _parsed, raw = call("GET", "/api/agents", nonce=nonce)
        self.assertEqual(first, 200, raw[:500])
        second, _parsed2, raw2 = call("GET", "/api/agents", nonce=nonce)
        self.assertEqual(second, 401, raw2[:500])

    def test_role_header_change_rejected(self) -> None:
        require_hmac(self)
        code, _parsed, raw = call("GET", "/api/agents", role="Viewer", sign_role="Admin")
        self.assertEqual(code, 401, raw[:500])

    def test_enroll_heartbeat_and_events(self) -> None:
        agent = windows_agent()
        assert_snake_id(self, {"agent_id": agent["agent_id"]})
        self.assertIsInstance(agent["config"], dict)
        self.assertEqual(agent["config"].get("heartbeat_interval_seconds"), 60)
        self.assertNotIn("heartbeatIntervalSeconds", agent["config"])
        hb_code, hb, hb_raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.1", "uptime_seconds": 42, "buffer_depth": 0},
            auth="agent",
            bearer=agent["jwt"],
        )
        self.assertEqual(hb_code, 200, hb_raw[:500])
        self.assertIsInstance(hb, dict)
        assert isinstance(hb, dict)
        self.assertIn("actions", hb)
        self.assertNotIn("Actions", hb)
        ev_code, _ev, ev_raw = post_events(
            agent,
            [event("process_snapshot", {"processes": []})],
        )
        self.assertEqual(ev_code, 202, ev_raw[:500])
        path = f"/api/agents/{agent['agent_id']}/events?type=process_snapshot&limit=50"
        read_code, rows, read_raw = call("GET", path)
        self.assertEqual(read_code, 200, read_raw[:500])
        self.assertIsInstance(rows, list)
        assert isinstance(rows, list)
        self.assertTrue(
            any(
                isinstance(row, dict)
                and row.get("agent_id") == agent["agent_id"]
                and row.get("type") == "process_snapshot"
                for row in rows
            ),
            read_raw[:500],
        )

    def test_client_event_id_dedupe(self) -> None:
        agent = windows_agent()
        client_event_id = str(uuid.uuid4())
        body = [
            event(
                "system_info",
                {"platform": "linux"},
                client_event_id=client_event_id,
            )
        ]
        first, _a, raw1 = post_events(agent, body)
        second, _b, raw2 = post_events(agent, body)
        self.assertEqual(first, 202, raw1[:500])
        self.assertEqual(second, 202, raw2[:500])
        path = f"/api/agents/{agent['agent_id']}/events?type=system_info&limit=200"
        code, rows, raw = call("GET", path)
        self.assertEqual(code, 200, raw[:500])
        assert isinstance(rows, list)
        matches = [row for row in rows if isinstance(row, dict) and row.get("client_event_id") == client_event_id]
        self.assertEqual(len(matches), 1, raw[:800])

    def test_client_event_replay_confidence(self) -> None:
        agent = windows_agent()
        client_event_id = str(uuid.uuid4())
        body = [
            event(
                "system_info",
                {"hostname": agent["hostname"]},
                client_event_id=client_event_id,
                sequence=1,
            )
        ]
        first, _a, raw1 = post_events(agent, body)
        second, _b, raw2 = post_events(agent, body)
        self.assertEqual(first, 202, raw1[:500])
        self.assertEqual(second, 202, raw2[:500])
        path = f"/api/agents/{agent['agent_id']}/events?type=system_info&limit=200"
        code, rows, raw = call("GET", path)
        self.assertEqual(code, 200, raw[:500])
        assert isinstance(rows, list)
        matches = [row for row in rows if isinstance(row, dict) and row.get("client_event_id") == client_event_id]
        self.assertEqual(len(matches), 1, raw[:800])
        row = matches[0]
        self.assertEqual(row.get("confidence"), "agent_reported")
        self.assertTrue(row.get("batch_id"))
        self.assertIn("agent_id", row)
        self.assertNotIn("agentId", row)

    def test_linux_enroll_device_public_key(self) -> None:
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        agent = enroll_host(
            "lin",
            "linux",
            "6.12.0-aws",
            "arm64",
            device_public_key=key,
            agent_version="0.1.0",
        )
        summary = agent["summary"]
        self.assertEqual(summary.get("operating_system"), "linux")
        self.assertEqual(summary.get("architecture"), "arm64")
        self.assertEqual(summary.get("hostname"), agent["hostname"])
        self.assertEqual(summary.get("status"), "online")
        self.assertNotIn("device_public_key", summary)
        self.assertNotIn("operatingSystem", summary)

    def test_enroll_rejects_control_hostname(self) -> None:
        code, _parsed, raw = self._rejected_enroll("host\ninjected", "linux", "arm64")
        self.assertEqual(code, 400, raw[:800])
        self.assertIn("hostname must not contain control characters.", raw)

    def test_enroll_rejects_freebsd(self) -> None:
        code, _parsed, raw = self._rejected_enroll("host", "freebsd", "arm64")
        self.assertEqual(code, 400, raw[:800])
        self.assertIn("os must be windows, macos, or linux.", raw)

    def test_enroll_rejects_sparc(self) -> None:
        code, _parsed, raw = self._rejected_enroll("host", "linux", "sparc")
        self.assertEqual(code, 400, raw[:800])
        self.assertIn("arch must be x64/amd64/x86_64 or arm64/aarch64.", raw)

    def test_heartbeat_rejects_negative_counters(self) -> None:
        agent = windows_agent()
        code, _parsed, raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.0", "uptime_seconds": -1, "buffer_depth": -1},
            auth="agent",
            bearer=agent["jwt"],
        )
        self.assertEqual(code, 400, raw[:800])
        self.assertIn("Uptime", raw)

    def test_native_rule_creates_alert(self) -> None:
        agent = windows_agent()
        marker = uniq("proc")
        name = uniq("rule")
        code, _rule, raw = call(
            "POST",
            "/api/alert-rules",
            {
                "name": name,
                "event_type": "process_snapshot",
                "severity": "high",
                "operator": "contains",
                "payload_path": "processes.name",
                "match_value": marker,
                "is_enabled": True,
                "mitre_techniques": ["T1059"],
            },
        )
        self.assertEqual(code, 201, raw[:800])
        ev_code, _ev, ev_raw = post_events(
            agent,
            [event("process_snapshot", {"processes": [{"name": marker, "pid": 4242}]})],
        )
        self.assertEqual(ev_code, 202, ev_raw[:500])
        found = wait_alerts(lambda row: row.get("title") == f"{name} on {agent['hostname']}")
        alert = found[0]
        self.assertEqual(alert.get("severity"), "high")
        self.assertEqual(alert.get("status"), "open")
        self.assertIn("mitre_techniques", alert)
        self.assertNotIn("mitreTechniques", alert)

    def test_sigma_import_creates_alert(self) -> None:
        agent = windows_agent()
        marker = uniq("sig")
        title = uniq("sigma")
        external_id = str(uuid.uuid4())
        rule_yaml = f"""title: {title}
id: {external_id}
status: experimental
description: Contract sigma match.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.name|contains: {marker}
  condition: selection
level: high
"""
        code, parsed, raw = call("POST", "/api/alert-rules/sigma", {"rule_yaml": rule_yaml})
        self.assertEqual(code, 201, raw[:800])
        self.assertIsInstance(parsed, dict)
        assert isinstance(parsed, dict)
        self.assertEqual(parsed.get("format"), "sigma")
        self.assertEqual(parsed.get("external_id"), external_id)
        self.assertEqual(parsed.get("event_type"), "process_snapshot")
        self.assertEqual(parsed.get("payload_path"), "processes.name")
        self.assertNotIn("externalId", parsed)
        ev_code, _ev, ev_raw = post_events(
            agent,
            [event("process_snapshot", {"processes": [{"name": f"very-{marker}.exe", "pid": 4242}]})],
        )
        self.assertEqual(ev_code, 202, ev_raw[:500])
        found = wait_alerts(lambda row: isinstance(row.get("title"), str) and title in row["title"])
        self.assertEqual(found[0].get("severity"), "high")

    def test_sigma_rejects_modifier_re(self) -> None:
        rule_yaml = f"""title: {uniq("badmod")}
detection:
  selection:
    processes.name|re: suspicious.exe
  condition: selection
level: high
"""
        code, _parsed, raw = call("POST", "/api/alert-rules/sigma", {"rule_yaml": rule_yaml})
        self.assertEqual(code, 400, raw[:800])
        self.assertIn("Unsupported Sigma field modifier 're'", raw)

    def test_stix_ioc_creates_alert(self) -> None:
        agent = windows_agent()
        host = f"{uuid.uuid4().hex[:8]}.example.com"
        ip = f"203.0.113.{secrets.randbelow(200) + 20}"
        sha256 = secrets.token_hex(32)
        stix = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "name": uniq("stix"),
                    "pattern_type": "stix",
                    "pattern": (
                        f"[ipv4-addr:value = '{ip}'] OR "
                        f"[domain-name:value = '{host}'] OR "
                        f"[file:hashes.'SHA-256' = '{sha256}']"
                    ),
                }
            ],
        }
        code, parsed, raw = call(
            "POST",
            "/api/alert-rules/iocs",
            {"definition": json.dumps(stix), "source_format": "stix"},
        )
        self.assertEqual(code, 201, raw[:800])
        self.assertIsInstance(parsed, dict)
        assert isinstance(parsed, dict)
        rules = parsed.get("rules")
        self.assertIsInstance(rules, list)
        assert isinstance(rules, list)
        self.assertEqual(len(rules), 4, raw[:800])
        paths = {row.get("payload_path") for row in rules if isinstance(row, dict)}
        self.assertEqual(
            paths,
            {"connections.remote_address", "new_sha256", "processes.command_line", "qname"},
        )
        self.assertTrue(all(isinstance(row, dict) and row.get("format") == "ioc" for row in rules))
        ev_code, _ev, ev_raw = post_events(
            agent,
            [
                event(
                    "network_snapshot",
                    {"connections": [{"remote_address": ip, "remote_port": 443}]},
                )
            ],
        )
        self.assertEqual(ev_code, 202, ev_raw[:500])
        found = wait_alerts(
            lambda row: row.get("hostname") == agent["hostname"]
            and isinstance(row.get("title"), str)
            and "IoC IP" in row["title"]
            and ip in row["title"]
        )
        self.assertEqual(found[0].get("severity"), "high")

    def test_raw_ioc_skips_md5(self) -> None:
        md5 = secrets.token_hex(16)
        sha1 = secrets.token_hex(20)
        definition = f"Hash list from advisory:\n{md5}\n{sha1}\n"
        code, parsed, raw = call(
            "POST",
            "/api/alert-rules/iocs",
            {"definition": definition, "source_format": "raw", "severity": "critical"},
        )
        self.assertEqual(code, 201, raw[:800])
        self.assertIsInstance(parsed, dict)
        assert isinstance(parsed, dict)
        self.assertIn("rules", parsed)
        self.assertIn("skipped_indicators", parsed)
        self.assertNotIn("skippedIndicators", parsed)
        rules = parsed["rules"]
        skipped = parsed["skipped_indicators"]
        self.assertIsInstance(rules, list)
        self.assertIsInstance(skipped, list)
        assert isinstance(rules, list) and isinstance(skipped, list)
        self.assertEqual(len(rules), 1, raw[:800])
        self.assertEqual(len(skipped), 1, raw[:800])
        self.assertIn("MD5", skipped[0])
        self.assertEqual(rules[0].get("payload_path"), "new_sha1")
        self.assertEqual(rules[0].get("severity"), "critical")

    def test_sigma_metadata_update_keeps_format(self) -> None:
        external_id = str(uuid.uuid4())
        title = uniq("meta")
        rule_yaml = f"""title: {title}
id: {external_id}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.name|contains: {uniq("exe")}
  condition: selection
level: high
"""
        code, rule, raw = call("POST", "/api/alert-rules/sigma", {"rule_yaml": rule_yaml})
        self.assertEqual(code, 201, raw[:800])
        assert isinstance(rule, dict)
        renamed = uniq("renamed")
        put_code, updated, put_raw = call(
            "PUT",
            f"/api/alert-rules/{rule['id']}",
            {
                "name": renamed,
                "event_type": rule.get("event_type"),
                "severity": "critical",
                "operator": rule.get("operator"),
                "payload_path": rule.get("payload_path"),
                "match_value": rule.get("match_value"),
                "is_enabled": False,
                "mitre_techniques": ["T1059"],
            },
        )
        self.assertEqual(put_code, 200, put_raw[:800])
        assert isinstance(updated, dict)
        self.assertEqual(updated.get("format"), "sigma")
        self.assertEqual(updated.get("external_id"), external_id)
        self.assertEqual(updated.get("source_definition"), rule_yaml)
        self.assertEqual(updated.get("name"), renamed)
        self.assertEqual(updated.get("severity"), "critical")
        self.assertIs(updated.get("is_enabled"), False)
        self.assertEqual(updated.get("mitre_techniques"), ["T1059"])

    def test_sigma_multi_selection_disable(self) -> None:
        external_id = str(uuid.uuid4())
        rule_yaml = f"""title: {uniq("multi")}
id: {external_id}
logsource:
  product: windows
  category: process_creation
detection:
  a:
    processes.name|contains: powershell
  b:
    processes.command_line|contains: -enc
  condition: a and b
level: high
"""
        code, rule, raw = call("POST", "/api/alert-rules/sigma", {"rule_yaml": rule_yaml})
        self.assertEqual(code, 201, raw[:800])
        assert isinstance(rule, dict)
        self.assertIsNone(rule.get("match_value"))
        put_code, updated, put_raw = call(
            "PUT",
            f"/api/alert-rules/{rule['id']}",
            {
                "name": rule.get("name"),
                "event_type": rule.get("event_type"),
                "severity": "high",
                "operator": rule.get("operator"),
                "payload_path": rule.get("payload_path"),
                "match_value": rule.get("match_value"),
                "is_enabled": False,
            },
        )
        self.assertEqual(put_code, 200, put_raw[:800])
        assert isinstance(updated, dict)
        self.assertIs(updated.get("is_enabled"), False)
        self.assertEqual(updated.get("format"), "sigma")

    def test_sigma_match_logic_change_rejected(self) -> None:
        external_id = str(uuid.uuid4())
        rule_yaml = f"""title: {uniq("lock")}
id: {external_id}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.name|contains: {uniq("exe")}
  condition: selection
level: high
"""
        code, rule, raw = call("POST", "/api/alert-rules/sigma", {"rule_yaml": rule_yaml})
        self.assertEqual(code, 201, raw[:800])
        assert isinstance(rule, dict)
        put_code, _updated, put_raw = call(
            "PUT",
            f"/api/alert-rules/{rule['id']}",
            {
                "name": rule.get("name"),
                "event_type": rule.get("event_type"),
                "severity": "high",
                "operator": rule.get("operator"),
                "payload_path": rule.get("payload_path"),
                "match_value": "something-else.exe",
                "is_enabled": True,
            },
        )
        self.assertEqual(put_code, 409, put_raw[:800])
        self.assertIn("cannot have their match logic edited", put_raw)

    def test_alerts_page_after_id_mitre_agent_os(self) -> None:
        agent = windows_agent()
        marker = uniq("page")
        name = uniq("page-rule")
        code, _rule, raw = call(
            "POST",
            "/api/alert-rules",
            {
                "name": name,
                "event_type": "process_snapshot",
                "severity": "high",
                "operator": "contains",
                "payload_path": "processes.name",
                "match_value": marker,
                "is_enabled": True,
                "mitre_techniques": ["T1059.001"],
            },
        )
        self.assertEqual(code, 201, raw[:800])
        listed, existing, list_raw = call("GET", "/api/alerts?limit=500")
        self.assertEqual(listed, 200, list_raw[:500])
        assert isinstance(existing, list)
        after = max((row["id"] for row in existing if isinstance(row, dict)), default=0)
        for _ in range(3):
            ev_code, _ev, ev_raw = post_events(
                agent,
                [event("process_snapshot", {"processes": [{"name": marker, "pid": 7}]})],
            )
            self.assertEqual(ev_code, 202, ev_raw[:400])
        wait_alerts(lambda row: row.get("title") == f"{name} on {agent['hostname']}", count=3)
        viewer = self._api_token("viewer", "viewer")
        page1_code, page1, page1_raw = call(
            "GET",
            f"/api/alerts?after_id={after}&limit=2",
            auth="api",
            bearer=viewer,
        )
        self.assertEqual(page1_code, 200, page1_raw[:800])
        self.assertIsInstance(page1, list)
        assert isinstance(page1, list)
        self.assertEqual(len(page1), 2, page1_raw[:800])
        self.assertLess(page1[0]["id"], page1[1]["id"])
        for row in page1:
            self.assertEqual(row.get("agent_id"), agent["agent_id"])
            self.assertEqual(row.get("hostname"), agent["hostname"])
            self.assertEqual(row.get("mitre_techniques"), ["T1059.001"])
            self.assertEqual(row.get("agent_os"), "windows")
            self.assertNotIn("agentOs", row)
            self.assertNotIn("mitreTechniques", row)
        page2_code, page2, page2_raw = call(
            "GET",
            f"/api/alerts?after_id={page1[1]['id']}&limit=2",
            auth="api",
            bearer=viewer,
        )
        self.assertEqual(page2_code, 200, page2_raw[:800])
        assert isinstance(page2, list)
        self.assertEqual(len(page2), 1, page2_raw[:800])
        self.assertGreater(page2[0]["id"], page1[1]["id"])
        page3_code, page3, page3_raw = call(
            "GET",
            f"/api/alerts?after_id={page2[0]['id']}&limit=2",
            auth="api",
            bearer=viewer,
        )
        self.assertEqual(page3_code, 200, page3_raw[:500])
        self.assertEqual(page3, [])
        one_code, one, one_raw = call(
            "GET",
            f"/api/alerts/{page1[0]['id']}",
            auth="api",
            bearer=viewer,
        )
        self.assertEqual(one_code, 200, one_raw[:500])
        assert isinstance(one, dict)
        self.assertEqual(one.get("id"), page1[0]["id"])
        actions_code, _actions, actions_raw = call(
            "GET",
            f"/api/agents/{agent['agent_id']}/actions",
            auth="api",
            bearer=viewer,
        )
        self.assertEqual(actions_code, 200, actions_raw[:500])
        sigma_code, _sigma, sigma_raw = call(
            "POST",
            "/api/alert-rules/sigma",
            {"rule_yaml": "title: x"},
            auth="api",
            bearer=viewer,
        )
        self.assertEqual(sigma_code, 403, sigma_raw[:500])

    def test_api_token_inventory_and_admin_action(self) -> None:
        agent = windows_agent()
        viewer = self._api_token("inv-viewer", "viewer")
        admin = self._api_token("inv-admin", "admin")
        code, rows, raw = call("GET", "/api/agents", auth="api", bearer=viewer)
        self.assertEqual(code, 200, raw[:500])
        assert isinstance(rows, list)
        self.assertTrue(
            any(isinstance(row, dict) and row.get("id") == agent["agent_id"] for row in rows),
            raw[:500],
        )
        self.assertTrue(all("hostname" in row and "operating_system" in row for row in rows if isinstance(row, dict)))
        denied, _d, denied_raw = call(
            "POST",
            f"/api/agents/{agent['agent_id']}/actions",
            {"action_type": "isolate_host", "payload": {"reason": "synthetic test"}},
            auth="api",
            bearer=viewer,
        )
        self.assertEqual(denied, 403, denied_raw[:500])
        created, action, created_raw = call(
            "POST",
            f"/api/agents/{agent['agent_id']}/actions",
            {
                "action_type": "isolate_host",
                "payload": {"reason": "synthetic test"},
                "idempotency_key": uniq("iso"),
            },
            auth="api",
            bearer=admin,
        )
        self.assertEqual(created, 201, created_raw[:800])
        assert isinstance(action, dict)
        self.assertIn("id", action)
        self.assertEqual(action.get("action_type"), "isolate_host")
        listed, actions, list_raw = call(
            "GET",
            f"/api/agents/{agent['agent_id']}/actions",
            auth="api",
            bearer=admin,
        )
        self.assertEqual(listed, 200, list_raw[:500])
        assert isinstance(actions, list)
        self.assertTrue(any(isinstance(row, dict) and row.get("id") == action["id"] for row in actions))

    def test_admin_token_sigma_and_action(self) -> None:
        agent = windows_agent()
        admin = self._api_token("sigma-admin", "admin")
        external_id = str(uuid.uuid4())
        rule_yaml = f"""title: {uniq("enc")}
id: {external_id}
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.command_line|contains: {uniq("enc")}
  condition: selection
level: high
"""
        code, rule, raw = call(
            "POST",
            "/api/alert-rules/sigma",
            {"rule_yaml": rule_yaml},
            auth="api",
            bearer=admin,
        )
        self.assertEqual(code, 201, raw[:800])
        assert isinstance(rule, dict)
        for key in ("id", "name", "event_type", "operator", "payload_path", "match_value"):
            self.assertIn(key, rule)
        put_code, _updated, put_raw = call(
            "PUT",
            f"/api/alert-rules/{rule['id']}",
            {
                "name": rule["name"],
                "event_type": rule["event_type"],
                "severity": "high",
                "operator": rule["operator"],
                "payload_path": rule["payload_path"],
                "match_value": rule["match_value"],
                "is_enabled": False,
            },
            auth="api",
            bearer=admin,
        )
        self.assertEqual(put_code, 200, put_raw[:800])
        del_code, _deleted, del_raw = call(
            "DELETE",
            f"/api/alert-rules/{rule['id']}",
            auth="api",
            bearer=admin,
        )
        self.assertEqual(del_code, 204, del_raw[:400])
        created, action, created_raw = call(
            "POST",
            f"/api/agents/{agent['agent_id']}/actions",
            {
                "action_type": "release_host",
                "payload": {},
                "idempotency_key": uniq("rel"),
            },
            auth="api",
            bearer=admin,
        )
        self.assertEqual(created, 201, created_raw[:800])
        assert isinstance(action, dict)
        got, fetched, got_raw = call(
            "GET",
            f"/api/agents/{agent['agent_id']}/actions/{action['id']}",
            auth="api",
            bearer=admin,
        )
        self.assertEqual(got, 200, got_raw[:500])
        assert isinstance(fetched, dict)
        self.assertEqual(fetched.get("id"), action["id"])
        agent_code, summary, agent_raw = call(
            "GET",
            f"/api/agents/{agent['agent_id']}",
            auth="api",
            bearer=admin,
        )
        self.assertEqual(agent_code, 200, agent_raw[:500])
        assert isinstance(summary, dict)
        self.assertIn("public_ip", summary)
        self.assertIn("tags", summary)
        self.assertIsInstance(summary["tags"], list)

    def test_response_action_dispatch_and_result(self) -> None:
        agent = windows_agent()
        pid = 20000 + secrets.randbelow(10000)
        created, action, created_raw = call(
            "POST",
            f"/api/agents/{agent['agent_id']}/actions",
            {"action_type": "kill_process", "payload": {"pid": pid}},
        )
        self.assertIn(created, (200, 201), created_raw[:800])
        hb_code, hb, hb_raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.1", "uptime_seconds": 42, "buffer_depth": 0},
            auth="agent",
            bearer=agent["jwt"],
        )
        self.assertEqual(hb_code, 200, hb_raw[:800])
        assert isinstance(hb, dict)
        actions = hb.get("actions")
        self.assertIsInstance(actions, list)
        assert isinstance(actions, list)
        match = next(
            (
                row
                for row in actions
                if isinstance(row, dict)
                and row.get("action_type") == "kill_process"
                and isinstance(row.get("payload"), dict)
                and row["payload"].get("pid") == pid
            ),
            None,
        )
        self.assertIsNotNone(match, hb_raw[:800])
        assert isinstance(match, dict)
        self.assertTrue(match.get("execution_token"))
        self.assertIn("payload_hash", match)
        result_code, _result, result_raw = call(
            "POST",
            f"/api/agents/actions/{match['id']}/result",
            {
                "status": "succeeded",
                "execution_token": match["execution_token"],
                "message": "process terminated",
                "result": {"exit_code": 0},
            },
            auth="agent",
            bearer=agent["jwt"],
        )
        self.assertEqual(result_code, 204, result_raw[:500])
        replay, _replay, replay_raw = call(
            "POST",
            f"/api/agents/actions/{match['id']}/result",
            {
                "status": "succeeded",
                "execution_token": match["execution_token"],
                "message": "replay",
                "result": {"exit_code": 0},
            },
            auth="agent",
            bearer=agent["jwt"],
        )
        self.assertIn(replay, (409, 401), replay_raw[:500])
        got, fetched, got_raw = call("GET", f"/api/agents/{agent['agent_id']}/actions/{match['id']}")
        self.assertEqual(got, 200, got_raw[:800])
        assert isinstance(fetched, dict)
        self.assertEqual(fetched.get("status"), "succeeded")
        self.assertIsNotNone(fetched.get("dispatched_at"))
        self.assertIsNotNone(fetched.get("completed_at"))
        self.assertIn("process terminated", got_raw)

    def test_other_agent_cannot_complete_action(self) -> None:
        owner = enroll_host("own", "windows", "11", "x64")
        other = enroll_host("oth", "linux", "6.1", "x64")
        pid = 30000 + secrets.randbelow(10000)
        created, _action, created_raw = call(
            "POST",
            f"/api/agents/{owner['agent_id']}/actions",
            {"action_type": "kill_process", "payload": {"pid": pid}},
        )
        self.assertIn(created, (200, 201), created_raw[:800])
        hb_code, hb, hb_raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.0", "uptime_seconds": 1, "buffer_depth": 0},
            auth="agent",
            bearer=owner["jwt"],
        )
        self.assertEqual(hb_code, 200, hb_raw[:800])
        assert isinstance(hb, dict)
        match = next(
            (
                row
                for row in hb.get("actions", [])
                if isinstance(row, dict)
                and isinstance(row.get("payload"), dict)
                and row["payload"].get("pid") == pid
            ),
            None,
        )
        self.assertIsNotNone(match, hb_raw[:800])
        assert isinstance(match, dict)
        code, _parsed, raw = call(
            "POST",
            f"/api/agents/actions/{match['id']}/result",
            {
                "status": "succeeded",
                "execution_token": match["execution_token"],
                "message": "nope",
                "result": {},
            },
            auth="agent",
            bearer=other["jwt"],
        )
        self.assertIn(code, (404, 401), raw[:500])

    def test_revoked_agent_cannot_ingest(self) -> None:
        agent = enroll_host("rev", "windows", "11", "x64")
        ok, _ok, ok_raw = post_events(agent, [event("process_snapshot", {"processes": []})])
        self.assertEqual(ok, 202, ok_raw[:500])
        rev_code, summary, rev_raw = call("POST", f"/api/agents/{agent['agent_id']}/revoke")
        self.assertEqual(rev_code, 200, rev_raw[:500])
        assert isinstance(summary, dict)
        self.assertEqual(summary.get("status"), "revoked")
        denied, _denied, denied_raw = post_events(agent, [event("process_snapshot", {"processes": []})])
        self.assertEqual(denied, 401, denied_raw[:500])

    def test_routine_ingest_skips_audit(self) -> None:
        agent = enroll_host("aud", "windows", "11", "x64", agent_version="0.1.0")
        for _ in range(3):
            code, _hb, raw = call(
                "POST",
                "/api/agents/heartbeat",
                {"agent_version": "0.1.0", "uptime_seconds": 1, "buffer_depth": 0},
                auth="agent",
                bearer=agent["jwt"],
            )
            self.assertEqual(code, 200, raw[:400])
        for _ in range(2):
            ev_code, _ev, ev_raw = post_events(agent, [event("process_snapshot", {"processes": []})])
            self.assertEqual(ev_code, 202, ev_raw[:400])
        for action in ("telemetry.ingest", "agent.heartbeat_change"):
            code, rows, raw = call("GET", f"/api/audit-logs?action={urllib.parse.quote(action)}&limit=500")
            self.assertEqual(code, 200, raw[:500])
            assert isinstance(rows, list)
            hits = [row for row in rows if isinstance(row, dict) and row.get("target") == agent["agent_id"]]
            self.assertEqual(hits, [], raw[:800])

    def test_sequence_rollback_audited(self) -> None:
        agent = windows_agent()
        high = event(
            "process_snapshot",
            {"processes": []},
            client_event_id=str(uuid.uuid4()),
            sequence=10,
        )
        low = event(
            "process_snapshot",
            {"processes": []},
            client_event_id=str(uuid.uuid4()),
            sequence=5,
        )
        first, _a, raw1 = post_events(agent, [high], batch_id=str(uuid.uuid4()))
        second, _b, raw2 = post_events(agent, [low], batch_id=str(uuid.uuid4()))
        self.assertEqual(first, 202, raw1[:400])
        self.assertEqual(second, 202, raw2[:400])
        code, rows, raw = call("GET", "/api/audit-logs?action=telemetry.sequence_rollback&limit=500")
        self.assertEqual(code, 200, raw[:500])
        assert isinstance(rows, list)
        self.assertTrue(
            any(isinstance(row, dict) and row.get("target") == agent["agent_id"] and row.get("action") == "telemetry.sequence_rollback" for row in rows),
            raw[:800],
        )

    def test_future_timestamp_rejected(self) -> None:
        agent = windows_agent()
        code, _parsed, raw = post_events(
            agent,
            [
                {
                    "type": "heartbeat",
                    "occurred_at": now_s() + 7200,
                    "payload": {"ok": True},
                }
            ],
        )
        self.assertEqual(code, 400, raw[:800])
        self.assertIn("occurred_at too far in the future", raw)

    def test_agent_heartbeat_rate_limit_429(self) -> None:
        agent = enroll_host("hb", "linux", "6.1", "x64")
        limited: dict | None = None
        last = ""
        for i in range(13):
            code, parsed, raw = call(
                "POST",
                "/api/agents/heartbeat",
                {"agent_version": "0.1.0", "uptime_seconds": i, "buffer_depth": 0},
                auth="agent",
                bearer=agent["jwt"],
            )
            last = raw
            if code == 429:
                self.assertIsInstance(parsed, dict, raw[:500])
                assert isinstance(parsed, dict)
                limited = parsed
                break
            self.assertEqual(code, 200, raw[:400])
        self.assertIsNotNone(limited, f"no heartbeat 429 within 13: {last[:500]}")
        assert isinstance(limited, dict)
        self.assertEqual(limited.get("error"), "rate_limited")
        self.assertEqual(limited.get("policy"), "agent-heartbeat")
        self.assertIn("detail", limited)

    def test_zz_agent_enrollment_rate_limit_429(self) -> None:
        global _rate_limit_phase
        _rate_limit_phase = True
        limited: dict | None = None
        last = ""
        for i in range(11):
            token = create_enrollment_token()
            note_enroll()
            code, parsed, raw = call(
                "POST",
                "/api/agents/enroll",
                {
                    "enrollment_token": token,
                    "hostname": uniq(f"rl{i}"),
                    "os": "linux",
                    "os_version": "6.1",
                    "arch": "x64",
                    "agent_version": "0.1.0",
                },
                auth="none",
            )
            last = raw
            if code == 429:
                self.assertIsInstance(parsed, dict, raw[:800])
                assert isinstance(parsed, dict)
                limited = parsed
                break
        self.assertIsNotNone(limited, f"no 429 within 11 enrolls: {last[:800]}")
        assert isinstance(limited, dict)
        self.assertEqual(limited.get("error"), "rate_limited")
        self.assertIn("detail", limited)
        self.assertEqual(limited.get("policy"), "agent-enrollment")
        self.assertNotIn("Error", limited)

    def _rejected_enroll(self, hostname: str, os_name: str, arch: str) -> tuple[int, object | None, str]:
        note_enroll()
        return call(
            "POST",
            "/api/agents/enroll",
            {
                "enrollment_token": "not-a-real-token",
                "hostname": hostname,
                "os": os_name,
                "os_version": "1",
                "arch": arch,
                "agent_version": "0.1.0",
            },
            auth="none",
        )

    def _api_token(self, prefix: str, role: str) -> str:
        code, parsed, raw = call(
            "POST",
            "/api/api-tokens",
            {"name": uniq(prefix), "role": role, "expires_at": None},
        )
        self.assertEqual(code, 201, raw[:800])
        self.assertIsInstance(parsed, dict)
        assert isinstance(parsed, dict)
        for key in ("id", "name", "token", "token_prefix", "role"):
            self.assertIn(key, parsed)
        self.assertNotIn("tokenPrefix", parsed)
        self.assertEqual(parsed.get("role"), role)
        return str(parsed["token"])


class AuthContractTests(unittest.TestCase):
    def setUp(self) -> None:
        if AUTH != "session":
            self.skipTest("session auth routes run against tawny-server")

    def test_admin_user_crud_default_viewer(self) -> None:
        email = f"{uniq('viewer')}@tawny.local"
        code, created, raw = call(
            "POST",
            "/api/users",
            {"email": email, "password": "viewer-password", "name": "Viewer One"},
        )
        self.assertEqual(code, 201, raw[:800])
        assert isinstance(created, dict)
        self.assertEqual(created.get("role"), "viewer")
        self.assertEqual(created.get("email"), email)
        self.assertNotIn("password", created)
        self.assertNotIn("password_hash", created)
        user_id = str(created["id"])

        again, _, again_raw = call(
            "POST",
            "/api/users",
            {"email": email, "password": "viewer-password"},
        )
        self.assertEqual(again, 409, again_raw[:500])
        self.assertIn("already exists", again_raw)

        anon, _, anon_raw = call(
            "POST",
            "/api/users",
            {"email": f"{uniq('nope')}@tawny.local", "password": "viewer-password"},
            auth="none",
        )
        self.assertEqual(anon, 401, anon_raw[:400])
        signup, _, signup_raw = call("POST", "/api/auth/signup", {"email": "x@y.z", "password": "viewer-password"}, auth="none")
        self.assertEqual(signup, 404, signup_raw[:400])

        bad_role, _, bad_raw = call(
            "POST",
            "/api/users",
            {"email": f"{uniq('role')}@tawny.local", "password": "viewer-password", "role": "owner"},
        )
        self.assertEqual(bad_role, 400, bad_raw[:400])

        cookie, csrf, _who = login_session(email, "viewer-password")
        forbidden, _, forbidden_raw = call(
            "POST",
            "/api/users",
            {"email": f"{uniq('denied')}@tawny.local", "password": "viewer-password"},
            session_cookie=cookie,
            csrf_token=csrf,
        )
        self.assertEqual(forbidden, 403, forbidden_raw[:400])
        no_csrf, _, no_csrf_raw = call(
            "POST",
            "/api/users",
            {"email": f"{uniq('csrf')}@tawny.local", "password": "viewer-password"},
            session_cookie=cookie,
            omit_csrf=True,
        )
        self.assertEqual(no_csrf, 403, no_csrf_raw[:400])

        promoted, promoted_body, promoted_raw = call(
            "PUT",
            f"/api/users/{user_id}",
            {"role": "admin", "name": "Viewer Admin"},
        )
        self.assertEqual(promoted, 200, promoted_raw[:500])
        assert isinstance(promoted_body, dict)
        self.assertEqual(promoted_body.get("role"), "admin")
        self.assertEqual(promoted_body.get("name"), "Viewer Admin")

        deleted, _, deleted_raw = call("DELETE", f"/api/users/{user_id}", {})
        self.assertEqual(deleted, 200, deleted_raw[:400])
        listed, rows, listed_raw = call("GET", "/api/users")
        self.assertEqual(listed, 200, listed_raw[:500])
        assert isinstance(rows, list)
        self.assertFalse(any(isinstance(row, dict) and row.get("email") == email for row in rows))
        missing, _, missing_raw = call("DELETE", f"/api/users/{user_id}", {})
        self.assertEqual(missing, 404, missing_raw[:400])

    def test_password_change(self) -> None:
        email = f"{uniq('pw')}@tawny.local"
        code, _, raw = call(
            "POST",
            "/api/users",
            {"email": email, "password": "old-password1", "name": "Pw"},
        )
        self.assertEqual(code, 201, raw[:500])
        cookie, csrf, _who = login_session(email, "old-password1")
        changed, _, changed_raw = call(
            "POST",
            "/api/auth/password",
            {"current_password": "old-password1", "new_password": "new-password2"},
            session_cookie=cookie,
            csrf_token=csrf,
        )
        self.assertEqual(changed, 200, changed_raw[:400])
        with self.assertRaises(AssertionError):
            login_session(email, "old-password1")
        _cookie2, _csrf2, who = login_session(email, "new-password2")
        self.assertEqual(who.get("email"), email)

    def test_github_oauth_links_existing_user_only(self) -> None:
        mock = os.environ.get("TAWNY_GITHUB_MOCK", "").rstrip("/")
        if not mock:
            self.skipTest("TAWNY_GITHUB_MOCK is unset")
        email = "oauth-linked@tawny.local"
        created, _, raw = call(
            "POST",
            "/api/users",
            {"email": email, "password": "oauth-password1", "name": "OAuth Linked"},
        )
        if created == 409:
            pass
        else:
            self.assertEqual(created, 201, raw[:500])

        status, location, _cookie, body = open_no_redirect("GET", "/api/auth/github/start")
        self.assertEqual(status, 302, body[:500])
        self.assertTrue(location.startswith(mock + "/authorize?"), location)
        self.assertIn("code_challenge=", location)
        self.assertIn("code_challenge_method=S256", location)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        state = (query.get("state") or [""])[0]
        self.assertTrue(state)

        bad, _, _, bad_body = open_no_redirect("GET", "/api/auth/github/callback?code=linked&state=not-a-real-state")
        self.assertEqual(bad, 400, bad_body[:500])
        self.assertIn("Invalid OAuth state", bad_body)

        ok, ok_loc, set_cookie, ok_body = open_no_redirect(
            "GET",
            "/api/auth/github/callback?code=linked&state=" + urllib.parse.quote(state),
        )
        self.assertEqual(ok, 302, ok_body[:800])
        self.assertTrue(ok_loc.endswith("/"), ok_loc)
        self.assertTrue(set_cookie.startswith("tawny_session="), set_cookie)
        session_cookie = set_cookie.split(";", 1)[0]
        sess_code, sess, sess_raw = call("GET", "/api/auth/session", session_cookie=session_cookie)
        self.assertEqual(sess_code, 200, sess_raw[:500])
        assert isinstance(sess, dict)
        self.assertEqual(sess.get("email"), email)

        listed, rows, listed_raw = call("GET", "/api/users")
        self.assertEqual(listed, 200, listed_raw[:800])
        assert isinstance(rows, list)
        linked = next((row for row in rows if isinstance(row, dict) and row.get("email") == email), None)
        self.assertIsNotNone(linked)
        assert isinstance(linked, dict)
        self.assertEqual(linked.get("github_id"), "424242")

        status2, location2, _, _ = open_no_redirect("GET", "/api/auth/github/start")
        self.assertEqual(status2, 302, location2)
        state2 = urllib.parse.parse_qs(urllib.parse.urlparse(location2).query)["state"][0]
        stranger, _, _, stranger_body = open_no_redirect(
            "GET",
            "/api/auth/github/callback?code=stranger&state=" + urllib.parse.quote(state2),
        )
        self.assertEqual(stranger, 403, stranger_body[:500])
        self.assertIn("No account is linked to this GitHub user", stranger_body)
        listed2, rows2, _ = call("GET", "/api/users")
        assert isinstance(rows2, list)
        self.assertFalse(
            any(isinstance(row, dict) and row.get("email") == "nobody-oauth@example.invalid" for row in rows2)
        )

    def test_rs256_heartbeat_rotates_to_eddsa(self) -> None:
        pem = os.environ.get("TAWNY_RS256_PEM", "")
        if not pem:
            self.skipTest("TAWNY_RS256_PEM is unset")
        agent = windows_agent()
        fresh_code, fresh, fresh_raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.1", "uptime_seconds": 1, "buffer_depth": 0},
            auth="agent",
            bearer=agent["jwt"],
        )
        self.assertEqual(fresh_code, 200, fresh_raw[:500])
        assert isinstance(fresh, dict)
        self.assertIsNone(fresh.get("rotated_jwt"))

        now = now_s()
        header = b64url(dumps({"alg": "RS256", "typ": "JWT"}))
        payload = b64url(
            dumps(
                {
                    "sub": agent["agent_id"],
                    "jti": uuid.uuid4().hex,
                    "agent_id": agent["agent_id"],
                    "tenant_id": TENANT,
                    "cv": "1",
                    "iss": "tawny",
                    "aud": "tawny-agents",
                    "nbf": now - 30,
                    "exp": now + 7200,
                    "iat": now - 30,
                }
            )
        )
        signing = f"{header}.{payload}".encode("ascii")
        token = signing.decode("ascii") + "." + sign_rs256(pem, signing)
        code, hb, raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.1", "uptime_seconds": 2, "buffer_depth": 0},
            auth="agent",
            bearer=token,
        )
        self.assertEqual(code, 200, raw[:800])
        assert isinstance(hb, dict)
        rotated = hb.get("rotated_jwt")
        self.assertIsInstance(rotated, str)
        assert isinstance(rotated, str)
        self.assertIsNotNone(hb.get("jwt_expires_at"))
        rh = rotated.split(".", 1)[0]
        pad = "=" * ((4 - len(rh) % 4) % 4)
        alg = json.loads(base64.urlsafe_b64decode(rh + pad))
        self.assertEqual(alg.get("alg"), "EdDSA")

        held_code, held, held_raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.1", "uptime_seconds": 3, "buffer_depth": 0},
            auth="agent",
            bearer=rotated,
        )
        self.assertEqual(held_code, 200, held_raw[:500])
        assert isinstance(held, dict)
        self.assertIsNone(held.get("rotated_jwt"))

        bad = token[:-1] + ("A" if token[-1] != "A" else "B")
        denied, _, denied_raw = call(
            "POST",
            "/api/agents/heartbeat",
            {"agent_version": "0.1.1", "uptime_seconds": 4, "buffer_depth": 0},
            auth="agent",
            bearer=bad,
        )
        self.assertEqual(denied, 401, denied_raw[:400])


def load_tests(loader: unittest.TestLoader, standard_tests: list, pattern: str | None):
    del loader, pattern
    rest: list[unittest.TestCase] = []
    last: list[unittest.TestCase] = []
    for group in standard_tests:
        for test in group:
            name = test.id().rsplit(".", 1)[-1]
            if name.startswith("test_zz_"):
                last.append(test)
            else:
                rest.append(test)
    suite = unittest.TestSuite()
    suite.addTests(rest)
    suite.addTests(last)
    return suite


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = load_tests(
        loader,
        [
            loader.loadTestsFromTestCase(AuthContractTests),
            loader.loadTestsFromTestCase(ContractTests),
        ],
        None,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
