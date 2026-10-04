#!/usr/bin/env python3
"""Enroll the shipped agent, wait for heartbeat and telemetry, then isolate.

Stdlib only. Prints status, never the enrollment token or the admin password.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("TAWNY_BASE_URL", "http://127.0.0.1:18080").rstrip("/")
EMAIL = os.environ.get("TAWNY_CONTRACT_EMAIL", "admin@tawny.local")
PASSWORD = os.environ.get("TAWNY_CONTRACT_PASSWORD", "contract-password")
AGENT_BIN = os.environ.get("TAWNY_AGENT_BIN", "")
NOT_IMPLEMENTED = "isolate_host is not implemented by this agent build"


def call(method: str, path: str, body: object | None, cookie: str, csrf: str) -> tuple[int, str]:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    if csrf and method not in ("GET", "HEAD"):
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", errors="replace")


def login() -> tuple[str, str]:
    req = urllib.request.Request(
        BASE + "/api/auth/login",
        data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            set_cookie = resp.headers.get("Set-Cookie") or ""
    except urllib.error.HTTPError as err:
        raise SystemExit(f"login failed status={err.code}") from err
    parsed = json.loads(payload.decode("utf-8"))
    token = parsed.get("csrf_token")
    if not isinstance(token, str) or not token:
        raise SystemExit("login missing csrf_token")
    if not set_cookie.startswith("tawny_session="):
        raise SystemExit("login missing session cookie")
    return set_cookie.split(";", 1)[0], token


def wait_until(label: str, seconds: float, probe) -> str:
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return last
        time.sleep(1)
    raise SystemExit(f"timeout waiting for {label}")


def main() -> None:
    if not AGENT_BIN or not Path(AGENT_BIN).is_file():
        raise SystemExit("TAWNY_AGENT_BIN is missing")
    code, health = call("GET", "/api/health", None, "", "")
    if code != 200 or '"status":"ok"' not in health:
        raise SystemExit(f"health status={code}")

    cookie, csrf = login()
    code, raw = call("POST", "/api/enrollment-tokens", {"lifetime_hours": 1}, cookie, csrf)
    if code != 200:
        raise SystemExit(f"enrollment token status={code}")
    token = json.loads(raw).get("token")
    if not isinstance(token, str) or not token.startswith("wte_") or len(token) < 20:
        raise SystemExit("enrollment token response missing wte_ token")
    print(f"enrollment_token_len={len(token)}")

    work = tempfile.TemporaryDirectory(prefix="tawny-agent-e2e-")
    try:
        root = Path(work.name)
        config_path = root / "config.toml"
        state_path = root / "state.toml"
        config_path.write_text(
            "\n".join(
                [
                    f'url = "{BASE}"',
                    f'enrollment_token = "{token}"',
                    "allow_insecure_http = true",
                    "heartbeat_interval_seconds = 1",
                    "system_interval_seconds = 3600",
                    "process_interval_seconds = 3600",
                    "process_events_interval_seconds = 3600",
                    "network_interval_seconds = 3600",
                    "users_interval_seconds = 3600",
                    "fim_interval_seconds = 3600",
                    "fs_events_interval_seconds = 3600",
                    "dns_interval_seconds = 3600",
                    "supply_chain_interval_seconds = 3600",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        log_path = root / "agent.log"
        log_file = log_path.open("w", encoding="utf-8")
        env = os.environ.copy()
        env["TAWNY_CONFIG"] = str(config_path)
        env["TAWNY_STATE_PATH"] = str(state_path)
        proc = subprocess.Popen(
            [AGENT_BIN],
            cwd=str(root),
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        failed = False
        try:
            def enrolled() -> str:
                if not state_path.exists():
                    return ""
                text = state_path.read_text(encoding="utf-8", errors="replace")
                marker = 'agent_id = "'
                start = text.find(marker)
                if start < 0:
                    return ""
                rest = text[start + len(marker) :]
                end = rest.find('"')
                if end != 36:
                    return ""
                return rest[:end]

            agent_id = wait_until("agent_id", 40, enrolled)
            print(f"agent_id={agent_id}")

            def heartbeat() -> str:
                status, body = call("GET", f"/api/agents/{agent_id}", None, cookie, csrf)
                if status != 200 or '"last_heartbeat_at":null' in body or '"last_heartbeat_at":' not in body:
                    return ""
                return "heartbeat"

            wait_until("heartbeat", 40, heartbeat)
            print("heartbeat_ok")

            def saw_event() -> str:
                status, body = call("GET", f"/api/agents/{agent_id}/events?limit=20", None, cookie, csrf)
                if status == 200 and "system_info" in body:
                    return "system_info"
                return ""

            kind = wait_until("system_info", 40, saw_event)
            print(f"event_ok={kind}")

            status, body = call(
                "POST",
                f"/api/agents/{agent_id}/actions",
                {"action_type": "isolate_host", "payload": {}},
                cookie,
                csrf,
            )
            if status != 201:
                raise SystemExit(f"isolate create status={status}")
            action_id = json.loads(body).get("id")
            if not isinstance(action_id, str) or not action_id:
                raise SystemExit("isolate create missing id")

            def action_result() -> str:
                code_a, raw_a = call(
                    "GET",
                    f"/api/agents/{agent_id}/actions/{action_id}",
                    None,
                    cookie,
                    csrf,
                )
                if code_a == 200 and NOT_IMPLEMENTED in raw_a:
                    return "failed"
                return ""

            wait_until("isolate result", 50, action_result)
            print("isolate_result_ok")
        except SystemExit:
            failed = True
            raise
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            log_file.close()
            print(f"agent_exit={proc.returncode}")
            if failed:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
                print(tail.replace(token, "wte_redacted"))
    finally:
        work.cleanup()
    print("e2e_ok")


if __name__ == "__main__":
    main()
