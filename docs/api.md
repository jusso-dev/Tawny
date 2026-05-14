# API

Base URL: `http://localhost:5080` for local dev, configurable in production.

All request and response bodies are JSON. Timestamps are RFC 3339 in UTC.

## Authentication

Two schemes:

- **Agent JWT.** `Authorization: Bearer <jwt>` on agent endpoints. RS256, issued at enrollment.
- **Web user.** Internal hop from Next.js. Requests carry `X-User-Id`, `X-User-Role`, `X-Timestamp`, `X-Signature`. The signature is `HMAC-SHA256(secret, "<method>\n<path>\n<timestamp>\n<userId>\n<role>")` hex-encoded. Requests older than 30 seconds are rejected.

## Agent endpoints

### POST `/api/agents/enroll`

Auth: enrollment token (no JWT yet).

```json
{
  "enrollment_token": "wte_xxxxxxxx",
  "hostname": "MACBOOK-JT",
  "os": "macos",
  "os_version": "14.5",
  "arch": "arm64",
  "agent_version": "0.1.0"
}
```

Response `200`:

```json
{
  "agent_id": "8f3c1a2b-...",
  "jwt": "eyJhbGciOi...",
  "jwt_expires_at": "2026-08-11T00:00:00Z",
  "config": { "heartbeat_interval_seconds": 60 }
}
```

Errors: `401` if token unknown or already used, `410` if token expired.

### POST `/api/agents/heartbeat`

Auth: Agent JWT.

```json
{ "agent_version": "0.1.0", "uptime_seconds": 4567, "buffer_depth": 0 }
```

Response `200`:

```json
{
  "latest_agent_version": "0.1.1",
  "download_url": "https://github.com/jusso-dev/tawny/releases/download/v0.1.1/tawny-agent-0.1.1.exe",
  "sha256": "abcd..."
}
```

If the JWT has fewer than 7 days left, the response also includes `rotated_jwt` and `jwt_expires_at` and the agent should persist them.

### POST `/api/agents/events`

Auth: Agent JWT. Max body 1 MB.

```json
{
  "events": [
    {
      "type": "process_snapshot",
      "occurred_at": "2026-05-13T01:23:45Z",
      "payload": { "processes": [/* ... */] }
    }
  ]
}
```

Response: `202 Accepted`, empty body. `413` if payload exceeds 1 MB.

Current agent event types:

| Type | Payload |
| --- | --- |
| `process_snapshot` | `{ "processes": [{ "pid": 123, "ppid": 1, "name": "..." }] }` |
| `network_snapshot` | Windows uses `iphlpapi` table snapshots; macOS currently emits `lsof -i -P -n` rows under `{ "source": "lsof", "connections": [...] }`. |
| `user_session` | Windows uses WTS sessions; macOS uses `utmpx`. Payload shape is `{ "source": "...", "sessions": [...] }`. |
| `system_info` | Hostname, platform, OS/kernel version, architecture, CPU, and memory facts. Emitted at startup and hourly. |
| `file_integrity` | `{ "path": "...", "old_sha256": "...", "new_sha256": "...", "size_bytes": 123, "exists": true }` on hash or existence changes for configured `fim_paths`. |

## Dashboard endpoints

### GET `/api/agents`

Auth: web user. Returns the agent list with status badges.

### GET `/api/agents/{id}`

Auth: web user. Single agent with system info.

### GET `/api/agents/{id}/events?type=process_snapshot&limit=50&before=...`

Auth: web user. Paginated, cursor-based on `received_at`.

### POST `/api/enrollment-tokens`

Auth: web user (Admin). Returns the raw token once; only the hash is stored.

### GET `/api/enrollment-tokens`

Auth: web user (Admin). Lists unused tokens.

### DELETE `/api/enrollment-tokens/{id}`

Auth: web user (Admin). Revokes.

### GET `/api/releases/latest?platform=windows-x64`

Auth: public or agent JWT. Returns the current latest release for a platform.

### GET `/api/dashboard/summary`

Auth: web user. Counts for the home page (total agents, online vs offline, recent event volume).

## Errors

All errors are RFC 7807 problem details:

```json
{
  "type": "https://tawny.example.com/errors/enrollment-token-used",
  "title": "Enrollment token already used",
  "status": 409,
  "detail": "Token wte_xxx was consumed at 2026-05-12T22:11:09Z.",
  "instance": "/api/agents/enroll"
}
```
