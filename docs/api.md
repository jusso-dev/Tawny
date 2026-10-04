# API

Base URL: `http://localhost:5080` for local dev, configurable in production.

All request and response bodies are JSON. Timestamps are RFC 3339 in UTC.

## Authentication

Three schemes:

- **Agent JWT.** `Authorization: Bearer <jwt>` on agent endpoints. RS256, short-lived (default 60m). Claims include `agent_id`, tenant, `jti`, and credential version `cv`. Revoked agents and stale `cv` values are rejected. Telemetry batches may include Ed25519 `signature` when a device public key was registered at enroll.
- **Web user.** Internal hop from Next.js. Headers: `X-User-Id`, `X-User-Role`, `X-Tenant-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`. Canonical string (HMAC-SHA256 hex):

  ```
  v2
  <METHOD>
  <path>
  <canonical-query>
  <sha256-hex(body)>
  <content-type>
  <userId>
  <role>
  <tenantId>
  <unix-timestamp>
  <nonce>
  ```

  Timestamp skew > 30s, reused nonces, and body/query/header mutations are rejected.
- **API token.** `Authorization: Bearer twny_...` on automation endpoints. Tokens inherit one tenant and an Admin or Viewer role.

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

If the JWT is close to expiry (within the rotation window, 15 minutes by default), the response also includes `rotated_jwt` and `jwt_expires_at` and the agent should persist them.

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

Auth: web user or `twny_` API token. Returns the agent list (id, hostname,
operating_system, os_version, agent_version, architecture, status,
last_heartbeat_at, enrolled_at, public_ip, tags).

### GET `/api/agents/{id}`

Auth: web user or `twny_` API token. Single agent, same shape.

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

## Automation endpoints

### POST `/api/threat-intel/lookup`

Auth: web user or API token. Looks up as many as 500 IP, domain, or hash values
against enabled, feed-backed IoC rules for the caller's tenant. Starter public
feeds (Feodo, OpenPhish, and opt-in companions) are seeded automatically per
tenant; this endpoint only returns hits once those feeds have imported rules.

```json
{
  "values": ["203.0.113.20", "payload.example"]
}
```

Response:

```json
{
  "matches": [
    {
      "value": "203.0.113.20",
      "kind": "ipv4",
      "rule_id": "18eb9df0-...",
      "rule_name": "TI feed OTX: ipv4 203.0.113.20",
      "description": "Known command-and-control host",
      "severity": "high",
      "feed_id": "17c2f11f-...",
      "feed_name": "OTX"
    }
  ]
}
```

Manually imported global IoC rules are excluded because they do not currently
carry tenant ownership. Feed-backed rules are joined to their tenant before
being returned.

### GET `/api/alerts?after_id=0&limit=500`

Accepts web users and `twny_` API tokens (Viewer or Admin). Without `after_id`
or `since`, the newest alerts come first (dashboard view). With either, alerts
are returned **oldest first by `id`** so integrations can page forward: store the
last `id` you received and pass it as `after_id` next time. `limit` is capped at
500. Each alert includes `mitre_techniques` (from its rule), `agent_id`,
`hostname`, `agent_os` (`windows|macos|linux`), `agent_os_version`, the
triggering telemetry `payload`, `severity` (`low|medium|high|critical`) and
`status`.

### POST `/api/agents/{id}/actions`

Admin web user or Admin `twny_` API token. Body:
`{"action_type":"kill_process"|"isolate_host"|"release_host","payload":{...},"idempotency_key":"..."}`.
`kill_process` requires `payload.pid` (positive integer). Re-posting the same
`idempotency_key` for the same agent returns the existing action. Poll
`GET /api/agents/{id}/actions` for the outcome; actions are delivered on the
agent's next heartbeat and finish as `succeeded`, `failed`, `cancelled` or
`expired`. Host isolation and release are not yet implemented by the agent and
currently complete as `failed`.

### GET `/api/agents/{id}/actions` and `/api/agents/{id}/actions/{actionId}`

Web user or any `twny_` API token (Viewer can read action history and status).

### GET `/api/alerts/{id}`

Single alert, same shape as the list. Web user or `twny_` API token.

### GET `/api/alert-rules`, POST `/api/alert-rules/sigma`

Listing accepts any `twny_` token; Sigma import needs an Admin web user or
Admin `twny_` token (used by BlakSoc detection deployment).

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
