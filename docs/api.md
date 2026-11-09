# API

Base URL: the Caddy origin (`https://localhost:8443` in the compose default). tawny-server speaks HTTP only behind that proxy.

All request and response bodies are JSON. Timestamps are RFC 3339 in UTC.

## Authentication

Three schemes:

- **Agent JWT.** `Authorization: Bearer <jwt>` on agent endpoints. New tokens are Ed25519 (EdDSA). Tokens signed with the previous RSA key still verify until the next heartbeat rotates them. Lifetime is 60 minutes. Claims include `agent_id`, `tenant_id`, `cv`, `jti`, `iss`, `aud`, `exp`, and `iat`. Revoked agents and a stale `cv` are rejected. Telemetry batches may include an Ed25519 `signature` when a device public key was registered at enroll.
- **Session.** HttpOnly, Secure, SameSite=Lax cookie `tawny_session`. Idle 8 hours, absolute 7 days. `GET /api/auth/session` returns the CSRF secret. State-changing session requests send `X-CSRF-Token`. There is no HMAC hop and no separate web process.
- **API token.** `Authorization: Bearer twny_...` on automation endpoints. Tokens inherit one tenant and an admin, analyst or viewer role. They do not send the session cookie or the CSRF header.
- **Microsoft Entra ID.** `GET /api/auth/oidc/start?tenant=<uuid>` and `/api/auth/oidc/callback` sign a user in and set the same session cookie. Setup is in [entra-sso.md](entra-sso.md). `GET /api/auth/methods?tenant=<uuid>` (public) says whether Entra ID is on and whether passwords are limited to break-glass admins.

## Roles and permissions

Three roles. Each route file in `server/src/routes/` declares its routes and the permission each needs (`pub const routes`). `server/src/http/permissions.zig` checks the permission before any handler runs, and its test checks every route below against each role. A route that is not declared answers 404. A signed-in user without the permission gets 403; no session gets 401.

| Permission | admin | analyst | viewer |
|---|---|---|---|
| `read`: agents, events, process trees, alerts, incidents, rules, hunts, feeds, exceptions, audit log, ATT&CK coverage, AI findings | yes | yes | yes |
| `triage`: acknowledge and resolve alerts, assign incidents, set incident status | yes | yes | no |
| `hunt_run`: run ad hoc and saved hunts | yes | yes | no |
| `respond`: request response actions | yes | yes, destructive ones may wait for approval | no |
| `exception_create`: add a suppression rule, with a reason | yes | yes, reason required | no |
| `admin`: users, API tokens, enrolment tokens, agent revoke, rules and rule imports, saved hunt changes, feeds, exception edit and delete, AI config, tenant settings, Entra ID config, jobs, approving actions | yes | no | no |

Per route:

| Route | Permission |
|---|---|
| `POST /api/auth/login`, `GET /api/auth/methods`, `GET /api/auth/github/start`, `GET /api/auth/github/callback`, `GET /api/auth/oidc/start`, `GET /api/auth/oidc/callback`, `POST /api/agents/enroll` | public |
| `POST /api/agents/heartbeat`, `POST /api/agents/events`, `POST /api/agents/actions/{id}/result`, `POST /api/agent/yara-rules`, `POST /api/agent/update-check` | agent JWT |
| `POST /api/auth/logout`, `GET /api/auth/session`, `POST /api/auth/password` | read |
| `GET /api/agents`, `GET /api/agents/{id}`, `GET /api/agents/{id}/events`, `GET /api/agents/{id}/events/stream`, `GET /api/agents/{id}/process-tree`, `GET /api/agents/{id}/actions`, `GET /api/agents/{id}/actions/{actionId}` | read |
| `GET /api/alerts`, `GET /api/alerts/{id}`, `GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/attack/coverage` | read |
| `GET /api/alert-rules`, `GET /api/hunts`, `GET /api/hunts/{id}`, `GET /api/hunts/{id}/runs`, `GET /api/threat-intel-feeds`, `GET /api/suppression-rules`, `POST /api/threat-intel/lookup` | read |
| `GET /api/api-tokens`, `GET /api/audit-logs`, `GET /api/releases/latest`, `GET /api/yara/rule-key`, `GET /api/ai/config`, `GET /api/ai/findings[/{id}]`, `GET /api/ai/investigations[/{id}]`, `GET /api/ai/metrics` | read |
| `POST /api/alerts/{id}/acknowledge`, `POST /api/alerts/{id}/resolve`, `POST /api/incidents/{id}/assign`, `POST /api/incidents/{id}/status` | triage |
| `POST /api/hunts/run`, `POST /api/hunts/{id}/run` | hunt_run |
| `POST /api/agents/{id}/actions` | respond |
| `POST /api/suppression-rules` | exception_create |
| `GET/POST /api/users`, `PUT/DELETE /api/users/{id}`, `POST /api/api-tokens`, `POST /api/enrollment-tokens`, `POST /api/agents/{id}/revoke`, `POST /api/agents/{id}/actions/{actionId}/approve` | admin |
| `POST /api/alert-rules`, `POST /api/alert-rules/{sigma,iocs,yara,exposures}`, `PUT/DELETE /api/alert-rules/{id}`, `POST /api/hunts`, `PUT/DELETE /api/hunts/{id}` | admin |
| `POST /api/threat-intel-feeds`, `PUT/DELETE /api/threat-intel-feeds/{id}`, `POST /api/threat-intel-feeds/{id}/run`, `PUT/DELETE /api/suppression-rules/{id}` | admin |
| `PUT /api/ai/config`, `POST /api/ai/observations`, `GET /api/admin/jobs`, `GET/PUT /api/settings/tenant`, `GET/PUT /api/settings/oidc` | admin |

### Tenant settings

`GET` and `PUT /api/settings/tenant`:

```json
{"password_login": "all", "analyst_destructive_needs_approval": false}
```

- `password_login`: `all`, or `break_glass` to allow passwords only for admins marked break-glass (`PUT /api/users/{id}` with `{"break_glass": true}`). Setting `break_glass` is refused while no active admin with a password is marked. The bootstrap admin is marked when it is created.
- `analyst_destructive_needs_approval`: when true, `isolate_host` and `quarantine_file` requested by an analyst are stored as `awaiting_approval`. The agent does not receive them until a different admin calls `POST /api/agents/{id}/actions/{actionId}/approve`, which sets `pending` and restarts the 15 minute deadline.

`GET` and `PUT /api/settings/oidc` hold the Entra ID configuration; see [entra-sso.md](entra-sso.md). The client secret is write only: `GET` returns `client_secret_set`.

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
  "action_public_key": "base64 Ed25519 public key",
  "yara_rule_key": "base64 Ed25519 public key",
  "config": { "heartbeat_interval_seconds": 60 }
}
```

`action_public_key` is the server action key. One Ed25519 key signs both
response actions and YARA rule packs, so `yara_rule_key` carries the same bytes
(kept for compatibility). The agent pins it in `<state>.actionkey` (and
`<state>.yarakey`) the first time and refuses actions or packs signed by any
other key. A `yara_rule_key` in the agent's `config.toml` takes precedence.

Trust on first use: an agent enrolled before the action key existed has no
pinned key. Its first heartbeat that carries `action_public_key` pins it, over
the same TLS channel the JWT already trusts, and the agent logs that it did.
The window is that first heartbeat; after it a different key is refused, so
changing the server key means re-enrolling agents or setting the key in config.

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

The response also has `yara_pack_version`, the version of the tenant's YARA rule pack (0 when there are no YARA rules). An agent with a lower version fetches the pack.

**Clean shutdown notice (#58).** As the agent stops for the service manager
or a signal it sends one more heartbeat with `"shutdown": true` and
`"shutdown_reason"` (`service_stop`, `system_shutdown`, `signal` or
`update_restart`, at most 64 characters). The server records
`clean_shutdown_at`, audits `agent.clean_shutdown`, and replies `{"actions":[]}`
with no rotated token. The next normal heartbeat clears the notice. An agent
that goes `offline` (15 minutes) without the notice raises an `Agent silent`
alert, which its next heartbeat closes (status `resolved`). Revoked agents
never raise it.

**Server-raised alerts.** `Agent silent`, `Sensor silent` and `Agent tamper`
alerts hang off one disabled rule per tenant (external ids
`tawny-system:agent-silent`, `tawny-system:sensor-silent`,
`tawny-system:agent-tamper`) and go to the usual sinks. `Agent silent` and
`Sensor silent` from the periodic job are anchored on a server-written event
of type `agent_silent` or `sensor_silent` with confidence `server_observed`.

- `agent_tamper` (schemas/events/agent_tamper.v1.json): one alert per event.
  `check` is `unexpected_stop`, `binary_changed`, `config_changed`,
  `identity_changed`, `sysmon_stopped` or `defender_exclusion`.
- `sensor_health` (per Windows channel) and `agent_health.sensors`
  (`[{name, status, last_event_age_seconds}]`) update per-sensor status. A
  sensor that was running and then reports stopped, failed, missing or
  access denied raises `Sensor silent`. For the continuous sensors (Sysmon and
  Security) the agent's own 15 minute `silent` state does too, and so does the
  server when `agent_health` shows no event for 15 minutes while the agent is
  still online. Delivering again closes the alert.
- `agent_health` also carries `key_protection` (`keychain`, `dpapi`, `tpm` or
  `file`) and `update` (`{state, version, ring, bucket, reason}`), stored on
  the agent row as `key_protection`, `update_state` and `update_version`.

### POST `/api/agent/update-check`

Auth: Agent JWT. Body `{"platform": "windows-x64"}` (a `ring` field from the
agent is ignored). The server picks the agent's ring: the `agents.update_ring`
override when set, else the bucket, `sha256(lower-case agent id)` first four
bytes big-endian mod 100, with buckets 0 to 9 in ring `10`, 10 to 49 in `50`
and the rest in `100`. `canary` and `internal` are only reached by override.

Response `200` when the latest release for the platform carries a signed
manifest and is open to the agent's ring (ring order canary, internal, 10,
50, 100; a release open to ring R is offered to R and every earlier ring):

```json
{ "manifest": "{\"version\":\"0.2.0\",...}", "signature": "untrusted comment: ...", "download_url": "https://...", "agent_ring": "50" }
```

`204` when nothing signed is offered. The server passes the manifest bytes on
and never trusts them; the agent verifies the minisign signature with its
compiled-in release key. The agent refuses every update while that key is the
placeholder (`update.state` = `disabled_no_release_key`).

Manifest: `{version, platform, sha256, size, min_from_version, ring, rollback}`,
signed as a file by `minisign -S` (prehashed `ED`; the legacy `Ed` form is
also accepted). The release job publishes `<asset stem>.manifest.json` and
`.manifest.json.minisig` beside each binary; the release sync stores them in
`agent_releases.manifest` and `manifest_signature`.

**Rings and promotion.** The release sync inserts new releases in ring
`canary`. Every hour the server moves a latest release to the next ring when
it has been in its ring for the soak period (24 hours) and no more than 5% of
agents that reported that version are `rolled_back` or `failed`. Releases
synced before #58 start in `100`.

### POST `/api/agent/yara-rules`

Auth: Agent JWT. Body `{}`. Returns the tenant's enabled YARA rules as one signed pack:

```json
{
  "format": "tawny-yara-pack-v1",
  "tenant_id": "00000000-...",
  "version": 1762732800000000,
  "created_at": "2026-11-10T00:00:00Z",
  "key_id": "first 16 bytes of SHA-256(public key), hex",
  "rules_b64": "base64 of the rule source",
  "sha256": "hex SHA-256 of the rule source",
  "signature": "base64 Ed25519"
}
```

The signature covers these lines, each ending in `\n`: `tawny-yara-pack-v1`, `tenant_id`, `version`, `created_at`, `sha256`. The agent checks the signature against its pinned key and the hash against the decoded source, and refuses the whole pack on any mismatch (`agent/src/rule_pack.zig`). It also refuses a pack older than the one it has.

Matches come back as `yara_match` events:

```json
{"rule":"eicar_test_file","tags":["test"],"file":{"path":"C:\\Users\\a\\x.exe","name":"x.exe","size":68,"hashes":{"sha256":"..."}},"trigger":"file_event","pack_version":1}
```

`trigger` is `file_event`, `response_action` or `scheduled`. Agent settings: `yara_rule_key`, `yara_scan_interval_seconds` (default 3600, 0 turns the scheduled scan off), `yara_timeout_seconds` (default 10), `yara_max_file_bytes` (default 64 MiB). YARA needs an agent built with `-Dyara=true`.

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

The body above is schema 1 (older agents). Current agents send schema 2,
described next. The server accepts both from the same agent.

#### Schema 2 (`"schema": 2`)

JSON Schema: `schemas/events/envelope.v2.json`; per-type `data` schemas in
`schemas/events/<type>.v1.json`.

```json
{
  "schema": 2,
  "batch_id": "6b1c...-uuid",
  "agent": {"agent_id": "uuid", "sensor_version": "0.1.0", "boot_id": "uuid"},
  "events": [{
    "event_id": "uuid",
    "event_type": "process_start",
    "v": 1,
    "ts": "2026-11-09T01:00:05.200Z",
    "seq": 9001,
    "data": {
      "process": {"entity_id": "wxjmbxyyq7eybnyac2lfc654ka", "pid": 5200, "start_time": "2026-11-09T01:00:05.200Z", "image": "C:\\...\\powershell.exe"},
      "parent": {"entity_id": "7iyrf5zm6b5flyledskp3lodvm", "pid": 4100}
    }
  }],
  "signature": "base64 Ed25519"
}
```

- `agent.agent_id` must match the JWT. `batch_id`, `event_id` and
  `agent.boot_id` are UUIDs. `ts` is ISO 8601 UTC. `seq` is the durable
  per-agent sequence (it survives agent restarts) and is at least 1.
- `event_type` uses the same names as schema 1 (`process_start`,
  `dns_query`, `system_info`, ...). Schema 1 `process_launch` is treated as
  `process_start` for process identity. `agent_health` is new in schema 2.
- Per-type checks: `process_start` and `process_exit` need `process.pid`,
  and any `entity_id` must be 26 base32 characters; `network_connect` needs
  `network`; `dns_query` needs `dns.query` or `qname`; `file_create` needs
  `file.path`; `registry_set` needs `registry.key`; `user_logon` needs
  `user`; `service_create` needs `service.name`; `powershell_script_block`
  needs `script_block.id` and `text`. Other types need `data` to be an
  object. A failed check is `400` with `events[i]: <reason>` in the title.
- `process.entity_id` is
  `base32(SHA-256(agent_id || pid_le32 || start_time_100ns_le64 || boot_id)[0..16])`;
  exact byte encoding in `docs/architecture/target-edr.md` section 2.4.

**Signature.** With a device key registered at enrol, every batch must be
signed. Schema 2 signs this string (UTF-8, `\n` line ends):

```
tawny-batch-v2
<agent_id>
<batch_id>
<agent.boot_id>
<agent.sensor_version>
<event_id>|<seq>|<event_type>|<v>|<ts>|<sha256 hex of the exact data bytes>   (one line per event)
```

`agent_id` is the authenticated agent. `boot_id` is signed because it feeds
every entity id; `sensor_version` so a version claim can't be changed in
transit; `v` because it picks the payload schema. `mono`, `priority` and
`sensor` are not signed because the server neither stores nor acts on them.
Schema 1 batches still verify against `tawny-batch-v1`
(`<client_event_id>|<sequence>|<type>|<occurred_at>|<sha256 of payload>`).
With `TAWNY_REQUIRE_SIGNED_BATCHES` on (the default), an agent with no key
is refused for either schema.

Current agent event types:

| Type | Payload |
| --- | --- |
| `process_snapshot` | `{ "processes": [{ "pid": 123, "ppid": 1, "name": "..." }] }` |
| `network_snapshot` | `{ "source": "procfs" \| "libproc" \| "iphlpapi", "connections": [{ "protocol", "local_address", "local_port", "remote_address", "remote_port", "state", "state_name", "pid" }] }`. Windows reads the TCP and UDP owner-pid tables for IPv4 and IPv6; `pid` is present on macOS and Windows. |
| `user_session` | Windows uses WTS sessions; macOS uses `utmpx`. Payload shape is `{ "source": "...", "sessions": [...] }`. |
| `system_info` | Hostname, platform, OS/kernel version, architecture, CPU, and memory facts. Emitted at startup and hourly. |
| `file_integrity` | `{ "path": "...", "old_sha256": "...", "new_sha256": "...", "size_bytes": 123, "exists": true }` on hash or existence changes for configured `fim_paths`. |
| `process_start` (Linux, macOS) | `process{entity_id,pid,start_time,name,image,command_line,user{uid},hashes{sha256}}`, `parent{entity_id,pid}` from the 5 s launch diff. Older agents sent this as `process_launch` with a flat payload (`pid`, `ppid`, `start_time_unix`, ...), which the server still accepts. |
| `process_exit` (Linux, macOS) | `process{entity_id,pid}`, `end_time` (when the diff noticed, up to one interval late). |
| `agent_health` | `sensor_version`, `buffer_depth`, `uptime_seconds`, `next_sequence`, `boot_id`, once per heartbeat. |

Windows event log types. Every payload carries `sensor` (`sysmon`, `security`,
`system`, `powershell`), `channel`, `event_id`, `record_id`, `ts` (event time,
ISO 8601 UTC) and `rule_name` when Sysmon matched a named rule. Field names
follow `docs/architecture/target-edr.md` section 2.2. Fields the event did not
carry (or carried as `-`) are left out.

| Type | Source | Payload |
| --- | --- | --- |
| `process_start` | Sysmon 1; Security 4688 when Sysmon is missing | `process{guid,pid,image,name,command_line,cwd,start_time,user{name,domain},session_id,integrity_level,logon_id,hashes{sha256,sha1,md5,imphash}}`, `parent{guid,pid,image,name,command_line,user}`. 4688 gives `pid`, `image`, `command_line`, `user{name,domain,sid}`, `integrity_level`, `elevation_type`, `elevated` and `parent{pid,image}`. |
| `process_exit` | Sysmon 5 | `process{guid,pid,image,name,user}` |
| `network_connect` | Sysmon 3 | `process{...}`, `network{protocol,direction,src_ip,src_port,src_hostname,dst_ip,dst_port,dst_hostname,dst_port_name,ipv6}` |
| `dns_query` | Sysmon 22 | `process{...}`, `dns{query,status,answers[]}`, plus top-level `qname` (same as `dns.query`) for existing DNS rules |
| `file_create` | Sysmon 11 | `process{...}`, `file{path,name,extension,creation_time}` |
| `file_delete` | Sysmon 23, 26 | `process{...}`, `file{path,name,extension,hashes,is_executable}`, `archived` |
| `registry_create`, `registry_delete` | Sysmon 12 | `process{...}`, `registry{key,value_name,operation}` |
| `registry_set` | Sysmon 13 | `process{...}`, `registry{key,value_name,value_type,data,data_truncated,operation}` (`data` capped at 1 KiB) |
| `registry_rename` | Sysmon 14 | `process{...}`, `registry{key,new_name,operation}` |
| `image_load` | Sysmon 7 | `process{...}`, `file{path,name,extension,hashes,signature{signed,status,signer}}` |
| `remote_thread` | Sysmon 8 | `process{...}` (source), `target{guid,pid,image,name,user}`, `thread{id,start_address,start_module,start_function}` |
| `process_access` | Sysmon 10 | `process{...}` (source), `target{...}`, `granted_access`, `call_trace` |
| `user_logon` | Security 4624 | `user{name,domain,sid}`, `subject{...}`, `logon{id,type,type_name,process,auth_package,workstation,elevated}`, `network{src_ip,src_port}`, `process{pid,image,name}` |
| `user_logon_failed` | Security 4625 | `user{...}`, `logon{type,type_name,process,auth_package,workstation,status,sub_status,failure_reason}`, `network{...}`, `process{...}` |
| `special_privileges` | Security 4672 | `user{...}`, `logon{id}`, `privileges[]` |
| `service_create` | System 7045 | `service{name,image_path,type,start_type,account}`, `user{sid}` |
| `powershell_script_block` | PowerShell 4104 | `script_block{id,text,path,parts_total,parts_received,complete,truncated}`, `process{pid}`, `user{sid}`. Parts are joined by `ScriptBlockId`; `text` is capped at 64 KiB. |
| `sensor_health` | agent | `{ "sensor": "windows_eventlog", "channel", "state": "ok" \| "missing" \| "access_denied" \| "silent" \| "failed", "previous_state", "status": "ok" \| "degraded", "sysmon_present", "process_start_source", "win32_error", "channels": {...}, "counters": {...} }`, sent when a channel's state changes. |

## Dashboard endpoints

### GET `/api/agents`

Auth: web user or `twny_` API token. Returns the agent list (id, hostname,
operating_system, os_version, agent_version, architecture, status,
last_heartbeat_at, enrolled_at, public_ip, tags).

### GET `/api/agents/{id}`

Auth: web user or `twny_` API token. Single agent, same shape.

### GET `/api/agents/{id}/process-tree?entity_id=...`

Auth: web user or `twny_` API token; same tenant check as the other agent
routes, and `process_entities` has row-level security. Returns the process,
its ancestors (parent first) and every descendant with `depth` (1 is a
direct child, at most 500), ordered by depth then start time:

```json
{
  "process": {"entity_id": "wxjm...", "parent_entity_id": "7iyr...", "pid": 5200, "image": "...", "command_line": "...", "user_name": "CORP\\alice", "start_time": "2026-11-09T01:00:05.200Z", "end_time": null, "first_event_id": 42},
  "ancestors": [{"entity_id": "7iyr...", "depth": 1, "...": "..."}],
  "children": [{"entity_id": "z64l...", "depth": 1, "...": "..."}]
}
```

Without `entity_id` it returns `{"processes": [...]}`, the 50 newest
processes on the agent. `400` for a malformed `entity_id`, `404` for an
unknown agent or process.

### GET `/api/agents/{id}/events?type=process_snapshot&limit=50&before=...`

Auth: web user. Paginated, cursor-based on `received_at`.

### POST `/api/enrollment-tokens`

Auth: web user (Admin). Returns the raw token once; only the hash is stored.

### GET `/api/enrollment-tokens`

Auth: web user (Admin). Lists unused tokens.

### DELETE `/api/enrollment-tokens/{id}`

Auth: web user (Admin). Revokes.

### GET `/api/releases/latest?platform=windows-x64`

Auth: session cookie or `twny_` API token. Anonymous and agent JWT requests are
401. Returns the current `is_latest` row for that platform
(`version`, `platform`, `download_url`, `sha256`, `released_at`, `ring`).
Optional `ring=canary|internal|10|50|100` returns the release only when it is
already open to that ring (else 404); any other value is 400. Unknown
platform is 404 `No release is published for that platform.` A missing
`platform` query is 400 `platform is required.` Enrolled agents still receive
`latest_agent_version`, `download_url`, and `sha256` on heartbeat.

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
`{"action_type":"kill_process"|"suspend_process"|"resume_process"|"quarantine_file"|"restore_file"|"isolate_host"|"release"|"release_host"|"yara_scan","payload":{...},"idempotency_key":"..."}`.
`kill_process`, `suspend_process` and `resume_process` take `payload.pid`
(positive integer) and optional `image_path` and `start_time_unix` for the PID
reuse guard. `quarantine_file` takes `payload.path` and `payload.sha256`;
`restore_file` takes `payload.sha256`. `yara_scan` takes `payload.path`, a file
or a folder (not recursive); matches arrive as `yara_match` events. Re-posting
the same `idempotency_key` for the same agent returns the existing action.

Every dispatched action is signed by the server action key. The agent verifies
the signature against its pinned key before it runs anything, and refuses
unsigned, expired, tampered or wrong-key actions, reporting `failed` with a
reason. The signed string is
`tawny-action-v1\n<action_id>\n<agent_id>\n<action_type>\n<expires_at>\n<sha256 of payload>`;
the heartbeat adds `signature` and `action_public_key` to its reply.

Poll `GET /api/agents/{id}/actions` for the outcome; actions are delivered on
the agent's next heartbeat and finish as `succeeded`, `failed`, `cancelled` or
`expired`. Process control, quarantine and restore run on Windows; quarantine
and restore also run on Linux and macOS. Host isolation (`isolate_host`,
`isolate`) and `release` run on Windows through WFP: isolation permits
loopback, the resolved server IPs, configured DNS resolvers and an optional
admin allowlist, blocks everything else, survives a reboot, and releases itself
when its `max_duration_seconds` deadline (default 24 h) passes with no renewal.
The `isolate_host` payload accepts `max_duration_seconds`, `server_ips`,
`dns_resolvers`, `admin_allowlist` and `nonce`. On Linux and macOS isolation
reports `failed` with a clear reason until nftables isolation lands (#59).

### GET `/api/agents/{id}/actions` and `/api/agents/{id}/actions/{actionId}`

Web user or any `twny_` API token (Viewer can read action history and status).

### POST `/api/alerts/{id}/acknowledge` and `/api/alerts/{id}/resolve`

Triage. Return `{"id": 7, "status": "acknowledged"}` or `"resolved"`. Acknowledging a resolved alert leaves it resolved.

### Incidents

Detection groups each new alert into an incident (`server/src/detect/incidents.zig`, target-edr section 8). An alert joins an open incident (`new` or `investigating`) last seen within 4 hours when:

1. `lineage`: same agent and the same lineage root, the oldest ancestor in `process_entities` below a session root such as `explorer.exe` or `services.exe`;
2. `artefact`: same agent and same user, and a shared file sha256, domain or public IP;
3. `indicator`: any agent, the same IOC rule or the same file sha256.

Otherwise it opens a new incident (`grouping` is `alert` when there was nothing to group on).

Risk is the section 7 noisy-OR: each distinct rule is one evidence item scored `weight × confidence × context`, and `risk = 100 × (1 − Π(1 − points/100))`. Weights come from rule severity (critical 60, high 30, medium 20, low 10) and IOC rules count 50. Severity is `critical` at 85 or more, `high` at 65, `medium` at 40, else `low`, and never lower than a critical alert in the incident. `risk_items` lists every item and its points.

- `GET /api/incidents?status=open|new|investigating|resolved|false_positive&limit=100`: newest first.
- `GET /api/incidents/{id}`: the incident plus `alerts`, its timeline, with each alert's event payload.
- `POST /api/incidents/{id}/assign` `{"owner_user_id": "<uuid>" | null}`: owner must be an active admin or analyst. Assigning a `new` incident moves it to `investigating`.
- `POST /api/incidents/{id}/status` `{"status": "new" | "investigating" | "resolved" | "false_positive"}`: resolving or marking false positive also resolves its open alerts.

Incident fields: `id`, `title`, `status`, `severity`, `risk`, `risk_items`, `owner_user_id`, `owner_email`, `grouping`, `root_entity_id`, `agent_ids`, `users`, `techniques`, `first_seen_at`, `last_seen_at`, `created_at`, `updated_at`, `alert_count`, `soc_case_status`.

When the Tawny-SOC sink is on (`TAWNY_SOC_ENABLED`, `TAWNY_SOC_ENDPOINT_URL`, `TAWNY_SOC_API_TOKEN`; `TAWNY_SOC_INCIDENTS_ENABLED=false` turns incidents off), each incident and each later change is posted to Tawny-SOC's `POST /api/ingest/tawny` as one alert with a stable `alert_id` and an `incident` object (risk, items, techniques, agents, link). Tawny-SOC's `/api/v1/cases` is read only, so the case itself is opened in Tawny-SOC.

### GET `/api/attack/coverage?platform=windows|linux|macos`

ATT&CK Enterprise 20.1 techniques (from `rules/attack/techniques.json`) by tactic, each with three states worked out separately:

- `telemetry.available`: an agent on the platform that heartbeated in the last 15 minutes, with no sensor failed, missing or denied, sent one of the technique's event types (from `rules/attack/coverage.yaml`) in the last 24 hours. `sources` names them; `expected` lists what the map wants.
- `detection.available`: an enabled rule lists the exact technique id. `rules` names them. A rule on `T1059` does not count for `T1059.001`.
- `response.available`: an action listed for the technique runs on the platform. `actions` names them.

None is read from another: a rule with no telemetry shows detection without telemetry. `mapped` is false for techniques with no coverage map entry.

### GET `/api/alerts/{id}`

Single alert, same shape as the list. Web user or `twny_` API token.

### GET `/api/alert-rules`, POST `/api/alert-rules/sigma`, POST `/api/alert-rules/yara`

Listing accepts any `twny_` token. Sigma import compiles the whole rule (see `docs/detections.md`) and answers `400` with the reason when any part is unsupported. `POST /api/alert-rules/yara` takes `{"rule_source":"rule x { ... }","name":"...","severity":"high","is_enabled":true}`; the server keeps the source and the rule names it declares, and the agent compiles the bundled pack. `GET /api/yara/rule-key` returns the pack signing public key for agent config. Sigma import, YARA rule creation, `PUT /api/alert-rules/{id}` (metadata such as `is_enabled` for imported rules) and `DELETE /api/alert-rules/{id}` need an Admin web user or
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
