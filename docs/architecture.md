# Architecture

## Components

### Zig agent

A single static binary (~hundreds of KB) per platform. Cross-compiled from one machine via `zig build -Dtarget=...`. The agent has three responsibilities:

1. **Enroll** once on first run by exchanging an enrollment token for an agent ID and a short-lived JWT (60 minutes by default) that is rotated on heartbeat.
2. **Collect** snapshots at fixed intervals from a small set of OS sources (processes, network connections, DNS and host mappings, logged-in users, system info, file integrity).
3. **Ship** batches over HTTPS, buffering locally when the backend is unreachable.

Platform-specific process code lives in `agent/src/platform/` and is selected at compile time. Collector modules live in `agent/src/collectors/`; each module keeps its own OS-specific syscall or command boundary. Linux network snapshots combine procfs sockets, ARP neighbors, resolver settings, and `/etc/hosts`; EC2 system snapshots add IMDSv2 instance network identity. Linux DNS events use supported resolver journal logs plus changed `/etc/hosts` entries. The macOS network collector intentionally starts with `lsof -i -P -n` as an MVP path and should move to a native `sysctl` implementation later.

### tawny-server

One Zig 0.17 process. It serves the agent API, the dashboard API, and the static UI. It speaks HTTP on the compose network. Caddy terminates TLS. PostgreSQL holds the data. Migrations are SQL files embedded in the binary and applied on startup when `TAWNY_APPLY_MIGRATIONS_ON_STARTUP=true`.

Three auth schemes:

- `AgentJwt` — new tokens are Ed25519, issued at enroll and rotated on heartbeat. Pre-cutover RS256 tokens still verify. Revocation and credential version are checked on every agent request.
- `Session` — HttpOnly, Secure, SameSite=Lax cookie. State-changing requests send `X-CSRF-Token`. There is no separate web process and no HMAC hop.
- `ApiToken` — `twny_` bearer tokens for automation. They skip the CSRF header.

### Static dashboard

Classic pages under `server/ui`, served by tawny-server from the same origin as the API. Unknown paths fall back to `index.html`. Hashed assets are cached. The browser never crosses to a second host.

### PostgreSQL

One database. The server, the session table, and the work queue share it. Postgres is not published to the host.

## Data flow: telemetry

```
Agent process loop
  collectors.tick()
    -> snapshot JSON
    -> buffer.push()
buffer.flush() (every flush_interval)
  -> POST /api/agents/events  [Bearer agent JWT]
    -> validate JWT, persist events, enqueue detection
  -> 202 Accepted
  -> buffer.commit()
```

Detection runs after the response is on the wire. The request path does not create alerts.

If the POST fails, `buffer.commit()` is not called and the events stay in the in-memory queue. After a configurable threshold the buffer spills to a disk overflow file so a long backend outage doesn't OOM the agent.

## Data flow: dashboard read

```
Browser -> Caddy (TLS) -> tawny-server
       -> session cookie, CSRF on writes
       -> PostgreSQL
```

The static UI polls. `GET /api/agents/{id}/events/stream` returns one `text/event-stream` payload and closes. It does not hold the connection open.

## Background jobs

Seven jobs run inside `tawny-server` after each request returns. There is no Hangfire process and no `/hangfire` route. An admin session reads `GET /api/admin/jobs`.

| Job | Schedule | Purpose |
| --- | --- | --- |
| Stale agents | Check about every minute | `stale` after 3 min and `offline` after 15 min without a heartbeat. |
| Purge | About hourly | Delete alerts older than 365 days, then telemetry older than 30 days that no surviving alert references. |
| Backup | About daily | Gzip JSONL of recent telemetry to a local path and/or S3 (SigV4). |
| Release check | About hourly | Poll GitHub releases and record the latest agent build per platform. |
| Hunts | Every 5 min | Run saved hunts. An event already matched by that hunt is not alerted again. |
| Threat intel | Every 10 min | Fetch due feeds (ETag, starter feeds, at most 5,000 indicators) and materialise IoC rules. |
| Reputation | Every 5 min | Enrich at most 100 alerts via VirusTotal, AbuseIPDB, and GreyNoise. Cache hits last 24h. |

## Failure modes

- **Backend unreachable.** Agent buffers events in memory, spills to disk after `max_in_memory_events`, retries with exponential backoff up to 5 minutes.
- **Agent compromised.** JWT is a bearer token; anyone with disk access can impersonate the agent. Mitigation: short-ish lifetime, rotation, and (later) OS keystore.
- **Replay of enrollment token.** Tokens are single-use; once `UsedAt` is set, further enrollment attempts return 409.
- **Clock skew.** Events carry both `OccurredAt` (agent clock) and `ReceivedAt` (server clock). The dashboard prefers `ReceivedAt` for sorting.
