# Architecture

## Components

### Zig agent

A single static binary (~hundreds of KB) per platform. Cross-compiled from one machine via `zig build -Dtarget=...`. The agent has three responsibilities:

1. **Enroll** once on first run by exchanging an enrollment token for an agent ID and a long-lived JWT.
2. **Collect** snapshots at fixed intervals from a small set of OS sources (processes, network connections, logged-in users, system info, file integrity).
3. **Ship** batches over HTTPS, buffering locally when the backend is unreachable.

Platform-specific code lives in `agent/src/platform/` and is selected at compile time. Collectors call into the platform module; the rest of the agent is OS-agnostic.

### .NET 10 backend

ASP.NET Core Web API split into four projects:

- `Tawny.Api` — controllers, auth handlers, Hangfire bootstrap, DI wiring.
- `Tawny.Domain` — entities and value objects. No EF or framework references.
- `Tawny.Infrastructure` — `TawnyDbContext`, migrations, external clients.
- `Tawny.Jobs` — Hangfire job classes.

Two auth schemes coexist:

- `AgentJwt` — RS256 bearer tokens issued at enrollment, validated by a custom authentication handler. Rotated on heartbeat once they enter the last week of their lifetime.
- `WebUser` — Better Auth runs in Next.js and sets a session cookie. Server-side calls from Next.js to the API include `X-User-Id`, `X-User-Role`, and `X-Signature` headers HMAC-signed with a shared secret. A `WebUserAuthHandler` validates the signature. This is deliberately simple for the MVP — production should use OIDC.

### Next.js 16 dashboard

App Router, Server Components by default. Better Auth handles login and stores sessions in SQL Server (same DB as the API). The Next.js route handlers under `/app/api/*` proxy to the .NET API, attaching the signed user headers. The browser never talks to the .NET API directly.

### SQL Server

One database, used by EF Core, Hangfire, and Better Auth. Migrations live in `Tawny.Infrastructure/Migrations/`.

## Data flow: telemetry

```
Agent process loop
  collectors.tick()
    -> snapshot JSON
    -> buffer.push()
buffer.flush() (every flush_interval)
  -> POST /api/agents/events  [Bearer agent JWT]
    -> AgentJwtHandler validates
    -> TelemetryController.Ingest()
    -> TawnyDbContext.TelemetryEvents.AddRange()
    -> SaveChangesAsync
  -> 202 Accepted
  -> buffer.commit()
```

If the POST fails, `buffer.commit()` is not called and the events stay in the in-memory queue. After a configurable threshold the buffer spills to a disk overflow file so a long backend outage doesn't OOM the agent.

## Data flow: dashboard read

```
Browser -> Next.js Server Component
       -> lib/api.ts (signs headers with HMAC)
       -> .NET API
       -> EF Core query
       -> SQL Server
```

TanStack Query handles client-side polling on pages that want auto-refresh (5s for dashboards, 2s for live event tabs).

## Background jobs

Hangfire is configured with SQL Server storage in the same database. The dashboard is mounted at `/hangfire` and gated behind the `WebUser` scheme with Admin role.

| Job | Schedule | Purpose |
| --- | --- | --- |
| `MarkStaleAgentsJob` | Every minute | Flip agents to `stale` after 3 min and `offline` after 15 min without a heartbeat. |
| `PurgeOldEventsJob` | Daily 02:00 | Delete telemetry older than the retention window (default 30 days). |
| `BackupTelemetryJob` | Daily 03:00 | Gzip the last 24h of events to a configured path or S3 bucket. |
| `CheckAgentReleasesJob` | Hourly | Poll GitHub releases; insert a new `AgentReleases` row when a newer version exists. |

## Failure modes

- **Backend unreachable.** Agent buffers events in memory, spills to disk after `max_in_memory_events`, retries with exponential backoff up to 5 minutes.
- **Agent compromised.** JWT is a bearer token; anyone with disk access can impersonate the agent. Mitigation: short-ish lifetime, rotation, and (later) OS keystore.
- **Replay of enrollment token.** Tokens are single-use; once `UsedAt` is set, further enrollment attempts return 409.
- **Clock skew.** Events carry both `OccurredAt` (agent clock) and `ReceivedAt` (server clock). The dashboard prefers `ReceivedAt` for sorting.
