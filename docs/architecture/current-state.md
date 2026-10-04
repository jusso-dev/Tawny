# Tawny — Current State (audit, 2026-10-04)

This document records what Tawny actually does today, as observed in code at
commit `9f0b20d` plus the uncommitted Brolga tenant-settings work in the tree.
It is the baseline for [target-edr.md](target-edr.md). Where existing docs
(`README.md`, `docs/*.md`) disagree with code, code wins and the disagreement
is noted in §13.

Paths are repo-relative. Line numbers are approximate and drift with edits.

> Several issues recorded here were fixed in Phase 0 (see
> [target-edr.md §16](target-edr.md#16-pre-existing-issues-to-fix-first-phase-0)).
> This file stays as the pre-Phase-0 baseline.

**Summary.** Tawny today is a well-hardened *telemetry and inventory* platform
with IOC/Sigma-lite alerting, not an EDR. The agent polls; only Linux has
near-real-time process/file/DNS collection. Process identity is PID-only, so
process trees cannot be reconstructed over time. There is no normalised event
model, no activity graph, no incident model, no risk scoring, and response is
limited to SIGTERM on POSIX. The backend's security plumbing (enrollment
tokens, JWT rotation, device-signed batches, HMAC web→API auth, audit log,
tenant isolation tests) is a solid foundation worth keeping.

---

## 1. Components

| Component | Tech | Location |
|---|---|---|
| Endpoint agent | Zig 0.16, single static binary, no third-party deps | `agent/` |
| API + jobs | ASP.NET Core / .NET 10, EF Core 10, Hangfire (in-process) | `backend/src/Tawny.{Api,Domain,Infrastructure,Jobs}` |
| Database | SQL Server 2022 (telemetry, alerts, rules, Hangfire, web auth) | `docker/docker-compose.yml` |
| Web UI | Next.js 16 App Router, React 19, TanStack Query, Better Auth + Prisma | `web/` |
| Integrations | Wazuh syslog + decoder/rules, Slack, Microsoft Sentinel (DCR), Tawny-SOC HTTP, Brolga reputation | `backend/src/Tawny.Api/Services`, `integrations/wazuh` |

No Redis, message queue, or columnar store. The API keeps several pieces of
state in process memory (live event broker, sequence-rule progress, web nonce
store), so it **cannot run as more than one instance**.

There are no AI features in this repo. Tawny-SOC is an external HTTP sink.

## 2. Agent architecture (`agent/src`)

- `main.zig` — one thread, one loop. Each collector has its own interval; they
  run sequentially, then the loop sleeps 1 s. A slow collector or HTTP call
  stalls heartbeats, uploads and response actions.
- `config.zig` — line-based TOML-ish parser (sections ignored, 64 KB cap).
  Static `config.toml` + mutable `state.toml`. No remote policy.
- `enrollment.zig`, `response_actions.zig`, `transport/http.zig`,
  `transport/buffer.zig`, `collectors/*` (12 modules), `platform/{linux,macos,windows}.zig`
  (process listing only).

Default intervals (s): heartbeat 60, process snapshot 30, process-launch diff 5,
network 30, users 300, system 3600, FIM 300, fs events 5, DNS 30,
supply-chain 21600.

**Windows service:** the installer registers `NT SERVICE\TawnyAgent` via
`sc.exe`, but the binary has no `StartServiceCtrlDispatcher`/`ServiceMain`.
A console exe started by the SCM will normally fail with a start timeout.
This must be verified on Windows and fixed before anything else on Windows.

## 3. Telemetry collectors

| Event type | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| `process_snapshot` | `/proc` | `ps` (no args) | Toolhelp32 (no real cmdline) | polled, ≤2048 procs, secrets scrubbed |
| `process_launch` | `/proc` diff keyed pid+starttime, every 5 s | — | — | misses short-lived procs; `signature` hard-coded `trusted:false`; SHA-256 ≤512 MB |
| `network_snapshot` | `/proc/net/*`, ARP, resolv.conf, hosts | raw `lsof` lines | only table sizes | **no PID on any connection**; 3 different shapes |
| `file_event` | inotify on configured paths (non-recursive) | — | — | no process attribution |
| `file_integrity` | all | all | all | polled hashing of `fim_paths`; baseline in memory only |
| `user_session` | `who` | utmpx | `WTSEnumerateSessionsW` | snapshot only; no logon/logoff/failure events |
| `dns_query` | journald text scraping (resolved/dnsmasq/unbound/named) | — | — | needs resolver debug logging; no PID |
| `system_info` | uname/meminfo + EC2 IMDSv2 | uname/sysctl | basic | hourly |
| `package_inventory`, `editor_extension`, `browser_extension`, `mcp_config` | **stubs — return empty** | | | parsers exist but are not wired |

Absent everywhere: ETW, eBPF, auditd, Endpoint Security, registry, services,
scheduled tasks/cron, PowerShell/AMSI, image loads, code-signature
verification, logon events, network flow events.

## 4. Event schema and transport

Wire envelope (`transport/http.zig`):

```json
{"batch_id":"<uuid>","events":[{"client_event_id":"<uuid>","type":"process_launch",
  "occurred_at":1730000000,"sequence":42,"payload":{...}}],"signature":"<b64 ed25519>"}
```

- No schema version on envelope or payloads. Payloads are hand-built JSON per
  collector; shapes differ per platform.
- `occurred_at` is *enqueue* time at 1 s resolution, not event time.
- `sequence` is in-memory, resets to 1 on restart, not persisted in spool.
- Process identity is PID only. Start time is read on Linux but not emitted.
- HTTPS POST via `std.http.Client`, new connection per request, no
  compression, system CA store, no pinning, no mTLS. Plain HTTP refused except
  loopback / explicit opt-in.
- Batches ≤500 events / ~900 KB. Exponential backoff with jitter.
- Ed25519 batch signature over canonical lines; **silently omitted if the key
  file is missing.**

Spool (`transport/buffer.zig`): append-only file with CRC'd records and an
acked offset; **fsync on every push**; replay and ack paths read the whole
file into memory (cap 256 MB default); compaction rewrites the file.
At-least-once delivery, deduped server-side by `client_event_id`. No priority.
When full, the newest event is dropped; drops go to stderr only — **no drop
counters**. Heartbeat reports only `agent_version`, `uptime_seconds`,
`buffer_depth`.

## 5. Enrollment, authentication, identity

Agent side (`enrollment.zig`):
- First run POSTs `{enrollment_token, hostname, os, os_version:"unknown", arch,
  agent_version, device_public_key}`; receives `{agent_id, jwt, jwt_expires_at}`.
- **Request JSON is built with unescaped string interpolation**; heartbeat
  `agent_version` likewise; action id is placed into a URL path unescaped.
- Enrollment token stays in `config.toml` after use.
- Ed25519 device seed stored raw in `<state>.devicekey` (0600; Windows relies
  on installer ACLs). Enrollment proceeds without a key if creation fails.
- JWT + agent id stored plaintext in `state.toml`. No DPAPI/Keychain/TPM.

Server side (`AgentsController`, `TelemetryController`, `AgentJwtService`):
- Single-use `wte_` enrollment tokens, SHA-256 hashed, 24 h default, race-safe.
- RS256 agent JWT (`agent_id`, `tenant_id`, `cv`), 60 min, rotated on heartbeat.
- Heartbeat checks revocation **and** credential version; **ingest checks
  revocation only, not `cv`.**
- Device signature mandatory only if the agent registered a key.
- Integrity checks: future/stale timestamps reject the batch; sequence gaps,
  volume spikes, source-IP change are audit-logged only.

Web users: Better Auth (email/password + optional GitHub) in Next.js; the web
server calls the API with an HMAC-SHA256 signed request (method, path, query,
body hash, user, role, tenant, timestamp, nonce). The API trusts the asserted
role and tenant.

> **Security issue:** `web/lib/auth.ts` enables email/password sign-up without
> `disableSignUp`, and the `role` field defaults to `"Admin"` (also in
> `web/prisma/schema.prisma`). Anyone able to reach the web UI can likely
> self-register as Admin. GitHub OAuth sign-in likewise creates Admins.

API tokens: `twny_` bearer, hashed, role + expiry + revocation.

## 6. Database schema (SQL Server, EF Core)

17 migrations (one uncommitted). Key tables:

- `Tenants` (+ uncommitted Brolga URL/encrypted token/enabled).
- `Agents` — host/OS facts, status, `CredentialVersion`, `RevokedAt`,
  `DevicePublicKey`, last telemetry sequence/batch/skew.
- `TelemetryEvents` — the only telemetry store. Promoted columns: tenant,
  agent, `EventType` (13-value enum), `OccurredAt`, `ReceivedAt`,
  `ClientEventId`, `BatchId`, `SequenceNumber`, `PayloadDigest`.
  **Payload is raw JSON in `nvarchar(max)`.** Unique filtered index on
  (tenant, agent, client_event_id).
- `AlertRules` — single table for Predicate, Sigma, IOC, Sequence, YARA-lite,
  PackageExposure. **Every IOC is its own rule row.** `MitreTechniquesJson`.
- `Alerts` — rule, agent, **one** `TelemetryEventId` (FK **ON DELETE
  CASCADE**), severity, status, `EnrichmentJson`, per-sink delivery columns
  (incl. leftover Kelpie columns).
- `ResponseActions` — type (KillProcess, IsolateHost), 7 statuses,
  requested/dispatched/received/completed/expires, payload hash, execution
  token hash, idempotency key, result.
- `SuppressionRules`, `ThreatIntelFeeds`, `ReputationCacheEntries`,
  `SavedHunts`/`HuntRuns`, `ApiTokens`, `EnrollmentTokens`, `AuditLogs`,
  `AgentReleases`, unused backend `Users`.
- A `Cases` model existed and was dropped in `20260729143148`.

Retention: `PurgeOldEventsJob` deletes telemetry > 30 days, **which cascades
and deletes alerts**. Audit log is never purged, and every heartbeat and
ingest writes an audit row.

## 7. Detection

- Runs **inline and synchronously** inside `POST /api/agents/events`, after
  save. All enabled rules for the tenant matching the event type are loaded
  per batch; each event payload is parsed and every rule evaluated —
  O(rules × events), no IOC index.
- Predicate operators: Exists, Equals, Contains, >, <, case-insensitive,
  dotted paths with array fan-out. No regex/startswith/endswith/CIDR.
- **Sigma** (`SigmaRuleImporter.cs`): YamlDotNet; conditions support
  and/or/not, parens, `1 of x*`, `all of x*`. One modifier per field;
  only `exists|contains|gt|lt` — anything else rejects the rule. Keyword
  lists and list-of-map selections rejected. `1 of them` unsupported.
  Wildcards in values not interpreted. ~9 hard-coded field mappings
  (e.g. `Image → processes.name`). Logsource category mapped by substring.
  ATT&CK techniques from `attack.tNNNN` tags. No compatibility statistics.
- **IOC** (`IocRuleImporter.cs`): STIX (regex over patterns), OpenIOC XML,
  raw text, ≤500 per import. SHA-256/SHA-1 vs FIM hashes, IP vs
  `connections.remote_address`, domain vs `dns_query.qname` and cmdline
  substring. **MD5 and URL skipped.**
- **Sequence rules:** 2–8 steps, ≤24 h, per host; progress in memory (lost on
  restart); `group_by` ignored.
- **YARA-lite:** string/regex over the JSON payload text, not files.
- **Package exposure:** OSV / version-pattern matching against inventory
  (which the agent currently never sends).
- **Suppression:** single predicate, optional agent scope, expiry, hit count.
- Alerts: one per (rule, event); no dedup, throttling, grouping, risk.
  **No backend endpoint to acknowledge/resolve alerts.** Sinks called
  synchronously in the ingest request.
- Editing a Sigma/IOC rule via `PUT /api/alert-rules/{id}` converts it to a
  plain predicate and drops its source.

## 8. Threat intelligence

- Feeds job every 10 min: URLhaus, OTX, MISP, TAXII 2.1 (single fetch, no
  discovery/pagination), generic CSV, OSV. ETag support, ≤5,000 indicators per
  feed. Indicators become IOC rules keyed `ti-feed:{id}:{kind}:{value}`.
- **No confidence, first/last seen, expiry, tags, actor/campaign. Indicators
  never age out.**
- Five starter feeds seeded per tenant (two enabled).
- Feed auth header stored **plaintext** in a column named `...Encrypted`.
- `ReputationEnricher`: VirusTotal, AbuseIPDB, GreyNoise, Brolga; cached
  24 h per tenant. `ReputationEnrichmentJob` annotates up to 100 recent alerts
  every 5 min. Verdicts do not affect severity; `AllowListed` unused; domain
  (`qname`) indicators not extracted; IPv6 labelled `ipv4`.
- Uncommitted: per-tenant Brolga settings (AES-GCM encrypted token,
  admin-only PUT/test, audit entry). Admin-controlled URL is an SSRF surface;
  test endpoint returns raw exception text; hard-coded homelab default URL.

## 9. Response

- `POST /api/agents/{id}/actions` (Admin): KillProcess(pid, optional
  start time/image), IsolateHost (payload unvalidated). ≤20 pending per agent,
  15 min expiry, idempotency keys, cancel.
- Delivered **only in the heartbeat response** (≤60 s latency), with a
  single-use execution token and payload hash. Result posted to
  `/api/agents/actions/{id}/result`.
- States: Pending, Dispatched, Running (never set), Succeeded, Failed,
  Cancelled, Expired. Every step audit-logged.
- Agent: `kill_process` = SIGTERM on POSIX; identity check only on Linux;
  image match falls back to basename. **Windows unsupported.**
  `isolate_host` always fails "not implemented". No local action journal,
  no dedup, no retry of result reporting, no intermediate states.
- No server-signed commands, release, quarantine, collection, suspend.

## 10. Hunting

KQL-like DSL (`HuntQuery.cs`): and/or/not, `:` contains, comparisons, IN,
`event_type:`/`agent:`/`from:`/`to:`/`last:`. SQL filters only tenant, type,
agent, time; then loads ≤5,000 rows and evaluates JSON in memory.
`ParseEventType` knows 6 of 13 types (`dns_query`, `process_launch` fail).
Saved/scheduled hunts (simple `Nm/Nh/Nd`); scheduled hunts re-alert on the
same events every run and bypass suppression and sinks.

## 11. Web UI

Pages: dashboard (incl. 7-day ATT&CK technique counts), agents list, agent
detail (tabs per event type, latest 12 events each; process tree built from
the latest snapshot by PPID), alerts (read-only), hunt workbench, detections
(Sigma/IOC/exposure import + built-in catalog), threat intel (+ Brolga
settings), suppressions, audit, API tokens, enrollment, login.

Missing: response actions UI, alert triage, incident view, process graph,
timeline, ATT&CK coverage. Live event stream calls
`/api/agents/[id]/events/stream`, which has **no Next.js route** (404).
Middleware matcher covers only three paths; pages do their own session checks.
Web tenant is fixed from an env var — the UI is effectively single-tenant.

## 12. Multi-tenancy

Tenant on every row; each controller filters by `TenantId`. No EF global
query filters or row-level security. `GetTenantId()` **falls back to the
default tenant** when the claim is missing. Some job queries are not tenant
scoped (e.g. `ScheduledHuntsJob.EnsureHuntRuleAsync`). Cross-tenant tests
cover 10 areas.

## 13. Tests, build, release

- Agent: 46 inline Zig unit tests; no backend integration or real-data
  collector tests. CI builds/tests/smoke-runs natively on linux-x64,
  windows-x64, macos-arm64; cross-builds linux-arm64, macos-x64.
- Backend: 77 xUnit tests, `WebApplicationFactory` on **EF InMemory** (SQL
  Server semantics untested). No tests for Sigma conditions, hunt DSL,
  sequences, YARA-lite, suppression, exposure, purge, reputation job.
- Web: lint, typecheck, build.
- Release (`release.yml`, `v*.*.*` tags): 5 agent targets (ReleaseSmall),
  `.sha256` sidecars, GitHub build attestations, `SHA256SUMS`, GHCR api/web
  images. **No Authenticode, no notarisation, images not signed.** Version
  hard-coded `0.1.0` in three places. No tags exist yet.
- Installers verify SHA-256 and `gh attestation verify`; staged upgrade with
  `.previous` rollback. Linux: hardened systemd unit as unprivileged `tawny`
  (cannot see/kill other users' processes). Windows: virtual service account.
  macOS: root LaunchDaemon. **No agent self-update.**
- Compose dev stack: SQL Server `sa` / `DevPassw0rd!`, API in Development,
  bootstrap admin `admin@example.com` / `ChangeMe123!`.

Doc drift: `docs/architecture.md` and `docs/api.md` disagree on JWT lifetime;
README says streaming is deferred while UI tries to stream; Kelpie, UniFi and
cloud still referenced in `docs/production.md`, `docs/threat-model.md`,
`Alert.cs`, appsettings; `PRODUCT.md` omits Linux.

## 14. Strengths to keep

- Enrollment token lifecycle, RS256 JWT with credential-version revocation.
- Ed25519 device key + canonical batch signature (make mandatory, don't replace).
- CRC'd persistent spool with acked offset (restructure, don't replace).
- HMAC-signed web→API calls; production fail-closed config checks.
- Response action model with execution tokens, payload hash, idempotency keys.
- TI feed fetchers (URLhaus/OTX/MISP/TAXII/CSV/OSV) and reputation providers.
- Sink integrations (Wazuh, Slack, Sentinel, Tawny-SOC).
- Installer supply-chain checks and service hardening.
- Cross-tenant isolation test suite and endpoint authorization inventory test.
