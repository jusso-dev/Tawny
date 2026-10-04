# Tawny — Target EDR Architecture

Status: **proposal**, 2026-10-04. Baseline: [current-state.md](current-state.md).

Goal: the smallest architecture that gives a small-business fleet useful
endpoint protection — rich Windows telemetry, process lineage, behavioural and
IOC detection, explainable risk, correlated incidents, and safe response —
while staying lightweight, self-hosted and deterministic.

Windows is Tier 1. macOS and Linux stay supported; they receive the same event
model and response contract, but sensor depth on them is a later phase.

## 0. Design principles

1. **Evolve, don't rewrite.** Keep the .NET/SQL Server/Next.js/Zig stack,
   enrollment, JWT, device signatures, spool format family, TI fetchers, sinks.
2. **One canonical event model**, versioned, shared by every platform and
   every consumer (detection, graph, hunting, UI, sinks).
3. **Process entity ID is the join key** for everything. PID is never identity.
4. **Deterministic enforcement.** Detection, risk and response decisions are
   rule-driven. No LLM in any blocking, scoring or enforcement path.
5. **Fail safe.** Unsupported rule constructs reject loudly; isolation has a
   local failsafe; updates must verify signatures; queues are bounded.
6. **Budgets are features.** CPU <1% typical, RSS tens of MB, bounded disk,
   measured in CI.
7. **Single-node first.** Target ≤1,000 endpoints on one API node + one SQL
   Server. Remove in-memory state that blocks a second node, but do not add
   Kafka/ClickHouse/Redis now.

## 1. Data flow

```
Agent sensors ─► priority ring buffers ─► spool (P0..P3) ─► uploader (gzip, signed)
                                                              │
                         POST /api/agents/events (v2) ◄───────┘
                                   │  validate, dedupe, persist (fast path only)
                                   ▼
                          Events (typed columns) ──► IngestQueue (DB-backed cursor)
                                                        │
                       ┌────────────────────────────────┼─────────────────────────┐
                       ▼                                ▼                         ▼
               Graph builder                    Detection engine            IOC matcher
         (ProcessEntities, Edges)        (atomic/sequence/threshold/   (hash/domain/IP/URL
                       │                  relationship/rarity, Sigma)    index, in memory)
                       └────────────────────────────────┬─────────────────────────┘
                                                        ▼
                                          Detections (evidence items)
                                                        ▼
                                  Correlator ─► Incidents ─► Risk engine
                                                        ▼
                                   Alerts/Incidents API, UI, sinks (async)
                                                        ▼
                                       Response engine ─► durable action queue ─► agent
TI feeds ─► Indicators (lifecycle) ─► IOC index        Reputation enrichment (async, cached)
```

Ingest commits telemetry and returns. Everything after `IngestQueue` is
asynchronous (hosted service draining a DB cursor), so slow TI providers,
sinks or rule evaluation never block agents. Restart-safe because the cursor
and sequence state live in SQL.

## 2. Canonical event model (schema v2)

### 2.1 Envelope

```json
{
  "schema": 2,
  "batch_id": "uuid",
  "agent": {"agent_id": "uuid", "sensor_version": "0.2.0", "boot_id": "uuid"},
  "events": [{
    "event_id": "uuid",
    "event_type": "PROCESS_START",
    "v": 1,                       // per-type payload version
    "ts": "2026-10-04T09:42:11.123456Z",   // event time from sensor
    "mono": 123456789012,         // monotonic ns since boot
    "seq": 9001,                  // durable per-agent sequence
    "priority": 1,
    "sensor": "etw.kernel-process",
    "data": { ... typed per event_type ... }
  }],
  "signature": "b64 ed25519"
}
```

- `tenant_id`, `endpoint_id`, `hostname`, `platform`, `os_version` are not
  sent per event; the server stamps them from the authenticated agent record.
- Unknown fields are ignored; unknown `event_type` stored as raw with a
  diagnostic. Old `schema: 1` (current) batches are accepted and mapped by a
  legacy normaliser for as long as v1 agents exist.
- Each event type has a JSON Schema in `schemas/events/<type>.v<N>.json`,
  generated into Zig structs and C# records, plus golden-file tests on both
  sides.

### 2.2 Common objects

```
process: entity_id, pid, start_time, image, name, command_line, cwd,
         user{name,sid|uid,domain}, session_id, integrity_level, elevated,
         hashes{sha256,sha1?,md5?}, signature{status,signer,issuer,thumbprint}
parent:  entity_id, pid, image (denormalised for detection without joins)
file:    path, name, extension, size, hashes, signature
network: protocol, src_ip, src_port, dst_ip, dst_port, direction
dns:     query, qtype, answers[], status
registry: key, value_name, value_type, data (truncated)
```

### 2.3 Event types (v1 payloads)

`PROCESS_START`, `PROCESS_EXIT`, `IMAGE_LOAD`, `FILE_CREATE`, `FILE_WRITE`,
`FILE_DELETE`, `FILE_RENAME`, `REGISTRY_CREATE`, `REGISTRY_SET`,
`REGISTRY_DELETE`, `NETWORK_CONNECT`, `NETWORK_LISTEN`, `DNS_QUERY`,
`USER_LOGON`, `USER_LOGOFF`, `USER_LOGON_FAILED`, `SERVICE_CREATE`,
`SERVICE_CHANGE`, `SCHEDULED_TASK_CREATE`, `SCHEDULED_TASK_CHANGE`,
`POWERSHELL_ACTIVITY`, `SCRIPT_ACTIVITY`, `SECURITY_PRODUCT_CHANGE`,
`AGENT_HEALTH`, `AGENT_TAMPER`, `RESPONSE_STATUS`, plus the existing
inventory types (`SYSTEM_INFO`, `PROCESS_SNAPSHOT`, `FILE_INTEGRITY`,
`PACKAGE_INVENTORY`, …) kept as P3.

### 2.4 Process entity ID

```
entity_id = base32( SHA-256( agent_id || pid_le32 || start_time_100ns_le64 || boot_id )[0..16] )
```

- Windows `start_time` = process creation FILETIME (from ETW event or
  `GetProcessTimes`); Linux = `/proc/<pid>/stat` starttime + boot time;
  macOS = `kp_proc.p_starttime`.
- The agent keeps a pid→entity table (bounded LRU, seeded at start from a
  snapshot) so it can fill `parent.entity_id` at creation time, before the
  parent can exit and its PID be reused.
- The server never derives identity from PID.

## 3. Agent architecture

### 3.1 Threads

| Thread | Work |
|---|---|
| sensor(s) | ETW consumer on Windows (blocking `ProcessTrace`); inotify/fanotify/eBPF later on Linux; ESF later on macOS. Push to rings only. |
| enrich | hashing, signature checks, pid→entity resolution, filtering, dedup cache. Bounded work queue; hashing is skipped and marked `hash_pending` under pressure. |
| collector | remaining polled collectors (inventory, FIM, snapshots) on timers. |
| uploader | spool → batch → gzip → sign → POST; heartbeat; action long-poll. |
| actions | executes response actions from the persisted action journal. |

Rings are fixed-size per priority. No unbounded allocation on the event path.

### 3.2 Priorities and backpressure

| Priority | Content |
|---|---|
| P0 | `AGENT_TAMPER`, `RESPONSE_STATUS`, local critical detections |
| P1 | process start/exit, persistence (service, task, run keys), logon, PowerShell script block |
| P2 | network, DNS, file create/write/rename in watched dirs, image load (filtered) |
| P3 | snapshots, inventory, FIM, health detail |

Under pressure: drop P3 → sample P2 (keep first-seen tuples) → never drop P0/P1
until spool hard cap, then drop oldest P1 before any P0. Every drop increments
`dropped[priority][reason]`, reported in `AGENT_HEALTH`.

### 3.3 Spool v2

- Segment files per priority (e.g. 4 MB), CRC'd records (reuse current record
  format), acked by segment + offset. Ack deletes whole segments — no
  full-file reads.
- Group commit: fsync every 250 ms or 256 records, P0 fsync immediately.
- Per-priority byte caps summing to `max_spool_bytes`.
- Optional at-rest encryption (XChaCha20-Poly1305, key from OS keystore) —
  default on for Windows/macOS.
- Reconnect upload: highest priority first, rate-limited (token bucket, server
  may lower via heartbeat `upload_rate` hint) to avoid catch-up storms.
- `seq` persisted in the spool header; monotonic across restarts.

### 3.4 Windows sensor (`agent/src/platform/windows/`)

User-mode only. No kernel driver.

| File | Source |
|---|---|
| `etw.zig` | thin wrapper: `StartTrace`/`EnableTraceEx2`/`OpenTrace`/`ProcessTrace`, TDH-free manifest decoding for the fixed event IDs we use, session `Tawny-Sensor`, restart on loss |
| `process.zig` | `Microsoft-Windows-Kernel-Process` (start 1, stop 2, image load 5); cmdline via `NtQueryInformationProcess(ProcessCommandLineInformation)`; token → user SID, session, integrity, elevation |
| `network.zig` | `Microsoft-Windows-Kernel-Network` TCP connect/accept, UDP send (first-seen tuple dedup) |
| `dns.zig` | `Microsoft-Windows-DNS-Client` event 3008 (query complete, with PID) |
| `filesystem.zig` | `Microsoft-Windows-Kernel-File` create/write/rename/delete, filtered in-sensor to executable/script extensions and watched dirs (user profiles, Temp, Startup, ProgramData, System32 writes) |
| `registry.zig` | `Microsoft-Windows-Kernel-Registry` set/create/delete, filtered to persistence and security-relevant keys (Run/RunOnce, Services, IFEO, Winlogon, AppInit, LSA, Defender policy) |
| `authentication.zig` | `EvtSubscribe` Security 4624/4625/4634/4647/4648/4672 (requires Event Log Readers or SYSTEM) |
| `services.zig` | `EvtSubscribe` System 7045/7040 + SCM queries for detail |
| `powershell.zig` | `Microsoft-Windows-PowerShell/Operational` 4104 script block (reassemble multi-part), 4103 optional |
| `signatures.zig` | `WinVerifyTrust` + catalog lookup (`CryptCATAdmin*`), cached by (path, size, mtime) |
| `sensor.zig` | lifecycle, provider health, emits `AGENT_HEALTH` / `AGENT_TAMPER` when a provider stops delivering |

Also: Defender state changes (`Microsoft-Windows-Windows Defender/Operational`
5001/5007/5010/5012) → `SECURITY_PRODUCT_CHANGE`; Task Scheduler Operational
106/140/141 → scheduled task events.

**Prerequisites:** a proper Windows service entry point
(`StartServiceCtrlDispatcherW`, stop/shutdown handling) and running as
`LocalSystem` (real-time kernel ETW and Security log subscriptions need it).
The restricted virtual account stays available for a telemetry-lite mode.

Process snapshots remain as a reconciliation pass (every 10 min) to detect ETW
gaps and seed the entity table.

### 3.5 Linux and macOS

Same envelope and types. Short term: Linux emits `PROCESS_START` from the
existing `/proc` diff with `entity_id`; macOS adds a `proc_listallpids` diff.
Later: Linux fanotify + eBPF (or auditd netlink) and macOS Endpoint Security
(requires entitlement). The Linux service must run with the capabilities needed
for visibility (`CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `CAP_KILL`) instead of
fully unprivileged.

## 4. Backend storage

Keep SQL Server. Add typed tables; keep the raw payload for fidelity.

```
Events          (Id bigint, TenantId, AgentId, EventId uuid unique, EventType smallint,
                 Ts datetime2(6), ReceivedAt, Seq, Priority, SchemaVersion,
                 ProcessEntityId binary(16) null, ParentEntityId binary(16) null,
                 UserName, ImageName, DstIp, DstPort, DnsQuery, FilePath, Sha256, RegistryKey,
                 Data nvarchar(max))         -- clustered columnstore + rowstore NCIs
ProcessEntities (TenantId, AgentId, EntityId PK, ParentEntityId, Pid, Ppid, StartTime, EndTime,
                 Image, CommandLine, UserName, UserSid, SessionId, Integrity, Elevated,
                 Sha256, SignatureStatus, Signer, FirstEventId)
ActivityEdges   (TenantId, AgentId, Ts, SrcEntityId, Relation smallint,
                 DstKind smallint, DstKey nvarchar(512), EventId)
```

Relations: `USER_STARTED_PROCESS`, `PROCESS_SPAWNED_PROCESS`,
`PROCESS_CONNECTED_TO_IP`, `PROCESS_QUERIED_DOMAIN`, `PROCESS_CREATED_FILE`,
`PROCESS_MODIFIED_FILE`, `PROCESS_EXECUTED_FILE` (file written then started:
join `FILE_*` path/sha256 to `PROCESS_START.image`), `PROCESS_MODIFIED_REGISTRY`,
`PROCESS_CREATED_SERVICE`, `PROCESS_CREATED_TASK`.

Trees via recursive CTE on `ProcessEntities.ParentEntityId` (depth-capped).
Late-arriving parents are linked when they appear (edges keyed by entity ID,
not row order).

Retention: separate policies for raw events (default 30 d), entities/edges
(90 d), detections/incidents/alerts (1 y). **Remove the alert→event cascade**;
detections store an evidence snapshot.

### Investigation APIs

```
GET /api/processes/{entityId}                 entity + parent chain
GET /api/processes/{entityId}/tree?depth=     ancestors + descendants
GET /api/processes/{entityId}/timeline        events by this entity (+children?)
GET /api/agents/{id}/timeline?from&to&filters endpoint timeline
GET /api/alerts/{id}/graph                    nodes + edges for the alert's lineage window
GET /api/incidents/{id} | /graph | /timeline
```

## 5. Detection engine

One engine over canonical fields (`process.name`, `parent.image`, `dns.query`,
…). Rule definitions in YAML; built-in packs under `rules/` in the repo,
tenant rules in DB.

| Kind | Semantics | State |
|---|---|---|
| atomic | predicate on one event | none |
| sequence | ordered steps within window, joined by `by:` key (e.g. `process.entity_id` lineage or `agent_id`) | DB table `SequenceState` (replaces in-memory) |
| relationship | predicate over an event plus its ancestors (`ancestor[n].image`), resolved via entity cache | entity cache |
| threshold | count/distinct-count of matching events per key in window | sliding counters, persisted on checkpoint |
| rarity | first-seen of a tuple per tenant/agent over baseline period (exe hash, parent→child pair, dst domain, exe dir, signer) | `Baselines` table, learning mode first N days |

Operators: eq, neq, contains, startswith, endswith, wildcard, regex (RE2-safe,
timeout), in, cidr, gt/lt, exists, base64/utf16 transforms. Case-insensitive
by default.

Each detection outputs **evidence items**: `{rule_id, key, weight, confidence,
severity, attack[], entity_ids[], event_ids[], explanation}`.

### Sigma

- Rebuild `SigmaRuleImporter` as a compiler to the same AST.
- Explicit mapping table `rules/sigma/field-map.yaml`
  (`Image→process.image`, `ParentImage→parent.image`,
  `CommandLine→process.command_line`, `TargetFilename→file.path`,
  `QueryName→dns.query`, `DestinationIp→network.dst_ip`,
  `TargetObject→registry.key`, `Hashes→process.hashes.*`, …) and logsource
  mapping (`product: windows, category: process_creation → PROCESS_START`).
- Support all value modifiers in common use (`contains|startswith|endswith|all|
  re|cidr|base64|base64offset|windash|wide|exists|gt|lt|gte|lte`), keyword
  lists, list-of-maps, `1 of them`, `all of them`, wildcards.
- Unsupported construct or unmapped field ⇒ rule **rejected** with
  diagnostic; never partially applied. Statuses: `supported`, `rejected`
  (reason), and `supported_with_notes` only where semantics are provably
  equivalent.
- CI job compiles a pinned SigmaHQ `rules/windows` snapshot and publishes
  counts (imported/supported/rejected by reason) to
  `docs/sigma-compatibility.md`; regression = test failure.

### IOC index

Indicators move out of `AlertRules` into an `Indicators` table (type, value,
source, confidence, severity, first/last seen, expires, tags, actor,
campaign, TLP). Matcher keeps per-tenant in-memory hash sets (rebuilt on
change) — O(1) per field instead of O(rules). Types: sha256, sha1, md5,
domain (exact + parent-domain), IP/CIDR, URL (normalised), signer
thumbprint. Expired indicators stop matching; aging job.

## 6. ATT&CK

- Rules carry `attack: [{tactic, technique, subtechnique}]`; alerts and
  incidents expose the union.
- `rules/attack/coverage.yaml` declares, per technique, which telemetry
  sources supply it. Coverage view computes three independent states per
  technique: **telemetry available** (sensor enabled and healthy on ≥1
  endpoint), **detection available** (enabled rule maps to it),
  **response available** (a response action is applicable). No state is
  inferred from another.

## 7. Risk engine

Per incident, deterministic:

```
for each evidence item e (deduped by e.key within incident):
    s_e = weight_e × confidence_e × context_e      # context: 0 if allowlisted, 0.5 signed-by-trusted-vendor, 1 otherwise
risk = 100 × (1 − Π(1 − s_e/100))                   # noisy-OR: saturates, never exceeds 100
severity = critical ≥85, high ≥65, medium ≥40, low otherwise
         (floor raised to a rule's own severity when that rule is marked "definitive")
```

Weights live in rule YAML (e.g. Office→PowerShell 25, encoded command 20,
unsigned exe written 20, rare destination 10, high-confidence TI match 50,
persistence 30). Duplicate evidence contributes once; time decay drops
evidence older than the incident window. The response lists every
contributing item with its points, so the analyst sees *why*.

## 8. Incident correlation

Detections are attached to an incident when, within a window (default 4 h):

1. Same agent and shared lineage root (nearest common ancestor below
   `explorer.exe`/`services.exe`/session root), or
2. Same agent and same user, plus a shared artifact (file sha256, domain, IP), or
3. Cross-agent: same high-confidence indicator or same new file hash.

Incident: title (from highest-weight evidence), endpoints, users, root
process, attack chain (lineage path through evidence entities), risk,
ATT&CK union, status (new/investigating/resolved/false_positive), owner.
Alerts become views of detections inside incidents; sinks receive incidents
and updates (debounced).

## 9. Response engine

### 9.1 Actions

`kill_process`, `suspend_process`, `resume_process`, `quarantine_file`,
`restore_file`, `collect_file`, `collect_process_info`, `collect_timeline`,
`block_indicator` (hash: deny execution via local check; IP/domain: WFP
filter), `isolate`, `release`, `collect_bundle`.

All process targeting by `entity_id` (agent verifies pid + start time before
acting). All file targeting by path + sha256 (agent verifies hash).

### 9.2 Durable queue

Server states: `QUEUED → DELIVERED → ACKNOWLEDGED → RUNNING → SUCCEEDED |
FAILED | EXPIRED | CANCELLED`. Each transition timestamped
(`requested_at`, `delivered_at`, `received_at`, `started_at`,
`completed_at`) and audited.

- Delivery: heartbeat piggyback **plus** long-poll
  `GET /api/agents/actions?wait=25` so latency is seconds, not 60 s.
- Commands are signed by a server action key (Ed25519, public key pinned at
  enrollment); agent rejects unsigned or mismatched commands.
- Agent writes the action to a local journal before acking; replays journal on
  restart; dedupes by `action_id`; reports status via P0 `RESPONSE_STATUS`
  events *and* the result endpoint (retried until acked).
- Server times out `DELIVERED` without ack → redeliver; `RUNNING` past deadline
  → `FAILED (timeout)` unless late result arrives (then recorded).
- Actions are idempotent by design (kill of exited entity = success
  "already gone"; isolate when isolated = success; quarantine checks hash).
- Destructive actions optionally require a second approver (tenant setting).

### 9.3 Windows isolation

WFP user-mode API, persistent filters in a Tawny sublayer at max weight:

- Permit: Tawny server IPs (resolved at isolation time + pinned list), DNS to
  configured resolvers only for the server hostname, DHCP, loopback,
  optional admin allowlist.
- Block: everything else in/out (ALE connect/accept v4/v6).
- **Verify:** agent probes a blocked target and the server, reports both.
- **Release:** delete sublayer filters, verify connectivity restored.
- **Failsafe:** isolation carries `max_duration` (default 24 h). Agent stores
  the deadline locally and releases automatically if it passes without a
  server renewal. Local break-glass: an offline release code (HMAC of
  agent_id + nonce with a per-agent secret shown in the UI) entered via
  `tawny-agent release --code`.
- On agent start, existing Tawny filters are reconciled against journal
  state, so a crash never leaves orphaned or missing isolation.

### 9.4 Quarantine

Move to `%ProgramData%\Tawny\Quarantine\<sha256>.bin` (SYSTEM-only ACL),
XOR-obfuscated/encrypted so AV and execution can't touch it, with sidecar
metadata (original path, ACL SDDL, owner, timestamps, hashes, source action).
Restore re-creates path + ACL. Original deleted only after the quarantine
copy is fsynced and its hash verified.

## 10. Agent identity, protection, updates, health

### Identity

1. Enrollment token (single use, existing).
2. Agent generates Ed25519 keypair **required**; private key protected by
   DPAPI (machine scope, Windows; TPM-backed CNG key later), Keychain
   (macOS), root-only 0600 file + optional TPM (Linux).
3. Server binds key to agent record; JWT refresh requires a signed challenge
   (proof of possession). Batch signatures mandatory for v2.
4. Ingest checks `cv` (fixes current gap). Pinned server action key and
   release key delivered at enrollment.

### Tamper detection (`AGENT_TAMPER`)

Service stop not initiated by SCM shutdown/upgrade (recorded on next start
via clean-shutdown marker), binary hash mismatch vs signed manifest, config or
identity file change (hash + mtime check, Windows directory change
notifications), ETW session stopped or provider disabled, Defender exclusion
added for Tawny paths. Server-side: heartbeat gap > N min with no shutdown
notice → `AGENT_SILENT` detection. Install ACLs and service DACL restrict
stop/delete to SYSTEM/Admins. No anti-debug or rootkit behaviour.

### Updates

- Release manifest `{version, platform, sha256, size, min_from_version,
  ring}` signed with an offline Ed25519 release key (minisign-compatible);
  public key compiled into the agent. CI signs; private key stays out of CI
  except via a protected environment.
- Agent: verify signature → verify hash → refuse version ≤ current
  (downgrade only via signed `rollback` manifest) → stage → swap (rename
  running exe on Windows) → restart → health check window → commit or roll
  back to `.previous`.
- Rings: `canary`, `internal`, `10%`, `50%`, `100%`; agent bucket =
  hash(agent_id) mod 100. Server promotes a ring only when crash/rollback rate
  in the previous ring stays under threshold for the soak period.
- Authenticode-sign Windows binaries and notarise macOS when certificates are
  available; the manifest signature is the trust root regardless.

### Health (`AGENT_HEALTH`, every heartbeat)

version, uptime, last event ts, queue depth per priority, spool bytes, events
generated / dropped per priority and reason, CPU %, RSS, disk free, per-sensor
status (running/degraded/stopped + last event age), isolation state, update
state. Server computes `healthy|degraded|silent|tampered`; agents list sorts
unhealthy first; silent > 15 min raises a detection.

## 11. False-positive management

Exceptions table generalises `SuppressionRules`: match on hash, signer,
path (glob), domain, process relationship (parent image → child image),
rule id; scope tenant / agent group / agent; temporary (expires) or permanent;
reason + creator required; every create/change/expiry audited. Suppressed
detections are **recorded** with the matching exception id (not discarded) so
the UI can show "suppressed by X because Y" and hit counts. Agent groups
(tags) added for scoping.

## 12. Investigation UI

- **Incident page:** header (what/why/risk breakdown/ATT&CK/TI matches),
  lineage graph (React Flow or ELK-layered SVG; click node → event details),
  timeline before/after, network destinations, files created, persistence,
  response action panel with live states.
- **Endpoint timeline:** virtualised list, filters by process, user, event
  type, severity, technique, destination, file.
- **ATT&CK coverage matrix** (three-state).
- **Agent health** column and fleet health page.
- **Exceptions** page with audit trail.
- Alerts triage (ack/resolve) — requires new backend endpoints.

## 13. Hunting

Extend the DSL to canonical field names (`process.name`, `parent.name`,
`dns.query`, `file.sha256`, `user.name`, `attack.technique`) with wildcards.
Fields that map to promoted columns are pushed to SQL; others filter in memory
after SQL narrowing. Field catalog endpoint for autocomplete. Add
`| count by field` and `| stats` for basic aggregation. Fix event-type parsing
to cover all types.

## 14. AI boundary

No AI exists in-repo today; Tawny-SOC receives alerts/telemetry externally.
If added: AI may summarise incidents, explain trees, propose hunts and
investigation steps, draft reports. AI output is advisory only. It cannot
create, approve or execute response actions, change exceptions, or alter
risk/severity. Any AI-suggested action is presented as a draft requiring a
human with Admin role to submit through the normal action API.

## 15. Performance

Budgets (engineering targets): idle CPU ≈0%, typical workstation <1% avg,
RSS <60 MB steady, spool ≤ configured cap, upload ≤ ~50 KB/min/endpoint
typical after gzip.

Bench harness (`agent/bench/`): synthetic ETW-rate generators plus scripted
real workloads on Windows CI runners — process storm (10k short procs),
`npm install` large tree, MSBuild compile, file storm (100k files), large
download, browser automation, boot/shutdown, offline 24 h + reconnect. Record
CPU, RSS, drops, upload rate; fail CI on regression beyond tolerance.

## 16. Pre-existing issues to fix first (Phase 0)

**Status: done (2026-10-04, branch `edr/phase-0`).** Also completed: Brolga
reputation provider removed, Kelpie leftovers removed, backend on .NET 10.0.12
with current packages, agent on Zig 0.17.0, Windows service runs as
`LocalSystem`.

| Issue | Where |
|---|---|
| Open sign-up with default `Admin` role | `web/lib/auth.ts`, `web/prisma/schema.prisma` |
| Windows agent lacks service entry point | `agent/src/main.zig` |
| Unescaped JSON / URL building in agent | `agent/src/enrollment.zig`, `transport/http.zig` |
| Ingest doesn't check credential version | `TelemetryController.cs` |
| Tenant claim falls back to default tenant | `TenantClaimExtensions.cs` |
| Alerts deleted by telemetry purge cascade | `TawnyDbContext.cs`, `PurgeOldEventsJob` |
| Feed auth header stored plaintext | `ThreatIntelFeedsController.cs` |
| Rule edit destroys Sigma/IOC source | `AlertRulesController.cs` |
| Audit row per heartbeat/ingest (unbounded growth) | `AgentsController.cs`, `TelemetryController.cs` |
| Live stream route missing in web | `web/app/agents/[id]/events-panel.tsx` |

## 17. Phased delivery

| Phase | Scope | Exit criteria |
|---|---|---|
| 0 | Fixes in §16 | tests for each; CI green |
| 1 | Event schema v2 + codegen; agent threading, priority rings, spool v2, gzip, durable seq, health; server v2 ingest + legacy normaliser + async ingest queue | v1 and v2 agents ingest side by side; spool fault-injection tests |
| 2 | Windows service + ETW sensor (process, image, network, DNS, file, registry, auth, services, tasks, PowerShell, signatures) | Windows CI integration test sees spawned chain with correct entity IDs; budgets measured |
| 3 | ProcessEntities/ActivityEdges, investigation APIs, endpoint timeline UI, process graph UI | reconstruct Office→PS→payload test chain from fixtures |
| 4 | Detection engine (atomic/sequence/relationship/threshold/rarity), Sigma compiler + compat CI, Indicators table + IOC index, ATT&CK coverage | SigmaHQ windows stats published; detection fixtures pass |
| 5 | Evidence → incidents → risk; incident UI; exceptions v2; alert triage | example chain yields single incident with explained score |
| 6 | Durable response queue, long-poll, signed commands; kill/suspend/quarantine/restore/collect on Windows; WFP isolation with failsafe | fault-injection: restart agent/server mid-action, duplicate delivery, offline isolation expiry |
| 7 | Key protection (DPAPI/Keychain), PoP refresh, tamper detection, signed self-update with rings | update/rollback/downgrade-rejection tests |
| 8 | Bench harness and budgets in CI; Linux/macOS parity work | budgets enforced |

## 18. Open decisions

1. **Scale target.** Design assumes ≤1,000 endpoints on SQL Server
   (columnstore). Larger fleets would need a telemetry store change.
2. **Windows service account.** Full sensor requires `LocalSystem`.
3. **Kernel visibility gaps accepted for now.** User-mode ETW cannot block
   execution pre-launch and can be tampered with by an admin-level attacker;
   prevention is limited to post-launch kill/quarantine and WFP blocking.
4. **Code-signing certificates** (Authenticode, Apple Developer ID) — needed
   for production trust and SmartScreen; procurement is outside the repo.
