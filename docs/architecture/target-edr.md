# Tawny — Target EDR Architecture

Status: **proposal**, 2026-10-04. Baseline: [current-state.md](current-state.md).

Goal: the smallest architecture that gives a small-business fleet useful
endpoint protection — rich Windows telemetry, process lineage, behavioural and
IOC detection, explainable risk, correlated incidents, and safe response —
while staying lightweight, self-hosted and deterministic.

Windows is Tier 1. macOS and Linux stay supported; they receive the same event
model and response contract, but sensor depth on them is a later phase.

## 0. Design principles

1. **Evolve the product, replace the host stack once.** Issue #49 replaces
   the .NET API, Next.js server, and SQL Server with one Zig `tawny-server`,
   PostgreSQL, and a static UI. Enrollment, device signatures, the spool
   format family, TI fetchers, and sinks stay. Agent JWTs move to EdDSA;
   RS256 tokens still verify until the following release. EDR features in
   Phases 1–8 still land on this base; they are not part of the cutover.
2. **One canonical event model**, versioned, shared by every platform and
   every consumer (detection, graph, hunting, UI, sinks).
3. **Process entity ID is the join key** for everything. PID is never identity.
4. **Deterministic enforcement.** Detection, risk and response decisions are
   rule-driven. No LLM in any blocking, scoring or enforcement path.
5. **Fail safe.** Unsupported rule constructs reject loudly; isolation has a
   local failsafe; updates must verify signatures; queues are bounded.
6. **Budgets are features.** CPU <1% typical, RSS tens of MB, bounded disk,
   measured in CI.
7. **Single-node first.** Target ≤1,000 endpoints on one `tawny-server` plus
   one PostgreSQL instance (2 vCPU / 4 GB reference box). Advisory locks and
   `SKIP LOCKED` keep a second instance safe later. Do not add
   Kafka/ClickHouse/Redis now.

## 1. Data flow

Cutover (issue #49): one Zig process, `tawny-server`. Caddy terminates TLS.
Zig does not. The browser loads the static SPA from that same origin and
calls the API with an HttpOnly session cookie. There is no web→API HMAC hop.
Agents keep enroll, heartbeat, event ingest, and action-result. Newly issued
agent JWTs are EdDSA. RS256 tokens signed by the current PEM still verify
and rotate to EdDSA on the next heartbeat.

```
Agent sensors ─► priority ring buffers ─► spool (P0..P3) ─► uploader (gzip, signed)
                                                              │
                         POST /api/agents/events ◄────────────┘
                                   │  validate, dedupe, persist, enqueue
                                   │  202 — detection does not run inline
                                   ▼
                            PostgreSQL work_queue
                                   │
           ┌───────────────────────┼────────────────────────┐
           ▼                       ▼                        ▼
    Detection worker          Sink delivery            SSE broker
    predicate, Sigma,         Wazuh, Slack,            LISTEN/NOTIFY
    IOC, sequence,            Sentinel, Tawny-SOC      /events/stream
    YARA-lite, exposure,
    suppression
           │
           ▼
    alerts ─► dashboard, BlakSoc, jobs
           │
           ▼
    response actions ─► heartbeat (≤10, execution token) ─► agent

Browser ──HTTPS──► Caddy ──HTTP──► tawny-server
                   static SPA, session cookie, CSRF on writes

TI feeds ─► indicators ─► IOC index     Reputation enrichment (async, 24 h cache)
```

Ingest only validates, persists, and enqueues. A worker creates alerts and
enqueues sink delivery after the `202` returns, so a slow provider never
blocks an agent. Sequence progress and the hunt cursor live in Postgres, so
a restart does not re-alert an event a scheduled hunt already matched.

The activity graph, incident correlator, and risk engine drawn in earlier
drafts of this section are Phases 1–8. They are not built here. The queue
is the seam they attach to later.

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
  plus golden-file tests on both sides. The backend is Zig on PostgreSQL
  (`server/`); the agent is Zig. There is no code generation: both sides
  check payloads against the schemas in tests (`agent/src/schema_check.zig`,
  `server/src/ingest/schema_check.zig`).

**Status (issue #55).** Built as above with these differences:

- `ts` is an ISO 8601 UTC string. `seq` is durable: it is stored in each
  spool record (`EVT2`) and in a `<spool>.seq` sidecar, so it keeps rising
  across restarts. `mono`, `priority` and `sensor` are accepted but not
  sent or stored yet.
- `event_type` keeps the agent's snake_case names (`process_start`,
  `dns_query`, ...), not the upper-case names in 2.3, so existing rules,
  hunts and backup type numbers keep working.
- `signature` is Ed25519 over the `tawny-batch-v2` canonical string, which
  covers `agent_id`, `batch_id`, `agent.boot_id`, `agent.sensor_version` and
  per event `event_id|seq|event_type|v|ts|sha256(data)`. See
  `server/src/crypto/batch_sig.zig` and `docs/api.md`.
- The server accepts schema 1 and schema 2 side by side. Schema 1 events are
  stored as sent; the legacy normaliser (`server/src/ingest/legacy.zig`)
  derives process identity for them (`process_launch` maps to
  `process_start`).
- Schemas exist for `process_start`, `process_exit`, `network_connect`,
  `dns_query`, `file_create`, `registry_set`, `user_logon`,
  `service_create`, `powershell_script_block`, `agent_health` and
  `sensor_health`. Snapshot and inventory types keep their payloads (P3).

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

**Status (issue #55).** Implemented in `agent/src/entity.zig` and, for v1
events only, `server/src/ingest/entity.zig`, with shared golden tests. Exact
bytes:

- `agent_id` and `boot_id`: the 36 ASCII bytes of the lower-case canonical
  UUID text. Unknown boot id: the nil UUID text.
- `pid_le32`: u32 little endian.
- `start_time_100ns_le64`: u64 little endian, 100 ns ticks since
  1970-01-01T00:00:00Z (Unix epoch, not 1601), truncated to whole
  milliseconds so Sysmon `UtcTime` and `GetProcessTimes` agree.
- base32: RFC 4648 alphabet, lower case, no padding (26 characters).
- Boot id sources: Linux `/proc/sys/kernel/random/boot_id`; macOS
  `kern.bootsessionuuid`; Windows a UUID derived from the registry `BootId`
  counter (`PrefetchParameters`).
- Start time sources: Windows Sysmon 1 `UtcTime`, Security 4688
  `TimeCreated`, `GetProcessTimes` for the start-up snapshot; Linux
  `/proc/<pid>/stat` starttime plus `btime`; macOS `pbi_start_tvsec/usec`.
- Sysmon `ProcessGuid` stays as `process.guid`, not the id.
- Schema 1 events have no boot id, so the server computes their ids with the
  nil boot id and links parents by pid and start time.
- Stored in `process_entities` (migration 0004, row-level security) and
  served by `GET /api/agents/{id}/process-tree?entity_id=`.

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

User-mode only. Tawny ships no kernel driver of its own.

**Status (issue #54): Sysmon plus `EvtSubscribe` comes first, ETW later.**
Sysmon already does the hard parts (process GUIDs, hashes, command lines,
network, registry, DNS), so the first Windows sensor reads event logs instead
of running its own ETW session:

| File | Source |
|---|---|
| `eventlog.zig` | wevtapi pull subscriptions (`EvtSubscribe` with a signal event, `EvtNext`, `EvtRender(EvtRenderEventXml)`), one bookmark per channel saved under the state directory |
| `evtxml.zig` | small parser for the rendered XML: `System/EventID`, `TimeCreated/@SystemTime`, `EventRecordID`, every `EventData/Data[@Name]` |
| `collectors/windows_events.zig` | one mapper per event ID to the section 2.2 field names, 4104 script block reassembly, per-tick cap, drop counters, `sensor_health` |

| Channel | Event IDs | Tawny event type |
|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | 1, 5 | `process_start`, `process_exit` |
| same | 3 | `network_connect` |
| same | 22 | `dns_query` |
| same | 11; 23 and 26 | `file_create`; `file_delete` |
| same | 12, 13, 14 | `registry_create` (or `registry_delete`), `registry_set`, `registry_rename` |
| same | 7, 8, 10 | `image_load`, `remote_thread`, `process_access` |
| `Security` | 4624, 4625, 4672, 4688 | `user_logon`, `user_logon_failed`, `special_privileges`, `process_start` (only while Sysmon is not delivering) |
| `System` | 7045 | `service_create` |
| `Microsoft-Windows-PowerShell/Operational` | 4104 | `powershell_script_block` |

Sysmon loads its own Microsoft-signed driver. "No driver" means Tawny ships
none. Sysmon is optional (`install.ps1 -InstallSysmon`); without it the agent
falls back to Security 4688 and reports `sensor_health` degraded.

The ETW design below is the later step. It stays the target for hosts where
Sysmon cannot be installed and for data Sysmon does not give (token detail,
Defender state).

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

PostgreSQL 16 or 17, volume-backed. The application connects as a role that
does not own the tables. Every tenant-owned table has `tenant_id` and
`FORCE ROW LEVEL SECURITY`, keyed on `current_setting('tawny.tenant_id', true)`
for the transaction. Queries still pass `tenant_id` (defence in depth).
Jobs that read across tenants use a separate `BYPASSRLS` role.

Identity columns: `uuid` where .NET used `Guid`, `bigint GENERATED ALWAYS AS
IDENTITY` where it used `long`. Timestamps are `timestamptz`. Telemetry and
rule payloads are `jsonb`. `alert_rules.mitre_techniques` and `agents.tags`
are `text[]`.

`telemetry_events` is range-partitioned by `received_at`, one partition per
month. Retention deletes alerts older than 365 days, then deletes telemetry
older than 30 days that no surviving alert references. A month partition is
detached only when no surviving alert still points at a row in it. Referenced
rows stay in that partition so the foreign key remains valid. PostgreSQL
requires a unique key on a partitioned table to include the partition column,
so the alert foreign key is `(telemetry_received_at, telemetry_event_id)` and
the wire field stays `telemetry_event_id`. `ON DELETE` is `NO ACTION` (no
cascade). Dedupe of `client_event_id` lives on the unpartitioned
`telemetry_dedupe` table, unique on `(tenant_id, agent_id, client_event_id)`,
because that unique key cannot include `received_at`.

Cutover tables: `tenants`, `users`, `sessions`, `agents`, `telemetry_events`,
`telemetry_dedupe`, `alert_rules`, `alerts`, `response_actions`,
`suppression_rules`, `threat_intel_feeds`, `reputation_cache`, `saved_hunts`,
`hunt_runs`, `hunt_cursors`, `api_tokens`, `enrollment_tokens`, `audit_log`,
`agent_releases`, `jobs`, `work_queue`, `sequence_state`, `schema_migrations`.

`audit_log` is append-only for the app role (`INSERT`, `SELECT`) and stores
a hash chain (`prev_hash`, `hash`). `sequence_state` persists partial
sequence-rule progress. `hunt_cursors` stores the last matched event per
scheduled hunt so a later run does not raise the same alert again.
`work_queue` is claimed with `FOR UPDATE SKIP LOCKED`. Each job takes
`pg_try_advisory_lock` before it runs.

`group_by` on sequence rules stays ignored, matching the .NET evaluator.
That choice is recorded in the release notes.

Graph tables (`process_entities`, `activity_edges`) and incident/risk tables
are not created by this migration. When they land, relations stay
`USER_STARTED_PROCESS`, `PROCESS_SPAWNED_PROCESS`, `PROCESS_CONNECTED_TO_IP`,
`PROCESS_QUERIED_DOMAIN`, `PROCESS_CREATED_FILE`, `PROCESS_MODIFIED_FILE`,
`PROCESS_EXECUTED_FILE`, `PROCESS_MODIFIED_REGISTRY`, `PROCESS_CREATED_SERVICE`,
`PROCESS_CREATED_TASK`, joined by entity id rather than row order.

### 4.1 Zig 0.17 standard-library spike

Toolchain `0.17.0`, the same `minimum_zig_version` as `agent/build.zig.zon`.
macOS arm64 tarball sha256
`b607e9b9234790a008116ae5bdb71c6243b84b9fb42a53a9e70fde41c06c536a`.
No third-party Zig packages.

`std.http.Server` handles one connection: `init(*Reader, *Writer)`,
`receiveHead`, `respond` / `respondStreaming`. It does not listen. The
accept loop is `std.Io.net.IpAddress.listen` and `std.Io.net.Server.accept`
on `std.Io.Threaded`. The reader buffer is the header cap;
`error.HttpHeadersOversize` is the slowloris / oversize-head signal.
`std.crypto.tls` exposes `Client` only. There is no TLS server, so Caddy
terminates TLS.

Crypto that the server uses from `std`, confirmed present in 0.17.0:

- `std.crypto.sign.Ed25519` to issue agent JWTs (`generate(io)`, `sign`, `verify`)
- `std.crypto.Certificate.rsa.PKCS1v1_5Signature` to verify legacy RS256 tokens
- `std.crypto.aead.aes_gcm.Aes256Gcm` for `v1.` integration secrets (12-byte nonce, 16-byte tag, empty AAD)
- `std.crypto.pwhash.argon2` and `std.crypto.pwhash.scrypt` for passwords
- HMAC-SHA256 and PBKDF2 for Postgres SCRAM-SHA-256 and AWS SigV4

The spike listens on `127.0.0.1:18717`, answers `GET /api/health` with
`{"status":"ok"}` (105-byte HTTP response, status 200), signs and verifies
an Ed25519 message, and round-trips AES-256-GCM. `std.crypto.tls.Client` is
referenced so a missing TLS server type fails the build. Run on Zig 0.17.0
aarch64-macos printed:

```
spike-ok http=std.http.Server tls_server=absent ed25519=ok aes256gcm=ok
```

### Investigation APIs

Not in this cutover. Phase 1+ will add:

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

**Status (#53, Nov 2026):** atomic rules and suppressions now match one field
by dotted path, with array fan-out, through `server/src/detect/match.zig`.
Operators in use today: `exists`, `equals`, `contains`, `startswith`,
`endswith`, `greater_than`, `less_than`. The old whole-payload text fallback is
gone. The rest of the list above arrives with the Sigma compiler (#56). See
`docs/detections.md`.

**Status (#56):** sequence and threshold rules run in the detect job after
atomic matching (`server/src/detect/sequence.zig`, `threshold.zig`). State
is in `sequence_state` (keyed by rule and `by` key, with `expires_at`) and
`threshold_counters` (one row per matching event), both on event time, so
it survives a restart; the purge job removes expired rows. The rule format
is in `rules/README.md` and the starter rules in `rules/builtin/` are
seeded per tenant. Relationship and rarity rules are not built yet.
Detections still produce alerts, not evidence items.

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

**Status (#56).** Built in `server/src/detect/sigma.zig` (compiler),
`yaml.zig` (YAML subset), `regex.zig` (linear-time `re` with a step limit)
and `ast.zig` (AST, JSON form, evaluator over `match.zig` paths). The AST is
stored in `alert_rules.compiled_expression_json` with `compile_status` and
`compile_notes` (migration 0005). The pinned snapshot is
`rules/windows/process_creation` only (`rules/sigma/sigmahq/`, DRL 1.1);
other `rules/windows` folders need event types the agent does not send yet.
The `sigma-compat` CI job fails when the compiled count drops below
`rules/sigma/sigmahq/baseline-supported.txt`. Not built: `N of` with N
above 1, aggregations and `timeframe` (use a Tawny threshold rule),
correlation rules, `fieldref`. `wide` is only accepted with `base64` or
`base64offset`.

### YARA

File scanning with YARA runs on the agent through libyara, never on the
server. Files stay on the host unless an analyst collects them.

- **Build.** libyara 4.6.0 (BSD-3-Clause) is a lazy, pinned source dependency
  in `agent/build.zig.zon`, compiled with Zig's C compiler in
  `agent/build.zig` behind `-Dyara=true`. The default build doesn't fetch or
  link it. Modules that need other libraries (magic, cuckoo, hash, dotnet,
  dex, macho, authenticode) and OpenSSL are off, so `pe.imphash()` and
  signature checks are not available. Process memory scanning is off on
  macOS (`proc/none.c`) because `mach_vm.h` needs the macOS SDK; the agent
  only scans files and buffers.
- **Agent.** `agent/src/yara.zig` (compile, scan buffer, scan file, timeout,
  size cap; files are read into memory, not mapped). `yara_scanner.zig` runs
  the triggers: a created or modified executable or script in a watched
  folder (file events over `fim_paths`), the `yara_scan` response action
  (`{"path": ...}`, a file or one folder), and a scheduled scan of startup and
  temp folders (`yara_scan_interval_seconds`, default 3600). Each match is a
  `yara_match` event with rule, tags, file path, size, SHA-256 and trigger.
- **Rule packs.** The server bundles a tenant's enabled `format = 'yara'`
  rules (`POST /api/agent/yara-rules`) and signs them with Ed25519
  (`tawny-yara-pack-v1`: tenant, version, time and SHA-256 of the source).
  The agent pins the public key from the enrolment reply (or
  `yara_rule_key` in config) and refuses unsigned, tampered, wrong-key or
  older packs, keeping the rules it has. The heartbeat reply carries
  `yara_pack_version` so agents fetch only on change.
- **Key.** The server action key (#57) signs both response actions and YARA
  rule packs. `TAWNY_ACTION_SIGNING_KEY`, or derived from the agent JWT seed
  with its own label, separate from the JWT key. `TAWNY_RULE_SIGNING_KEY` is a
  deprecated alias. `state.rulePackKey` forwards to `state.actionKey`.
- **Alerts.** A `yara_match` raises an alert through the `yara` rule that
  declares the matched rule name, so suppressions and sinks work as usual.

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

**Status (#57).** The server signs every action with the action key and the
agent verifies it before acting, with a local journal for dedupe and restart
replay. Windows kill, suspend and resume work with the identity guard and the
critical-process refusal list. Quarantine and restore work on Windows, Linux
and macOS (XOR obfuscation, SDDL on Windows, owner-only elsewhere). WFP
isolation has the filter-building plan, the auto-release deadline, the
reconcile-on-start design and the break-glass release code as pure, tested
logic; the live FwpmEngine integration and the `tawny-agent release --code`
CLI are not wired yet, and `isolate_host`/`release` report `failed` until then.
Linux nftables isolation lands in #59.

## 10. Agent identity, protection, updates, health

### Identity

1. Enrollment token (single use, existing).
2. Agent generates Ed25519 keypair **required**; private key protected by
   DPAPI (machine scope, Windows; TPM-backed CNG key later), Keychain
   (macOS), root-only 0600 file + optional TPM (Linux).
3. Server binds key to agent record; JWT refresh requires a signed challenge
   (proof of possession). Batch signatures mandatory for v2.

   **Status (#53, Nov 2026):** batch signatures are verified now, not only
   checked for presence (`server/src/crypto/batch_sig.zig`). An agent with a
   stored key must sign every batch. Unsigned batches from keyless agents are
   refused while `TAWNY_REQUIRE_SIGNED_BATCHES` is on (the default). The
   server also refuses to start without a valid `TAWNY_AGENT_JWT_SEED`.
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

1. **Scale target.** Design assumes ≤1,000 endpoints on PostgreSQL
   (Zig `tawny-server`, telemetry partitioned by month). Larger fleets would
   need a telemetry store change.
2. **Windows service account.** Full sensor requires `LocalSystem`.
3. **Kernel visibility gaps accepted for now.** User-mode ETW cannot block
   execution pre-launch and can be tampered with by an admin-level attacker;
   prevention is limited to post-launch kill/quarantine and WFP blocking.
4. **Code-signing certificates** (Authenticode, Apple Developer ID) — needed
   for production trust and SmartScreen; procurement is outside the repo.
