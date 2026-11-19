# Windows endpoint security platform (WESP) — adoption plan

Status: **direction**, 2026-11-19. Source: Microsoft, "What's next: Windows
endpoint security platform and driver quality", Windows IT Pro Blog,
2026-11-17 —
<https://techcommunity.microsoft.com/blog/windows-itpro-blog/whats-next-windows-endpoint-security-platform-and-driver-quality/4572663>.

This document aligns Tawny's Windows direction with that announcement. It
changes nothing running today: Windows signal depth (Phase 2) shipped as
Sysmon plus event-log subscriptions, and enforcement (Phase 6) shipped as
signed response actions with WFP isolation. It changes where Windows
signal and enforcement come from **next** in
[architecture/target-edr.md](architecture/target-edr.md).

## What the announcement changes

The Windows endpoint security platform (WESP) reached general availability
on Windows 11 in November 2026. It gives security products **user-mode
APIs** for capabilities that historically required kernel-mode code:

- **Observation** — monitoring across file systems, processes, the
  registry, and the Object Manager, with notification of relevant events.
- **Enforcement** — filtering and blocking: a security product can block
  events as appropriate, from user mode, with no kernel component of its
  own.
- **Resilience** — if a client or protection rule causes a problem during
  startup, Windows recovery mechanisms restore the system. Resilience is a
  property of the platform, not a burden repeated in every vendor's driver.

The same announcement covers the Driver Quality Initiative (DQI), whose
direction is unambiguous: more drivers in user mode, Microsoft-maintained
class drivers, stronger partner verification, full lifecycle servicing,
and quality measures broadened "beyond crashes to include installation and
startup failures, functional reliability, and performance".

For Tawny this confirms the founding constraint — *no kernel hooks, no
driver signing* — and turns it into the strategy. The shipped Windows
sensor leans on Sysmon, which loads its own Microsoft-signed driver and
remains optional; WESP is the step that removes the driver dependency
entirely and adds the one capability the current stack lacks: blocking
before launch, from user mode, with Windows-managed recovery. Tawny never
ships a Windows kernel component either way; what a kernel driver would
have provided now comes from the platform.

Major vendors have announced WESP adoption across Q4 2026 (Bitdefender,
Sophos) and H1 2027 (CrowdStrike Falcon, ESET, SentinelOne, Trellix,
TrendAI, Microsoft Defender in preview). The ecosystem direction and the
CrowdStrike-style outage lesson behind it are the context for this plan.

## Signal mapping

WESP's initial monitored areas map onto Tawny's canonical event model
(schema v2, target-edr.md §2.3) almost one-to-one:

| WESP area | Tawny event types | Envelope `sensor` |
| --- | --- | --- |
| Processes | `PROCESS_START`, `PROCESS_EXIT` | `wesp.process` |
| File system | `FILE_CREATE`, `FILE_WRITE`, `FILE_DELETE`, `FILE_RENAME` | `wesp.file` |
| Registry | `REGISTRY_CREATE`, `REGISTRY_SET`, `REGISTRY_DELETE` | `wesp.registry` |
| Object Manager | object/handle activity — stored as raw/diagnostic events until a typed payload is designed | `wesp.object` |

The current sensor (Sysmon plus `EvtSubscribe`, with Security 4688 when
Sysmon is absent) stays the source for what WESP's initial release does not
cover: DNS, PowerShell 4104, authentication, service/task lifecycle,
Defender state, and image loads — and for every host without WESP:

- **Sysmon plus the event log is the shipping baseline** — works on
  Windows 10/11/Server, no partner gating, observe-only, needs the
  optional Microsoft-signed Sysmon driver.
- **WESP adds depth and blocking** on capable Windows 11 hosts with no
  driver at all, and replaces the Sysmon-backed file/process/registry rows
  where it exists (one authoritative path per area, not double emission).
- **ETW stays the later-step design** in target-edr.md §3.4 for hosts
  where Sysmon cannot be installed and for data neither WESP nor Sysmon
  gives (token detail, Defender state).

## Enforcement mapping

Target-edr.md §18.3 accepted a gap: the user-mode stack can observe but
not block before launch, so prevention was limited to post-launch kill,
quarantine, and WFP network blocking (the latter now live). WESP closes
that gap on capable hosts:

| Response action | Mechanism with WESP | Fallback without WESP |
| --- | --- | --- |
| `block_indicator` (hash/path) | WESP file/process protection rule: deny execution or write, pre-launch | local deny check on exec; post-launch kill |
| `quarantine_file` | WESP deny plus the quarantine move (§9.4) | quarantine move after detection |
| Registry tamper prevention | WESP registry protection rule | detect-only (`REGISTRY_*`) |
| `isolate` (network) | unchanged — WFP sublayer with failsafe (§9.3); WESP is not a network filter | same |

Windows partners cite WESP for boot-time protection as well; Tawny's
analogue is startup ordering plus the observe-only-until-healthy rule
below, not a boot driver.

## Resilience requirements

Windows manages recovery for WESP client failures at startup. Tawny's own
rules must not undo that property:

1. **Blocking rules expire locally.** Every WESP blocking rule carries
   `max_duration` (default 24 h), stored beside the action journal,
   mirroring the isolation failsafe in §9.3. The agent clears expired
   rules at startup and on a timer without server contact.
2. **Rules are journaled and reconciled.** On start, existing Tawny WESP
   rules are reconciled against journal state so a crash can neither
   orphan a rule nor silently drop one.
3. **Observe-only until healthy.** The agent starts with blocking
   disabled and switches to enforce only after a successful heartbeat, so
   a bad rule or a degraded sensor can never brick an endpoint's boot
   before the server can retract it.
4. **Fail closed to observe, never to permissive silence.** A sensor that
   fails its health check drops to observe-only and raises
   `AGENT_HEALTH`/`AGENT_TAMPER`; it does not keep enforcing with stale
   state and does not pretend to be healthy.

## DQI-aligned quality gates

DQI's user-experience-correlated quality measures become Tawny's agent
quality gates, enforced in the Phase 8 bench harness and reported through
`AGENT_HEALTH`:

| DQI measure | Tawny gate |
| --- | --- |
| Installation failures | installer self-verification (SHA-256, GitHub provenance) already fail-closed; add post-install smoke (`tawny-agent` banner + config check) and an install-failure counter |
| Startup failures | time from service start to first heartbeat; crash-loop detection that falls back to observe-only |
| Functional reliability | per-sensor status and last-event age in `AGENT_HEALTH`; periodic reconciliation snapshot vs live sensor diff (already planned for ETW in §3.4) |
| Performance | existing budgets: idle CPU ≈0%, <1% typical, RSS <60 MB, bounded spool, upload caps |

## Fleet readiness (landed in this change)

WESP is Windows 11, and partner availability varies by provider. The
first operational prerequisite is knowing what each endpoint runs.

- Enrollment now reports a real `os_version`: Windows
  `major.minor.build` via `RtlGetVersion` (build ≥ 22000 is Windows 11),
  macOS product version via `kern.osproductversion`, Linux kernel release.
  Previously every agent enrolled as `unknown`, although `docs/api.md`
  already documented a real version in the enroll payload.
- The agents table shows that value, so a fleet's Windows 11 population
  is visible at a glance instead of buried in hourly `system_info`
  telemetry.
- Agents enrolled before this change keep their stored `os_version` until
  they re-enroll; heartbeat does not rewrite identity facts.

## Open questions

- The announcement does not state the minimum Windows 11 build for WESP
  clients, and the public API surface details live at
  <https://aka.ms/windowsendpointsecurityplatform>. Do not code against
  invented API shapes; revisit this section when Microsoft publishes the
  SDK contract.
- WESP access may be gated on a Microsoft security partner program. If
  access is unavailable to Tawny, the shipped Sysmon-plus-event-log sensor
  and ETW later-step design in §3.4 remain the sensor plan, enforcement
  stays post-launch plus WFP, and this document becomes a watch-item rather
  than a commitment. The architecture does not change either way; only
  blocking depth does.
- Windows Server and Windows 10 fleets never receive WESP per the
  announcement ("general availability on Windows 11"); the observe-only
  baseline plus post-launch response is the permanent story there.
