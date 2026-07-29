<p align="center">
  <img src="web/public/logo.png" alt="Tawny EDR" width="320" />
</p>

# Tawny

> Quiet eyes on every endpoint.

Tawny is a self-hosted, lightweight EDR (endpoint detection and response) system. A tiny Zig agent runs on Windows, macOS, and Linux, ships telemetry to a .NET 10 backend over HTTPS, evaluates alert rules, and surfaces it through a polished Next.js 16 dashboard. Hangfire handles offline detection, retention, backups, and agent update checks.

The MVP is intentionally small. No kernel hooks, no driver signing, and no attempt to replace a SIEM. Clean architecture, real telemetry, detection imports, Wazuh, Slack, and Microsoft Sentinel forwarding, and a UI that looks like a product.

## Screenshots

<details open>
<summary><strong>Dark mode gallery</strong></summary>

![Dashboard](docs/screenshots/dashboard.png)

![Command palette](docs/screenshots/command-palette.png)

![Detections](docs/screenshots/detections.png)

![Alerts](docs/screenshots/alerts.png)

![Agents](docs/screenshots/agents.png)

![Agent detail](docs/screenshots/agent-detail-processes.png)

![Network events](docs/screenshots/agent-detail-network.png)

![FIM events](docs/screenshots/agent-detail-fim.png)

![Session events](docs/screenshots/agent-detail-sessions.png)

![Raw events](docs/screenshots/agent-detail-raw-events.png)

![Enrollment](docs/screenshots/enrollment.png)

</details>

<details>
<summary><strong>Light mode gallery</strong></summary>

![Light dashboard](docs/screenshots/light/dashboard.png)

![Light command palette](docs/screenshots/light/command-palette.png)

![Light detections](docs/screenshots/light/detections.png)

![Light alerts](docs/screenshots/light/alerts.png)

![Light agents](docs/screenshots/light/agents.png)

![Light agent detail](docs/screenshots/light/agent-detail-processes.png)

![Light network events](docs/screenshots/light/agent-detail-network.png)

![Light FIM events](docs/screenshots/light/agent-detail-fim.png)

![Light session events](docs/screenshots/light/agent-detail-sessions.png)

![Light raw events](docs/screenshots/light/agent-detail-raw-events.png)

![Light enrollment](docs/screenshots/light/enrollment.png)

</details>

<details open>
<summary><strong>Wazuh integration</strong></summary>

![Wazuh Tawny events](docs/screenshots/integrations/wazuh-tawny-events.png)

![Wazuh Tawny event fields](docs/screenshots/integrations/wazuh-tawny-event-detail.png)

</details>

Generate README-ready product screenshots from the running Docker stack:

```bash
cd web
pnpm screenshots:readme
```

The script logs in with the local bootstrap admin, forces dark mode by default, and writes screenshots to `docs/screenshots/`. To capture light mode as well:

```bash
TAWNY_SCREENSHOT_THEME=light TAWNY_SCREENSHOT_OUT_DIR=docs/screenshots/light pnpm screenshots:readme
```

## Why "Tawny"?

Tawny is named after the tawny frogmouth, an Australian nocturnal bird famous for sitting perfectly still on a branch and being mistaken for part of the tree. It watches everything around it, makes no noise, and only acts when it needs to. That is roughly the job description of a good EDR agent: blend in, observe quietly, raise the alarm when something is worth your attention.

The tawny frogmouth is also small, unassuming, and frequently underestimated. The agent is a single Zig binary measured in kilobytes. The bird and the binary share a philosophy: do one thing well and stay out of the way.

## Architecture

```
+------------------------+        HTTPS         +-------------------------+
| Zig Agent              | -------------------> | .NET 10 API             |
| (Windows/macOS/Linux)  |  JWT, batched JSON   | ASP.NET Core            |
|                        |                      | EF Core + SQL Server    |
+------------------------+                      | Hangfire (in-process)   |
                                                +-----------+-------------+
                                                            |
                                                            v
                                                +-------------------------+
                                                | SQL Server 2022         |
                                                +-------------------------+
                                                            ^
                                                            | REST (cookie auth)
                                                +-------------------------+
                                                | Next.js 16 Dashboard    |
                                                | Better Auth, shadcn/ui  |
                                                +-------------------------+
```

See [docs/architecture.md](docs/architecture.md) for the deeper version.

## Features

- Cross-platform Zig agent for Windows, macOS, and Linux with enrollment, heartbeat, local buffering, and HTTPS event batching.
- Process, network, user session, system info, and file integrity telemetry, visible through per-agent event tabs with raw payload inspection.
- Short-lived, single-use enrollment tokens and generated install commands for Windows services, macOS launchd jobs, and Linux systemd services.
- Multi-tenant data model and request scoping across agents, telemetry, alerts, enrollment tokens, audit logs, and response actions.
- Alert rule evaluation on ingest with Tawny predicates, focused Sigma YAML imports, and threat-intel IoC imports from STIX 2.1, OpenIOC, CSV, or raw advisory text.
- IoC hunts for SHA-1/SHA-256 file hashes, IPv4/IPv6 remote addresses, and domains in DNS query telemetry (`qname`).
- Default public threat-intel feeds (Kelpie-parity starters) seeded per tenant on API startup; matching IoCs raise Tawny alerts without Kelpie, UniFi, or other sinks.
- Alert review workflow with severity, status, matched telemetry payloads, Slack delivery state, Kelpie case delivery, and generated Wazuh-compatible syslog events.
- Repo-scoped Codex personal-agent skill for Tawny TI lookups, configurable local UniFi event hunts, Kelpie case creation, deduplication, and safe cron command generation.
- Response action queue with heartbeat dispatch and agent result reporting. `kill_process` is implemented; host isolation is modeled but waits for OS firewall handlers.
- Hangfire jobs for stale/offline agent status, retention cleanup, telemetry backups, and GitHub release synchronization.
- Better Auth dashboard login with email/password and optional GitHub OAuth, plus HMAC-signed server-to-API calls.
- Docker bootstrap scripts for repeatable local development, optional real Linux agent container, SQL migrations, generated secrets, and seeded admin user.
- CI builds and unit-tests the Zig agent natively on Windows, macOS, and Linux (plus cross-compiles remaining release targets), with on-demand `workflow_dispatch`; security audit and release workflows publish agent artefacts with SHA-256 sidecars.

## Repo layout

```
tawny/
  agent/      # Zig agent
  backend/    # .NET 10 solution (Api / Domain / Infrastructure / Jobs / Tests)
  web/        # Next.js 16 dashboard
  docker/     # docker-compose for local dev
  docs/       # architecture, threat model, API
  .github/    # CI + release workflows
```

## Quickstart (local dev)

Requirements:

- Docker 24+
- macOS Apple Silicon: enable Docker Desktop's x86/amd64 emulation/Rosetta support for SQL Server, or pass `--platform linux/amd64`
- .NET 10 SDK, Node 22 + pnpm 10, and Zig 0.16+ only if you want to work outside Docker or build the agent locally

```bash
# macOS / Linux
docker/scripts/bootstrap-docker.sh

# macOS Apple Silicon, if SQL Server needs amd64 emulation
docker/scripts/bootstrap-docker.sh --platform linux/amd64
```

```powershell
# Windows PowerShell
.\docker\scripts\bootstrap-docker.ps1
```

The bootstrap scripts generate local secrets, start SQL Server + API + Web, apply API and web database migrations, seed the first admin user when the database is empty, and verify the local HTTP endpoints. They default to web `3000`, API `5080`, and SQL Server `1433`, but automatically pick the next available host port when one is already in use.

Open the dashboard at the URL printed by the script. It is usually:

```text
http://localhost:3000
```

For a remote homelab host, set public LAN URLs before bootstrap so browser
sessions and generated agent enrollment commands do not point at the remote
host's loopback interface:

```bash
TAWNY_PUBLIC_WEB_URL=http://192.168.1.10:3000
TAWNY_PUBLIC_API_URL=http://192.168.1.10:5080
docker/scripts/bootstrap-docker.sh
```

The backend and web app still communicate over Docker's private network.
Only browser-facing and agent-facing URLs use these public settings.

Default local login:

```text
Email: admin@example.com
Password: ChangeMe123!
```

Override the local admin during bootstrap:

```bash
BOOTSTRAP_ADMIN_EMAIL='you@example.com' \
BOOTSTRAP_ADMIN_PASSWORD='better-local-password' \
docker/scripts/bootstrap-docker.sh
```

```powershell
.\docker\scripts\bootstrap-docker.ps1 -AdminEmail "you@example.com" -AdminPassword "better-local-password"
```

Create an enrollment token from the `/enrollment` page, then run the agent against your local backend:

```bash
cd agent
zig build run -- --enrollment-token wte_xxx --backend http://localhost:5080
```

To test telemetry end to end entirely in Docker, start the real Linux agent container:

```bash
docker/scripts/bootstrap-docker.sh --with-agent
```

```powershell
.\docker\scripts\bootstrap-docker.ps1 -WithAgent
```

Or create an enrollment token in the dashboard and start it against an already-running stack:

```bash
cd docker
printf 'TAWNY_AGENT_ENROLLMENT_TOKEN=wte_xxx\n' >> .env
docker compose -p tawny --env-file .env --profile agent up -d --build agent
docker compose -p tawny --env-file .env --profile agent logs -f agent
```

The container runs the same Zig agent binary used on hosts. Its first start consumes `TAWNY_AGENT_ENROLLMENT_TOKEN`, writes a persistent config into the `agent-state` volume, and then heartbeats and posts Linux process, network, system, session, and FIM telemetry through the normal agent APIs.

Agent detail event tabs poll for fresh telemetry every two seconds by default. Use Pause to freeze the table while inspecting payloads. SSE streaming is intentionally deferred to v0.2; the current polling route is marked with `X-Tawny-Event-Feed: polling`.

EF migrations live in `backend/src/Tawny.Infrastructure/Migrations`. Automatic migration application is opt-in with `Tawny__ApplyMigrationsOnStartup=true` or `TAWNY_APPLY_MIGRATIONS_ON_STARTUP=true` in `docker/.env`. For production, leave that flag off and run:

```bash
cd backend
dotnet ef database update --project src/Tawny.Infrastructure --startup-project src/Tawny.Api
```

## Why Zig?

Zig produces small, static binaries and cross-compiles to Windows, macOS, and Linux from one machine without a fleet of toolchains. The C interop story is excellent, which matters when you are calling `CreateToolhelp32Snapshot` on Windows, `sysctl` on macOS, and procfs-backed collectors on Linux. No runtime, no GC, predictable memory. A good fit for an endpoint agent that has to live quietly inside other people's machines.

## Why this stack?

.NET 10 with EF Core and Hangfire keeps the backend boring and productive. Hangfire's SQL Server storage means one database to operate. Next.js 16 with the App Router and Server Components keeps the dashboard fast and lets us colocate data fetching with the views that need it. Better Auth handles email/password and GitHub OAuth without owning a session store. shadcn/ui plus Tailwind keeps the visual surface coherent without designing from scratch.

## Not in scope for MVP

This is still a portfolio MVP. These areas are intentionally limited or deferred:

- Real-time streaming (polling for now; SSE in v0.2)
- Kernel-level collection (ETW, EndpointSecurity)
- Code signing and notarisation (ship SHA256 in releases, sign later)
- Enterprise OIDC SSO and SCIM provisioning
- Privileged packet-level DNS capture on hosts without a supported local resolver log
- Full host isolation enforcement; the action exists but agents currently report it unsupported

## Roadmap

- [x] Repo and CI scaffold
- [x] Backend skeleton: enrollment, heartbeat, JWT
- [x] Zig agent skeleton: config, enroll, heartbeat loop
- [x] Next.js scaffold: login, agents list
- [x] Process collector end-to-end
- [x] Events ingestion + storage
- [x] Hangfire: MarkStaleAgents, PurgeOldEvents
- [x] Agent detail page with event timeline
- [x] Network + FIM collectors (polling)
- [x] Install scripts (Windows + macOS + Linux)
- [x] Release workflow with cross-compiled agent artefacts
- [x] Docs: architecture, threat model, API, deployment
- [x] Alert rules engine with Tawny predicates
- [x] Sigma rule imports and starter catalog
- [x] Threat-intel IoC imports from STIX, OpenIOC, CSV, and raw text
- [x] Default Kelpie-parity public TI feed seed (Feodo + OpenPhish enabled)
- [x] Wazuh alert forwarding
- [x] Slack alert forwarding with delivery state
- [x] Microsoft Sentinel OAuth/DCR alert and telemetry forwarding
- [x] Response action queue and heartbeat dispatch
- [x] Multi-tenant persistence and request scoping
- [x] Optional GitHub OAuth for dashboard login

Post-MVP: Linux eBPF, kernel-level Windows/macOS collection, broader Sigma coverage, packet-level DNS telemetry, enforced host isolation, enterprise OIDC SSO.

## Detection rules

Alert rules are moving toward Sigma-compatible detection-as-code instead of a custom Tawny rule language. The current importer accepts a focused Sigma subset: `title`, `id`, `description`, `logsource`, one named `detection` selection, a single-selection `condition`, and `level`. Tawny compiles that into its event matcher and keeps the original Sigma YAML with the rule so the supported subset can grow without inventing a parallel format.

The detections page also imports common advisory IoCs from STIX 2.1 indicator bundles, OpenIOC XML, CSV, and raw text. Tawny turns supported indicators into normal alert rules so enrolled agents can hunt for:

- SHA-256 and SHA-1 file hashes in file integrity telemetry.
- IPv4 and IPv6 addresses in network connection telemetry.
- Domains in DNS query telemetry from `systemd-resolved`, dnsmasq, Unbound, BIND, and `/etc/hosts`, with process command lines retained as a fallback.

MD5 values are reported as skipped because the agents do not currently emit MD5 file hashes.

## Threat intelligence feeds

On API startup (and before each feed poll job), Tawny seeds **Kelpie-parity
starter sources** for every tenant if they are missing. No manual install is
required for the defaults:

| Feed | Default | What it matches |
| --- | --- | --- |
| Feodo Tracker Botnet C2 IPs | **Enabled** | Remote IPv4 on network telemetry |
| OpenPhish Community Phishing URLs | **Enabled** | Domains (from phishing URLs) on DNS `qname` |
| PhishTank Online Valid Phishing URLs | Off (opt-in) | Domains from verified phishing URLs |
| Emerging Threats Compromised IPs | Off (opt-in) | Compromised-host IPs |
| Blocklist.de Recent Attackers | Off (opt-in) | Recent attacker IPs (noisy) |

Hangfire pulls enabled feeds on a schedule (about every 10 minutes, or sooner
when a feed’s own interval is due). Each indicator becomes an **enabled IoC
alert rule**. When agent telemetry matches, Tawny creates a normal **alert**
in the Alerts UI. That path does **not** depend on Kelpie, UniFi, Slack, or
other sinks — those only forward alerts after creation.

The **Threat Intel** page still lists the same sources as installable presets
and lets admins add OTX, MISP, TAXII, or private CSV/text feeds with **New
feed**. OpenPhish-style URLs are normalized to domains. Tawny keeps at most
5,000 unique indicators per feed run so large public lists cannot grow the
rule set without bound.

## Wazuh sink

Tawny can forward generated alerts to Wazuh over syslog. Enable the sink by pointing the API at a Wazuh manager or syslog listener:

```bash
TAWNY_WAZUH_ENABLED=true
TAWNY_WAZUH_HOST=wazuh-manager.example.com
TAWNY_WAZUH_PORT=514
TAWNY_WAZUH_PROTOCOL=udp
```

Each alert is emitted as one syslog event with a flat JSON body containing Tawny tenant, agent, alert, rule, telemetry event, and matched telemetry payload fields. Configure Wazuh to accept syslog input from the Tawny API host, then install the decoder/rules in `integrations/wazuh/` so Tawny events appear as Wazuh alerts.

In Docker-based Wazuh deployments, check `/var/ossec/logs/ossec.log` after the first send. If Wazuh logs `Message from 'x.x.x.x' not allowed`, add that exact IP to the Wazuh syslog `<allowed-ips>` list and restart the manager container.

## Slack sink

Tawny can also post newly generated alerts to a Slack incoming webhook. Delivery state is stored on each alert as `not_configured`, `pending`, `sent`, or `failed` and is visible in the alerts table.

```bash
TAWNY_SLACK_ENABLED=true
TAWNY_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TAWNY_SLACK_USERNAME=Tawny
TAWNY_SLACK_ICON_EMOJI=:rotating_light:
```

## Microsoft Sentinel sink

Tawny can send generated alerts and optional telemetry batches to Microsoft Sentinel through Azure Monitor Logs Ingestion API, using Microsoft Entra OAuth and a DCR. The shared-key Data Collector API is not used.

```bash
TAWNY_SENTINEL_ENABLED=true
TAWNY_SENTINEL_ALERTS_ENABLED=true
TAWNY_SENTINEL_TELEMETRY_ENABLED=false
TAWNY_SENTINEL_TENANT_ID=00000000-0000-0000-0000-000000000000
TAWNY_SENTINEL_CLIENT_ID=00000000-0000-0000-0000-000000000000
TAWNY_SENTINEL_CLIENT_SECRET=...
TAWNY_SENTINEL_ENDPOINT_URL=https://<dcr-or-dce>.<region>.ingest.monitor.azure.com
TAWNY_SENTINEL_DCR_IMMUTABLE_ID=dcr-00000000000000000000000000000000
TAWNY_SENTINEL_ALERT_STREAM_NAME=Custom-TawnyAlert_CL
TAWNY_SENTINEL_TELEMETRY_STREAM_NAME=Custom-TawnyTelemetry_CL
```

Create the destination tables and DCR streams first, then assign the Tawny app registration or managed identity the `Monitoring Metrics Publisher` role on the DCR. Telemetry forwarding stays disabled by default to avoid unexpected ingestion cost. Full setup notes and sample KQL are in [docs/production.md](docs/production.md).

## Tawny SOC HTTP sink

Tawny can post alert batches and optional raw telemetry batches to a downstream SOC HTTP ingest endpoint:

```bash
TAWNY_SOC_ENABLED=true
TAWNY_SOC_ALERTS_ENABLED=true
TAWNY_SOC_TELEMETRY_ENABLED=false
TAWNY_SOC_ENDPOINT_URL=https://soc.example.com/api/ingest/tawny
TAWNY_SOC_API_TOKEN=replace-me
```

Requests use JSON and an optional bearer token. Raw telemetry is off by default because it is sensitive and high-volume. Use HTTPS outside a trusted local development network.

## Kelpie case sink

Tawny owns endpoint telemetry, detections, and alerts. It does not provide an
internal case-management workspace; optional cases live in Kelpie.

Tawny can create a detailed [Kelpie](https://github.com/jusso-dev/Kelpie) case
for every new alert. Each case includes rule, endpoint, telemetry, enrichment,
and a stable `tawny-alert-<id>` tag. Delivery state and Kelpie case number appear
on the alert.

```bash
TAWNY_KELPIE_ENABLED=true
TAWNY_KELPIE_BASE_URL=http://kelpie:3000
TAWNY_KELPIE_API_TOKEN=...
TAWNY_KELPIE_INCLUDE_TELEMETRY_PAYLOAD=true
```

Kelpie token needs `cases:write`. See
[Personal AI agent](docs/personal-agent.md) for Codex/local-agent TI lookup,
UniFi matching, case creation, and cron setup.

## UniFi integration

Administrators can configure the local UniFi connector from **Integrations >
UniFi Network**. Tawny encrypts the API key before storing it, tests the local
Network API, polls a configured JSON event endpoint on schedule, matches IPs and
domains against imported threat intelligence, and creates deduplicated Kelpie
cases.

Create the API key and find the supported read endpoint in **UniFi Network >
Settings > Control Plane > Integrations**. Use the controller's private IP in
Tawny; public destinations are rejected. UniFi OS and Network versions are
separate: **Save and test** reports the installed Network application version
and verifies the configured event endpoint and records path.
See [Personal AI agent](docs/personal-agent.md#ui-managed-unifi-connector) for
field-by-field setup and transport limitations.

## Cloud hunting and monitoring

Administrators can configure least-privilege AWS and Azure connections from
**Integrations > Cloud hunting**. Tawny queries CloudTrail, GuardDuty, Azure
Activity Logs, and Microsoft Entra audit/sign-in logs on demand or on a
per-hunt schedule, then stores bounded,
deduplicated findings with actor, resource, severity, and raw evidence. It does
not ingest every provider log or attempt CSPM posture management.

AWS uses AssumeRole plus external ID; Azure prefers managed/workload identity
and supports an encrypted client-secret fallback. Setup policies, query JSON,
watermark behavior, and operational limits are documented in
[Cloud hunting and monitoring](docs/cloud-hunting.md).

## Security notes

- Agent JWTs are bearer tokens. Mutable identity is kept in a mode-`0600`
  state file, separate from the read-only static config. Anyone who can read
  that state can impersonate the agent; OS-keystore integration remains future
  hardening.
- No Authenticode signing or macOS notarisation is in place yet. Production
  installers fail closed on a missing or invalid SHA-256 and verify GitHub
  artifact provenance by default.
- Enrollment tokens are single-use and short-lived. Rotate the signing key if leaked.
- SQL Server creds live in env vars; use Key Vault or similar in production.
- Integration credentials are encrypted with `TAWNY_INTEGRATION_ENCRYPTION_KEY`.
  Back up this key with the database; rotating or losing it makes stored
  integration secrets unreadable.
- Linux uses a locked `tawny` service account and Windows uses a restricted
  virtual service account. macOS currently runs the launch daemon as root.
  Protected process and file data may require narrowly scoped ACLs.
- Response actions are queued through the API and dispatched on heartbeat.
  `kill_process` requires a positive `pid`; host isolation remains unsupported.
  Delivery does not yet have a durable lease/journal/ack protocol, so a crash
  around execution can leave an action outcome unknown.

Production deployments must terminate TLS before traffic reaches the API or web
containers. See [docs/production.md](docs/production.md) for server deployment
and [docs/production-agent-hardening.md](docs/production-agent-hardening.md) for
release trust, service permissions, EC2 guidance, rollout gates, and rollback.

## Agent install scripts

The dashboard enrollment page templates the supported one-liners:

```powershell
irm https://raw.githubusercontent.com/jusso-dev/Tawny/main/agent/install/install.ps1 | iex; Install-TawnyAgent -BackendUrl 'https://api.example.com' -EnrollmentToken 'wte_xxx'
```

```bash
curl -fsSL https://raw.githubusercontent.com/jusso-dev/Tawny/main/agent/install/install.sh | sudo bash -s -- --backend-url 'https://api.example.com' --enrollment-token 'wte_xxx'
```

Both scripts preserve the platform `config.toml`, keep mutable identity in a
separate protected state directory, download the latest matching release,
require SHA-256 verification, verify GitHub artifact provenance, stage upgrades
atomically, and retain the previous binary for rollback. They register a
Windows service, macOS launchd job, or hardened Linux systemd service. Use
`-DryRun` on Windows or `--dry-run` on macOS/Linux to inspect local actions
without changing the host.

## Production secrets

Agent JWTs must be signed by a stable RSA private key in production. Generate one with:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out tawny-jwt-key
chmod 0600 tawny-jwt-key
```

Set `Tawny__AgentJwt__SigningKeyPem` to the PEM file path or the inline PEM value. In production, `AgentJwtService` refuses to start without a configured signing key. Docker compose mounts `docker/secrets` at `/run/secrets`; `docker/scripts/init-secrets.sh` creates `docker/secrets/tawny-jwt-key`, `TAWNY_WEB_HMAC_SECRET`, and `BETTER_AUTH_SECRET` for local development.

See [docs/threat-model.md](docs/threat-model.md).

## License

MIT. See `LICENSE`.
