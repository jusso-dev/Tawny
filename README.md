<p align="center">
  <img src="docs/logo.png" alt="Tawny EDR" width="320" />
</p>

# Tawny

> Quiet eyes on every endpoint.

Tawny is a self-hosted, lightweight EDR (endpoint detection and response) system. A tiny Zig agent runs on Windows, macOS, and Linux and ships telemetry over HTTPS to `tawny-server`. That one Zig process stores events in PostgreSQL, evaluates alert rules off the request path, serves the dashboard, and runs retention, backup, hunt, threat-intel, reputation, and release-check jobs. Caddy terminates TLS.

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

The gallery above was captured from the previous Next.js dashboard. The running UI is the static pages `tawny-server` serves on the Caddy origin.

## Why "Tawny"?

Tawny is named after the tawny frogmouth, an Australian nocturnal bird famous for sitting perfectly still on a branch and being mistaken for part of the tree. It watches everything around it, makes no noise, and only acts when it needs to. That is roughly the job description of a good EDR agent: blend in, observe quietly, raise the alarm when something is worth your attention.

The tawny frogmouth is also small, unassuming, and frequently underestimated. The agent is a single Zig binary measured in kilobytes. The bird and the binary share a philosophy: do one thing well and stay out of the way.

## Architecture

```
+------------------------+   HTTPS (Caddy)   +---------------------------+
| Zig Agent              | ----------------> | tawny-server              |
| (Windows/macOS/Linux)  |  JWT, batched JSON| Zig: API, static UI, jobs |
+------------------------+                   +-------------+-------------+
                                                           |
                                                           v
                                             +---------------------------+
                                             | PostgreSQL                |
                                             +---------------------------+
                                                           ^
                                                           | same origin, session cookie
                                             +---------------------------+
                                             | Browser                   |
                                             +---------------------------+
```

See [docs/architecture.md](docs/architecture.md) for the deeper version.

## Features

- Cross-platform Zig agent for Windows, macOS, and Linux with enrollment, heartbeat, local buffering, and HTTPS event batching.
- Process, network, user session, system info, and file integrity telemetry, visible through per-agent event tabs with raw payload inspection.
- Short-lived, single-use enrollment tokens and generated install commands for Windows services, macOS launchd jobs, and Linux systemd services.
- Multi-tenant data model and request scoping across agents, telemetry, alerts, enrollment tokens, audit logs, and response actions.
- Alert rule evaluation after ingest returns 202, with Tawny predicates, focused Sigma YAML imports, and threat-intel IoC imports from STIX 2.1, OpenIOC, CSV, or raw advisory text.
- IoC hunts for SHA-1/SHA-256 file hashes, IPv4/IPv6 remote addresses, and domains in DNS query telemetry (`qname`).
- Default public threat-intel feeds seeded per tenant on API startup; matching IoCs raise Tawny alerts.
- Alert review workflow with severity, status, matched telemetry payloads, Slack/Sentinel delivery state, and generated Wazuh-compatible syslog events.
- Response action queue with heartbeat dispatch and agent result reporting. `kill_process` is implemented; host isolation is modeled but waits for OS firewall handlers.
- In-process jobs for stale/offline agent status, retention cleanup, telemetry backups, saved hunts, threat-intel refresh, alert reputation, and GitHub release synchronization.
- Dashboard login with an HttpOnly session cookie, email/password, and optional GitHub OAuth that only links an existing user. No self-service signup and no HMAC hop.
- Docker bootstrap for PostgreSQL, tawny-server, and Caddy, plus an optional Linux agent container, generated secrets, and a first admin only when the user table is empty.
- CI builds and unit-tests the Zig agent natively on Windows, macOS, and Linux (plus cross-compiles remaining release targets), with on-demand `workflow_dispatch`; security audit and release workflows publish agent artefacts with SHA-256 sidecars.

## Repo layout

```
tawny/
  agent/      # Zig agent
  server/     # Zig tawny-server and static UI (server/ui)
  docker/     # PostgreSQL + tawny-server + Caddy
  docs/       # architecture, threat model, API
  .github/    # CI + release workflows
```

## Quickstart (local dev)

Requirements:

- Docker 24+ with Compose v2
- Zig 0.17 if you build `tawny-server` or the agent outside Docker

```bash
docker/scripts/bootstrap-docker.sh
```

On Windows, run that script from Git Bash or WSL. `docker/scripts/bootstrap-docker.ps1` exits on purpose: it targeted SQL Server and the old two-process stack.

The script writes `docker/.env` and an RSA PEM under `docker/secrets`, starts PostgreSQL, `tawny-server`, and Caddy, and waits until `https://localhost:8443/api/health` answers. Postgres is not published. Caddy publishes host ports `8080` (HTTP) and `8443` (HTTPS) unless `docker/.env` already chose others. `tls internal` uses Caddy's local CA. `curl` needs `-k` until that CA is trusted. For a public name, set `TAWNY_DOMAIN` and remove `tls internal` from `docker/Caddyfile`.

Open the dashboard at the URL the script prints. The default is:

```text
https://localhost:8443
```

For a LAN host, set the public origin before bootstrap so enrollment commands do not point at loopback:

```bash
TAWNY_PUBLIC_URL=https://192.168.1.10:8443
TAWNY_DOMAIN=192.168.1.10
docker/scripts/bootstrap-docker.sh
```

The first admin email defaults to `admin@tawny.local`. `init-secrets.sh` prints the password once, when it creates `TAWNY_BOOTSTRAP_ADMIN_PASSWORD`, and stores it in `docker/.env`. The server uses that password only when the user table is empty, and it does not log it. Override it before the first boot:

```bash
TAWNY_BOOTSTRAP_ADMIN_EMAIL='you@example.com' \
TAWNY_BOOTSTRAP_ADMIN_PASSWORD='better-local-password' \
docker/scripts/bootstrap-docker.sh
```

Create an enrollment token on `/enrollment`, then point a host agent at the Caddy origin. The agent reads `url` and `enrollment_token` from its config file. It does not take those as flags. Trust Caddy's local root (`caddy` container path `/data/caddy/pki/authorities/local/root.crt`) or the TLS handshake fails.

```bash
cd agent
cat > config.toml <<'EOF'
url = "https://localhost:8443"
enrollment_token = "wte_xxx"
EOF
TAWNY_CONFIG=./config.toml zig build run
```

The optional compose agent talks to `http://tawny-server:8080` on the compose network and sets `allow_insecure_http`. Put an enrollment token in `docker/.env` first. Bootstrap does not mint one.

```bash
printf 'TAWNY_AGENT_ENROLLMENT_TOKEN=wte_xxx\n' >> docker/.env
docker/scripts/bootstrap-docker.sh --with-agent
```

Or, against a stack that is already up:

```bash
cd docker
printf 'TAWNY_AGENT_ENROLLMENT_TOKEN=wte_xxx\n' >> .env
docker compose -p tawny --env-file .env --profile agent up -d --build agent
docker compose -p tawny --env-file .env --profile agent logs -f agent
```

The container runs the same Zig agent binary used on hosts. Its first start consumes `TAWNY_AGENT_ENROLLMENT_TOKEN`, writes a persistent config into the `agent-state` volume, and then heartbeats and posts Linux process, network, system, session, and FIM telemetry through the normal agent APIs.

Agent detail holds `GET /api/agents/{id}/events/stream` open. Each `data:` frame is a JSON array of the latest telemetry. A `: keep-alive` comment arrives about every 15 seconds, and a new frame arrives when a newer event is stored.

`tawny-server` applies the embedded SQL migrations on startup (`TAWNY_APPLY_MIGRATIONS_ON_STARTUP=true` in compose). `tawny-server migrate` applies the same files without listening.

## Why Zig?

Zig produces small, static binaries and cross-compiles to Windows, macOS, and Linux from one machine without a fleet of toolchains. The C interop story is excellent, which matters when you are calling `CreateToolhelp32Snapshot` on Windows, `sysctl` on macOS, and procfs-backed collectors on Linux. No runtime, no GC, predictable memory. A good fit for an endpoint agent, and for the one server process that replaced the API and the dashboard.

## Why this stack?

One static binary keeps the operator surface small: PostgreSQL for state, Caddy for TLS, `tawny-server` for the API, the UI, and the jobs. The browser and the API share an origin, so the session cookie does not cross a second host. There is no HMAC secret between a web process and an API process.

## Not in scope for MVP

This is still a portfolio MVP. These areas are intentionally limited or deferred:

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
- [x] Default public TI feed seed (Feodo + OpenPhish enabled)
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

On API startup (and before each feed poll job), Tawny seeds **starter TI
sources** for every tenant if they are missing. No manual install is
required for the defaults:

| Feed | Default | What it matches |
| --- | --- | --- |
| Feodo Tracker Botnet C2 IPs | **Enabled** | Remote IPv4 on network telemetry |
| OpenPhish Community Phishing URLs | **Enabled** | Domains (from phishing URLs) on DNS `qname` |
| PhishTank Online Valid Phishing URLs | Off (opt-in) | Domains from verified phishing URLs |
| Emerging Threats Compromised IPs | Off (opt-in) | Compromised-host IPs |
| Blocklist.de Recent Attackers | Off (opt-in) | Recent attacker IPs (noisy) |

`tawny-server` pulls enabled feeds about every 10 minutes, or sooner
when a feed’s own interval is due. Each indicator becomes an **enabled IoC
alert rule**. When agent telemetry matches, Tawny creates a normal **alert**
in the Alerts UI. That path does **not** depend on Slack, Sentinel, or
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

## Security notes

- Agent JWTs are bearer tokens. Mutable identity is kept in a mode-`0600`
  state file, separate from the read-only static config. Anyone who can read
  that state can impersonate the agent; OS-keystore integration remains future
  hardening.
- No Authenticode signing or macOS notarisation is in place yet. Production
  installers fail closed on a missing or invalid SHA-256 and verify GitHub
  artifact provenance by default.
- Enrollment tokens are single-use and short-lived. Rotate the signing key if leaked.
- Postgres is not published. `POSTGRES_PASSWORD` lives in `docker/.env`; use a secret store in production.
- Integration credentials are encrypted with `TAWNY_INTEGRATION_ENCRYPTION_KEY`.
  Back up this key with the database; rotating or losing it makes stored
  integration secrets unreadable.
- Linux uses a locked `tawny` service account. Windows runs the service as
  `LocalSystem` (required for ETW kernel sessions and the Security event log)
  with install folders restricted to SYSTEM and Administrators. macOS currently
  runs the launch daemon as root.
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

New agent JWTs are Ed25519. Set `TAWNY_AGENT_JWT_SEED` to 64 hex characters so that seed survives a restart. `TAWNY_AGENT_JWT_SIGNING_KEY_PEM` is the RSA PEM, or a path to it, and is used only to verify tokens issued before the cutover. Compose mounts `docker/secrets/tawny-jwt-key` at `/run/secrets/tawny-jwt-key`. This engine ignores secret uid and mode, so `init-secrets.sh` leaves the PEM mode `0644` and the server reads it as uid 65532. `docker/scripts/init-secrets.sh` creates that PEM, `POSTGRES_PASSWORD`, `TAWNY_INTEGRATION_ENCRYPTION_KEY`, and `TAWNY_AGENT_JWT_SEED`. It does not create an HMAC secret.

See [docs/threat-model.md](docs/threat-model.md).

## License

MIT. See `LICENSE`.
