<p align="center">
  <img src="web/public/logo.jpg" alt="Tawny EDR" width="320" />
</p>

# Tawny

> Quiet eyes on every endpoint.

Tawny is a self-hosted, lightweight EDR (endpoint detection and response) system. A tiny Zig agent runs on Windows, macOS, and Linux, ships telemetry to a .NET 10 backend over HTTPS, and surfaces it through a polished Next.js 16 dashboard. Hangfire handles offline detection, retention, backups, and agent update checks.

The MVP is intentionally small. No kernel hooks, no driver signing, no SIEM-grade ingestion. Clean architecture, real telemetry, and a UI that looks like a product.

## Screenshots

<details open>
<summary><strong>Dark mode gallery</strong></summary>

![Dashboard](docs/screenshots/dashboard.png)

![Command palette](docs/screenshots/command-palette.png)

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

![Light agents](docs/screenshots/light/agents.png)

![Light agent detail](docs/screenshots/light/agent-detail-processes.png)

![Light network events](docs/screenshots/light/agent-detail-network.png)

![Light FIM events](docs/screenshots/light/agent-detail-fim.png)

![Light session events](docs/screenshots/light/agent-detail-sessions.png)

![Light raw events](docs/screenshots/light/agent-detail-raw-events.png)

![Light enrollment](docs/screenshots/light/enrollment.png)

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
- .NET 10 SDK, Node 22 + pnpm 10, and Zig 0.14+ only if you want to work outside Docker or build the agent locally

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

To test telemetry end to end entirely in Docker, start the synthetic telemetry agent:

```bash
docker/scripts/bootstrap-docker.sh --with-synthetic-agent
```

```powershell
.\docker\scripts\bootstrap-docker.ps1 -WithSyntheticAgent
```

Or start it against an already-running stack:

```bash
cd docker
docker compose -p tawny --env-file .env --profile telemetry up -d synthetic-agent
docker compose -p tawny --env-file .env --profile telemetry logs -f synthetic-agent
```

The synthetic agent creates a real enrollment token through the API, enrolls as `tawny-docker-agent`, heartbeats every minute, and posts small system, process, network, FIM, and session telemetry batches every 5 minutes. `SYNTHETIC_AGENT_MAX_BATCHES=0` means continuous low-rate telemetry, which is the Docker default so the agent stays online for demos. It is a Docker test harness, not the production endpoint agent.

To run the real Linux endpoint agent in Docker instead:

```bash
docker/scripts/bootstrap-docker.sh --with-docker-agent
```

```powershell
.\docker\scripts\bootstrap-docker.ps1 -WithDockerAgent
```

The Docker agent image builds the Zig Linux binary, creates a local enrollment token through the API on first boot, persists its config in a named volume, and then sends real Linux container telemetry from procfs.

You can cap it for a short test run:

```bash
SYNTHETIC_AGENT_EVENT_INTERVAL_SECONDS=30 SYNTHETIC_AGENT_MAX_BATCHES=2 \
docker compose -p tawny --env-file docker/.env -f docker/docker-compose.yml --profile telemetry up -d synthetic-agent
```

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

This is a portfolio MVP. To keep it shippable in a sprint, the following are explicitly out:

- Multi-tenancy
- Real-time streaming (polling for now; SSE in v0.2)
- Alerting rules engine
- Response actions (kill process, isolate host)
- Kernel-level collection (ETW, EndpointSecurity)
- Code signing and notarisation (ship SHA256 in releases, sign later)

## Roadmap

- [x] Repo and CI scaffold
- [x] Backend skeleton: enrollment, heartbeat, JWT
- [x] Zig agent skeleton: config, enroll, heartbeat loop
- [x] Next.js scaffold: login, agents list
- [ ] Process collector end-to-end
- [ ] Events ingestion + storage
- [ ] Hangfire: MarkStaleAgents, PurgeOldEvents
- [ ] Agent detail page with event timeline
- [ ] Network + FIM collectors (polling)
- [ ] Install scripts (Windows + macOS)
- [ ] Release workflow with cross-compiled agent artefacts
- [ ] Docs: architecture, threat model, deployment

Post-MVP: eBPF collectors, kernel-level collection, alerting DSL, response actions, multi-tenancy, OIDC SSO.

## Security notes

- Agent JWTs are bearer tokens. Anyone with the file on disk can impersonate the agent. Mitigate later with the OS keystore.
- No Authenticode signing or macOS notarisation is in place yet. The install scripts verify release SHA-256 sidecar files when available, and both scripts accept an explicit `--sha256` / `-Sha256` value for pinned deployments.
- Enrollment tokens are single-use and short-lived. Rotate the signing key if leaked.
- SQL Server creds live in env vars; use Key Vault or similar in production.
- The agent runs as the local user in MVP, not as root or SYSTEM. Telemetry is limited accordingly.

Production deployments must terminate TLS before traffic reaches the API or web containers. See [docs/production.md](docs/production.md) for a Caddy reverse proxy sample, rate-limit behavior, audit logging notes, and the OS keystore path for agent JWTs.

## Agent install scripts

The dashboard enrollment page templates the supported one-liners:

```powershell
irm https://raw.githubusercontent.com/jusso-dev/Tawny/main/agent/install/install.ps1 | iex; Install-TawnyAgent -BackendUrl 'https://api.example.com' -EnrollmentToken 'wte_xxx'
```

```bash
curl -fsSL https://raw.githubusercontent.com/jusso-dev/Tawny/main/agent/install/install.sh | sudo bash -s -- --backend-url 'https://api.example.com' --enrollment-token 'wte_xxx'
```

Both scripts write the platform default `config.toml`, download the latest matching release asset, verify SHA-256 when a release sidecar is present, and register the agent as a Windows service, macOS launchd job, or Linux systemd service. Use `-DryRun` on Windows or `--dry-run` on macOS/Linux to inspect local actions without changing the host.

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
