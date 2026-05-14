<p align="center">
  <img src="web/public/logo.jpg" alt="Tawny EDR" width="320" />
</p>

# Tawny

> Quiet eyes on every endpoint.

Tawny is a self-hosted, lightweight EDR (endpoint detection and response) system. A tiny Zig agent runs on Windows and macOS, ships telemetry to a .NET 10 backend over HTTPS, and surfaces it through a polished Next.js 16 dashboard. Hangfire handles offline detection, retention, backups, and agent update checks.

The MVP is intentionally small. No kernel hooks, no driver signing, no SIEM-grade ingestion. Clean architecture, real telemetry, and a UI that looks like a product.

## Why "Tawny"?

Tawny is named after the tawny frogmouth, an Australian nocturnal bird famous for sitting perfectly still on a branch and being mistaken for part of the tree. It watches everything around it, makes no noise, and only acts when it needs to. That is roughly the job description of a good EDR agent: blend in, observe quietly, raise the alarm when something is worth your attention.

The tawny frogmouth is also small, unassuming, and frequently underestimated. The agent is a single Zig binary measured in kilobytes. The bird and the binary share a philosophy: do one thing well and stay out of the way.

## Architecture

```
+------------------------+        HTTPS         +-------------------------+
| Zig Agent              | -------------------> | .NET 10 API             |
| (Windows / macOS)      |  JWT, batched JSON   | ASP.NET Core            |
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
- .NET 10 SDK
- Node 22+ and pnpm 10+
- Zig 0.14+ (only needed if you want to build the agent)

```bash
# 1. Bring up SQL Server + API + Web
cd docker
docker compose up --build

# 2. Apply migrations (one-off)
cd ../backend
dotnet ef database update --project src/Tawny.Infrastructure --startup-project src/Tawny.Api

# 3. Open the dashboard
open http://localhost:3000

# 4. Create an enrollment token (via the dashboard or curl)
curl -X POST http://localhost:5080/api/enrollment-tokens \
  -H "X-User-Id: bootstrap" -H "X-User-Role: Admin" \
  -H "X-Signature: $(scripts/sign.sh)"

# 5. Run the agent against your local backend
cd ../agent
zig build run -- --enrollment-token wte_xxx --backend http://localhost:5080
```

## Why Zig?

Zig produces small, static binaries and cross-compiles to Windows and macOS from one machine without a fleet of toolchains. The C interop story is excellent, which matters when you are calling `CreateToolhelp32Snapshot` on Windows and `sysctl` on macOS. No runtime, no GC, predictable memory. A good fit for an endpoint agent that has to live quietly inside other people's machines.

## Why this stack?

.NET 10 with EF Core and Hangfire keeps the backend boring and productive. Hangfire's SQL Server storage means one database to operate. Next.js 16 with the App Router and Server Components keeps the dashboard fast and lets us colocate data fetching with the views that need it. Better Auth handles email/password and GitHub OAuth without owning a session store. shadcn/ui plus Tailwind keeps the visual surface coherent without designing from scratch.

## Not in scope for MVP

This is a portfolio MVP. To keep it shippable in a sprint, the following are explicitly out:

- Multi-tenancy
- Linux agent
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

Post-MVP: Linux agent (eBPF), kernel-level collection, alerting DSL, response actions, multi-tenancy, OIDC SSO.

## Security notes

- Agent JWTs are bearer tokens. Anyone with the file on disk can impersonate the agent. Mitigate later with the OS keystore.
- No Authenticode signing or macOS notarisation is in place yet. The install scripts verify release SHA-256 sidecar files when available, and both scripts accept an explicit `--sha256` / `-Sha256` value for pinned deployments.
- Enrollment tokens are single-use and short-lived. Rotate the signing key if leaked.
- SQL Server creds live in env vars; use Key Vault or similar in production.
- The agent runs as the local user in MVP, not as root or SYSTEM. Telemetry is limited accordingly.

## Agent install scripts

The dashboard enrollment page templates the supported one-liners:

```powershell
irm https://raw.githubusercontent.com/jusso-dev/Tawny/main/agent/install/install.ps1 | iex; Install-TawnyAgent -BackendUrl 'https://api.example.com' -EnrollmentToken 'wte_xxx'
```

```bash
curl -fsSL https://raw.githubusercontent.com/jusso-dev/Tawny/main/agent/install/install.sh | sudo bash -s -- --backend-url 'https://api.example.com' --enrollment-token 'wte_xxx'
```

Both scripts write the platform default `config.toml`, download the latest matching release asset, verify SHA-256 when a release sidecar is present, and register the agent as a Windows service or macOS launchd job. Use `-DryRun` on Windows or `--dry-run` on macOS to inspect local actions without changing the host.

See [docs/threat-model.md](docs/threat-model.md).

## License

MIT. See `LICENSE`.
