# Threat model

Honest threat model for Tawny as a self-hosted EDR. Not a substitute for a formal review.

## Assets

- **Telemetry data.** Process lists, network tables, FIM events, DNS — reveals endpoint activity.
- **Agent credentials.** Short-lived JWTs (plus future device keys) granting write access for an agent identity.
- **Enrollment tokens.** One-shot credentials that register a new agent into a tenant.
- **Session secret.** HttpOnly cookie value. Possession is that user's dashboard session until idle or absolute expiry.
- **Dashboard user credentials.** Email/password hashes and optional GitHub OAuth links. No self-service signup.
- **Integration secrets.** Slack, Sentinel, Tawny-SOC, reputation providers, TI feed auth headers (AES-GCM at rest).
- **Agent JWT seed.** Ed25519 seed that signs newly issued agent tokens. The RSA PEM only verifies tokens issued before that cutover.
- **Response-action authority.** Ability to kill processes / future isolate on enrolled endpoints.
- **PostgreSQL.** Holds tenants, agents, telemetry, sessions, the work queue, and the audit log.

## Trust boundaries

1. **Agent host ↔ tawny-server.** WAN agents use HTTPS terminated by Caddy. Remote HTTP is rejected unless `allow_insecure_http=true`. Loopback HTTP is allowed for local dev. The optional compose agent uses HTTP only on the compose network.
2. **Browser ↔ tawny-server.** Same origin. HttpOnly, Secure, SameSite=Lax session cookie. State-changing session requests send `X-CSRF-Token`. There is no separate web process and no HMAC hop.
3. **Admin operator ↔ jobs.** `GET /api/admin/jobs` requires an admin session. There is no Hangfire dashboard.
4. **Tenant boundary.** Multi-tenant queries scope by the authenticated tenant, never a client-supplied tenant for authorization.

## Threats and mitigations

| Threat | Mitigation | Residual / future |
| --- | --- | --- |
| Enrollment token theft | Single-use, hashed at rest, short TTL | Bind to expected host / CIDR |
| Agent JWT theft from disk | Short-lived JWT (minutes), `jti`, `cv` credential version, admin revoke bumps version. macOS Keychain; Windows DPAPI machine scope with fixed entropy and a SYSTEM/Administrators ACL, TPM-wrapped through the Platform Crypto Provider when present (#58) | Linux keeps a root-only 0600 file; tpm2-tss sealing not done. An administrator on the host can still read DPAPI secrets |
| Stolen JWT after revoke | Every agent endpoint (JWT validation hook) rejects revoked agents and credential-version mismatch, and audits the rejection | Global denylist of `jti` |
| Stolen session cookie | HttpOnly, Secure, SameSite=Lax; idle 8h and absolute 7d; logout deletes the row | XSS that can read a non-HttpOnly token is out of this cookie's reach; CSRF still applies |
| Cross-site session use | `X-CSRF-Token` required on state-changing session requests. API tokens and agent JWTs are exempt | A stolen cookie plus a stolen CSRF secret is a full session |
| Cross-tenant IDOR | Controllers filter by `User.GetTenantId()`; alerts/rules/response actions store TenantId; regression suite covers agents, alerts, rules, hunts, TI, tokens, audit | Keep expanding matrix |
| Telemetry fabrication / replay | `client_event_id` de-dupe, batch id, sequence watermark, future/past timestamp bounds, confidence=`agent_reported`, audit for gaps/rollback/volume spikes | Signed batches / external correlation |
| Response-action replay | Single-use execution token hash, expiry, terminal-state lock, server `ReceivedAt`, local action journal dedupes by `action_id` and replays on restart | Approval workflow for destructive actions |
| Forged or tampered response action | Server signs each action with the Ed25519 action key (`tawny-action-v1` over id, agent, type, expiry and payload hash); the agent verifies against its pinned key and refuses unsigned, expired, tampered or wrong-key actions. Key pinned at enrolment, or trust on first use from the first heartbeat that carries it | Mutual TLS client certs |
| PID reuse on kill/suspend/resume | Image path and start time compared against the live process (Linux `/proc`, Windows `QueryFullProcessImageNameW` + `GetProcessTimes`); critical-process refusal list | Strong OS process identity (entity id) APIs |
| Compromised enrolled endpoint | Agent is trusted for *its own* telemetry only; cannot escalate to other agents without their credentials | Telemetry confidence labels, sequence numbers |
| Telemetry fabrication | Authenticated agent can fabricate events for itself; server stamps `received_at` | Sequence/replay detection, signed batches |
| Forged agent identity | New JWTs are Ed25519. Pre-cutover RS256 tokens still verify. Claims include agent_id, tenant, and cv | Per-agent asymmetric enrollment keys |
| SQL injection | Parameterized queries | Least-privilege DB user (`tawny_app` does not bypass RLS; the current server still connects as the database owner) |
| XSS in dashboard | Static pages must escape telemetry and operator text on insert | Trusted Types |
| OpenAPI probe in production | tawny-server does not publish an OpenAPI document | — |
| Reverse-proxy misconfig | Document HTTPS termination; public URL HTTPS checks in production | Trusted proxy / forwarded headers validation |
| Supply-chain agent release | Published SHA-256 and build attestations. Self-update only installs a binary named by a minisign-signed manifest (`ED`, BLAKE2b prehashed) checked against the release key compiled into the agent, then checks size and SHA-256, refuses downgrades except a signed `rollback`, and rolls back after a failed health window (#58) | Authenticode and notarisation steps exist but need certificates (docs/code-signing.md). The release key is a placeholder until the owner creates it, so self-update is off |
| Insider DB access | Audit log of security-sensitive actions | Column encryption, append-only audit sink |
| Agent stopped or killed to blind the host | Clean shutdown marker plus a final `shutdown` heartbeat on service stop and SIGTERM. A start without the marker sends `agent_tamper` `unexpected_stop`. An agent that goes offline without the notice raises `Agent silent` (closed by its next heartbeat; revoked agents never alert). Installer service DACL lets only SYSTEM and Administrators stop or delete the service (#58) | An administrator can still stop the service and delete the marker first; the server still sees the missing heartbeat |
| Sensor silenced (Sysmon stopped, channel cleared, Defender exclusion) | `sensor_health` and `agent_health.sensors` feed per-sensor status. A sensor that was running and stops, fails, or (Sysmon, Security) delivers nothing for 15 minutes raises `Sensor silent`. Tamper checks report the Sysmon service stopping, Defender 5007 exclusions covering Tawny paths, the binary hash changing, and config or identity files changing outside the agent | User-mode only; an attacker with kernel access can hide these. No anti-debug or rootkit behaviour by design |

## Decision: no mutual TLS for now (#58)

Agents authenticate with short-lived JWT bearer tokens over server-side TLS.
Mutual TLS was considered and left out for this release. The risks it would
cover are already covered: every event batch is signed with the agent's
Ed25519 device key and verified by the server, every response action is
signed by the server action key and verified by the agent, and the agent's
secrets are held in the OS keystore (Keychain, DPAPI with optional TPM wrap).
mTLS would add certificate issuance, rotation and revocation, and would break
TLS-terminating proxies such as Caddy in front of the server, for little
gain over those. Revisit if agents ever need to talk to the server through an
untrusted proxy that could replay bearer tokens.

## Explicit coverage (required scenarios)

| Scenario | What Tawny mitigates | Inherent limitation |
| --- | --- | --- |
| Compromised enrolled endpoint | Scope limited to that agent identity; revoke works server-side | User-space agent can lie about local state |
| Stolen agent credential | Short lifetime, version bump revoke | Window until expiry if version not checked on every request path |
| Compromised tawny-server | One process holds the database URL, session rows, and agent JWT seed | No separate dashboard host to split that trust |
| Compromised integration credential | Scoped to that integration’s capabilities | External system blast radius |
| Malicious tenant admin | Admin can act within tenant; not across tenants if isolation holds | Admin is powerful inside tenant by design |
| Cross-tenant access attempts | Auth claims + DB filters | Bugs in unscoped queries |
| Telemetry fabrication | Server receipt time; confidence labels (planned) | Cannot prove endpoint honesty |
| Response-action forgery | Execution token + agent JWT + state machine | Compromised agent can still refuse/misreport |
| Replay attacks | Session expiry, single-use action tokens, JWT exp | Clock skew windows |
| Database compromise | Application controls bypassed | Full data exposure; encrypt backups offline |
| Supply-chain compromise of agent | Version pinning / SHA256 (partial) | Signed releases still future work |

## Out of scope

- Anti-tamper / anti-debug on the agent binary.
- Kernel-level attestation of process truth.
- Full side-channel resistance on the dashboard.

## Production obligations (operators)

- HTTPS from Caddy to browsers and WAN agents. Zig does not terminate TLS.
- No web-to-API HMAC secret.
- Stable `TAWNY_AGENT_JWT_SEED`. Keep the RSA PEM until every agent has heartbeated onto Ed25519.
- `TAWNY_PUBLIC_URL` is the `https://` origin enrollment commands use.
- `GET /api/admin/jobs` stays on an admin session. Do not publish Postgres.
- Rotate secrets after suspected compromise; revoke agents via `POST /api/agents/{id}/revoke`.
