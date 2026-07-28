# Threat model

Honest threat model for Tawny as a self-hosted EDR. Not a substitute for a formal review.

## Assets

- **Telemetry data.** Process lists, network tables, FIM events, DNS — reveals endpoint activity.
- **Agent credentials.** Short-lived JWTs (plus future device keys) granting write access for an agent identity.
- **Enrollment tokens.** One-shot credentials that register a new agent into a tenant.
- **Web→API HMAC secret.** Shared secret between Next.js and the .NET API; possession forges dashboard identity claims.
- **Dashboard user credentials.** Email/password and OAuth identities (Better Auth).
- **Integration secrets.** UniFi, cloud, Slack, Kelpie, Sentinel, TI feeds.
- **Response-action authority.** Ability to kill processes / future isolate on enrolled endpoints.
- **SQL Server.** Holds tenants, agents, telemetry, Hangfire state, audit log.

## Trust boundaries

1. **Agent host ↔ backend.** Prefer HTTPS. Remote HTTP is rejected unless `allow_insecure_http=true`. Loopback HTTP allowed for local dev.
2. **Browser ↔ Next.js.** Cookie session (Better Auth). CSRF and cookie scope apply.
3. **Next.js ↔ .NET API.** HMAC-signed request protocol `v2`: method, path, canonical query, body SHA-256, content-type, user, role, tenant, timestamp, single-use nonce. Secret ≥ 32 bytes in production.
4. **Admin operator ↔ Hangfire / OpenAPI.** Hangfire requires WebUser Admin. OpenAPI disabled in production unless explicitly enabled.
5. **Tenant boundary.** All multi-tenant queries must scope by authenticated tenant claim, never client-supplied tenant for authorization.

## Threats and mitigations

| Threat | Mitigation | Residual / future |
| --- | --- | --- |
| Enrollment token theft | Single-use, hashed at rest, short TTL | Bind to expected host / CIDR |
| Agent JWT theft from disk | Short-lived JWT (minutes), `jti`, `cv` credential version, admin revoke bumps version | Platform keystores (DPAPI/Keychain/TPM), device-bound keys |
| Stolen JWT after revoke | Heartbeat rejects revoked agents and credential-version mismatch | Global denylist of `jti` |
| Replay of signed web→API request | Timestamp window + single-use nonce; body/query bound into signature | mTLS or short-lived service JWT |
| Body/query swap on captured signature | Canonical v2 includes body digest and sorted query | — |
| Weak HMAC secret | Startup validation fails production on short/missing secret | Secret rotation runbook |
| Cross-tenant IDOR | Controllers filter by `User.GetTenantId()`; alerts/rules/response actions store TenantId; regression suite covers agents, alerts, rules, hunts, TI, tokens, audit | Keep expanding matrix |
| Telemetry fabrication / replay | `client_event_id` de-dupe, batch id, sequence watermark, future/past timestamp bounds, confidence=`agent_reported`, audit for gaps/rollback/volume spikes | Signed batches / external correlation |
| Response-action replay | Single-use execution token hash, expiry, terminal-state lock, server `ReceivedAt` | Approval workflow for destructive actions |
| PID reuse on kill_process | Optional image/path/start-time/hash fields in payload (agent best-effort match) | Strong OS process identity APIs |
| Compromised enrolled endpoint | Agent is trusted for *its own* telemetry only; cannot escalate to other agents without their credentials | Telemetry confidence labels, sequence numbers |
| Telemetry fabrication | Authenticated agent can fabricate events for itself; server stamps `received_at` | Sequence/replay detection, signed batches |
| Forged agent identity | RSA-signed JWT with agent_id + tenant + cv | Per-agent asymmetric enrollment keys |
| SQL injection | EF Core parameterized queries | Least-privilege DB user |
| XSS in dashboard | React + sanitization where free text rendered | Trusted Types |
| OpenAPI probe in production | OpenAPI unmapped unless non-production or explicit enable | Admin-only OpenAPI gateway |
| Reverse-proxy misconfig | Document HTTPS termination; public URL HTTPS checks in production | Trusted proxy / forwarded headers validation |
| Supply-chain agent release | Published SHA-256 | Sigstore / Authenticode / notarisation |
| Insider DB access | Audit log of security-sensitive actions | Column encryption, append-only audit sink |

## Explicit coverage (required scenarios)

| Scenario | What Tawny mitigates | Inherent limitation |
| --- | --- | --- |
| Compromised enrolled endpoint | Scope limited to that agent identity; revoke works server-side | User-space agent can lie about local state |
| Stolen agent credential | Short lifetime, version bump revoke | Window until expiry if version not checked on every request path |
| Compromised dashboard server | HMAC secret theft = full API admin impersonation | Shared secret trust model; prefer mTLS long-term |
| Compromised integration credential | Scoped to that integration’s capabilities | External system blast radius |
| Malicious tenant admin | Admin can act within tenant; not across tenants if isolation holds | Admin is powerful inside tenant by design |
| Cross-tenant access attempts | Auth claims + DB filters | Bugs in unscoped queries |
| Telemetry fabrication | Server receipt time; confidence labels (planned) | Cannot prove endpoint honesty |
| Response-action forgery | Execution token + agent JWT + state machine | Compromised agent can still refuse/misreport |
| Replay attacks | Nonce/HMAC, action tokens, JWT exp | Clock skew windows |
| Database compromise | Application controls bypassed | Full data exposure; encrypt backups offline |
| Supply-chain compromise of agent | Version pinning / SHA256 (partial) | Signed releases still future work |

## Out of scope

- Anti-tamper / anti-debug on the agent binary.
- Kernel-level attestation of process truth.
- Full side-channel resistance on the dashboard.

## Production obligations (operators)

- HTTPS to agents and browsers.
- `Tawny:WebUserHmacSecret` ≥ 32 random bytes.
- Stable `Tawny:AgentJwt:SigningKeyPem`.
- Public API/web HTTPS URLs configured (or explicit insecure override).
- Hangfire not exposed publicly without auth.
- Rotate secrets after suspected compromise; revoke agents via `POST /api/agents/{id}/revoke`.
