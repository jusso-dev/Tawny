# Threat model

A deliberately small, honest threat model for the MVP. Not a substitute for a formal review.

## Assets

- **Telemetry data.** Process lists, network connection tables, FIM events. Sensitive because they reveal what's running on protected endpoints.
- **Agent JWTs.** Bearer credentials that grant write access to the events endpoint.
- **Enrollment tokens.** One-shot credentials that grant the right to register a new agent.
- **Dashboard user credentials.** Email/password and OAuth identities managed by Better Auth.
- **SQL Server.** Holds everything above plus Hangfire job state.

## Trust boundaries

1. **Agent host** ↔ **backend over HTTPS.** TLS is mandatory in production. The agent does not validate certificates against a pinned CA in the MVP — note this as a limitation.
2. **Browser** ↔ **Next.js.** Standard web boundary. Better Auth handles CSRF and cookie scope.
3. **Next.js server** ↔ **.NET API.** Internal hop, secured by HMAC-signed headers (`X-User-Id`, `X-User-Role`, `X-Signature`). The shared secret is in env vars.

## Threats and mitigations

| Threat | Mitigation in MVP | Future work |
| --- | --- | --- |
| Enrollment token theft | Tokens are single-use, expire in 24h by default, and are stored hashed server-side. | Bind tokens to expected hostname or IP range. |
| Agent JWT theft from disk | None beyond filesystem ACLs. Documented as a known limitation. | Store JWT in DPAPI on Windows / Keychain on macOS. |
| Replay of telemetry batch | `received_at` is server-stamped; duplicates are tolerated by design (snapshots). | Optional client nonce + server-side de-dupe. |
| Forged dashboard requests to API | Next.js server signs every outbound API call with an HMAC. The API rejects unsigned or stale (>30s) requests. | Replace with OIDC / mTLS. |
| SQL injection | EF Core with parameterised queries. | Defense in depth: least-privilege DB user. |
| XSS in dashboard | React + DOMPurify on any rendered free-text fields. Strict CSP. | Add `Trusted Types` once browser support catches up. |
| Compromised CI signing the agent | No code signing in MVP. SHA256 of every release is published. | Sigstore / proper Authenticode + notarisation. |
| Insider with DB access | None in MVP. | Column-level encryption for PII; audit table is append-only. |
| DoS on `/api/agents/events` | Per-agent rate limit (token bucket, future). 1 MB payload cap returns 413. | Add proper rate limiting middleware. |

## Out of scope

- Anti-tamper on the agent binary itself.
- Detection of a malicious agent supplying fake telemetry. Agents are trusted within their own scope; this is a property of the deployment model, not a bug.
- Side-channel leakage from the dashboard (timing, cache).

## Open questions

- Should heartbeats be signed separately so a stolen JWT can't be replayed indefinitely? Probably yes, but not for MVP.
- Should FIM events include a snippet of file contents? No — too easy to leak secrets. Hash only.
