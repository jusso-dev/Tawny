# Production deployment notes

## TLS termination

The development compose stack exposes the API and web containers over HTTP. Production deployments should place a reverse proxy in front of both services and terminate TLS there.

Example Caddyfile:

```caddyfile
tawny.example.com {
  encode zstd gzip
  reverse_proxy tawny-web:3000
}

api.tawny.example.com {
  encode zstd gzip
  reverse_proxy tawny-api:5080
}
```

Set `BETTER_AUTH_URL=https://tawny.example.com`, `TAWNY_API_URL=http://tawny-api:5080` for server-side web-to-API calls, and `NEXT_PUBLIC_TAWNY_AGENT_BACKEND_URL=https://api.tawny.example.com` so enrollment install commands point agents at the TLS endpoint.

## Agent JWT storage

Agent JWTs are bearer credentials. The MVP config file supports plaintext for local development, but production installers should store the token with the operating system credential facility and leave only non-secret settings in `config.toml`:

- Windows: protect the JWT with DPAPI scoped to LocalMachine or the service identity.
- macOS: store the JWT in Keychain as a generic password for the Tawny agent service account.

If a host is rebuilt or the service account changes, re-enroll the agent or restore the OS credential item with the same protection scope.

## Rate limiting and audit logs

`POST /api/agents/events` is rate limited with a per-agent token bucket. The API returns `429` and a JSON error body when an agent exceeds the ingest budget.

State-changing endpoints write to `AuditLog`, including enrollment token creation/revocation, agent enrollment, heartbeat updates, and telemetry ingest batches. Ship this table to your operational log store if database access is tightly restricted.
