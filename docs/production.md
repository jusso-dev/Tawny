# Production deployment notes

## Secure configuration (required)

`docker compose` runs PostgreSQL 17, one `tawny-server` process, and Caddy. Caddy terminates TLS. The Zig process speaks HTTP only on the compose network and is not published. Postgres is not published. An optional `agent` profile joins the same network.

| Setting | Requirement |
| --- | --- |
| `POSTGRES_PASSWORD` | Random (`openssl rand -hex 24`). Only the compose network sees it. |
| `TAWNY_DATABASE_URL` | `postgres://tawny:<password>@postgres:5432/tawny` |
| `TAWNY_INTEGRATION_ENCRYPTION_KEY` | ≥ 32 random bytes. Losing it makes stored integration secrets unreadable. |
| `TAWNY_AGENT_JWT_SEED` | 64 hex characters. Stable Ed25519 seed for newly issued agent JWTs. |
| `TAWNY_AGENT_JWT_SIGNING_KEY_PEM` | RSA PEM used only to verify tokens issued before the Ed25519 cutover. |
| `TAWNY_PUBLIC_URL` | `https://…` origin browsers and enrollment commands use. |

There is no web-to-API HMAC secret and no separate web process. The browser holds an HttpOnly, Secure, SameSite=Lax session cookie. State-changing session requests send `X-CSRF-Token`. API tokens (`twny_`) and agent JWTs do not use that cookie.

Dashboard accounts are not self-service. GitHub OAuth links an existing user and does not create one. The first admin is created from `TAWNY_BOOTSTRAP_ADMIN_EMAIL` / `TAWNY_BOOTSTRAP_ADMIN_PASSWORD` only when the user table is empty. The server does not log that password. Later users default to Viewer.

`tawny-server import-mssql <export.json>` loads a SQL Server plus Better Auth export into the current database. The command is idempotent. It keeps agent id, credential version, and device public key, stores `twny_` and `wte_` SHA-256 hashes as exported, and leaves `v1.` feed secrets unchanged (it decrypts them with `TAWNY_INTEGRATION_ENCRYPTION_KEY` only to prove the key still opens them). Better Auth user ids that are not UUIDs are mapped to a stable UUID. A legacy `saltHex:keyHex` scrypt password is kept until that user logs in, then replaced with argon2id. The command prints inserted and unchanged row counts plus `report_sha256`. `server/fixtures/sqlserver-export.json` is a small export fixture. A copy of a real install is still required for a production rehearsal.

`docker/scripts/init-secrets.sh` writes `docker/.env` and the RSA PEM. Compose mounts `docker/secrets/tawny-jwt-key` at `/run/secrets/tawny-jwt-key`. This Compose engine ignores secret uid and mode, so the script sets the file mode to `0644` and uid 65532 can read it. An unset backup path is `off` inside the read-only container; set `TAWNY_BACKUP_LOCAL_PATH` to a mounted directory, or set `TAWNY_BACKUP_S3_BUCKET`, to keep the daily backup. The script prints the bootstrap password once, when it first creates it.

## TLS termination

Caddy is the only published listener. `docker/Caddyfile` reverse-proxies `tawny-server:8080`. `tls internal` is the local and LAN default. For a public name, set `TAWNY_DOMAIN` and remove the `tls internal` line so Caddy can obtain a public certificate.

```caddyfile
{$TAWNY_DOMAIN:localhost} {
	tls internal
	encode gzip
	reverse_proxy tawny-server:8080
}
```

Enrollment install commands must use `TAWNY_PUBLIC_URL` (`https://…`). The optional compose agent profile talks to `http://tawny-server:8080` with `allow_insecure_http` because that hop stays on the compose network. Do not point a WAN agent at plaintext HTTP.

### Agent HTTPS defaults

The Zig agent:

- accepts `https://` backends always;
- accepts `http://localhost`, `http://127.0.0.1`, and `http://[::1]` for local development;
- **rejects** other `http://` backends unless `allow_insecure_http = true` in `config.toml`.

Never send enrollment tokens over plaintext WAN links.

## Agent JWT storage and revocation

Agent JWTs are short-lived (default 60 minutes, rotate within 15). Heartbeats issue rotated JWTs. Each agent has a `CredentialVersion`; admin revoke increments it so old tokens fail.

### Device-bound public keys and signed batches

At enrollment the agent generates an Ed25519 keypair and registers the base64 public key as `device_public_key`. The seed is stored in the OS keystore where one is implemented (macOS Keychain, see below); otherwise, or if the keystore write fails, in `{state_path}.devicekey` (`0600` when possible).

Each telemetry flush includes optional `signature` (base64 Ed25519) over a deterministic canonical form (`tawny-batch-v1` + agent id + batch id + per-event digests). When `Tawny:TelemetryIntegrity:RequireSignatureWhenDeviceKeyPresent` is true (default), agents that registered a device key **must** present a valid signature. Agents enrolled without a device key remain accepted for compatibility.


Revoke immediately:

```http
POST /api/agents/{id}/revoke
```

(Admin session or API token.)

### Where the agent keeps its secrets

`state.toml` holds only `agent_id` when a keystore is in use. The JWT and the device seed live in the keystore:

| Platform | Secret store | Status |
| --- | --- | --- |
| macOS LaunchDaemon (root) | `/Library/Keychains/System.keychain`, generic password, service `dev.jusso.tawny-agent`, accounts `agent-jwt` and `device-seed` | implemented |
| macOS `--user` LaunchAgent | the user's login keychain, same service/accounts | implemented |
| Windows | `state.toml` / `.devicekey` under the SYSTEM + Administrators ACL on `%ProgramData%\Tawny` | DPAPI planned |
| Linux | root/`tawny`-owned `0600` `state.toml` / `.devicekey` | keyring/TPM planned |

On macOS:

- **Migration.** On start, a JWT found in `state.toml` and a `.devicekey` file are copied into the keychain, read back and compared, and only then removed: `state.toml` is atomically rewritten without `agent_jwt`, and the seed file is overwritten with zeros and deleted (best effort; APFS may keep old blocks).
- **Fallback.** If the keychain cannot be written (locked login keychain, missing System keychain, any Security.framework error), the agent logs a warning with the `OSStatus` and keeps or writes the plaintext file as before. A JWT present in `state.toml` always wins over the keychain copy, so a fallback write is never shadowed by an older keychain value. `TAWNY_KEYSTORE=file` forces the plaintext backend.
- **No UI.** All keychain calls run with user interaction disabled; anything that would prompt fails with `errSecInteractionNotAllowed` / `errSecAuthFailed` instead.
- **File-based keychain, not the data-protection keychain.** The data-protection keychain needs a `keychain-access-groups` entitlement and so a real code signature. The agent ships ad-hoc signed, so it uses the file-based System/login keychain. `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` is set but ignored by file-based keychains; items are never synchronizable.
- **Who can read the items.** Since macOS 10.12 the keychain adds a partition list naming the creating binary. For an ad-hoc signed binary that is its `cdhash`, so only the exact agent build that wrote an item can read it without a prompt. The item ACL is opened to any application only so that newer builds and `security delete-generic-password` can replace or delete stale items; it does not grant reads. Once the agent ships with a Developer ID signature, the partition becomes the team ID and this can be tightened to the agent's designated requirement.
- **Upgrades.** Because a new build cannot read the old build's items, `install.sh` stops the job and runs the *old* binary with `--export-credentials` before replacing it. That copies the JWT and seed back into `0600` files (verified) and deletes the keychain items; the new build moves them back into the keychain on first start. Rollback runs the same export with the new build before restoring the old one. If the binary is replaced any other way, the agent exits with `AgentJwtUnavailable` (`OSStatus -25293`); run the old binary with `--export-credentials`, or re-enroll the host.
- **Removing items** (uninstall or forced re-enrollment):

  ```bash
  sudo security delete-generic-password -s dev.jusso.tawny-agent -a agent-jwt /Library/Keychains/System.keychain
  sudo security delete-generic-password -s dev.jusso.tawny-agent -a device-seed /Library/Keychains/System.keychain
  ```

  Listing them (`security find-generic-password -s dev.jusso.tawny-agent ...` without `-w`) shows attributes only and never prompts.

If a host is rebuilt, re-enroll (new credential version).

## Response actions

Dispatched actions include a single-use `execution_token`, payload hash, and expiry. Results without a valid unused token are rejected. Cancel pending/dispatched actions with:

```http
POST /api/agents/{agentId}/actions/{id}/cancel
```

## Jobs

There is no Hangfire dashboard. An admin session reads `GET /api/admin/jobs`. The seven jobs run inside `tawny-server`.

## Incident recovery (short)

1. Rotate `TAWNY_AGENT_JWT_SEED` only with a planned re-enroll window. Keep the RSA PEM until every agent has heartbeated onto Ed25519.
2. Revoke compromised agents; re-issue enrollment tokens.
3. Preserve the audit log and database backups offline and encrypted.
4. Keep `TAWNY_INTEGRATION_ENCRYPTION_KEY` with the database backup. A new key does not decrypt old rows.
5. After restore, confirm `GET /api/health/ready` and `GET /api/admin/jobs`.

## Linux and Amazon EC2 network collection

Linux agents collect current TCP/UDP sockets from procfs, ARP neighbors, DNS servers and search domains from `/etc/resolv.conf`, and address-to-host mappings from `/etc/hosts`. Procfs IPv6 values are normalized to canonical text so IPv6 IoCs can match stored telemetry.

On Amazon EC2, the hourly system snapshot also records instance ID, Region, Availability Zone, private/public hostnames, and private IPv4, public IPv4, and IPv6 values across up to 16 attached network interfaces when available. The agent:

- confirms EC2 through DMI before contacting the link-local metadata address;
- uses IMDSv2 tokens only and never emits the token;
- bypasses proxies for `169.254.169.254`;
- applies one-second connect and two-second total request limits;
- needs `curl` installed, but no IAM permissions.

If IMDS is disabled, or an instance has no public address or hostname, those fields are omitted. No AWS credentials are read.

Live DNS query events come from the journals for `systemd-resolved`, dnsmasq, Unbound, and BIND. The agent service account needs journal read access. `systemd-resolved` usually needs query logging enabled:

```bash
sudo resolvectl log-level debug
```

`/etc/hosts` entries are emitted once at startup and again only after file content changes. Hosts without a supported resolver log still contribute static host mappings, resolver settings, EC2 hostnames, and domains found in process command lines; packet-level DNS visibility remains a future eBPF capability.

## Rate limiting and audit logs

Agent policies (partitioned by IP or tenant+agent):

- `agent-enrollment`, `agent-heartbeat`, `agent-events`

Dashboard / admin policies (partitioned by **tenant + user or API token**, not IP alone):

- `web-read` — authenticated reads  
- `web-mutate` / `web-admin-mutate` — mutations  
- `response-actions` — kill/isolate dispatch  
- `rule-imports` — Sigma/YARA/IoC imports  
- `hunts` — hunt execution  
- `search` — search/pivot style endpoints  

`429` responses include `{ "error": "rate_limited", "policy": "..." }`.

### Telemetry integrity

Agents may send optional `batch_id` and per-event `sequence`. Server:

- stamps authoritative `received_at`;
- rejects timestamps too far future/past (`Tawny:TelemetryIntegrity`);
- de-dupes `client_event_id`;
- audits sequence gap/rollback and volume spikes;
- labels confidence `agent_reported` (server never upgrades agent data to higher confidence without correlation).

`POST /api/agents/events` is rate limited with a per-agent token bucket. The API returns `429` and a JSON error body when an agent exceeds the ingest budget.

State-changing endpoints write to `AuditLog`, including enrollment token creation/revocation, agent enrollment, credential issue/rotation/revocation, agent auth failures, agent status or version changes, telemetry integrity anomalies, and response actions. Routine heartbeats and ingest batches are not audited. Ship this table to your operational log store if database access is tightly restricted.

## Wazuh SIEM sink

Tawny can publish generated alerts to Wazuh using syslog. The sink is disabled by default and emits one syslog message per Tawny alert. The syslog body is JSON with stable top-level fields:

- `integration`: always `tawny`
- `event_kind`: always `alert`
- `alert_id`, `alert_title`, `alert_description`, `alert_severity`, `alert_status`, `alert_created_at`, and `rule_id`
- `agent_id`, `tenant_id`, `agent_hostname`, `agent_os`, `agent_architecture`, and `agent_version`
- `telemetry_id`, `telemetry_type`, `telemetry_occurred_at`, `telemetry_received_at`, and `telemetry_payload_json`

The JSON is intentionally flat for Wazuh compatibility. Wazuh's JSON decoder can extract arrays, but not arrays of objects, so Tawny sends the matched telemetry payload as an escaped JSON string in `telemetry_payload_json`. If the event would exceed `MaxMessageBytes`, Tawny omits that field and sets `telemetry_payload_omitted=true`.

Configure the API:

```bash
Tawny__Wazuh__Enabled=true
Tawny__Wazuh__Host=wazuh-manager.example.com
Tawny__Wazuh__Port=514
Tawny__Wazuh__Protocol=udp
Tawny__Wazuh__Facility=16
Tawny__Wazuh__AppName=tawny
```

The Docker stack exposes the same settings with `TAWNY_WAZUH_*` variables in `docker/.env`:

```bash
TAWNY_WAZUH_ENABLED=true
TAWNY_WAZUH_HOST=wazuh-manager.example.com
TAWNY_WAZUH_PORT=514
TAWNY_WAZUH_PROTOCOL=udp
```

Configure the Wazuh manager to listen for syslog from the Tawny API host. Example manager `ossec.conf` block:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.0.0.25</allowed-ips>
</remote>
```

Use `tcp` instead of `udp` on both sides if you want connection-oriented delivery. When Tawny runs in Docker Desktop or crosses NAT, Wazuh may see a translated source IP rather than the Tawny container IP or the desktop LAN IP. Put the IP that Wazuh actually reports in `allowed-ips`.

If the Wazuh manager log contains a message like this:

```text
wazuh-remoted: WARNING: (1213): Message from '172.67.157.37' not allowed. Cannot find the ID of the agent.
```

then Wazuh received the Tawny packet but rejected it. Add that exact source to the syslog block:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.0.0.25</allowed-ips>
  <allowed-ips>172.67.157.37</allowed-ips>
</remote>
```

For Wazuh running in Docker, confirm the manager publishes UDP 514 on the host:

```bash
MANAGER=$(docker ps --format '{{.Names}}' | grep -Ei 'wazuh.*manager|manager' | head -1)
docker port "$MANAGER" | grep '514/udp'
```

Install the bundled decoder and rules so Tawny events become Wazuh alerts:

```bash
sudo cp integrations/wazuh/tawny_decoder.xml /var/ossec/etc/decoders/tawny_decoder.xml
sudo cp integrations/wazuh/tawny_rules.xml /var/ossec/etc/rules/tawny_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/decoders/tawny_decoder.xml /var/ossec/etc/rules/tawny_rules.xml
sudo chmod 660 /var/ossec/etc/decoders/tawny_decoder.xml /var/ossec/etc/rules/tawny_rules.xml
sudo systemctl restart wazuh-manager
```

For a Docker-based Wazuh manager, copy the same files into the manager container and restart it:

```bash
MANAGER=$(docker ps --format '{{.Names}}' | grep -Ei 'wazuh.*manager|manager' | head -1)
docker cp integrations/wazuh/tawny_decoder.xml "$MANAGER":/var/ossec/etc/decoders/tawny_decoder.xml
docker cp integrations/wazuh/tawny_rules.xml "$MANAGER":/var/ossec/etc/rules/tawny_rules.xml
docker exec "$MANAGER" chown wazuh:wazuh /var/ossec/etc/decoders/tawny_decoder.xml /var/ossec/etc/rules/tawny_rules.xml
docker exec "$MANAGER" chmod 660 /var/ossec/etc/decoders/tawny_decoder.xml /var/ossec/etc/rules/tawny_rules.xml
docker restart "$MANAGER"
```

Test the decoder/rule on the Wazuh manager:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a Tawny syslog line such as:

```text
May 14 08:59:11 tawny-api-local tawny: {"integration":"tawny","event_kind":"alert","alert_id":7,"alert_title":"Linux Download To Temp Path","alert_severity":"medium","alert_status":"open","rule_id":"8b47c9e6-9928-4a87-8d40-beddd733ed34","agent_id":"dcb05d83-ba08-4eca-9b50-a6f434e30486","tenant_id":"00000000-0000-0000-0000-000000000001","agent_hostname":"linux-agent","agent_os":"linux","agent_architecture":"arm64","agent_version":"0.1.0","telemetry_id":1722,"telemetry_type":"process_snapshot","telemetry_payload_json":"{\"processes\":[{\"name\":\"tail\",\"command_line\":\"tail -f /tmp/tawny-wazuh-trigger\"}]}","telemetry_payload_omitted":false}
```

The expected result is a rule match on `110500` and group `tawny_alert`.

After sending live Tawny alerts, confirm Wazuh accepted them:

```bash
docker exec "$MANAGER" sh -c 'grep -R "Linux Download To Temp Path\\|tawny" /var/ossec/logs/archives/ /var/ossec/logs/alerts/ 2>/dev/null | tail -20'
docker exec "$MANAGER" sh -c 'tail -200 /var/ossec/logs/ossec.log | grep -iE "tawny|syslog|remote|514|not allowed|error"'
```

In the Wazuh dashboard, search `wazuh-alerts-*` over the last 24 hours for:

```text
rule.id:110500 OR tawny_alert OR "Linux Download To Temp Path"
```

## Slack alert sink

Slack alerting is disabled by default. Create a Slack incoming webhook and configure the API with:

```bash
Tawny__Slack__Enabled=true
Tawny__Slack__WebhookUrl=https://hooks.slack.com/services/...
Tawny__Slack__Username=Tawny
Tawny__Slack__IconEmoji=:rotating_light:
Tawny__Slack__TimeoutSeconds=5
```

For Docker deployments, use the matching environment variables:

```bash
TAWNY_SLACK_ENABLED=true
TAWNY_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TAWNY_SLACK_USERNAME=Tawny
TAWNY_SLACK_ICON_EMOJI=:rotating_light:
TAWNY_SLACK_TIMEOUT_SECONDS=5
```

Only new alerts generated after Slack is enabled are posted. Tawny records Slack delivery state on the alert row so the dashboard can show whether the webhook send was `sent`, `failed`, `pending`, or `not_configured`.

## Threat intelligence (default feeds)

Tawny seeds public starter feeds for every tenant on API startup
and before each threat-intel poll (idempotent by URL). Feodo Tracker and
OpenPhish are **enabled** by default; PhishTank, Emerging Threats, and
blocklist.de ship disabled. Imported indicators become IoC alert rules and
raise Tawny alerts on matching agent telemetry without enabling any alert sink.

Operators can disable feeds, change intervals, or add OTX/MISP/TAXII/CSV feeds
from the **Threat Intel** dashboard. No environment variable is required for
the default seed. See the README “Threat intelligence feeds” section for the
full source table.

## Microsoft Sentinel / Azure Monitor sink

Tawny can send generated alerts and, separately, raw telemetry batches to Microsoft Sentinel through the Azure Monitor Logs Ingestion API. This uses Microsoft Entra OAuth and a Data Collection Rule (DCR); Tawny does not implement the legacy Log Analytics workspace ID/shared-key collector path.

Azure setup:

1. Create the destination custom tables in the Log Analytics workspace, for example `TawnyAlert_CL` and `TawnyTelemetry_CL`.
2. Create a DCR with direct logs ingestion enabled and streams that match the payload fields Tawny sends. Use DCR endpoints for new deployments. Use a Data Collection Endpoint only for Private Link or older DCR designs that do not expose a logs ingestion URI.
3. Map the alert stream to `Custom-TawnyAlert_CL` and, if enabled, the telemetry stream to `Custom-TawnyTelemetry_CL`.
4. Create an app registration and client secret, or use a managed identity for Azure-hosted API deployments.
5. Grant that identity the `Monitoring Metrics Publisher` role on the DCR scope.
6. Copy the DCR logs ingestion URI and immutable ID from the DCR overview or JSON view.

Recommended alert stream fields:

- `TimeGenerated`, `EventKind`, `TawnyTenantId`
- `AgentId`, `AgentHostname`, `AgentOs`, `AgentOsVersion`, `AgentArchitecture`, `AgentVersion`
- `AlertId`, `AlertRuleId`, `AlertTitle`, `AlertDescription`, `AlertSeverity`, `AlertStatus`, `AlertCreatedAt`
- `TelemetryEventId`, `TelemetryEventType`, `TelemetryOccurredAt`, `TelemetryReceivedAt`, `TelemetryPayload`

Recommended telemetry stream fields:

- `TimeGenerated`, `EventKind`, `TawnyTenantId`
- `AgentId`, `AgentHostname`, `AgentOs`, `AgentOsVersion`, `AgentArchitecture`, `AgentVersion`
- `TelemetryEventId`, `TelemetryEventType`, `TelemetryOccurredAt`, `TelemetryReceivedAt`, `TelemetryPayload`

Configure client-secret authentication:

```bash
Tawny__Sentinel__Enabled=true
Tawny__Sentinel__AlertsEnabled=true
Tawny__Sentinel__TelemetryEnabled=false
Tawny__Sentinel__AuthenticationMode=client_secret
Tawny__Sentinel__TenantId=00000000-0000-0000-0000-000000000000
Tawny__Sentinel__ClientId=00000000-0000-0000-0000-000000000000
Tawny__Sentinel__ClientSecret=...
Tawny__Sentinel__EndpointUrl=https://<dcr-or-dce>.<region>.ingest.monitor.azure.com
Tawny__Sentinel__DcrImmutableId=dcr-00000000000000000000000000000000
Tawny__Sentinel__AlertStreamName=Custom-TawnyAlert_CL
Tawny__Sentinel__TelemetryStreamName=Custom-TawnyTelemetry_CL
Tawny__Sentinel__BatchSize=100
Tawny__Sentinel__MaxRetries=3
```

For managed identity, assign the identity to the Tawny API host, grant it the DCR role, and switch the auth mode:

```bash
Tawny__Sentinel__AuthenticationMode=managed_identity
Tawny__Sentinel__ClientId=<user-assigned-managed-identity-client-id-if-needed>
```

Telemetry ingestion is off by default because full agent telemetry can increase Azure Monitor ingestion cost quickly. Enable `TelemetryEnabled` only after the DCR/table schema is ready and you have chosen retention and cost controls.

Tawny records Sentinel alert delivery state on each alert row as `sent`, `failed`, `pending`, or `not_configured`. Telemetry batches are high-volume, so Tawny logs delivery failures with the agent ID and batch size instead of persisting per-event delivery state.

## Tawny SOC HTTP sink

The generic SOC sink posts snake-case JSON batches to one HTTP endpoint. Alert batches include related telemetry when available; telemetry batches forward raw stored event payloads. Configure the API directly with:

```bash
Tawny__TawnySoc__Enabled=true
Tawny__TawnySoc__AlertsEnabled=true
Tawny__TawnySoc__TelemetryEnabled=false
Tawny__TawnySoc__EndpointUrl=https://soc.example.com/api/ingest/tawny
Tawny__TawnySoc__ApiToken=replace-me
Tawny__TawnySoc__BatchSize=100
Tawny__TawnySoc__TimeoutSeconds=10
```

For Docker Compose, use the matching `TAWNY_SOC_*` variables. `ApiToken` becomes a bearer token and should come from the deployment secret store. Use HTTPS in production. Keep telemetry forwarding disabled until the downstream schema, data handling, retention, and ingest volume are approved.

Sample KQL:

```kql
TawnyAlert_CL
| where TimeGenerated > ago(24h)
| summarize Alerts=count() by AlertSeverity, AgentHostname
| order by Alerts desc
```

```kql
TawnyTelemetry_CL
| where TimeGenerated > ago(1h)
| summarize Events=count() by TelemetryEventType, AgentHostname
| order by Events desc
```
