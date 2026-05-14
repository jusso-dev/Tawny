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
