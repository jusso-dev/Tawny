# Personal AI agent

Tawny ships a repo-scoped Codex skill at
`.agents/skills/tawny-personal-agent`. Codex discovers it when launched inside
the repository. Invoke it with:

```text
$tawny-personal-agent check the latest UniFi events against Tawny TI, show me a dry run, and prepare a five-minute cron entry
```

The skill delegates actions to a deterministic, dependency-free Python CLI.
Codex or a local model decides which command fits the request; the CLI owns API
authentication, indicator extraction, TI lookup, case payloads, and local
deduplication.

## UI-managed UniFi connector

The normal deployment path is now the Tawny dashboard:

1. In UniFi Network, open **Settings > Control Plane > Integrations**.
2. Create a local API key and open the API documentation generated for the
   installed Network application version.
3. Find a supported `GET` endpoint that returns the event records you want to
   match. Do not copy an undocumented browser route.
4. In Tawny, open **Integrations > UniFi Network** and enter:
   - **Controller URL**: the console's private IP, for example
     `https://192.168.1.1`.
   - **Events URL**: the full supported local API endpoint.
   - **API key header**: normally `X-API-Key`.
   - **API key**: stored encrypted and never returned after save.
   - **Records path**: dot-separated path to the response array, such as
     `data` or `result.events`; leave blank for a top-level array.
   - **Check every**: 1 to 1440 minutes.
5. Use **Save and test**. Tawny calls
   `/proxy/network/integration/v1/info` and records the installed Network
   application version.
6. Enable scheduled matching. A Hangfire job checks due connectors every
   minute. Successful event/indicator pairs are persisted and will not create
   duplicate Kelpie cases.

The API accepts only loopback or private-LAN IP destinations to limit
server-side request forgery. Keep TLS verification enabled when the console
certificate is trusted. For a self-signed local console, install its CA where
possible; disable verification only when that risk is understood.

UniFi OS 5.1.19 is new enough for the local integration info route, but it does
not identify the installed Network application version. Traffic Flows require
Network 9.1 or later and a supported gateway. If the version-specific local API
does not expose historical events or flows, use UniFi CEF/syslog or IPFIX export
instead of an undocumented UI endpoint.

## Configure

For Codex CLI, Hermes, or another local agent that should own the schedule
outside Tawny, create `~/.config/tawny-agent/config.json` and restrict it to
your user:

```json
{
  "tawny": {
    "base_url": "http://localhost:5080",
    "api_token": "twny_..."
  },
  "kelpie": {
    "base_url": "http://localhost:3001",
    "api_token": "..."
  },
  "unifi": {
    "base_url": "https://192.168.1.1",
    "events_url": "https://192.168.1.1/<version-specific-event-path>",
    "api_key": "...",
    "api_key_header": "X-API-Key",
    "verify_tls": true,
    "records_path": "data"
  },
  "state_path": "~/.local/state/tawny-agent/state.json"
}
```

```bash
chmod 0600 ~/.config/tawny-agent/config.json
```

Create the Tawny token from **Tokens**. Create a Kelpie token with
`cases:write`. If Kelpie also grants `cases:read`, future reconciliation can
recover deduplication state after local state loss.

Discover installed UniFi Network version:

```bash
python3 .agents/skills/tawny-personal-agent/scripts/tawny_agent.py \
  --config ~/.config/tawny-agent/config.json \
  unifi-info
```

## Run directly

```bash
python3 .agents/skills/tawny-personal-agent/scripts/tawny_agent.py \
  --config ~/.config/tawny-agent/config.json \
  ti-lookup 203.0.113.20 payload.example
```

```bash
python3 .agents/skills/tawny-personal-agent/scripts/tawny_agent.py \
  --config ~/.config/tawny-agent/config.json \
  unifi-hunt --dry-run
```

Remove `--dry-run` to create one detailed Kelpie case per new matching UniFi
event. Successful event/indicator pairs are recorded in the state file and are
not sent twice.

Generate, but do not install, a cron entry:

```bash
python3 .agents/skills/tawny-personal-agent/scripts/tawny_agent.py \
  --config ~/.config/tawny-agent/config.json \
  cron-command --schedule '*/5 * * * *'
```

Review the printed command before adding it with `crontab -e`. Keep model-driven
automation at this boundary: model may propose schedule and invoke supported
commands, but should not generate arbitrary privileged shell jobs.

## UniFi transport

UniFi Network exposes local API documentation for the installed version under
**Settings > Control Plane > Integrations**. Set `events_url` to a read endpoint
that returns a top-level array or an array beneath `records_path`.

The current official Network API covers sites, devices, clients, and traffic
usage, but a stable historical Traffic Flows pull endpoint is not guaranteed
across versions. UniFi documents IPFIX and syslog/CEF export for detailed flow
and system logs:

- [Getting Started with the Official UniFi API](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
- [Traffic Flows and Traffic Logging](https://help.ui.com/hc/en-us/articles/32201256219799-Traffic-Flows-and-Traffic-Logging-in-UniFi-Network)
- [System Logs and SIEM Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration)

For controllers without a supported event read endpoint, next connector should
consume local IPFIX or CEF rather than depend on an undocumented UI route. CLI
keeps URL and response path configurable so a supported version-specific local
endpoint can be used now.
