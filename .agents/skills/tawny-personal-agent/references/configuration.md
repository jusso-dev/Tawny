# Configuration

Create a user-readable-only JSON file:

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

Tawny token needs read access and calls
`POST /api/threat-intel/lookup`. Kelpie token needs `cases:write`.

`events_url` must return either a top-level JSON array or an object containing
an array at `records_path`. Dot-separated paths work, for example
`result.events`.

`unifi-info` calls
`<base_url>/proxy/network/integration/v1/info` and returns installed Network
application version. UniFi OS 5.0.3 or newer supports this connector route.

UniFi local API paths differ across Network releases. Find exact read endpoint
in UniFi Network under **Settings > Control Plane > Integrations**. Current
official API documents site, device, client, and usage reads, but detailed
historical flow logs may require IPFIX or syslog export instead. Never guess an
undocumented path.

For a self-signed local console, prefer installing its CA certificate. Use
`"verify_tls": false` only when user accepts local interception risk.
