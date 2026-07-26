---
name: tawny-personal-agent
description: Operate Tawny security automation through a deterministic local CLI. Use when Codex or another local AI agent needs to look up threat-intelligence indicators, inspect configured UniFi event API records, create detailed Kelpie cases for matches, or prepare a cron entry for a recurring UniFi hunt.
---

# Tawny personal agent

Keep model in planning role. Execute security actions through
`scripts/tawny_agent.py`; never construct ad-hoc Kelpie or Tawny API payloads when
script supports requested action.

## Workflow

1. Read `references/configuration.md` when setup, credentials, or UniFi transport
   needs work.
2. Use `unifi-info` to discover installed Network application version.
3. Use `ti-lookup` for explicit IP, domain, or hash questions.
4. Use `unifi-hunt --dry-run` first when user asks to check UniFi events.
5. Show dry-run match count and proposed cases. Run without `--dry-run` only
   when user asked to create cases.
6. Use `cron-command` to generate a cron line. Do not install or modify user
   crontab without explicit approval.

## Commands

Set script path relative to this skill:

```bash
python3 scripts/tawny_agent.py --config /path/to/config.json ti-lookup 203.0.113.20
python3 scripts/tawny_agent.py --config /path/to/config.json unifi-info
python3 scripts/tawny_agent.py --config /path/to/config.json unifi-hunt --dry-run
python3 scripts/tawny_agent.py --config /path/to/config.json unifi-hunt
python3 scripts/tawny_agent.py --config /path/to/config.json cron-command --schedule '*/5 * * * *'
```

Treat config and output as sensitive: they may contain internal IPs, hostnames,
domains, and security evidence. Never print API tokens.

## Guardrails

- Use HTTPS unless endpoint is loopback, private LAN, or trusted container DNS.
- Keep TLS verification enabled. Disable only for user-confirmed self-signed
  local controller.
- Let Tawny decide TI matches. Do not label indicator malicious from model
  judgment alone.
- Let CLI deduplicate UniFi event/indicator pairs before creating Kelpie cases.
- Keep UniFi event path configurable. Official UniFi API surface varies by
  Network version and does not guarantee historical flow-log pull.
