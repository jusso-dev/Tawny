# ISM mapping

This maps Tawny features to controls in the Australian Government Information Security Manual (ISM), **September 2026 release**. Each control ID and its wording was checked on 10-11-2026 against two sources: the September 2026 guideline pages on cyber.gov.au (`https://www.cyber.gov.au/ism/2026-09/…`) and ASD's OSCAL catalogue release `v2026.09.4` (`AustralianCyberSecurityCentre/ism-oscal`, "based on the September 2026 Information security manual"). No row below uses an ID that was not found in both.

"Supports" means Tawny gives you a way to meet part of the control. It does not mean Tawny meets the control for you: most of these also need process, configuration or coverage that Tawny does not provide. "Gap" says what is left.

## Event logging and centralised logging

| Control | Wording (short) | How Tawny supports it | Gap |
|---|---|---|---|
| ISM-0582 | Security-relevant events for Microsoft Windows are centrally logged. | The Windows agent forwards Sysmon (process, network, image load, file, registry, DNS), Security 4624, 4625, 4672, 4688, System 7045 and PowerShell 4104 to the server. | Only these event IDs. No AppLocker or WDAC, no group membership (4728, 4732, 4756), no Defender events. Hosts without an agent are not covered. |
| ISM-1977 | Security-relevant events for Linux are centrally logged. | The Linux agent sends process, network, DNS, file integrity, user and package inventory events. | No auditd or journald forwarding. |
| ISM-1976 | Security-relevant events for macOS are centrally logged. | The macOS agent sends process, network, file and user events. | No Endpoint Security framework or unified log forwarding. |
| ISM-1405 | A centralised event logging facility is implemented. | `tawny-server` with PostgreSQL stores telemetry from every agent, partitioned by month. | One server per deployment; sizing is for up to about 1,000 endpoints (target-edr section 18). |
| ISM-1983 | Event logs are sent to the central facility as soon as possible. | Agents send batches continuously, with a local spool when the server is unreachable. | Spooled events arrive late after an outage. |
| ISM-1984 | Event logs sent to the central facility are encrypted in transit with ASD-approved cryptography. | Agents talk to the server over HTTPS through the Caddy proxy (`docs/production.md`). | Cipher choice is the proxy's configuration; check it against the ISM cryptography guidelines. The compose network hop behind the proxy is plain HTTP. |
| ISM-1985 | Event logs are protected from unauthorised access. | Session and token authentication on every route, row-level security per tenant, and the admin, analyst and viewer roles (`docs/api.md`). | Database and backup access are protected by your hosting, not by Tawny. |
| ISM-1815 | Event logs are protected from unauthorised modification and deletion. | No API edits or deletes telemetry. Batches can be Ed25519 signed by the agent. The audit log is hash chained. | A database administrator can still change rows. Retention purges delete old telemetry (see below). |
| ISM-0988 | An accurate and consistent time source is used. | The server records `received_at` from its own clock and the agent's `occurred_at`, and tracks agent clock skew. | Time sync on hosts and the server is your configuration. |
| ISM-0585 | Each event captures date and time, user or process, filename, description and the equipment. | The v2 event envelope carries time, agent and host, process with entity id, user, and file path where the event has one (`schemas/events`). | Fields depend on the source event. |
| ISM-1959 | Event logs are captured and stored in a consistent, structured format. | One JSON schema per event type, versioned, with golden tests. | None known. |
| ISM-1623 | PowerShell module logging, script block logging and transcription events are centrally logged. | Script block events (4104) are collected and reassembled. | Module logging (4103) and transcription files are not collected. Script block logging must be turned on in Group Policy. |
| ISM-1509 | Privileged access events are centrally logged. | Security 4672 (special privileges for a new logon) and 4624 logons. | Only Windows, and only where the agent runs. |
| ISM-1650 | Privileged user account and security group management events are centrally logged. | | **Not supported.** The agent does not collect 4720, 4728, 4732 or 4756 yet. |

## Event log monitoring and incidents

| Control | Wording (short) | How Tawny supports it | Gap |
|---|---|---|---|
| ISM-0120 | Cyber security personnel have sufficient tools to detect events and identify incidents. | Rules (native, Sigma, IOC, sequence, threshold, YARA), hunts, process trees, incidents with an explained risk score, ATT&CK coverage. | Coverage depends on the rules you enable and the telemetry you collect. |
| ISM-0109 | Event logs from workstations are analysed in a timely manner. | Detection runs on every ingested event; alerts are grouped into incidents. Analysts triage in the UI. | Someone has to look. Tawny does not staff a SOC. |
| ISM-1228 | Cyber security events are analysed in a timely manner to identify incidents. | Incidents group related alerts by host, lineage and shared artefacts within 4 hours, and are sent to Tawny-SOC. | Grouping rules are fixed (target-edr section 8); tune them with exceptions. |
| ISM-2116 | Cyber threat intelligence services support detection. | Threat intel feeds become IOC rules; lookups and reputation enrichment on alerts. | Feed quality is the provider's. |
| ISM-0125 | A cyber security incident register is developed, implemented and maintained. | Tawny incidents can feed a register: each has status, owner, timeline and risk, and goes to Tawny-SOC. | Tawny's incidents are detection groups, not a register. Case management, reporting and lessons learnt live in Tawny-SOC or your own register. |

## Endpoint detection and response

| Control | Wording (short) | How Tawny supports it | Gap |
|---|---|---|---|
| ISM-1341 | A HIPS or EDR solution is implemented on workstations. | The Tawny agent on Windows, macOS and Linux workstations, with kill, suspend, quarantine and (Windows) isolation. | Detection is after execution; Tawny does not prevent execution (target-edr section 18, item 3). Isolation is Windows only. |
| ISM-1034 | A HIPS or EDR solution is implemented on critical servers and high-value servers. | The same agent on Windows and Linux servers. | Same as above. |
| ISM-1584 | Unprivileged users are prevented from bypassing, disabling or modifying security functionality. | The agent runs as LocalSystem or root, its service DACL and key protection are hardened, and tamper and silent-agent alerts are raised (`docs/production-agent-hardening.md`). | Tawny detects tampering; it cannot stop an administrator. |

## Event log retention

| Control | Wording (short) | How Tawny supports it | Gap |
|---|---|---|---|
| ISM-1988 | Event logs are retained in a searchable manner for at least 12 months. | Alerts are kept 365 days. Telemetry is backed up daily as gzip JSON lines to a local path or S3 (`TAWNY_BACKUP_*`). | **Partly met.** Raw telemetry in the database is purged after 30 days unless an alert references it. Backups are not searchable from Tawny. To meet the control, keep the backups for 12 months in a store you can search, or forward telemetry to a SIEM that keeps it. |

## Controls Tawny gives evidence for but does not implement

These are Essential Eight controls where Tawny's telemetry shows whether the control is working, but the control is configured elsewhere. See [essential-eight.md](essential-eight.md).

| Control | Wording (short) | What Tawny shows |
|---|---|---|
| ISM-0843 | Application control is implemented on workstations. | Nothing about enforcement. Tawny shows unsigned or new executables running, which application control should have stopped. |
| ISM-1660 | Allowed and blocked application control events are centrally logged. | **Not supported.** AppLocker and WDAC events are not collected. |
| ISM-1667 | Microsoft Office is blocked from creating child processes. | The built-in `office-spawns-shell` rule fires when Office starts a shell, which means the block is missing or bypassed. |
| ISM-1683 | Successful and unsuccessful MFA events are centrally logged. | **Not supported.** MFA events live in the identity provider. |
| ISM-1698, ISM-1807, ISM-1808 | Vulnerability scanning and asset discovery. | Agent inventory and OSV exposure for language packages only. Tawny is not a vulnerability scanner. |

## IDs not checked

None. Every ID above was found on the cyber.gov.au September 2026 pages and in OSCAL `v2026.09.4`. When the ISM is next released, check each row again: ASD amends and renumbers controls each quarter.
