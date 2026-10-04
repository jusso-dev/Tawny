# Production agent hardening

Native installation is recommended for EC2 and other SOC-monitored hosts. A
container sees its own namespaces by default and cannot provide complete host
process, user, socket, or file-integrity telemetry without broad host mounts and
privileges.

## Release trust policy

Production installs must satisfy both controls:

1. Match the release asset against its SHA-256 sidecar or `SHA256SUMS`.
2. Verify GitHub build provenance:

   ```bash
   gh attestation verify tawny-agent-<version>-<platform> \
     --repo jusso-dev/Tawny
   ```

Tagged release workflows verify the pinned Zig toolchain, generate checksums,
and publish GitHub artifact attestations. GitHub Actions dependencies are pinned
to immutable commits. The installers fail closed when the checksum is missing
or invalid and require attestation verification by default. Treat
`--skip-attestation`/`-SkipAttestation` as a documented, time-bounded exception,
not a normal install option.

Keep a copy of each approved binary, `SHA256SUMS`, release tag, attestation
verification output, and deployment approval in the SOC change record.

## Linux and EC2

Prerequisites: root, `curl`, Python 3, GitHub CLI, systemd, and outbound HTTPS to
the Tawny backend, GitHub API/releases, and Sigstore services used by GitHub
attestation verification.

```bash
sudo ./install.sh \
  --backend-url https://tawny.example.com \
  --enrollment-token "$TAWNY_ENROLLMENT_TOKEN"
```

Installer creates locked `tawny` system user, root-owned configuration readable
by that group, writable `/var/lib/tawny`, and hardened systemd unit. Mutable
identity state is stored separately at `/var/lib/tawny/state.toml`; `/etc/tawny`
remains read-only to agent. Existing configuration survives upgrades. Previous binary remains at
`/usr/local/tawny/tawny-agent.previous`.

Because `/etc/tawny` is read-only to the agent, it cannot delete the spent
`enrollment_token` itself; after enrollment it never resends the token and logs
a warning on each start until an operator removes the line:
`sudo sed -i '/^[[:space:]]*enrollment_token[[:space:]]*=/d' /etc/tawny/config.toml`.

Before broad rollout, validate on each AMI family:

```bash
sudo systemctl is-active tawny-agent
sudo systemctl status tawny-agent --no-pager
sudo journalctl -u tawny-agent --since=-15m --no-pager
sudo systemd-analyze security tawny-agent.service
sudo -u tawny test -r /proc/1/status
sudo -u tawny test -r /etc/hosts
```

Linux kernels mounted with `hidepid`, SELinux/AppArmor policy, or restrictive
file permissions can reduce process and FIM visibility for the unprivileged
service. Grant only the specific read access required by the agreed collection
scope; do not switch to root without a documented threat-model decision.

Use an instance role and IMDSv2-required EC2 metadata options. Do not place AWS
access keys in agent config or service environment. Restrict backend egress with
security groups, Network Firewall, or an authenticated proxy. Keep host time
synchronized and alert on repeated service restarts, stale heartbeats, queue
growth, and enrollment failures.

## Windows

Run elevated PowerShell:

```powershell
. .\install.ps1
Install-TawnyAgent `
  -BackendUrl https://tawny.example.com `
  -EnrollmentToken $env:TAWNY_ENROLLMENT_TOKEN
```

Service runs as `LocalSystem` (required for ETW kernel trace sessions and
Security event log access), with delayed automatic start, an unrestricted
service SID, a bounded restart policy (`restart/5s`, `restart/15s`,
`restart/60s`, reset after 24h, `failureflag 1` so a non-zero service exit also
triggers restart), and the `TAWNY_CONFIG`/`TAWNY_STATE_PATH` service
environment. The binary registers with the Service Control Manager via
`StartServiceCtrlDispatcherW`, reports `SERVICE_RUNNING`, and exits cleanly on
stop, shutdown, and pre-shutdown controls. Run interactively (not via the SCM)
it falls back to console mode.

Because LocalSystem is fully privileged, filesystem hardening carries the
isolation:

- `%ProgramFiles%\Tawny`, `%ProgramData%\Tawny` (config) and the state
  directory have inheritance removed and grant Full Control only to `SYSTEM`
  and `Administrators`. No other principal can write, and config/state
  (enrollment token, agent JWT, device key, spool) are readable only by those
  two principals.
- Upgrades from the earlier `NT SERVICE\TawnyAgent` virtual-account install
  switch the service to LocalSystem, set the SID type to `unrestricted`, and
  strip the legacy virtual-account ACEs from the install, config, and state
  trees.
- After successful enrollment the agent atomically rewrites `config.toml`
  (temp file + rename, inheriting the protected directory ACL) to delete the
  spent `enrollment_token` line. If the rewrite fails, the agent logs a warning;
  remove the line manually.

Validate:

```powershell
Get-Service TawnyAgent
sc.exe qc TawnyAgent            # SERVICE_START_NAME : LocalSystem
sc.exe qsidtype TawnyAgent      # SERVICE_SID_TYPE: UNRESTRICTED
sc.exe qfailure TawnyAgent
icacls "$env:ProgramData\Tawny"  # only NT AUTHORITY\SYSTEM and BUILTIN\Administrators
Select-String -Path "$env:ProgramData\Tawny\config.toml" -Pattern enrollment_token  # no match after enrollment
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=(Get-Date).AddMinutes(-15)}
```

Confirm EDR policy does not quarantine approved binary. LocalSystem can read
all local FIM paths, so no per-path ACL grants are needed.

## macOS

Installer registers root-owned system LaunchDaemon with restrictive file modes,
umask, restart throttling, and preserved configuration. Agent remains root on
macOS because launchd offers no systemd-equivalent filesystem sandbox and
unprivileged process visibility is incomplete. Deploy only after endpoint
threat-model approval.

LaunchDaemon settings and why:

| Key | Value | Reason |
| --- | --- | --- |
| user | root (implicit) | Process and socket visibility across all users. |
| `KeepAlive` | `true` | Restart after any exit, including a stray `SIGTERM`; `launchctl bootout` still stops it. |
| `ThrottleInterval` | `10` | At most one restart every 10 s on a crash loop. |
| `ProcessType` | `Standard` | `Background` adds CPU, I/O and timer throttling that delays collection. |
| `LowPriorityIO` | unset (off) | Spool writes must not be starved; collection intervals already bound disk use. |
| `Umask` | `63` (`077`) | Everything the agent creates is owner-only. |
| `SessionCreate` | `false` | No security session needed; the System keychain is reachable without one. |
| `ExitTimeOut` | `30` | Time to flush before `SIGKILL` on stop. |
| `StandardOutPath` / `StandardErrorPath` | `/Library/Logs/Tawny/agent.log` | Pre-created `root:wheel 0600` in a `0700` directory. |

File ownership: the plist is `root:wheel 0644`, `/usr/local/tawny` and the
binary are `root:wheel 0755`, and the config/state directory
`/Library/Application Support/Tawny` is `root:wheel 0700` with `config.toml`
`0600`. The agent JWT and device seed are stored in the System keychain, not
in `state.toml` (see `production.md`, "Where the agent keeps its secrets").

```bash
sudo launchctl print system/dev.jusso.tawny-agent
sudo tail -n 100 /Library/Logs/Tawny/agent.log
sudo plutil -lint /Library/LaunchDaemons/dev.jusso.tawny-agent.plist
sudo security find-generic-password -s dev.jusso.tawny-agent -a agent-jwt /Library/Keychains/System.keychain  # attributes only
grep -c agent_jwt "/Library/Application Support/Tawny/state.toml"  # 0 once migrated
```

`./install.sh --dry-run` prints the generated plist (validated with
`plutil -lint`) without touching the host.

For a developer workstation where a system daemon is not appropriate, `--user`
installs a LaunchAgent under the current account with configuration in
`~/.config/tawny`, mutable state in `~/.local/state/tawny`, logs in
`~/Library/Logs/Tawny/agent.log`, and secrets in the login keychain. Do not use
this reduced-visibility mode for production SOC coverage.

### macOS telemetry sources

All collection is user mode (no Endpoint Security, no kernel extension):

| Event | Source |
| --- | --- |
| `process_snapshot` | libproc (`proc_listallpids`, `proc_pidinfo`, `proc_pidpath`) + `KERN_PROCARGS2` for full argv |
| `process_launch` | 5 s libproc diff keyed on pid + start time (very short-lived processes can be missed) |
| `network_snapshot` | libproc socket enumeration with owning `pid`/`process_name`; ARP neighbors, resolvers |
| `file_event` | FSEvents (recursive) on the configured watch paths |
| `dns_query` | `log stream` of the `com.apple.mDNSResponder` subsystem; network lookups only (cached answers are not logged), no response IPs |

macOS redacts DNS query names in the unified log as `<private>` by default.
`install.sh --enable-macos-dns-logging` writes (or merges into)
`/Library/Preferences/Logging/Subsystems/com.apple.mDNSResponder.plist`
setting `Enable-Private-Data` and `Info` level for that one subsystem only — not
the system-wide private-data switch. This makes DNS names visible to anyone who
can read the unified log on that Mac (admins), so treat it as a privacy decision
and prefer deploying the same profile via MDM. Without it the DNS collector
detects redaction, stays idle and retries hourly. To revert, delete that plist.

macOS upgrades: keychain items are readable only by the exact ad-hoc signed
build that created them, so the installer stops the job and runs the current
binary with `--export-credentials` before swapping binaries (and the new one
before a rollback). Replace the binary only through `install.sh`; otherwise
run `<old binary> --export-credentials` (with the job's `TAWNY_CONFIG` and
`TAWNY_STATE_PATH`) first, or re-enroll.

## Upgrade, rollback, and uninstall

Re-run same installer with new release asset. It stages download on same
filesystem, verifies checksum and provenance before replacement, retains existing
config, restarts service, and restores prior binary if service activation fails.
When the configured path already contains a config file, enrollment URL and token
are not required and are never rewritten:

```bash
# Linux/macOS system install: fetch and verify the latest release.
sudo ./install.sh

# Existing macOS user install.
./install.sh --user
```

An approved binary can also be reinstalled without release-network access.
Supply its recorded checksum; attestation verification remains enabled:

```bash
sudo ./install.sh \
  --binary-path /secure/change-record/tawny-agent-linux-x64 \
  --sha256 "$APPROVED_SHA256"
```

Use `--skip-attestation` only for a documented source-build recovery where no
GitHub attestation exists. Windows upgrades follow the same rules: omit
`-BackendUrl` and `-EnrollmentToken` when the config exists, and use
`-LocalBinaryPath` with `-Sha256` for a pinned local artifact.

Manual Linux rollback:

```bash
sudo systemctl stop tawny-agent
sudo mv /usr/local/tawny/tawny-agent.previous /usr/local/tawny/tawny-agent
sudo systemctl start tawny-agent
```

Uninstall service and binary while preserving forensic state:

```bash
sudo systemctl disable --now tawny-agent
sudo rm /etc/systemd/system/tawny-agent.service
sudo systemctl daemon-reload
sudo rm /usr/local/tawny/tawny-agent /usr/local/tawny/tawny-agent.previous
```

Archive then remove `/etc/tawny` and `/var/lib/tawny` only after retention and
incident-response requirements are met. Remove `tawny` account only after
confirming no files or ACLs still reference it. Equivalent Windows/macOS removal
must stop and delete service registration first, preserve config/spool for
retention review, then remove program files. On macOS also delete the
`dev.jusso.tawny-agent` keychain items (`agent-jwt`, `device-seed`) with
`security delete-generic-password`, as shown in `production.md`.

## Rollout gate

Canary one host per OS/AMI. Require valid attestation, successful enrollment,
healthy service after reboot, expected host identity, expected IP/domain/process
coverage, bounded CPU/RAM/disk/network use under peak load, spool recovery after
backend outage, and no secrets in logs. Expand gradually with automatic rollback
criteria and SOC ownership for heartbeat and upgrade alerts.

## Known residual risk

Response actions do not yet have durable lease, execution journal, or explicit
agent acknowledgement semantics. Backend can mark an action `Dispatched` before
host execution; agent crash or network loss can therefore leave outcome unknown.
Until protocol adds leased delivery, idempotency keys, durable agent journal, and
result acknowledgement, treat response actions as operator-supervised and verify
effect independently on host.

Telemetry `client_event_id` provides retry deduplication; monitor rejected or
duplicate batches during outage recovery. Production backend and SOC sink URLs
must use HTTPS. Plain HTTP escape hatches exist only for isolated development and
must not appear in production service definitions.
