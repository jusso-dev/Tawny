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

Service uses restricted virtual service account `NT SERVICE\TawnyAgent`, delayed
automatic start, service-SID isolation, bounded restart policy, protected config,
and separate writable state directory. Validate:

```powershell
Get-Service TawnyAgent
sc.exe qc TawnyAgent
sc.exe qsidtype TawnyAgent
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddMinutes(-15)}
```

Confirm EDR policy does not quarantine approved binary and that service account
can read each intended FIM path. Add narrow ACL entries per path when needed.

## macOS

Installer registers root-owned system LaunchDaemon with restrictive file modes,
umask, restart throttling, and preserved configuration. Agent remains root on
macOS because launchd offers no systemd-equivalent filesystem sandbox and
unprivileged process visibility is incomplete. Deploy only after endpoint
threat-model approval.

```bash
sudo launchctl print system/dev.jusso.tawny-agent
sudo tail -n 100 "/Library/Application Support/Tawny/agent.err"
sudo plutil -lint /Library/LaunchDaemons/dev.jusso.tawny-agent.plist
```

For a developer workstation where a system daemon is not appropriate, `--user`
installs a LaunchAgent under the current account with configuration in
`~/.config/tawny` and mutable state in `~/.local/state/tawny`. Do not use this
reduced-visibility mode for production SOC coverage.

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
retention review, then remove program files.

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
