# Linux kernel sensor: decision record (#59)

Status: accepted, November 2026.

## Problem

Linux telemetry came from a `/proc` diff every few seconds and non-recursive
inotify. A process that starts and exits between two polls is never seen, and
an outbound connection is only visible if it is still open at the next
`/proc/net` snapshot. The agent ran as the unprivileged `tawny` user with no
capabilities, so it could not read or signal other users' processes.

## Options

| Option | What it gives | Cost to run | Fit for Tawny |
|---|---|---|---|
| Tetragon (Cilium, Apache-2.0) | exec, exit, kprobe (`tcp_connect`) and file events with ancestry, JSON export to a file | a separate privileged daemon, kernel with BTF (most distros from 5.x), Helm or package install | good data, but a second privileged daemon to install, patch and watch |
| Falco (CNCF, Apache-2.0) | rule-driven syscall events, JSON to a file, HTTP or gRPC | a separate privileged daemon with the modern eBPF probe | its events are rule outputs, not a raw event stream, so mapping to our types needs Falco rules we would also have to ship |
| auditd netlink in the agent | `execve`, `execveat`, `connect`, `exit_group` and directory watches from the kernel audit subsystem | `CAP_AUDIT_READ` and `CAP_AUDIT_CONTROL`; only one process can own the audit socket, so it can clash with an existing auditd | no extra daemon, works on every kernel we support (3.x and later), and the record format is stable and documented |

## Decision

The agent reads the kernel audit subsystem itself over `NETLINK_AUDIT`
(`agent/src/platform/linux/audit.zig`). Tetragon is an optional second source:
when Tetragon is already installed and writing its JSON export, the agent can
tail that file instead (`agent/src/platform/linux/tetragon.zig`). Falco is not
used.

Why auditd netlink:

- Nothing else to install. The agent binary and its systemd unit are the whole
  footprint, which matters for the one-line installer.
- It works without BTF or eBPF, so older kernels and locked-down hosts still
  get kernel events.
- Records carry a per-event serial, so `SYSCALL`, `EXECVE`, `CWD`, `PATH` and
  `SOCKADDR` records join into one Tawny event without guessing.
- The capability cost is two capabilities, which the unit grants through
  `AmbientCapabilities=` while keeping `User=tawny` and `NoNewPrivileges`.

Costs we accept:

- Audit adds per-syscall overhead on the audited syscalls. The rules are kept
  narrow: native architecture only, `exit,always` on exec, connect (IPv4 and
  IPv6 only where the kernel supports `saddr_fam`) and `exit_group`, plus
  write watches on configured folders.
- 32-bit (compat) processes on a 64-bit kernel are not audited by these rules.
- If the agent is killed with `SIGKILL` its rules stay loaded until the next
  start, and the kernel logs those records to the kernel log meanwhile. A clean
  stop removes them.

## How the agent picks a source

`linux_sensor = auto` (the default) tries, in order:

1. Audit netlink as the audit daemon. No other daemon owns the socket: the
   agent registers itself, raises the backlog limit, and loads its rules (key
   `tawny`). `sensor_health` state `ok`, status `ok`.
2. Audit multicast. auditd already owns the socket: the agent joins the
   read-only multicast group with `CAP_AUDIT_READ` and sees whatever auditd's
   rules produce. It does not add or remove rules. Status `degraded`, because
   coverage depends on the host's audit rules.
3. The audit log (`audit_log_path`, default `/var/log/audit/audit.log`) when
   multicast is refused and the log is readable. Status `degraded`.
4. The Tetragon JSON export (`tetragon_export_path`) when it exists.
5. The `/proc` poller only. `sensor_health` status `degraded` with the reason.

`linux_sensor = audit`, `audit_log`, `tetragon` or `proc` forces one source. With a kernel
source running, the `/proc` poller stays on as a reconciliation pass every 10
minutes; without one it keeps its normal interval.

## What is tested where

- Record parsing, the serial join and mapping to `process_start`,
  `process_exit`, `network_connect` and `file_create` are pure functions with
  captured records under `agent/src/platform/linux/testdata/`. They run on
  every OS in `zig build test`.
- Kernel constants (message types, field ids, netlink family, syscall numbers)
  have a pin test against `linux/audit.h`.
- CI `agent (linux-x64)` runs the agent's sensor dump with exactly the unit's
  capabilities through `sudo setpriv`, runs `/bin/true` 50 times and expects at
  least 50 `process_start` events. It also runs the dump with no capabilities
  and expects the degraded fallback.
- Docker containers (including OrbStack) refuse audit netlink because the
  container is not in the initial PID namespace, so live audit is only proved
  on the CI VM.

## Not in this change

- nftables host isolation (`isolate_host` on Linux) is a follow-up. The agent
  still answers "isolate_host is not supported on linux yet".
- fanotify file events and eBPF in the agent itself.
- Falco.
