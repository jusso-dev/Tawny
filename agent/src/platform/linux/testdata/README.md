# Linux audit samples

Records in the shape the kernel emits them, used by the parsing and mapping
tests in `../audit.zig` and `../tetragon.zig`. Hosts, users and addresses are
made up (documentation ranges); nothing here comes from a real machine.

- `netlink_exec_connect.txt`: netlink records as `<message type> <payload>`,
  one per line, as the agent reads them from `NETLINK_AUDIT`: an `execve` of
  `curl`, an IPv4 `connect`, a non-blocking IPv6 `connect` (`EINPROGRESS`),
  `exit_group`, and an unrelated AppArmor record.
- `audit.log`: auditd log lines (no `EOE` records, some with `node=` and the
  enriched `\x1d` suffix): a long split argument, `execveat` with only a
  `PROCTITLE`, a `connect`, two file creations (one under a `PARENT` path,
  one under the `CWD`) and an `exit_group`.
- `tetragon.jsonl`: Tetragon JSON export lines.
