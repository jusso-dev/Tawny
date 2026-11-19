# Release notes

Decisions that change or freeze behavior relative to the .NET server.

- Sequence rule `group_by` stays ignored, matching `SequenceRuleEvaluator`. Progress is stored in `sequence_state`, so a partial sequence survives a process restart.
- Detection does not run inside ingest. Ingest validates, stores, enqueues, and returns 202. A worker creates alerts and enqueues sink delivery.
- `GET /api/releases/latest?platform=` is served for a session or a `twny_` API token. The .NET server documented this path and did not implement it. Agent JWTs do not call it; heartbeat still carries the latest build for that agent.
- Hunt queries accept a leading `AND` or `OR` after a consumed directive (`event_type:`, `last:`, `from:`, `to:`, `agent:`, `agent_id:`), a `/...` value such as `path:/etc/`, and a dotted name inside a list (`cmd.exe`) as one value. Those are the starter queries in the hunt page.
- Compose is PostgreSQL, `tawny-server`, and Caddy. Caddy terminates TLS. The optional agent profile uses HTTP on the compose network with `allow_insecure_http`. WAN agents still require HTTPS.
- Agents enroll with a real `os_version` (Windows `major.minor.build` via `RtlGetVersion`, macOS `kern.osproductversion`, Linux kernel release) instead of the hard-coded `unknown`, matching the documented enroll payload. The agents table now shows per-endpoint OS builds — the fleet fact Windows endpoint security platform (WESP) eligibility on Windows 11 depends on ([windows-endpoint-security-platform.md](windows-endpoint-security-platform.md)). Agents enrolled earlier keep their stored value until they re-enroll; heartbeat does not rewrite identity facts.
