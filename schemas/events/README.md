# Event schemas

JSON Schemas (draft 2020-12) for telemetry. `envelope.v2.json` is the batch
body for `"schema": 2`; each `<type>.v1.json` is the `data` object of one
event type, using the common objects in `common.v1.json`
(docs/architecture/target-edr.md section 2.2).

`golden/` holds one example payload per type. Tests on both sides check the
golden payloads, and payloads the agent builds, against these files:
`agent/src/schema_check.zig` and `server/src/ingest/schema_check.zig`. The
checker covers `type`, `required`, `properties`, `items`, `enum`, `const`,
`anyOf`, `minLength`, `maxLength`, `minimum` and `$ref`. `pattern` and
`format` are documentation only.

P3 types keep their current payloads and have no schema yet:
`process_snapshot`, `network_snapshot`, `user_session`, `system_info`,
`file_integrity`, `file_event`, `package_inventory`, `editor_extension`,
`browser_extension`, `mcp_config`, `heartbeat`. Windows types without a
schema yet: `image_load`, `remote_thread`, `process_access`, `file_delete`,
`registry_create`, `registry_delete`, `registry_rename`, `user_logon_failed`,
`special_privileges`.
