# Tawny rules

- `sigma/field-map.yaml`: Sigma field and logsource map used by the Sigma compiler (`server/src/detect/sigma.zig`).
- `sigma/sigmahq/`: pinned SigmaHQ snapshot for the compatibility check (`docs/sigma-compatibility.md`). Test data only.
- `builtin/`: rules seeded into every tenant (format below).

The server embeds copies of `sigma/field-map.yaml` (`server/src/detect/sigma-field-map.yaml`) and `builtin/` (`server/src/detect/builtin/`), because Zig can only embed files inside the package. Tests fail when a copy differs, so edit both.

## Tawny rule format

A Tawny rule is a YAML file with a `kind`. Selections (`where`) use the Sigma selection syntax: a map of fields that must all match, or a list of maps where any one matches. Field names are Sigma names from `sigma/field-map.yaml` (`Image`, `CommandLine`, `TargetUserName`, `IpAddress`, ...) or Tawny dotted paths (`process.image`, `network.direction`). Sigma value modifiers work (`|contains`, `|endswith`, `|windash`, `|re`, `|cidr`, ...). A rule that uses anything the compiler doesn't support is refused whole.

Common keys:

| Key | Meaning |
| --- | --- |
| `id` | Stable id. Built-ins start with `tawny-builtin:`. |
| `title`, `description` | Shown on the rule and on alerts. |
| `kind` | `atomic`, `sequence` or `threshold`. |
| `level` | `low`, `medium`, `high` or `critical` (`informational` is stored as `low`). |
| `tags` | `attack.tNNNN` tags become MITRE technique ids. |

### `kind: atomic`

One event matches one selection.

```yaml
kind: atomic
event_type: service_create
where:
  ImagePath|contains: ['\Users\', '\Temp\']
```

### `kind: sequence`

Ordered steps for the same `by` key inside `within`.

```yaml
kind: sequence
by: TargetUserName        # or a list of up to 4 fields; agent_id is the agent
within: 10m               # s, m or h; at most 24h, counted from the first event
steps:                    # 2 to 8 steps
  - name: failures
    event_type: user_logon_failed
    count: 5              # matches needed before the next step (default 1)
  - name: success
    event_type: user_logon
    where: {LogonType: 10}
    by: TargetUserName    # optional per-step key fields, same number as the rule's
```

- Each event moves a sequence at most one step. Steps are checked from last to first, so one event can't both start and finish a sequence.
- The window runs on event time (`occurred_at`), not on arrival time.
- When the last step matches, one alert is raised on that event and the state for the key is cleared. The alert description lists the event ids.
- An event with no value for a `by` field is ignored by that rule.

State is in `sequence_state` (one row per rule and key, with `expires_at`), so it survives a restart.

### `kind: threshold`

Count matching events per `by` key in a sliding window.

```yaml
kind: threshold
event_type: user_logon_failed
by: IpAddress
window: 5m                # at most 24h
min: 21                   # fires when the count reaches this (at least 2)
distinct: TargetUserName  # optional: count distinct values of this field instead
where: {LogonType: 3}     # optional
```

Every matching event is a row in `threshold_counters`, so the window slides exactly and survives a restart. When the rule fires, the rows for that key are cleared, so a burst raises one alert and the count starts again.

The daily purge job deletes sequence state and counters an hour after they expire.

## Built-in rules

| File | Kind | What it finds |
| --- | --- | --- |
| `failed-logons-then-success.yml` | sequence | 5 failed logons (4625) then a success (4624) for the same user within 10 minutes |
| `failed-logons-from-one-ip.yml` | threshold | more than 20 failed logons from one IP in 5 minutes |
| `office-spawns-shell.yml` | atomic | an Office app starting `powershell.exe`, `pwsh.exe` or `cmd.exe` |
| `service-in-user-writable-folder.yml` | atomic | a new service (7045) whose image path is in a user-writable folder |
| `encoded-powershell-then-connect.yml` | sequence | PowerShell with `-enc` (and short forms) then an outbound connection from the same process entity |

The server seeds them into every tenant on its first job pass and whenever the tenant count changes (`server/src/detect/builtin.zig`). A tenant that disables or edits a built-in keeps the change. A deleted built-in comes back, so disable it instead.

Fixture tests in `server/src/detect/correlation_test.zig` fire each built-in once and check that near misses do not fire.
