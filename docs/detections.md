# Detection rules: how matching works

A rule (format `tawny_predicate` or `ioc`) has an event type, a field path, an operator and a value. A suppression has the same three match fields. The detect job (`server/src/jobs/detect.zig`) parses each event payload once and checks every enabled rule for that event type against it. The matcher is `server/src/detect/match.zig`.

## Operators

| Operator | Matches when |
| --- | --- |
| `exists` | the field is present and not `null` |
| `equals` | the field equals the value. Text compares without case. Numbers compare as numbers, so `7` equals `7.0`. |
| `contains` | the field contains the value, without case |
| `startswith` | the field starts with the value, without case |
| `endswith` | the field ends with the value, without case |
| `greater_than` | the field is a number (or numeric text) above the value. Fails when the value isn't a number. |
| `less_than` | the same, below the value |

## Paths

Paths are dotted keys into the payload, for example `processes.name` or `connections.remote_address`.

When a path step reaches an array, every element is tried, and the rule matches if any element matches. So `processes.name equals cmd.exe` matches `{"processes":[{"name":"x"},{"name":"CMD.EXE"}]}`.

A rule only looks at the field its path names. It never searches the rest of the payload. `processes.name equals cmd.exe` does not match `{"processes":[{"name":"x","command_line":"cmd.exe /c"}]}`.

## Rules that can't be evaluated

A rule with no path, an empty path, an unknown operator, or no value (for any operator except `exists`) is skipped, and the detect job logs a line naming the rule. The API refuses to create such a rule, but older rows and imported Sigma rules with several selections can still have no path.

## Suppressions

A suppression is scoped to one rule or to all rules, and optionally to one agent. With no path it hides every alert in that scope. With a path it hides an alert only when its own field matches. A suppression for `processes.user equals svc-backup` doesn't hide an alert for another user whose command line happens to mention `svc-backup`.

## Sigma rules

`POST /api/alert-rules/sigma` compiles the rule with `server/src/detect/sigma.zig` and stores the result in `compiled_expression_json`. The detect job evaluates that tree with the same path and fan-out rules as above. The YAML stays in `source_definition`.

- Fields are mapped by `rules/sigma/field-map.yaml` (`Image` to `process.image`, `CommandLine` to `process.command_line`, `User` to `process.user.domain` and `process.user.name` joined with `\`, and so on). A dotted name that is not a Sigma field, like `processes.name`, is used as a Tawny path as it is, with a note.
- The logsource picks the event type (`category: process_creation` gives `process_start`; `service: security` uses the rule's `EventID`).
- Conditions: `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them`, and lists of conditions.
- Selections: maps (all fields must match), lists of maps (any map), and keyword lists. Keyword lists match the logsource's keyword field only (`process.command_line`, or `script_block.text` for `ps_script`), never the whole payload.
- Modifiers: `contains`, `startswith`, `endswith`, `all`, `re` (with `|i`), `cidr`, `base64`, `base64offset`, `wide`, `windash`, `exists`, `cased`, `gt`, `gte`, `lt`, `lte`. Values support `*` and `?` wildcards with `\*`, `\?` and `\\` escapes.
- `re` runs on a linear-time engine (`server/src/detect/regex.zig`) with a step limit. Backreferences, lookaround, atomic groups, possessive quantifiers, Unicode classes and inline flags other than a leading `(?i)` are refused.
- Anything else (an unmapped field, logsource or modifier, `N of` with N above 1, aggregations, `timeframe`, correlation rules) rejects the whole rule with a reason. A rule is never partly applied.
- A stored rule has `compile_status` `supported` or `supported_with_notes`, and `compile_notes`.

Counts for the pinned SigmaHQ snapshot are in `docs/sigma-compatibility.md`.

## Sequence and threshold rules

See `rules/README.md` for the format and the built-in rules.

## Change from earlier builds

Before #53, a rule that didn't match by path fell back to a text search of the whole payload, and every operator behaved like "contains anywhere". Rules that leaned on that now need the right path. Before #56, Sigma imports kept one field and mapped `Image` to `processes.name`. Sigma rules are now compiled whole against the schema v2 fields. Sigma rows imported before #56 have no compiled expression and still run their single stored predicate; import them again to compile them.
