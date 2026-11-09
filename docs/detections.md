# Detection rules: how matching works

A rule (format `tawny_predicate`, `sigma` or `ioc`) has an event type, a field path, an operator and a value. A suppression has the same three match fields. The detect job (`server/src/jobs/detect.zig`) parses each event payload once and checks every enabled rule for that event type against it. The matcher is `server/src/detect/match.zig`.

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

## Change from earlier builds

Before #53, a rule that didn't match by path fell back to a text search of the whole payload, and every operator behaved like "contains anywhere". Rules that leaned on that now need the right path. Sigma imports map `Image` to `processes.name`, so a Sigma rule for a full image path with `equals` won't match a bare process name. The Sigma compiler in #56 replaces that mapping.
