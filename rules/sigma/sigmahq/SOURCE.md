# SigmaHQ snapshot

- Upstream: https://github.com/SigmaHQ/sigma
- Commit: `53b90df66c5b6d1b9be6ba9289c56fe49dd74a73` (committed 2026-11-07), also in `COMMIT`
- Fetched: `curl https://codeload.github.com/SigmaHQ/sigma/tar.gz/<commit>` on 10-11-2026
- Contents: `rules/windows/process_creation/` only (1193 rules), unmodified
- Licence: the rules are under the Detection Rule License (DRL) 1.1. The text is in
  `LICENSE.Detection.Rules.md`, from https://github.com/SigmaHQ/Detection-Rule-License
  at commit `bcbdc605172d00390572cd774ba395ec9e975dfc`. The upstream repository `LICENSE` is kept as `LICENSE`.

DRL 1.1 asks that shared rules keep the author and a link to the rule set, and
that messages based on a rule match keep the author. Each rule file keeps its
`author` field. When a Sigma rule is imported, Tawny keeps the YAML in
`source_definition` and adds the author to the rule description, which alerts
link to.

These files are test data for the compatibility check
(`server/src/detect/sigma_compat.zig`, report in `docs/sigma-compatibility.md`).
They are not loaded into any tenant.

To update: pick a new commit, replace `rules/windows/process_creation/` from that
tarball, update `COMMIT` and this file, run the compatibility check, and update
`baseline-supported.txt` if the supported count changes on purpose.
