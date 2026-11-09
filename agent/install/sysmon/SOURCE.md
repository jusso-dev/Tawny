# Sysmon configuration source

`sysmonconfig.xml` is a byte-for-byte copy of an upstream build. Tawny has not
edited it.

| | |
|---|---|
| Upstream repository | https://github.com/olafhartong/sysmon-modular |
| Commit | `a45dedb13a43c0d8ea1fc6b580a0ac396fa74457` (committed 14-10-2026) |
| Release asset | `sysmonconfig-with-filedelete.xml` from release `configs-a45dedb13a43` |
| SHA-256 | `a7832f4423aae16e39342e08f3a2962291eafb7972eb9dfb070009781fde50d9` (matches the release `SHA256SUMS`) |
| Schema | `4.91` (Sysmon 15.x) |
| Licence | MIT, copied in `LICENSE-sysmon-modular.md` (upstream `license.md` at the same commit) |

## Why this variant

The `with-filedelete` build is the default `sysmonconfig.xml` plus event 23
(file delete archived) rules. It has rule groups for every event ID the Tawny
agent maps:

| Event ID | Sysmon event | Upstream rule mode |
|---|---|---|
| 1 | ProcessCreate | include and exclude groups |
| 3 | NetworkConnect | include and exclude groups |
| 5 | ProcessTerminate | include only, limited to security tools (Defender, MDE) being stopped |
| 7 | ImageLoad | include only, filtered to a short list of DLLs |
| 8 | CreateRemoteThread | include and exclude groups |
| 10 | ProcessAccess | include and exclude groups |
| 11 | FileCreate | include and exclude groups |
| 12, 13, 14 | RegistryEvent | include and exclude groups |
| 22 | DnsQuery | exclude only (everything else is logged) |
| 23 | FileDelete | include and exclude groups (archives deleted executables to `C:\Sysmon`) |
| 26 | FileDeleteDetected | include and exclude groups |

Event 5 is narrow by upstream design. Process exit for every process is not
logged with this config. Change the `ProcessTerminate` group to
`onmatch="exclude"` with no rules if you need it, and expect more volume.

`HashAlgorithms` is `*` (MD5, SHA1, SHA256, IMPHASH), so `process.hashes`
carries all four.

## Updating

1. Pick a newer `configs-<sha>` release in olafhartong/sysmon-modular.
2. Download `sysmonconfig-with-filedelete.xml` and `SHA256SUMS`, check the hash.
3. Replace `sysmonconfig.xml`, update the commit, release and hash above, and
   check the licence file has not changed.
4. Re-run `install.ps1 -InstallSysmon` on a test host and confirm
   `Sysmon64.exe -c` shows the new configuration hash.

## Not included

No Sysmon binary is in this repository. The Sysinternals licence restricts
redistribution. `install.ps1 -InstallSysmon` downloads `Sysmon.zip` from
`https://download.sysinternals.com/files/Sysmon.zip` at install time and checks
that the Authenticode signature is valid and from Microsoft Corporation before
running it.
