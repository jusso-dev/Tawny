# Essential Eight: what Tawny shows and what it does not

The Essential Eight are eight mitigation strategies from the Australian Signals Directorate. Most of them are controls you configure on endpoints and in your directory: application control, macro settings, patching, admin rights, MFA, backups. Tawny does not configure or enforce any of them. Tawny is an endpoint detection and response tool: it collects telemetry, raises alerts and incidents, and can kill a process, quarantine a file or isolate a Windows host when asked.

So for each strategy this page says what evidence Tawny can give you that the control is working or being bypassed, and what it cannot. Use it to plan; do not use it as an assessment. A maturity level is reached by implementing the controls in the [Essential Eight Maturity Model](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model), not by running Tawny.

Telemetry below means what the agent sends today (`agent/src/collectors/`, `schemas/events/`). Windows detail comes from Sysmon and the Security, System and PowerShell logs; without Sysmon, Windows process telemetry comes from Security 4688 only.

## 1. Application control

**Tawny is not an application control product.** It does not stop anything from running. It sees programs after they start.

What Tawny shows:

- Every process start with image path, command line, parent, user and hashes (Sysmon 1, Security 4688, the Linux and macOS process collectors).
- Image loads with signature status and signer (Sysmon 7).
- Files written to user profiles and temp folders (Sysmon 11), and new services (System 7045), including the built-in rule for a service in a user-writable folder.
- Hunts and rules for programs running from user profiles or temporary folders, unsigned images, or a hash not seen before in the fleet.
- After the fact, `kill_process` and `quarantine_file`.

What Tawny does not do:

- Block execution, enforce an allow list or apply Microsoft's recommended block rules. Use WDAC (App Control for Business) or AppLocker for that.
- Collect AppLocker or WDAC events today. It cannot show which executions your application control allowed or blocked.
- Check application control on servers it has no agent on.

## 2. Patch applications

What Tawny shows:

- `package_inventory`: language and developer packages (npm, pnpm, yarn, bun, Go, RubyGems, Composer, PyPI) found on the host, and OSV exposure for them through the package exposure rules and feeds (`docs/detections.md`).
- Browser and editor extensions, and MCP configuration.

What Tawny does not show:

- Installed desktop applications and their versions (Office, browsers, PDF readers) from Windows Installer, the Store or macOS app bundles.
- Missing vendor patches. Tawny is not a vulnerability scanner and does not match installed software to CVEs outside the package ecosystems above.
- Whether an update was installed within the time the maturity level asks for.

## 3. Configure Microsoft Office macro settings

What Tawny shows:

- Office applications starting PowerShell or cmd (built-in rule `office-spawns-shell`), and Office children in general through hunts.
- Files Office writes, and network connections from Office processes (Sysmon 3 and 11).

What Tawny does not show:

- The macro settings themselves (Group Policy or Intune), whether macros from the internet are blocked, or Trusted Locations.
- Office's own macro events or macro antivirus scanning results.

## 4. User application hardening

What Tawny shows:

- Browser extensions installed per user.
- PowerShell script block logging events (4104), reassembled, when script block logging is on.
- Children of browsers and PDF readers through process lineage.

What Tawny does not show:

- Browser, Office and PDF reader configuration, or whether ASD hardening guidance has been applied.
- Whether PowerShell 2.0 is removed or Constrained Language Mode is set.
- .NET Framework, Java or IE status.

## 5. Restrict administrative privileges

What Tawny shows:

- Security 4672 (special privileges assigned to a new logon), mapped to `special_privileges` events, and 4624 and 4625 logons with logon type.
- Processes running elevated (`integrity_level`, `elevated` on process events where the sensor reports them).
- Inside Tawny itself: the admin, analyst and viewer roles, an audit log of admin actions, and Entra ID sign-in with group-based roles.

What Tawny does not show:

- Changes to admin group membership. The agent does not subscribe to Security 4728, 4732 or 4756 yet. Add them before relying on Tawny for this.
- Who should have admin rights, privileged access reviews, or just-in-time access.
- Whether privileged accounts are kept off email and the web.

## 6. Patch operating systems

What Tawny shows:

- OS name, version and architecture for every agent (`GET /api/agents`).
- Agent version and update ring state for Tawny's own agent.

What Tawny does not show:

- Missing OS patches or build revisions mapped to vulnerabilities.
- End-of-support status for an OS version.
- Firmware and driver patch levels.

## 7. Multi-factor authentication

What Tawny shows:

- Windows logon events (4624, 4625) and failed-logon rules (`failed-logons-then-success`, `failed-logons-from-one-ip`), which show password guessing against hosts.
- Inside Tawny itself: Entra ID sign-in, so the MFA policy in your directory applies to Tawny users. Tawny's own password sign-in has no second factor; limit it to break-glass admins (see [entra-sso.md](../entra-sso.md)).

What Tawny does not show:

- Whether MFA is enforced for your users, online services or remote access. That lives in Entra ID Conditional Access and your identity provider logs, which Tawny does not collect.
- MFA success and failure events.

## 8. Regular backups

What Tawny shows:

- Commands that delete shadow copies or disable recovery (ATT&CK T1490, Inhibit System Recovery) through Sigma rules and hunts, when they are imported and enabled.
- Tawny backs up its own telemetry daily to a local path or S3 (`TAWNY_BACKUP_*`).

What Tawny does not show:

- Whether your backups ran, are complete, are immutable or can be restored.
- Access to backup systems.

## Summary

| Strategy | Tawny gives evidence of | Tawny cannot show |
|---|---|---|
| Application control | Unsigned or new executables running, programs in user-writable paths | Enforcement, AppLocker or WDAC events |
| Patch applications | Language package inventory and OSV exposure | Desktop application patch levels, CVE scanning |
| Office macro settings | Office starting shells or writing files | The macro settings |
| User application hardening | Browser extensions, PowerShell script blocks | Application configuration |
| Restrict admin privileges | 4672 special logons, elevated processes | Admin group changes (4728, 4732, 4756 not collected yet) |
| Patch operating systems | OS versions per agent | Missing OS patches |
| Multi-factor authentication | Password guessing against hosts | MFA enforcement and events |
| Regular backups | Recovery-inhibiting commands | Backup health |

## Planned

- Security 4728, 4732 and 4756 (group membership) and AppLocker or WDAC event subscriptions on Windows.
- A per-agent report of the checks above as pass, fail or no data (issue #60, optional item, not built).
