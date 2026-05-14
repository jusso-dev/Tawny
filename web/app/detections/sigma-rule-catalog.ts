export type SigmaCatalogPlatform = "all" | "linux" | "macos" | "windows";
export type SigmaCatalogCategory = "process" | "network" | "file" | "identity" | "system";

export type SigmaCatalogRule = {
  id: string;
  name: string;
  description: string;
  platform: SigmaCatalogPlatform;
  category: SigmaCatalogCategory;
  severity: "low" | "medium" | "high" | "critical";
  yaml: string;
};

export const sigmaCatalog: SigmaCatalogRule[] = [
  {
    id: "linux-shell-from-web",
    name: "Linux shell spawned by service path",
    description: "Flags shell processes with a web or service-oriented command line.",
    platform: "linux",
    category: "process",
    severity: "high",
    yaml: `title: Linux Shell Spawned By Service Path
id: 6c4428d4-2361-4b4d-8619-646f218fe3ab
description: Detects shell execution with common service or web paths in the command line.
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    processes.command_line|contains: /var/www
  condition: selection
level: high
`,
  },
  {
    id: "linux-temp-download",
    name: "Linux download to temp path",
    description: "Looks for curl or wget style activity writing into temporary locations.",
    platform: "linux",
    category: "process",
    severity: "medium",
    yaml: `title: Linux Download To Temp Path
id: 3f446e6a-f29e-4fd5-aac2-6506f185a9a2
description: Detects command lines that reference temporary download locations.
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    processes.command_line|contains: /tmp/
  condition: selection
level: medium
`,
  },
  {
    id: "linux-passwd-change",
    name: "Linux passwd file change",
    description: "Watches for file integrity events touching account database files.",
    platform: "linux",
    category: "file",
    severity: "critical",
    yaml: `title: Linux Account Database File Change
id: 5cd8159e-1776-4427-961d-d7f9a8fe8c63
description: Detects file integrity changes to sensitive local account files.
logsource:
  product: linux
  category: file_event
detection:
  selection:
    path|contains: /etc/passwd
  condition: selection
level: critical
`,
  },
  {
    id: "linux-high-port",
    name: "Linux high destination port",
    description: "Identifies outbound connections to high numbered destination ports.",
    platform: "linux",
    category: "network",
    severity: "low",
    yaml: `title: Linux High Destination Port
id: d99b821d-dd7a-4a45-91f7-85b6934785fc
description: Detects outbound connections to high destination ports.
logsource:
  product: linux
  category: network_connection
detection:
  selection:
    connections.remote_port|gt: 49151
  condition: selection
level: low
`,
  },
  {
    id: "windows-powershell-encoded",
    name: "PowerShell encoded command",
    description: "Flags encoded PowerShell command usage.",
    platform: "windows",
    category: "process",
    severity: "high",
    yaml: `title: PowerShell Encoded Command
id: 7e2d8a9b-9034-4e7b-97f1-a43c00e2b162
description: Detects PowerShell encoded command execution.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.command_line|contains: -enc
  condition: selection
level: high
`,
  },
  {
    id: "windows-lsass-reference",
    name: "LSASS referenced in command line",
    description: "Looks for command lines that reference LSASS.",
    platform: "windows",
    category: "process",
    severity: "critical",
    yaml: `title: LSASS Referenced In Command Line
id: db822c1f-7f8c-4664-97e4-6897e4a5411d
description: Detects process command lines referencing lsass.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.command_line|contains: lsass
  condition: selection
level: critical
`,
  },
  {
    id: "windows-suspicious-system32-write",
    name: "System32 file integrity change",
    description: "Watches for file events under System32.",
    platform: "windows",
    category: "file",
    severity: "high",
    yaml: `title: Windows System32 File Integrity Change
id: 2869f137-9fa9-4f1e-83d6-726ca81766c4
description: Detects file integrity changes under System32.
logsource:
  product: windows
  category: file_event
detection:
  selection:
    path|contains: C:\\Windows\\System32
  condition: selection
level: high
`,
  },
  {
    id: "macos-osascript",
    name: "macOS osascript execution",
    description: "Flags AppleScript execution through osascript.",
    platform: "macos",
    category: "process",
    severity: "medium",
    yaml: `title: macOS Osascript Execution
id: 53bbfc56-b1c2-4b01-86de-c20b6bd8b40b
description: Detects osascript process execution.
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    processes.name|contains: osascript
  condition: selection
level: medium
`,
  },
  {
    id: "macos-launch-agent",
    name: "macOS LaunchAgent change",
    description: "Watches for file integrity changes in LaunchAgent paths.",
    platform: "macos",
    category: "file",
    severity: "high",
    yaml: `title: macOS LaunchAgent File Change
id: a0e520ec-d3ca-4d1a-bb0c-173802567b24
description: Detects LaunchAgent persistence path changes.
logsource:
  product: macos
  category: file_event
detection:
  selection:
    path|contains: LaunchAgents
  condition: selection
level: high
`,
  },
  {
    id: "macos-sudo-session",
    name: "macOS sudo session reference",
    description: "Looks for sudo references in user session telemetry.",
    platform: "macos",
    category: "identity",
    severity: "medium",
    yaml: `title: macOS Sudo Session Reference
id: bdcf3f20-b252-49ad-9183-b6f119ac2f59
description: Detects sudo references in user session telemetry.
logsource:
  product: macos
  category: session
detection:
  selection:
    username|contains: root
  condition: selection
level: medium
`,
  },
  {
    id: "any-suspicious-process-name",
    name: "Suspicious process name",
    description: "A portable process-name starter rule for suspicious executable names.",
    platform: "all",
    category: "process",
    severity: "high",
    yaml: `title: Suspicious Process Name
id: 8c6f0f07-5a44-4c41-83cc-2e0e0f6ef9f1
description: Detects a suspicious process name from Tawny process telemetry.
logsource:
  category: process_creation
detection:
  selection:
    processes.name|contains: suspicious
  condition: selection
level: high
`,
  },
  {
    id: "any-system-hostname",
    name: "System hostname marker",
    description: "Starter system-info rule matching a known hostname marker.",
    platform: "all",
    category: "system",
    severity: "low",
    yaml: `title: System Hostname Marker
id: 456c43b2-04f9-450c-bb3a-87a754d8be42
description: Detects a hostname marker in system information telemetry.
logsource:
  category: system
detection:
  selection:
    hostname|contains: tawny
  condition: selection
level: low
`,
  },
];
