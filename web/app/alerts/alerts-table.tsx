"use client";

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { z } from "zod";
import { cn } from "@/lib/cn";

type Severity = "low" | "medium" | "high" | "critical";
type AlertStatus = "open" | "acknowledged" | "resolved";
type AlertNotificationStatus = "not_configured" | "pending" | "sent" | "failed";
type EventType =
  | "process_snapshot"
  | "network_snapshot"
  | "user_session"
  | "system_info"
  | "file_integrity"
  | "heartbeat";
type RuleOperator = "exists" | "equals" | "contains" | "greater_than" | "less_than";

export type Alert = {
  id: number;
  alert_rule_id: string;
  rule_name: string;
  rule_event_type: EventType | null;
  rule_operator: RuleOperator;
  rule_payload_path: string | null;
  rule_match_value: string | null;
  agent_id: string;
  hostname: string;
  telemetry_event_id: number;
  event_type: EventType;
  occurred_at: string;
  received_at: string;
  payload: unknown;
  severity: Severity;
  status: AlertStatus;
  slack_notification_status: AlertNotificationStatus;
  slack_notified_at: string | null;
  slack_notification_error: string | null;
  title: string;
  description: string | null;
  created_at: string;
};

type EvidenceItem = {
  label: string;
  value: string;
  mono?: boolean;
};

type EvidenceSection = {
  title: string;
  items: EvidenceItem[];
};

const scalarSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]).optional();
const processSchema = z.object({
  pid: scalarSchema,
  ppid: scalarSchema,
  name: scalarSchema,
  command_line: scalarSchema,
});
const processSnapshotSchema = z.object({
  processes: z.array(processSchema).default([]),
});
const connectionSchema = z.object({
  protocol: scalarSchema,
  local_address: scalarSchema,
  local_port: scalarSchema,
  remote_address: scalarSchema,
  remote_port: scalarSchema,
  state: scalarSchema,
  raw: scalarSchema,
});
const networkSnapshotSchema = z.object({
  source: scalarSchema,
  connections: z.array(connectionSchema).default([]),
});
const fileEventSchema = z.object({
  path: scalarSchema,
  old_sha1: scalarSchema,
  new_sha1: scalarSchema,
  old_sha256: scalarSchema,
  new_sha256: scalarSchema,
  size_bytes: scalarSchema,
  exists: scalarSchema,
});
const sessionSchema = z.object({
  user: scalarSchema,
  username: scalarSchema,
  line: scalarSchema,
  pid: scalarSchema,
  session_id: scalarSchema,
  station: scalarSchema,
  raw: scalarSchema,
});
const userSessionSchema = z.object({
  source: scalarSchema,
  sessions: z.array(sessionSchema).default([]),
});
const systemInfoSchema = z.record(z.unknown());

const severityTone: Record<Severity, string> = {
  low: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)] ring-[color:var(--color-border)]",
  medium: "bg-[color:var(--color-accent)]/12 text-[color:var(--color-accent)] ring-[color:var(--color-accent)]/25",
  high: "bg-[color:var(--color-warning)]/12 text-[color:var(--color-warning)] ring-[color:var(--color-warning)]/25",
  critical: "bg-[color:var(--color-danger)]/12 text-[color:var(--color-danger)] ring-[color:var(--color-danger)]/25",
};

const statusTone: Record<AlertStatus, string> = {
  open: "bg-[color:var(--color-danger)]/12 text-[color:var(--color-danger)] ring-[color:var(--color-danger)]/25",
  acknowledged: "bg-[color:var(--color-warning)]/12 text-[color:var(--color-warning)] ring-[color:var(--color-warning)]/25",
  resolved: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)] ring-[color:var(--color-border)]",
};

const notificationTone: Record<AlertNotificationStatus, string> = {
  not_configured: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)] ring-[color:var(--color-border)]",
  pending: "bg-[color:var(--color-accent)]/12 text-[color:var(--color-accent)] ring-[color:var(--color-accent)]/25",
  sent: "bg-[color:var(--color-success)]/12 text-[color:var(--color-success)] ring-[color:var(--color-success)]/25",
  failed: "bg-[color:var(--color-danger)]/12 text-[color:var(--color-danger)] ring-[color:var(--color-danger)]/25",
};

const eventTypeLabels: Record<EventType, string> = {
  process_snapshot: "Process",
  network_snapshot: "Network",
  user_session: "Identity",
  system_info: "System",
  file_integrity: "File",
  heartbeat: "Heartbeat",
};

export function AlertsTable({ alerts }: { alerts: Alert[] }) {
  const [expanded, setExpanded] = useState<number | null>(alerts[0]?.id ?? null);
  const openCount = alerts.filter((alert) => alert.status === "open").length;
  const slackSentCount = alerts.filter((alert) => alert.slack_notification_status === "sent").length;

  return (
    <section className="mt-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2 text-sm">
          <SummaryPill label="Open" value={openCount} />
          <SummaryPill label="Slack sent" value={slackSentCount} />
          <SummaryPill label="Shown" value={alerts.length} />
        </div>
        <p className="text-sm text-[color:var(--color-muted-foreground)]">
          Expand an alert to inspect matched evidence and raw telemetry.
        </p>
      </div>

      <div className="mt-3 overflow-x-auto rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <table className="w-full min-w-[58rem] text-sm">
          <thead className="bg-[color:var(--color-muted)] text-left">
            <tr>
              <th className="w-10 px-3 py-3 font-medium" aria-label="Expand" />
              <th className="px-4 py-3 font-medium">Alert</th>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Agent</th>
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Slack</th>
              <th className="px-4 py-3 font-medium">Created</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                  No alerts have fired yet.
                </td>
              </tr>
            )}
            {alerts.map((alert) => {
              const isExpanded = expanded === alert.id;
              return (
                <FragmentRow
                  key={alert.id}
                  alert={alert}
                  isExpanded={isExpanded}
                  onToggle={() => setExpanded(isExpanded ? null : alert.id)}
                />
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FragmentRow({
  alert,
  isExpanded,
  onToggle,
}: {
  alert: Alert;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const evidence = useMemo(() => buildEvidence(alert), [alert]);

  return (
    <>
      <tr className="border-t border-[color:var(--color-border)] align-top">
        <td className="px-3 py-3">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={isExpanded}
            aria-label={isExpanded ? "Collapse alert" : "Expand alert"}
            className="grid size-8 place-items-center rounded-md text-[color:var(--color-muted-foreground)] hover:bg-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)]"
          >
            {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </button>
        </td>
        <td className="max-w-md px-4 py-3">
          <button type="button" onClick={onToggle} className="text-left">
            <span className="block font-medium">{alert.title}</span>
            <span className="mt-1 block text-xs text-[color:var(--color-muted-foreground)]">
              {alert.description ?? alert.rule_name}
            </span>
          </button>
        </td>
        <td className="whitespace-nowrap px-4 py-3">
          {eventTypeLabels[alert.event_type]}
        </td>
        <td className="px-4 py-3">
          <p>{alert.hostname}</p>
          <p className="mt-1 font-mono text-xs text-[color:var(--color-muted-foreground)]">
            {alert.agent_id.slice(0, 8)}
          </p>
        </td>
        <td className="px-4 py-3">
          <Badge tone={severityTone[alert.severity]}>{alert.severity}</Badge>
        </td>
        <td className="px-4 py-3">
          <Badge tone={statusTone[alert.status]}>{alert.status}</Badge>
        </td>
        <td className="px-4 py-3">
          <Badge tone={notificationTone[alert.slack_notification_status]}>
            {formatNotificationStatus(alert.slack_notification_status)}
          </Badge>
        </td>
        <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
          {formatDate(alert.created_at)}
        </td>
      </tr>
      {isExpanded ? (
        <tr className="border-t border-[color:var(--color-border)]">
          <td colSpan={8} className="bg-[color:var(--color-background)] px-4 py-4">
            <AlertDetails alert={alert} evidence={evidence} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function AlertDetails({ alert, evidence }: { alert: Alert; evidence: EvidenceSection[] }) {
  return (
    <div className="grid gap-4">
      <div className="grid gap-3 md:grid-cols-3">
        <DetailItem label="Rule predicate" value={formatPredicate(alert)} mono />
        <DetailItem label="Telemetry event" value={`#${alert.telemetry_event_id} (${alert.event_type})`} mono />
        <DetailItem label="Received" value={formatDate(alert.received_at)} />
        <DetailItem label="Slack delivery" value={formatSlackDelivery(alert)} />
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        {evidence.map((section) => (
          <section key={section.title} className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <div className="border-b border-[color:var(--color-border)] px-4 py-3">
              <h3 className="text-sm font-semibold">{section.title}</h3>
            </div>
            <div className="grid gap-2 p-4">
              {section.items.map((item) => (
                <DetailItem key={item.label} label={item.label} value={item.value} mono={item.mono} />
              ))}
            </div>
          </section>
        ))}
      </div>

      <details className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <summary className="cursor-pointer px-4 py-3 text-sm font-semibold">Raw telemetry payload</summary>
        <pre className="max-h-96 overflow-auto border-t border-[color:var(--color-border)] p-4 text-xs leading-relaxed text-[color:var(--color-muted-foreground)]">
          {JSON.stringify(alert.payload, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function buildEvidence(alert: Alert): EvidenceSection[] {
  switch (alert.event_type) {
    case "process_snapshot":
      return processEvidence(alert);
    case "network_snapshot":
      return networkEvidence(alert);
    case "file_integrity":
      return fileEvidence(alert);
    case "user_session":
      return sessionEvidence(alert);
    case "system_info":
      return systemEvidence(alert);
    case "heartbeat":
      return genericEvidence(alert, "Heartbeat evidence");
  }
}

function processEvidence(alert: Alert): EvidenceSection[] {
  const parsed = processSnapshotSchema.safeParse(alert.payload);
  if (!parsed.success) return genericEvidence(alert, "Process evidence");
  const suffix = stripPrefix(alert.rule_payload_path, "processes.");
  const matches = parsed.data.processes.filter((process) => itemMatches(process, suffix, alert));
  const selected = matches.length > 0 ? matches : parsed.data.processes.slice(0, 3);

  return selected.map((process, index) => ({
    title: matches.length > 0 ? `Matched process ${index + 1}` : `Process sample ${index + 1}`,
    items: compactItems([
      item("PID", process.pid, true),
      item("Parent PID", process.ppid, true),
      item("Name", process.name),
      item("Command line", process.command_line, true),
    ]),
  }));
}

function networkEvidence(alert: Alert): EvidenceSection[] {
  const parsed = networkSnapshotSchema.safeParse(alert.payload);
  if (!parsed.success) return genericEvidence(alert, "Network evidence");
  const suffix = stripPrefix(alert.rule_payload_path, "connections.");
  const matches = parsed.data.connections.filter((connection) => itemMatches(connection, suffix, alert));
  const selected = matches.length > 0 ? matches : parsed.data.connections.slice(0, 3);

  return selected.map((connection, index) => {
    const parsedRaw = parseProcNetRaw(stringValue(connection.raw));
    return {
      title: matches.length > 0 ? `Matched connection ${index + 1}` : `Connection sample ${index + 1}`,
      items: compactItems([
        item("Protocol", connection.protocol ?? parsedRaw?.protocol),
        item("Local IP", connection.local_address ?? parsedRaw?.localAddress, true),
        item("Local port", connection.local_port ?? parsedRaw?.localPort, true),
        item("Remote IP", connection.remote_address ?? parsedRaw?.remoteAddress, true),
        item("Remote port", connection.remote_port ?? parsedRaw?.remotePort, true),
        item("State", connection.state ?? parsedRaw?.state, true),
        item("Raw row", connection.raw, true),
      ]),
    };
  });
}

function fileEvidence(alert: Alert): EvidenceSection[] {
  const parsed = fileEventSchema.safeParse(alert.payload);
  if (!parsed.success) return genericEvidence(alert, "File evidence");

  return [
    {
      title: "Matched file",
      items: compactItems([
        item("Path", parsed.data.path, true),
        item("Exists", parsed.data.exists),
        item("Size", parsed.data.size_bytes, true),
        item("Old SHA-1", parsed.data.old_sha1 ?? "Not captured", true),
        item("New SHA-1", parsed.data.new_sha1 ?? "Not captured", true),
        item("Old SHA-256 (SHA-2)", parsed.data.old_sha256, true),
        item("New SHA-256 (SHA-2)", parsed.data.new_sha256, true),
      ]),
    },
  ];
}

function sessionEvidence(alert: Alert): EvidenceSection[] {
  const parsed = userSessionSchema.safeParse(alert.payload);
  if (!parsed.success) return genericEvidence(alert, "Identity evidence");
  const suffix = stripPrefix(alert.rule_payload_path, "sessions.");
  const matches = parsed.data.sessions.filter((session) => itemMatches(session, suffix, alert));
  const selected = matches.length > 0 ? matches : parsed.data.sessions.slice(0, 3);

  if (selected.length === 0) {
    return [{ title: "Identity evidence", items: [item("Source", parsed.data.source ?? "No active sessions")] }];
  }

  return selected.map((session, index) => ({
    title: matches.length > 0 ? `Matched session ${index + 1}` : `Session sample ${index + 1}`,
    items: compactItems([
      item("User", session.user ?? session.username),
      item("Line", session.line),
      item("PID", session.pid, true),
      item("Session ID", session.session_id, true),
      item("Station", session.station),
      item("Raw row", session.raw, true),
    ]),
  }));
}

function systemEvidence(alert: Alert): EvidenceSection[] {
  const parsed = systemInfoSchema.safeParse(alert.payload);
  if (!parsed.success) return genericEvidence(alert, "System evidence");
  const path = alert.rule_payload_path;
  const matchedValue = path ? resolvePath(parsed.data, path).map(stringValue).filter(Boolean).join(", ") : "";

  return [
    {
      title: "System evidence",
      items: compactItems([
        item("Matched field", path),
        item("Matched value", matchedValue || undefined, true),
        item("Hostname", parsed.data.hostname),
        item("Platform", parsed.data.platform),
        item("Kernel", parsed.data.kernel),
        item("Architecture", parsed.data.architecture),
        item("CPU count", parsed.data.cpu_count, true),
        item("Memory bytes", parsed.data.memory_bytes, true),
      ]),
    },
  ];
}

function genericEvidence(alert: Alert, title: string): EvidenceSection[] {
  const values = alert.rule_payload_path ? resolvePath(alert.payload, alert.rule_payload_path) : [];
  return [
    {
      title,
      items: compactItems([
        item("Matched field", alert.rule_payload_path),
        item("Matched value", values.map(stringValue).filter(Boolean).join(", ") || undefined, true),
        item("Operator", alert.rule_operator),
        item("Expected", alert.rule_match_value, true),
      ]),
    },
  ];
}

function item(label: string, value: unknown, mono = false): EvidenceItem {
  return { label, value: stringValue(value) || "Not captured", mono };
}

function compactItems(items: EvidenceItem[]) {
  return items.filter((entry) => entry.value !== "Not captured" || entry.label.includes("SHA-1"));
}

function itemMatches(itemValue: Record<string, unknown>, suffix: string | null, alert: Alert) {
  if (!suffix) return true;
  const values = resolvePath(itemValue, suffix);
  if (values.length === 0) return false;
  return values.some((value) => matchesRule(value, alert.rule_operator, alert.rule_match_value));
}

function matchesRule(value: unknown, operator: RuleOperator, expected: string | null) {
  if (operator === "exists") return value !== undefined && value !== null;
  const left = stringValue(value).toLowerCase();
  const candidates = matchValues(expected).map((candidate) => candidate.toLowerCase());
  if (operator === "equals") return candidates.some((candidate) => left === candidate);
  if (operator === "contains") return candidates.some((candidate) => left.includes(candidate));
  if (operator === "greater_than" || operator === "less_than") {
    const leftNumber = Number(left);
    return candidates.some((candidate) => {
      const rightNumber = Number(candidate);
      if (!Number.isFinite(leftNumber) || !Number.isFinite(rightNumber)) return false;
      return operator === "greater_than" ? leftNumber > rightNumber : leftNumber < rightNumber;
    });
  }
  return false;
}

function matchValues(expected: string | null) {
  if (!expected) return [""];
  if (!expected.trimStart().startsWith("[")) return [expected];
  try {
    const parsed = JSON.parse(expected) as unknown;
    return Array.isArray(parsed) ? parsed.map(stringValue) : [expected];
  } catch {
    return [expected];
  }
}

function resolvePath(root: unknown, path: string): unknown[] {
  const parts = path.split(".").filter(Boolean);
  return resolveParts(root, parts);
}

function resolveParts(current: unknown, parts: string[]): unknown[] {
  if (parts.length === 0) return [current];
  if (Array.isArray(current)) return current.flatMap((item) => resolveParts(item, parts));
  if (!current || typeof current !== "object") return [];
  const [head, ...tail] = parts;
  if (!head || !(head in current)) return [];
  return resolveParts((current as Record<string, unknown>)[head], tail);
}

function stripPrefix(path: string | null, prefix: string) {
  if (!path) return null;
  return path.startsWith(prefix) ? path.slice(prefix.length) : path;
}

function parseProcNetRaw(raw: string) {
  const parts = raw.trim().split(/\s+/);
  if (parts.length < 4) return null;
  const local = parseProcEndpoint(parts[1]);
  const remote = parseProcEndpoint(parts[2]);
  return {
    protocol: undefined,
    localAddress: local?.address,
    localPort: local?.port,
    remoteAddress: remote?.address,
    remotePort: remote?.port,
    state: parts[3],
  };
}

function parseProcEndpoint(value: string | undefined) {
  if (!value) return null;
  const [addressHex, portHex] = value.split(":");
  if (!addressHex || !portHex) return null;
  const port = Number.parseInt(portHex, 16);
  if (addressHex.length !== 8) return { address: addressHex, port };
  const raw = Number.parseInt(addressHex, 16);
  return {
    address: [raw & 0xff, (raw >> 8) & 0xff, (raw >> 16) & 0xff, (raw >> 24) & 0xff].join("."),
    port,
  };
}

function stringValue(value: unknown) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function formatPredicate(alert: Alert) {
  return `${alert.rule_payload_path ?? "event"} ${alert.rule_operator}${alert.rule_match_value ? ` ${alert.rule_match_value}` : ""}`;
}

function formatNotificationStatus(status: AlertNotificationStatus) {
  return status.replace("_", " ");
}

function formatSlackDelivery(alert: Alert) {
  if (alert.slack_notification_status === "sent" && alert.slack_notified_at) {
    return `Sent ${formatDate(alert.slack_notified_at)}`;
  }

  if (alert.slack_notification_status === "failed") {
    return alert.slack_notification_error ? `Failed: ${alert.slack_notification_error}` : "Failed";
  }

  return formatNotificationStatus(alert.slack_notification_status);
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function SummaryPill({ label, value }: { label: string; value: number }) {
  return (
    <span className="inline-flex min-h-8 items-center gap-2 rounded-md border border-[color:var(--color-border)] px-3 text-[color:var(--color-muted-foreground)]">
      {label}
      <span className="font-medium text-[color:var(--color-foreground)]">{value}</span>
    </span>
  );
}

function Badge({ tone, children }: { tone: string; children: ReactNode }) {
  return (
    <span className={cn("rounded-full px-2.5 py-1 text-xs font-medium capitalize ring-1", tone)}>
      {children}
    </span>
  );
}

function DetailItem({ label, value, mono = false }: EvidenceItem) {
  return (
    <div className="grid gap-1 rounded-md bg-[color:var(--color-muted)] px-3 py-2 sm:grid-cols-[8.5rem_1fr] sm:gap-3">
      <span className="text-xs font-medium uppercase text-[color:var(--color-muted-foreground)]">{label}</span>
      <span className={cn("min-w-0 break-words text-sm", mono ? "font-mono text-xs" : "")}>{value}</span>
    </div>
  );
}
