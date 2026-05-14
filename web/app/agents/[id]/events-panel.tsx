"use client";

import { useMemo, useState } from "react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/cn";

type EventType =
  | "process_snapshot"
  | "network_snapshot"
  | "file_integrity"
  | "user_session"
  | "system_info"
  | "heartbeat";

type TelemetryEvent = {
  id: number;
  agent_id: string;
  type: EventType;
  occurred_at: string;
  received_at: string;
  payload: unknown;
};

type Tab = {
  key: string;
  label: string;
  type?: EventType;
  live?: boolean;
};

const TABS: Tab[] = [
  { key: "processes", label: "Processes", type: "process_snapshot", live: true },
  { key: "network", label: "Network", type: "network_snapshot" },
  { key: "fim", label: "FIM", type: "file_integrity" },
  { key: "sessions", label: "Sessions", type: "user_session" },
  { key: "raw", label: "Raw events" },
];

export function AgentEventsPanel({ agentId }: { agentId: string }) {
  const [queryClient] = useState(() => new QueryClient());

  return (
    <QueryClientProvider client={queryClient}>
      <AgentEvents agentId={agentId} />
    </QueryClientProvider>
  );
}

function AgentEvents({ agentId }: { agentId: string }) {
  const [activeKey, setActiveKey] = useState(TABS[0]!.key);
  const activeTab = useMemo(
    () => TABS.find((tab) => tab.key === activeKey) ?? TABS[0]!,
    [activeKey],
  );

  const { data, error, isFetching } = useQuery({
    queryKey: ["agent-events", agentId, activeTab.type ?? "all"],
    queryFn: async () => {
      const params = new URLSearchParams({ limit: "50" });
      if (activeTab.type) params.set("type", activeTab.type);

      const res = await fetch(`/api/agents/${agentId}/events?${params.toString()}`);
      if (!res.ok) throw new Error(`Event request failed with ${res.status}`);
      return (await res.json()) as TelemetryEvent[];
    },
    refetchInterval: activeTab.live ? 2000 : false,
  });

  const events = data ?? [];

  return (
    <section className="mt-8">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[color:var(--color-border)]">
        <div className="flex gap-1 overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => setActiveKey(tab.key)}
              className={cn(
                "whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium",
                tab.key === activeTab.key
                  ? "border-[color:var(--color-accent)] text-[color:var(--color-foreground)]"
                  : "border-transparent text-[color:var(--color-muted-foreground)] hover:text-[color:var(--color-foreground)]",
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <p className="pb-2 text-xs text-[color:var(--color-muted-foreground)]">
          {activeTab.live ? "Live refresh every 2s" : "Latest 50 events"}
          {isFetching ? " · updating" : ""}
        </p>
      </div>

      {error ? (
        <div className="mt-6 rounded-md border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 p-4 text-sm text-[color:var(--color-danger)]">
          Events could not be loaded.
        </div>
      ) : events.length === 0 && !isFetching ? (
        <div className="mt-6 rounded-md border border-[color:var(--color-border)] p-8 text-center text-sm text-[color:var(--color-muted-foreground)]">
          No {activeTab.label.toLowerCase()} telemetry has arrived yet.
        </div>
      ) : (
        <div className="mt-6 overflow-hidden rounded-lg border border-[color:var(--color-border)]">
          <table className="w-full text-sm">
            <thead className="bg-[color:var(--color-muted)] text-left">
              <tr>
                <th className="px-4 py-3 font-medium">Received</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Summary</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id} className="border-t border-[color:var(--color-border)] align-top">
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {formatDate(event.received_at)}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 font-medium">
                    {formatType(event.type)}
                  </td>
                  <td className="px-4 py-3">
                    <pre className="max-h-28 overflow-auto whitespace-pre-wrap break-words rounded bg-[color:var(--color-muted)] p-3 text-xs leading-relaxed text-[color:var(--color-muted-foreground)]">
                      {summarizePayload(event)}
                    </pre>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    month: "short",
    day: "numeric",
  }).format(new Date(value));
}

function formatType(type: EventType) {
  return type.replaceAll("_", " ");
}

function summarizePayload(event: TelemetryEvent) {
  if (event.type === "process_snapshot" && isProcessSnapshot(event.payload)) {
    const names = event.payload.processes
      .slice(0, 8)
      .map((process) => process.name)
      .join(", ");
    return `${event.payload.processes.length} processes${names ? `: ${names}` : ""}`;
  }

  return JSON.stringify(event.payload, null, 2);
}

function isProcessSnapshot(payload: unknown): payload is { processes: Array<{ name: string }> } {
  if (!payload || typeof payload !== "object" || !("processes" in payload)) {
    return false;
  }
  const processes = (payload as { processes: unknown }).processes;
  return Array.isArray(processes);
}
