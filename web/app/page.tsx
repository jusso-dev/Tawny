import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { StatusDonut, VolumeSparkline } from "@/components/dashboard-charts";
import { AppShell, PageHeader, PrimaryLink } from "@/components/app-shell";
import { StatusBadge } from "@/components/ui/status-badge";

type Agent = {
  id: string;
  hostname: string;
  status: "online" | "stale" | "offline" | "unknown";
};

type DashboardSummary = {
  total_agents: number;
  online_agents: number;
  offline_agents: number;
  stale_agents: number;
  unknown_agents: number;
  recent_events: Array<{
    id: number;
    agent_id: string;
    hostname: string;
    type: string;
    occurred_at: string;
    received_at: string;
  }>;
  event_volume: Array<{
    bucket_start: string;
    count: number;
  }>;
};

const eventTypeLabels: Record<string, string> = {
  process_snapshot: "Processes",
  network_snapshot: "Network",
  user_session: "Session",
  system_info: "System",
  file_integrity: "FIM",
  heartbeat: "Heartbeat",
};

export default async function Home() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const [summary, agents] = await Promise.all([
    apiGet<DashboardSummary>("/api/dashboard/summary", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  const donutData = [
    { name: "Online", value: summary.online_agents, color: "var(--color-success)" },
    { name: "Stale", value: summary.stale_agents, color: "var(--color-warning)" },
    { name: "Offline", value: summary.offline_agents, color: "var(--color-danger)" },
    { name: "Unknown", value: summary.unknown_agents, color: "var(--color-muted-foreground)" },
  ];

  return (
    <AppShell agents={agents} active="dashboard">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Dashboard"
          title="Endpoint operations"
          description="Agent health, telemetry arrival, and recent endpoint activity from the local Tawny stack."
          actions={<PrimaryLink href="/enrollment">New token</PrimaryLink>}
        />

        <section className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Total agents" value={summary.total_agents} />
          <Metric label="Online" value={summary.online_agents} tone="success" />
          <Metric label="Offline" value={summary.offline_agents} tone="danger" />
          <Metric
            label="Events, 24h"
            value={summary.event_volume.reduce((sum, point) => sum + point.count, 0)}
          />
        </section>

        <section className="mt-5 grid gap-5 lg:grid-cols-[0.82fr_1.18fr]">
          <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-5">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold">Agent state</h2>
              <Link href="/agents" className="text-sm text-[color:var(--color-muted-foreground)] hover:text-[color:var(--color-foreground)]">
                View all
              </Link>
            </div>
            <StatusDonut data={donutData} />
            <div className="grid grid-cols-2 gap-2 text-sm">
              {donutData.map((point) => (
                <div key={point.name} className="flex items-center justify-between rounded-md bg-[color:var(--color-muted)] px-3 py-2">
                  <span>{point.name}</span>
                  <span className="font-medium">{point.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-5">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold">Event volume</h2>
              <span className="text-sm text-[color:var(--color-muted-foreground)]">Last 24 hours</span>
            </div>
            <VolumeSparkline data={summary.event_volume} />
          </div>
        </section>

        <section className="mt-5 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
          <div className="flex items-center justify-between border-b border-[color:var(--color-border)] px-5 py-4">
            <h2 className="font-semibold">Recent events</h2>
            <span className="text-sm text-[color:var(--color-muted-foreground)]">
              {summary.recent_events.length} latest
            </span>
          </div>
          <div className="divide-y divide-[color:var(--color-border)]">
            {summary.recent_events.length === 0 && (
              <p className="px-5 py-10 text-center text-sm text-[color:var(--color-muted-foreground)]">
                No telemetry has arrived yet.
              </p>
            )}
            {summary.recent_events.map((event) => (
              <Link
                key={event.id}
                href={`/agents/${event.agent_id}`}
                className="grid gap-2 px-5 py-4 transition-colors hover:bg-[color:var(--color-muted)]/75 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
              >
                <span className="flex min-w-0 items-center gap-3">
                  <span className="truncate font-medium">{event.hostname}</span>
                  <span className="rounded-full bg-[color:var(--color-muted)] px-2 py-0.5 text-xs text-[color:var(--color-muted-foreground)]">
                    {eventTypeLabels[event.type] ?? event.type.replaceAll("_", " ")}
                  </span>
                </span>
                <time className="text-sm text-[color:var(--color-muted-foreground)]">
                  {new Date(event.received_at).toLocaleString()}
                </time>
              </Link>
            ))}
          </div>
        </section>
      </main>
    </AppShell>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "success" | "danger";
}) {
  return (
    <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-[color:var(--color-muted-foreground)]">{label}</p>
        {tone === "success" ? <StatusBadge status="online" /> : null}
        {tone === "danger" ? <StatusBadge status="offline" /> : null}
      </div>
      <p className="mt-3 text-2xl font-semibold tracking-tight">{value}</p>
    </div>
  );
}
