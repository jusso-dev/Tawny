import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { CommandPalette } from "@/components/command-palette";
import { StatusDonut, VolumeSparkline } from "@/components/dashboard-charts";
import { ThemeToggle } from "@/components/theme-toggle";

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
  users_snapshot: "Users",
  system_info: "System",
  file_integrity: "FIM",
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
    <main className="mx-auto max-w-6xl px-6 py-10">
      <CommandPalette agents={agents} />
      <header className="flex flex-col gap-5 border-b border-[color:var(--color-border)] pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-sm text-[color:var(--color-muted-foreground)]">Dashboard</p>
          <h1 className="mt-2 text-3xl font-semibold">Tawny operations</h1>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className="rounded-md border border-[color:var(--color-border)] px-3 py-2 text-xs text-[color:var(--color-muted-foreground)]">
            Press Cmd+K to jump to an agent
          </span>
          <ThemeToggle />
          <Link
            href="/enrollment"
            className="rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-medium text-black hover:opacity-90"
          >
            New token
          </Link>
        </div>
      </header>

      <section className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-[color:var(--color-border)] p-5">
          <p className="text-sm text-[color:var(--color-muted-foreground)]">Total agents</p>
          <p className="mt-3 text-3xl font-semibold">{summary.total_agents}</p>
        </div>
        <div className="rounded-lg border border-[color:var(--color-border)] p-5">
          <p className="text-sm text-[color:var(--color-muted-foreground)]">Online</p>
          <p className="mt-3 text-3xl font-semibold text-[color:var(--color-success)]">
            {summary.online_agents}
          </p>
        </div>
        <div className="rounded-lg border border-[color:var(--color-border)] p-5">
          <p className="text-sm text-[color:var(--color-muted-foreground)]">Offline</p>
          <p className="mt-3 text-3xl font-semibold text-[color:var(--color-danger)]">
            {summary.offline_agents}
          </p>
        </div>
        <div className="rounded-lg border border-[color:var(--color-border)] p-5">
          <p className="text-sm text-[color:var(--color-muted-foreground)]">Events, 24h</p>
          <p className="mt-3 text-3xl font-semibold">
            {summary.event_volume.reduce((sum, point) => sum + point.count, 0)}
          </p>
        </div>
      </section>

      <section className="mt-6 grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
        <div className="rounded-lg border border-[color:var(--color-border)] p-5">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Agent state</h2>
            <Link href="/agents" className="text-sm text-[color:var(--color-muted-foreground)] hover:underline">
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

        <div className="rounded-lg border border-[color:var(--color-border)] p-5">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Event volume</h2>
            <span className="text-sm text-[color:var(--color-muted-foreground)]">Last 24 hours</span>
          </div>
          <VolumeSparkline data={summary.event_volume} />
        </div>
      </section>

      <section className="mt-6 rounded-lg border border-[color:var(--color-border)]">
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
              className="flex flex-col gap-2 px-5 py-4 hover:bg-[color:var(--color-muted)] sm:flex-row sm:items-center sm:justify-between"
            >
              <span>
                <span className="font-medium">{event.hostname}</span>
                <span className="ml-3 text-sm text-[color:var(--color-muted-foreground)]">
                  {eventTypeLabels[event.type] ?? event.type}
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
  );
}
