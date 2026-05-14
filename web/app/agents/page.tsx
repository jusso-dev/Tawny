import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AgentsTable } from "./agents-table";
import { AppShell, PageHeader, PrimaryLink } from "@/components/app-shell";

type Agent = {
  id: string;
  hostname: string;
  operating_system: "windows" | "macos" | "linux";
  os_version: string;
  agent_version: string;
  architecture: "x64" | "arm64";
  status: "online" | "stale" | "offline" | "unknown";
  last_heartbeat_at: string | null;
  enrolled_at: string;
};

export default async function AgentsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const agents = await apiGet<Agent[]>("/api/agents", session.user.id, authRole(session.user));
  const online = agents.filter((agent) => agent.status === "online").length;
  const stale = agents.filter((agent) => agent.status === "stale").length;

  return (
    <AppShell agents={agents} active="agents">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Agents"
          title="Endpoint inventory"
          description="Track enrolled endpoints, agent versions, heartbeat recency, and current status."
          actions={<PrimaryLink href="/enrollment">New enrollment token</PrimaryLink>}
        />

        <section className="mt-5 grid gap-3 sm:grid-cols-3">
          <Summary label="Enrolled" value={agents.length} />
          <Summary label="Online" value={online} />
          <Summary label="Stale" value={stale} />
        </section>

        <AgentsTable agents={agents} />
      </main>
    </AppShell>
  );
}

function Summary({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-4 py-3">
      <p className="text-xs uppercase text-[color:var(--color-muted-foreground)]">{label}</p>
      <p className="mt-1 text-xl font-semibold">{value}</p>
    </div>
  );
}
