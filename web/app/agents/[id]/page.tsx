import { headers } from "next/headers";
import { redirect, notFound } from "next/navigation";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { StatusBadge } from "@/components/ui/status-badge";
import { AgentEventsPanel } from "./events-panel";
import { AppShell } from "@/components/app-shell";

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

export default async function AgentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const { id } = await params;
  let agent: Agent;
  try {
    agent = await apiGet<Agent>(`/api/agents/${id}`, session.user.id, authRole(session.user));
  } catch {
    notFound();
  }

  return (
    <AppShell agents={[agent]} active="agents">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Link
          href="/agents"
          className="inline-flex items-center gap-2 text-sm text-[color:var(--color-muted-foreground)] hover:text-[color:var(--color-foreground)]"
        >
          <ArrowLeft size={15} />
          All agents
        </Link>

        <header className="mt-4 flex flex-col gap-5 border-b border-[color:var(--color-border)] pb-6 sm:flex-row sm:items-end sm:justify-between">
          <div className="min-w-0">
            <h1 className="truncate text-3xl font-semibold tracking-tight">{agent.hostname}</h1>
            <p className="mt-2 text-sm text-[color:var(--color-muted-foreground)]">
              {agent.operating_system} {agent.os_version}, {agent.architecture}, agent v{agent.agent_version}
            </p>
          </div>
          <StatusBadge status={agent.status} />
        </header>

        <section className="mt-5 grid gap-3 sm:grid-cols-3">
          <Fact label="Last heartbeat" value={agent.last_heartbeat_at ? new Date(agent.last_heartbeat_at).toLocaleString() : "Never"} />
          <Fact label="Enrolled" value={new Date(agent.enrolled_at).toLocaleString()} />
          <Fact label="Agent id" value={agent.id} mono />
        </section>

        <AgentEventsPanel agentId={agent.id} />
      </main>
    </AppShell>
  );
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-4 py-3">
      <p className="text-xs uppercase text-[color:var(--color-muted-foreground)]">{label}</p>
      <p className={`mt-1 truncate text-sm ${mono ? "font-mono" : "font-medium"}`}>{value}</p>
    </div>
  );
}
