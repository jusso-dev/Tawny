import { headers } from "next/headers";
import { redirect, notFound } from "next/navigation";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { apiGet } from "@/lib/api";
import { StatusBadge } from "@/components/ui/status-badge";
import { AgentEventsPanel } from "./events-panel";

type Agent = {
  id: string;
  hostname: string;
  operating_system: "windows" | "macos";
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
    agent = await apiGet<Agent>(`/api/agents/${id}`, session.user.id, "Admin");
  } catch {
    notFound();
  }

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <Link
        href="/agents"
        className="text-sm text-[color:var(--color-muted-foreground)] hover:underline"
      >
        ← All agents
      </Link>

      <header className="mt-4 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold">{agent.hostname}</h1>
          <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
            {agent.operating_system} {agent.os_version} · {agent.architecture} · agent v{agent.agent_version}
          </p>
        </div>
        <StatusBadge status={agent.status} />
      </header>

      <AgentEventsPanel agentId={agent.id} />
    </main>
  );
}
