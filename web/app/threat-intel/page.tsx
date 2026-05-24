import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { ThreatIntelPanel, type TiFeed } from "./threat-intel-panel";

type Agent = { id: string; hostname: string; status: string };

export default async function ThreatIntelPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const [feeds, agents] = await Promise.all([
    apiGet<TiFeed[]>("/api/threat-intel-feeds", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="threat-intel">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Threat intel"
          title="Threat intel feeds"
          description="Pull IoCs from upstream feeds on a schedule. New indicators show up as IoC alert rules and start matching against live telemetry."
        />
        <ThreatIntelPanel initial={feeds} role={role} />
      </main>
    </AppShell>
  );
}
