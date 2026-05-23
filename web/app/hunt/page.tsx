import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { HuntWorkbench, type SavedHunt } from "./hunt-workbench";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

export default async function HuntPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const [hunts, agents] = await Promise.all([
    apiGet<SavedHunt[]>("/api/hunts", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="hunt">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Threat hunting"
          title="Hunt across telemetry"
          description="Write a KQL-style query, run it against the last 24h of telemetry, then save or schedule it as a recurring detection."
        />
        <HuntWorkbench initialHunts={hunts} role={role} />
      </main>
    </AppShell>
  );
}
