import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { AlertsTable, type Alert } from "./alerts-table";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

export default async function AlertsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const [alerts, agents] = await Promise.all([
    apiGet<Alert[]>("/api/alerts?limit=100", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="alerts">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Alerts"
          title="Detection matches"
          description="Review fired rules, matched telemetry, and the exact evidence that caused each alert."
        />

        <AlertsTable alerts={alerts} />
      </main>
    </AppShell>
  );
}
