import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { SuppressionsPanel, type SuppressionRule } from "./suppressions-panel";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

type AlertRuleStub = {
  id: string;
  name: string;
};

export default async function SuppressionsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const [rules, agents, alertRules] = await Promise.all([
    apiGet<SuppressionRule[]>("/api/suppression-rules", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
    apiGet<AlertRuleStub[]>("/api/alert-rules", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="suppressions">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Suppressions"
          title="Alert suppressions"
          description="Suppress noisy alerts when a known-good process, host, or payload pattern is matching a detection rule. Evaluated at alert-creation time."
        />
        <SuppressionsPanel
          initialRules={rules}
          alertRules={alertRules}
          agents={agents}
          role={role}
        />
      </main>
    </AppShell>
  );
}
