import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { ApiTokensPanel, type ApiToken } from "./api-tokens-panel";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

export default async function ApiTokensPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  if (role !== "Admin") {
    return (
      <AppShell active="tokens">
        <main className="mx-auto max-w-3xl px-6 py-8">
          <PageHeader
            eyebrow="Tokens"
            title="Admin only"
            description="Only administrators can manage API tokens."
          />
        </main>
      </AppShell>
    );
  }

  const [tokens, agents] = await Promise.all([
    apiGet<ApiToken[]>("/api/api-tokens", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="tokens">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Tokens"
          title="API tokens"
          description="Bearer tokens for programmatic access to the Tawny API. Use them with curl or your SIEM/SOAR for hunts and rule management."
        />
        <ApiTokensPanel initialTokens={tokens} />
      </main>
    </AppShell>
  );
}
