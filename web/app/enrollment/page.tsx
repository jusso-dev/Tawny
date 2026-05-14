import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { EnrollmentActions } from "./enrollment-actions";
import { AppShell, PageHeader } from "@/components/app-shell";

type EnrollmentToken = {
  id: string;
  expires_at: string;
  created_at: string;
  used_at: string | null;
  used_by_agent_id: string | null;
};

const dateFormat = new Intl.DateTimeFormat("en", {
  dateStyle: "medium",
  timeStyle: "short",
});

function tokenStatus(token: EnrollmentToken) {
  if (token.used_at) return "Used";
  if (new Date(token.expires_at).getTime() <= Date.now()) return "Expired";
  return "Active";
}

function statusClass(status: string) {
  if (status === "Active") return "bg-[color:var(--color-success)]/15 text-[color:var(--color-success)] ring-[color:var(--color-success)]/25";
  if (status === "Used") return "bg-[color:var(--color-accent)]/15 text-[color:var(--color-accent)] ring-[color:var(--color-accent)]/25";
  return "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)] ring-[color:var(--color-border)]";
}

export default async function EnrollmentPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const tokens = await apiGet<EnrollmentToken[]>(
    "/api/enrollment-tokens",
    session.user.id,
    authRole(session.user),
  );
  const backendUrl =
    process.env.NEXT_PUBLIC_TAWNY_AGENT_BACKEND_URL ??
    process.env.TAWNY_PUBLIC_API_URL ??
    process.env.TAWNY_API_URL ??
    "http://localhost:5080";

  return (
    <AppShell active="enrollment">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Enrollment"
          title="Install new agents"
          description="Create short-lived, single-use tokens and copy the install commands for Windows or macOS endpoints."
          actions={
            <Link
              href="/agents"
              className="inline-flex min-h-10 items-center rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-4 text-sm hover:bg-[color:var(--color-muted)]"
            >
              Back to agents
            </Link>
          }
        />

        <EnrollmentActions backendUrl={backendUrl} />

        <section className="mt-8">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase text-[color:var(--color-muted-foreground)]">
              Existing tokens
            </h2>
            <span className="text-sm text-[color:var(--color-muted-foreground)]">
              {tokens.length} total
            </span>
          </div>

          <div className="mt-3 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <table className="w-full text-sm">
              <thead className="bg-[color:var(--color-muted)] text-left">
                <tr>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Created</th>
                  <th className="px-4 py-3 font-medium">Expires</th>
                  <th className="px-4 py-3 font-medium">Used by</th>
                  <th className="px-4 py-3 font-medium">Token id</th>
                </tr>
              </thead>
              <tbody>
                {tokens.length === 0 && (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]"
                    >
                      No tokens yet. Create one before installing an agent.
                    </td>
                  </tr>
                )}
                {tokens.map((token) => {
                  const status = tokenStatus(token);
                  return (
                    <tr key={token.id} className="border-t border-[color:var(--color-border)]">
                      <td className="px-4 py-3">
                        <span className={`rounded-full px-2.5 py-1 text-xs font-medium ring-1 ${statusClass(status)}`}>
                          {status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">
                        {dateFormat.format(new Date(token.created_at))}
                      </td>
                      <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">
                        {dateFormat.format(new Date(token.expires_at))}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                        {token.used_by_agent_id ?? "Unused"}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                        {token.id}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </AppShell>
  );
}
