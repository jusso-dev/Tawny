import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { EnrollmentActions } from "./enrollment-actions";

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
  if (status === "Active") return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";
  if (status === "Used") return "bg-blue-500/15 text-blue-700 dark:text-blue-300";
  return "bg-zinc-500/15 text-zinc-700 dark:text-zinc-300";
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
    <main className="mx-auto max-w-6xl px-6 py-10">
      <header className="border-b border-[color:var(--color-border)] pb-6">
        <div>
          <Link
            href="/agents"
            className="text-sm text-[color:var(--color-muted-foreground)] hover:underline"
          >
            Back to agents
          </Link>
          <h1 className="mt-3 text-2xl font-semibold">Enrollment tokens</h1>
          <p className="mt-1 max-w-2xl text-sm text-[color:var(--color-muted-foreground)]">
            Create short-lived, single-use tokens for installing new endpoint agents.
          </p>
        </div>
      </header>

      <EnrollmentActions backendUrl={backendUrl} />

      <section className="mt-8">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[color:var(--color-muted-foreground)]">
            Existing tokens
          </h2>
          <span className="text-sm text-[color:var(--color-muted-foreground)]">
            {tokens.length} total
          </span>
        </div>

        <div className="mt-3 overflow-hidden rounded-lg border border-[color:var(--color-border)]">
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
                      <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${statusClass(status)}`}>
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
  );
}
