import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

type AuditLogEntry = {
  id: number;
  user_id: string | null;
  action: string;
  target: string | null;
  metadata: unknown;
  occurred_at: string;
};

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ action?: string }>;
}) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const { action } = await searchParams;
  const qs = new URLSearchParams({ limit: "200" });
  if (action) qs.set("action", action);

  const [entries, agents] = await Promise.all([
    apiGet<AuditLogEntry[]>(`/api/audit-logs?${qs.toString()}`, session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="audit">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Audit"
          title="Audit log"
          description="Every action that mutates state is recorded — rule edits, response actions, token usage, hunts, suppressions."
        />

        <form className="mt-6 flex flex-wrap items-center gap-3" action="/audit">
          <input
            name="action"
            defaultValue={action ?? ""}
            placeholder="Filter by action substring, e.g. alert_rule.update"
            className="min-h-9 flex-1 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          />
          <button
            type="submit"
            className="inline-flex min-h-9 items-center rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white"
          >
            Filter
          </button>
        </form>

        <div className="mt-5 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
          <table className="w-full text-sm">
            <thead className="bg-[color:var(--color-muted)] text-left">
              <tr>
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">User</th>
                <th className="px-4 py-3 font-medium">Metadata</th>
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                    No audit log entries match these filters.
                  </td>
                </tr>
              ) : (
                entries.map((e) => (
                  <tr key={e.id} className="border-t border-[color:var(--color-border)] align-top">
                    <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                      {new Date(e.occurred_at).toLocaleString()}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{e.action}</td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                      {e.target ?? "—"}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                      {e.user_id ? e.user_id.slice(0, 8) : "system"}
                    </td>
                    <td className="px-4 py-3">
                      {e.metadata ? (
                        <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-md bg-[color:var(--color-muted)] p-2 font-mono text-[11px] leading-5 text-[color:var(--color-muted-foreground)]">
                          {JSON.stringify(e.metadata, null, 2)}
                        </pre>
                      ) : (
                        <span className="text-[color:var(--color-muted-foreground)]">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </main>
    </AppShell>
  );
}
