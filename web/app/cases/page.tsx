import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";
import type { Route } from "next";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { CreateCaseButton } from "./create-case-button";

type Agent = { id: string; hostname: string; status: string };

export type CaseSummary = {
  id: number;
  title: string;
  summary: string | null;
  status: "open" | "investigating" | "contained" | "resolved" | "closed";
  priority: "low" | "medium" | "high" | "critical";
  assigned_to_user_id: string | null;
  created_by_user_id: string | null;
  alert_count: number;
  note_count: number;
  mitre_techniques: string[];
  created_at: string;
  updated_at: string;
  closed_at: string | null;
};

const STATUS_TONE: Record<CaseSummary["status"], string> = {
  open: "bg-[color:var(--color-warning)]/15 text-[color:var(--color-warning)]",
  investigating: "bg-[color:var(--color-accent)]/15 text-[color:var(--color-accent)]",
  contained: "bg-[color:var(--color-warning)]/15 text-[color:var(--color-warning)]",
  resolved: "bg-[color:var(--color-success)]/15 text-[color:var(--color-success)]",
  closed: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)]",
};

const PRIORITY_TONE: Record<CaseSummary["priority"], string> = {
  low: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)]",
  medium: "bg-[color:var(--color-accent)]/15 text-[color:var(--color-accent)]",
  high: "bg-[color:var(--color-warning)]/15 text-[color:var(--color-warning)]",
  critical: "bg-[color:var(--color-danger)]/15 text-[color:var(--color-danger)]",
};

export default async function CasesPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const [cases, agents] = await Promise.all([
    apiGet<CaseSummary[]>("/api/cases?limit=100", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="cases">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Cases"
          title="Investigations"
          description="Group related alerts into a single case, keep investigation notes, and track status from open through resolved."
          actions={<CreateCaseButton />}
        />

        <div className="mt-6 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
          <table className="w-full text-sm">
            <thead className="bg-[color:var(--color-muted)] text-left">
              <tr>
                <th className="px-4 py-3 font-medium">Title</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Priority</th>
                <th className="px-4 py-3 font-medium">Alerts</th>
                <th className="px-4 py-3 font-medium">Notes</th>
                <th className="px-4 py-3 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {cases.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                    No cases yet. Use the button above, or POST to /api/cases.
                  </td>
                </tr>
              ) : (
                cases.map((c) => (
                  <tr key={c.id} className="border-t border-[color:var(--color-border)] align-top">
                    <td className="px-4 py-3">
                      <Link
                        href={`/cases/${c.id}` as Route}
                        className="font-medium hover:text-[color:var(--color-accent)] hover:underline"
                      >
                        {c.title}
                      </Link>
                      {c.summary ? (
                        <p className="mt-1 truncate text-xs text-[color:var(--color-muted-foreground)]">
                          {c.summary}
                        </p>
                      ) : null}
                      {c.mitre_techniques.length > 0 ? (
                        <p className="mt-1 flex flex-wrap gap-1">
                          {c.mitre_techniques.map((t) => (
                            <span
                              key={t}
                              className="rounded-full bg-[color:var(--color-muted)] px-2 py-0.5 font-mono text-[10px] text-[color:var(--color-muted-foreground)]"
                            >
                              {t}
                            </span>
                          ))}
                        </p>
                      ) : null}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-1 text-xs font-medium capitalize ${STATUS_TONE[c.status]}`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-1 text-xs font-medium capitalize ${PRIORITY_TONE[c.priority]}`}
                      >
                        {c.priority}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">{c.alert_count}</td>
                    <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">{c.note_count}</td>
                    <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                      {new Date(c.updated_at).toLocaleString()}
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
