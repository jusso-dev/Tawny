import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import type { Route } from "next";
import { ArrowLeft } from "lucide-react";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiGet } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import { CaseDetailPanel, type CaseDetail } from "./case-detail-panel";

type Agent = { id: string; hostname: string; status: string };

export default async function CaseDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const { id } = await params;
  const role = authRole(session.user);

  let caseDetail: CaseDetail;
  try {
    caseDetail = await apiGet<CaseDetail>(`/api/cases/${id}`, session.user.id, role);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }
  const agents = await apiGet<Agent[]>("/api/agents", session.user.id, role).catch(() => []);

  return (
    <AppShell agents={agents} active="cases">
      <main className="mx-auto max-w-5xl px-6 py-8">
        <Link
          href={"/cases" as Route}
          className="inline-flex items-center gap-2 text-sm text-[color:var(--color-muted-foreground)] hover:text-[color:var(--color-foreground)]"
        >
          <ArrowLeft size={15} />
          All cases
        </Link>
        <CaseDetailPanel initial={caseDetail} role={role} />
      </main>
    </AppShell>
  );
}
