import { headers } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";
import type { Route } from "next";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

type PivotHit = {
  agent_id: string;
  hostname: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
};

type PivotResponse = {
  kind: string;
  value: string;
  host_count: number;
  hosts: PivotHit[];
};

export default async function PivotPage({
  searchParams,
}: {
  searchParams: Promise<{ value?: string; kind?: string; days?: string }>;
}) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const params = await searchParams;
  const value = params.value?.trim() ?? "";
  const kind = params.kind?.trim() ?? "any";
  const days = params.days?.trim() ?? "30";

  let result: PivotResponse | null = null;
  let pivotError: string | null = null;
  if (value) {
    try {
      const qs = new URLSearchParams({ kind, value, days });
      result = await apiGet<PivotResponse>(`/api/pivot?${qs.toString()}`, session.user.id, role);
    } catch (err) {
      pivotError = err instanceof ApiError ? err.message : "Pivot lookup failed.";
    }
  }

  const agents = await apiGet<Agent[]>("/api/agents", session.user.id, role).catch(() => []);

  return (
    <AppShell agents={agents} active="alerts">
      <main className="mx-auto max-w-4xl px-6 py-8">
        <PageHeader
          eyebrow="Cross-host pivot"
          title="Find every host that saw an indicator"
          description="Searches the last 30 days of telemetry for a hash, IP, or domain. Use it to scope an incident across the fleet."
        />

        <form className="mt-6 grid gap-3 sm:grid-cols-[6rem_1fr_5rem_auto]" action="/pivot">
          <select
            name="kind"
            defaultValue={kind}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          >
            <option value="any">Any</option>
            <option value="sha256">SHA-256</option>
            <option value="sha1">SHA-1</option>
            <option value="ipv4">IPv4</option>
            <option value="domain">Domain</option>
          </select>
          <input
            name="value"
            defaultValue={value}
            placeholder="paste an IP, hash, or domain"
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
          />
          <input
            name="days"
            defaultValue={days}
            type="number"
            min="1"
            max="365"
            title="Days to search back"
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          />
          <button
            type="submit"
            className="inline-flex min-h-9 items-center rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white"
          >
            Pivot
          </button>
        </form>

        {pivotError ? (
          <p className="mt-6 rounded-md border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 px-4 py-3 text-sm text-[color:var(--color-danger)]">
            {pivotError}
          </p>
        ) : null}

        {result ? (
          <section className="mt-6 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <div className="flex items-center justify-between border-b border-[color:var(--color-border)] px-5 py-3">
              <h2 className="text-sm font-semibold">
                {result.host_count} {result.host_count === 1 ? "host" : "hosts"} matched
              </h2>
              <code className="font-mono text-xs text-[color:var(--color-muted-foreground)]">{result.value}</code>
            </div>
            {result.hosts.length === 0 ? (
              <p className="px-5 py-10 text-center text-sm text-[color:var(--color-muted-foreground)]">
                No host has telemetry containing this value in the selected window.
              </p>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-[color:var(--color-muted)] text-left">
                  <tr>
                    <th className="px-4 py-3 font-medium">Hostname</th>
                    <th className="px-4 py-3 font-medium">Events</th>
                    <th className="px-4 py-3 font-medium">First seen</th>
                    <th className="px-4 py-3 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {result.hosts.map((h) => (
                    <tr key={h.agent_id} className="border-t border-[color:var(--color-border)]">
                      <td className="px-4 py-3 font-medium">
                        <Link
                          href={`/agents/${h.agent_id}` as Route}
                          className="hover:text-[color:var(--color-accent)] hover:underline"
                        >
                          {h.hostname}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">{h.event_count}</td>
                      <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                        {new Date(h.first_seen).toLocaleString()}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                        {new Date(h.last_seen).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        ) : null}
      </main>
    </AppShell>
  );
}
