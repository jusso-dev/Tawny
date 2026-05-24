import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";
import type { Route } from "next";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { NetworkGraphSvg } from "./network-graph-svg";

type Agent = { id: string; hostname: string; status: string };

type ProcessTreeHostHit = {
  agent_id: string;
  hostname: string;
  seen_count: number;
  last_seen: string;
};

type ProcessTreeRow = {
  process_name: string;
  host_count: number;
  total_seen: number;
  hosts: ProcessTreeHostHit[];
};

type ProcessTreeResponse = {
  rows: ProcessTreeRow[];
  from: string;
  to: string;
};

type NetworkGraphNode = {
  id: string;
  label: string;
  kind: "host" | "endpoint";
  weight: number;
};

type NetworkGraphEdge = {
  source_id: string;
  target_id: string;
  weight: number;
};

type NetworkGraphResponse = {
  nodes: NetworkGraphNode[];
  edges: NetworkGraphEdge[];
  from: string;
  to: string;
};

export default async function InvestigationPage({
  searchParams,
}: {
  searchParams: Promise<{ hours?: string; name?: string }>;
}) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const params = await searchParams;
  const hours = params.hours ?? "24";
  const name = params.name ?? "";
  const role = authRole(session.user);

  const treeQs = new URLSearchParams({ hours, limit: "50" });
  if (name) treeQs.set("nameFilter", name);
  const graphQs = new URLSearchParams({ hours, maxEndpoints: "60" });

  const [tree, graph, agents] = await Promise.all([
    apiGet<ProcessTreeResponse>(`/api/investigation/process-tree?${treeQs.toString()}`, session.user.id, role),
    apiGet<NetworkGraphResponse>(`/api/investigation/network-graph?${graphQs.toString()}`, session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="investigation">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Investigate"
          title="Cross-host views"
          description="Aggregations across every agent. Use these to spot the same binary on multiple hosts or to see who is talking to a given remote endpoint."
        />

        <form className="mt-6 flex flex-wrap items-center gap-3" action="/investigation">
          <label className="text-xs text-[color:var(--color-muted-foreground)]">Window</label>
          <select
            name="hours"
            defaultValue={hours}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          >
            <option value="1">1h</option>
            <option value="6">6h</option>
            <option value="24">24h</option>
            <option value="72">3d</option>
            <option value="168">7d</option>
          </select>
          <label className="text-xs text-[color:var(--color-muted-foreground)]">Process name contains</label>
          <input
            name="name"
            defaultValue={name}
            placeholder="optional filter"
            className="min-h-9 flex-1 min-w-48 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          />
          <button
            type="submit"
            className="inline-flex min-h-9 items-center rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white"
          >
            Apply
          </button>
        </form>

        <section className="mt-6 grid gap-3">
          <h2 className="text-sm font-semibold">Processes seen across hosts</h2>
          <div className="overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <table className="w-full text-sm">
              <thead className="bg-[color:var(--color-muted)] text-left">
                <tr>
                  <th className="px-4 py-3 font-medium">Process</th>
                  <th className="px-4 py-3 font-medium">Hosts</th>
                  <th className="px-4 py-3 font-medium">Total snapshots</th>
                  <th className="px-4 py-3 font-medium">Where</th>
                </tr>
              </thead>
              <tbody>
                {tree.rows.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-10 text-center text-[color:var(--color-muted-foreground)]">
                      No process snapshots in the selected window.
                    </td>
                  </tr>
                ) : (
                  tree.rows.map((row) => (
                    <tr key={row.process_name} className="border-t border-[color:var(--color-border)] align-top">
                      <td className="px-4 py-3 font-mono text-xs">{row.process_name}</td>
                      <td className="px-4 py-3">{row.host_count}</td>
                      <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">{row.total_seen}</td>
                      <td className="px-4 py-3 text-xs text-[color:var(--color-muted-foreground)]">
                        <div className="flex flex-wrap gap-1">
                          {row.hosts.slice(0, 6).map((h) => (
                            <Link
                              key={h.agent_id}
                              href={`/agents/${h.agent_id}` as Route}
                              className="rounded-full bg-[color:var(--color-muted)] px-2 py-0.5 hover:bg-[color:var(--color-muted)]/70 hover:text-[color:var(--color-foreground)]"
                            >
                              {h.hostname} ({h.seen_count})
                            </Link>
                          ))}
                          {row.hosts.length > 6 ? (
                            <span className="rounded-full bg-[color:var(--color-muted)] px-2 py-0.5">
                              +{row.hosts.length - 6} more
                            </span>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="mt-8 grid gap-3">
          <h2 className="text-sm font-semibold">Host → remote endpoint graph</h2>
          <p className="text-xs text-[color:var(--color-muted-foreground)]">
            {graph.nodes.length} nodes, {graph.edges.length} edges in the window. Edge width = number of observed connections.
          </p>
          <NetworkGraphSvg nodes={graph.nodes} edges={graph.edges} />
        </section>
      </main>
    </AppShell>
  );
}
