import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Image from "next/image";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { apiGet } from "@/lib/api";
import { StatusBadge } from "@/components/ui/status-badge";

type Agent = {
  id: string;
  hostname: string;
  operating_system: "windows" | "macos";
  os_version: string;
  agent_version: string;
  architecture: "x64" | "arm64";
  status: "online" | "stale" | "offline" | "unknown";
  last_heartbeat_at: string | null;
  enrolled_at: string;
};

export default async function AgentsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const agents = await apiGet<Agent[]>("/api/agents", session.user.id, "Admin");

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <header className="flex items-end justify-between">
        <div className="flex items-center gap-3">
          <Image
            src="/logo.jpg"
            alt=""
            width={40}
            height={40}
            className="rounded"
          />
          <div>
            <h1 className="text-2xl font-semibold">Agents</h1>
            <p className="text-sm text-[color:var(--color-muted-foreground)]">
              {agents.length} enrolled
            </p>
          </div>
        </div>
        <Link
          href="/enrollment"
          className="rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-medium text-black hover:opacity-90"
        >
          New enrollment token
        </Link>
      </header>

      <div className="mt-8 overflow-hidden rounded-lg border border-[color:var(--color-border)]">
        <table className="w-full text-sm">
          <thead className="bg-[color:var(--color-muted)] text-left">
            <tr>
              <th className="px-4 py-3 font-medium">Hostname</th>
              <th className="px-4 py-3 font-medium">OS</th>
              <th className="px-4 py-3 font-medium">Version</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {agents.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                  No agents yet.{" "}
                  <Link href="/enrollment" className="underline">
                    Create an enrollment token
                  </Link>{" "}
                  to onboard your first endpoint.
                </td>
              </tr>
            )}
            {agents.map((a) => (
              <tr key={a.id} className="border-t border-[color:var(--color-border)]">
                <td className="px-4 py-3">
                  <Link href={`/agents/${a.id}`} className="font-medium hover:underline">
                    {a.hostname}
                  </Link>
                </td>
                <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">
                  {a.operating_system} {a.os_version} ({a.architecture})
                </td>
                <td className="px-4 py-3 font-mono text-xs">{a.agent_version}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={a.status} />
                </td>
                <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">
                  {a.last_heartbeat_at
                    ? new Date(a.last_heartbeat_at).toLocaleString()
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
