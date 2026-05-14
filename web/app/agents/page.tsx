import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Image from "next/image";
import Link from "next/link";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AgentsTable } from "./agents-table";
import { CommandPalette } from "@/components/command-palette";
import { ThemeToggle } from "@/components/theme-toggle";

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
  const session = process.env.TAWNY_E2E_AUTH_BYPASS === "1"
    ? { user: { id: "e2e-admin", role: "Admin" } }
    : await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const agents = await apiGet<Agent[]>("/api/agents", session.user.id, authRole(session.user));

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <CommandPalette agents={agents} />
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
        <div className="flex items-center gap-3">
          <ThemeToggle />
          <Link
            href="/enrollment"
            className="rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-medium text-black hover:opacity-90"
          >
            New enrollment token
          </Link>
        </div>
      </header>

      <AgentsTable agents={agents} />
    </main>
  );
}
