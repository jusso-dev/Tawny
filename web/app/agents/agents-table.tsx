"use client";

import Link from "next/link";
import type { Route } from "next";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { StatusBadge } from "@/components/ui/status-badge";

type Agent = {
  id: string;
  hostname: string;
  operating_system: "windows" | "macos" | "linux";
  os_version: string;
  agent_version: string;
  architecture: "x64" | "arm64";
  status: "online" | "stale" | "offline" | "unknown";
  last_heartbeat_at: string | null;
  enrolled_at: string;
};

export function AgentsTable({ agents }: { agents: Agent[] }) {
  const router = useRouter();
  const [activeIndex, setActiveIndex] = useState(0);

  function move(delta: number) {
    setActiveIndex((current) => {
      if (agents.length === 0) return 0;
      return Math.max(0, Math.min(agents.length - 1, current + delta));
    });
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      move(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1);
    } else if (event.key === "Enter" && agents[activeIndex]) {
      event.preventDefault();
      router.push(`/agents/${agents[activeIndex].id}` as Route);
    }
  }

  return (
    <>
      <div
        className="mt-5 hidden overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] focus:outline-none focus:ring-2 focus:ring-[color:var(--color-accent)] md:block"
        tabIndex={0}
        onKeyDown={onKeyDown}
        aria-label="Agents table"
      >
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
                  <Link href="/enrollment" className="text-[color:var(--color-accent)] underline underline-offset-4">
                    Create an enrollment token
                  </Link>{" "}
                  to onboard your first endpoint.
                </td>
              </tr>
            )}
            {agents.map((agent, index) => (
              <tr
                key={agent.id}
                className={`border-t border-[color:var(--color-border)] transition-colors ${
                  index === activeIndex ? "bg-[color:var(--color-muted)]/70" : "hover:bg-[color:var(--color-muted)]/45"
                }`}
                aria-selected={index === activeIndex}
                onMouseEnter={() => setActiveIndex(index)}
              >
                <td className="px-4 py-3">
                  <Link href={`/agents/${agent.id}`} className="font-medium hover:text-[color:var(--color-accent)]">
                    {agent.hostname}
                  </Link>
                </td>
                <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">
                  {agent.operating_system} {agent.os_version} ({agent.architecture})
                </td>
                <td className="px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                  {agent.agent_version}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={agent.status} />
                </td>
                <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">
                  {agent.last_heartbeat_at ? new Date(agent.last_heartbeat_at).toLocaleString() : "Never"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-5 space-y-3 md:hidden" aria-label="Agents">
        {agents.length === 0 ? (
          <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-4 py-8 text-center text-sm text-[color:var(--color-muted-foreground)]">
            <p>No agents yet.</p>
            <Link
              href="/enrollment"
              className="mt-3 inline-flex min-h-11 items-center whitespace-nowrap text-[color:var(--color-accent)] underline underline-offset-4"
            >
              Create an enrollment token
            </Link>
          </div>
        ) : null}

        {agents.map((agent) => (
          <Link
            key={agent.id}
            href={`/agents/${agent.id}`}
            className="block rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-4 transition-colors hover:bg-[color:var(--color-muted)]/45"
          >
            <div className="flex min-w-0 items-start justify-between gap-3">
              <span className="min-w-0 truncate font-medium">{agent.hostname}</span>
              <StatusBadge status={agent.status} />
            </div>
            <dl className="mt-4 grid grid-cols-[5rem_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
              <dt className="text-[color:var(--color-muted-foreground)]">OS</dt>
              <dd className="min-w-0 break-words text-right">
                {agent.operating_system} {agent.os_version} ({agent.architecture})
              </dd>
              <dt className="text-[color:var(--color-muted-foreground)]">Version</dt>
              <dd className="font-mono text-right text-xs">{agent.agent_version}</dd>
              <dt className="text-[color:var(--color-muted-foreground)]">Last seen</dt>
              <dd className="text-right text-[color:var(--color-muted-foreground)]">
                {agent.last_heartbeat_at ? new Date(agent.last_heartbeat_at).toLocaleString() : "Never"}
              </dd>
            </dl>
          </Link>
        ))}
      </div>
    </>
  );
}
