"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
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
      router.push(`/agents/${agents[activeIndex].id}`);
    }
  }

  return (
    <div
      className="mt-8 overflow-hidden rounded-lg border border-[color:var(--color-border)] focus:outline-none focus:ring-2 focus:ring-[color:var(--color-accent)]"
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
                <Link href="/enrollment" className="underline">
                  Create an enrollment token
                </Link>{" "}
                to onboard your first endpoint.
              </td>
            </tr>
          )}
          {agents.map((agent, index) => (
            <tr
              key={agent.id}
              className={`border-t border-[color:var(--color-border)] ${
                index === activeIndex ? "bg-[color:var(--color-muted)]/70" : ""
              }`}
              aria-selected={index === activeIndex}
              onMouseEnter={() => setActiveIndex(index)}
            >
              <td className="px-4 py-3">
                <Link href={`/agents/${agent.id}`} className="font-medium hover:underline">
                  {agent.hostname}
                </Link>
              </td>
              <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">
                {agent.operating_system} {agent.os_version} ({agent.architecture})
              </td>
              <td className="px-4 py-3 font-mono text-xs">{agent.agent_version}</td>
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
  );
}
