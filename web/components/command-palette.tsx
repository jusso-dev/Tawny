"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import { Activity, Search } from "lucide-react";
import { cn } from "@/lib/cn";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

export function CommandPalette({ agents }: { agents: Agent[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((value) => !value);
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  function goToAgent(id: string) {
    setOpen(false);
    router.push(`/agents/${id}`);
  }

  return (
    <Command.Dialog
      open={open}
      onOpenChange={setOpen}
      label="Jump to agent"
      className="fixed left-1/2 top-24 z-50 w-[min(92vw,42rem)] -translate-x-1/2 overflow-hidden rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-2 shadow-[0_24px_70px_oklch(0.08_0.01_58_/_0.35)]"
      overlayClassName="fixed inset-0 z-40 bg-[oklch(0.08_0.01_58_/_0.46)]"
    >
      <div className="flex min-h-12 items-center gap-3 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 shadow-inner shadow-[oklch(0.08_0.01_58_/_0.08)] focus-within:border-[color:var(--color-accent)] focus-within:ring-2 focus-within:ring-[color:var(--color-accent)]/20">
        <Search size={17} className="shrink-0 text-[color:var(--color-muted-foreground)]" />
        <Command.Input
          placeholder="Search agents by hostname"
          className="h-11 w-full bg-transparent text-sm outline-none placeholder:text-[color:var(--color-muted-foreground)]"
        />
        <kbd className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-muted)] px-1.5 py-0.5 text-[11px] text-[color:var(--color-muted-foreground)]">
          esc
        </kbd>
      </div>
      <Command.List className="mt-2 max-h-80 overflow-y-auto rounded-lg p-1">
        <Command.Empty className="px-3 py-10 text-center text-sm text-[color:var(--color-muted-foreground)]">
          No agents found.
        </Command.Empty>
        <Command.Group
          heading="Agents"
          className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pb-1.5 [&_[cmdk-group-heading]]:pt-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:text-[color:var(--color-muted-foreground)]"
        >
          {agents.map((agent) => (
            <Command.Item
              key={agent.id}
              value={`${agent.hostname} ${agent.status}`}
              onSelect={() => goToAgent(agent.id)}
              className="flex cursor-pointer items-center justify-between gap-4 rounded-lg px-3 py-2.5 text-sm text-[color:var(--color-foreground)] transition-colors aria-selected:bg-[color:var(--color-muted)] aria-selected:shadow-sm"
            >
              <span className="flex min-w-0 items-center gap-2.5">
                <span className="grid size-7 shrink-0 place-items-center rounded-md bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)]">
                  <Activity size={14} />
                </span>
                <span className="truncate font-medium">{agent.hostname}</span>
              </span>
              <span
                className={cn(
                  "inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 text-xs capitalize ring-1",
                  statusTone(agent.status),
                )}
              >
                <span className="size-1.5 rounded-full bg-current" />
                {agent.status}
              </span>
            </Command.Item>
          ))}
        </Command.Group>
      </Command.List>
    </Command.Dialog>
  );
}

function statusTone(status: string) {
  switch (status.toLowerCase()) {
    case "online":
      return "bg-[color:var(--color-success)]/12 text-[color:var(--color-success)] ring-[color:var(--color-success)]/25";
    case "stale":
      return "bg-[color:var(--color-warning)]/12 text-[color:var(--color-warning)] ring-[color:var(--color-warning)]/25";
    case "offline":
      return "bg-[color:var(--color-danger)]/12 text-[color:var(--color-danger)] ring-[color:var(--color-danger)]/25";
    default:
      return "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)] ring-[color:var(--color-border)]";
  }
}
