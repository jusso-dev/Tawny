"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import { Search } from "lucide-react";

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
      className="fixed left-1/2 top-24 z-50 w-[min(92vw,40rem)] -translate-x-1/2 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-background)] shadow-2xl"
      overlayClassName="fixed inset-0 z-40 bg-black/40"
    >
      <div className="flex items-center gap-3 border-b border-[color:var(--color-border)] px-4 py-3">
        <Search size={18} className="text-[color:var(--color-muted-foreground)]" />
        <Command.Input
          placeholder="Search agents by hostname"
          className="w-full bg-transparent text-sm outline-none placeholder:text-[color:var(--color-muted-foreground)]"
        />
        <kbd className="rounded border border-[color:var(--color-border)] px-1.5 py-0.5 text-xs text-[color:var(--color-muted-foreground)]">
          esc
        </kbd>
      </div>
      <Command.List className="max-h-80 overflow-y-auto p-2">
        <Command.Empty className="px-3 py-8 text-center text-sm text-[color:var(--color-muted-foreground)]">
          No agents found.
        </Command.Empty>
        <Command.Group heading="Agents" className="text-xs text-[color:var(--color-muted-foreground)]">
          {agents.map((agent) => (
            <Command.Item
              key={agent.id}
              value={`${agent.hostname} ${agent.status}`}
              onSelect={() => goToAgent(agent.id)}
              className="flex cursor-pointer items-center justify-between rounded-md px-3 py-2 text-sm text-[color:var(--color-foreground)] aria-selected:bg-[color:var(--color-muted)]"
            >
              <span className="font-medium">{agent.hostname}</span>
              <span className="text-xs capitalize text-[color:var(--color-muted-foreground)]">
                {agent.status}
              </span>
            </Command.Item>
          ))}
        </Command.Group>
      </Command.List>
    </Command.Dialog>
  );
}
