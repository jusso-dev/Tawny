"use client";

import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import type { ProcessRow } from "./events-panel";

type TreeNode = ProcessRow & {
  children: TreeNode[];
};

export function ProcessTreeView({ processes }: { processes: ProcessRow[] }) {
  const [filter, setFilter] = useState("");

  const { roots, totalNodes } = useMemo(() => buildForest(processes), [processes]);
  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return roots;
    return filterTree(roots, (n) =>
      n.name.toLowerCase().includes(needle)
      || (n.command_line ?? "").toLowerCase().includes(needle)
      || String(n.pid).includes(needle));
  }, [roots, filter]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">Process tree</h3>
          <p className="text-xs text-[color:var(--color-muted-foreground)]">
            {totalNodes} processes from the latest snapshot, nested by parent_pid.
          </p>
        </div>
        <label className="relative block w-full max-w-xs">
          <Search
            size={14}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-muted-foreground)]"
          />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by name, pid, command"
            className="min-h-9 w-full rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] pl-9 pr-3 text-sm"
          />
        </label>
      </div>

      {filtered.length === 0 ? (
        <p className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-muted)] px-4 py-6 text-center text-sm text-[color:var(--color-muted-foreground)]">
          No processes match this filter.
        </p>
      ) : (
        <ul className="space-y-0.5 font-mono text-xs">
          {filtered.map((node) => (
            <TreeNodeView key={`${node.pid}-root`} node={node} depth={0} defaultOpen />
          ))}
        </ul>
      )}
    </div>
  );
}

function TreeNodeView({
  node,
  depth,
  defaultOpen = false,
}: {
  node: TreeNode;
  depth: number;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen || depth < 2);
  const hasChildren = node.children.length > 0;
  return (
    <li>
      <div
        className="flex items-start gap-2 rounded px-2 py-1 hover:bg-[color:var(--color-muted)]/60"
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
      >
        <button
          type="button"
          onClick={() => setOpen((current) => !current)}
          disabled={!hasChildren}
          aria-expanded={open}
          className="flex h-5 w-5 shrink-0 items-center justify-center rounded text-[color:var(--color-muted-foreground)] hover:text-[color:var(--color-foreground)] disabled:opacity-30"
        >
          {hasChildren ? (open ? <ChevronDown size={14} /> : <ChevronRight size={14} />) : null}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-3">
            <span className="font-semibold text-[color:var(--color-foreground)]">{node.name}</span>
            <span className="text-[color:var(--color-muted-foreground)]">pid {node.pid}</span>
            {typeof node.ppid === "number" ? (
              <span className="text-[color:var(--color-muted-foreground)]">ppid {node.ppid}</span>
            ) : null}
          </div>
          {node.command_line ? (
            <p className="truncate text-[color:var(--color-muted-foreground)]" title={node.command_line}>
              {node.command_line}
            </p>
          ) : null}
        </div>
      </div>
      {hasChildren && open ? (
        <ul className="space-y-0.5">
          {node.children.map((child) => (
            <TreeNodeView key={`${node.pid}-${child.pid}`} node={child} depth={depth + 1} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function buildForest(processes: ProcessRow[]): { roots: TreeNode[]; totalNodes: number } {
  const byPid = new Map<number, TreeNode>();
  for (const p of processes) {
    byPid.set(p.pid, { ...p, children: [] });
  }
  const roots: TreeNode[] = [];
  for (const node of byPid.values()) {
    if (node.ppid && byPid.has(node.ppid) && node.ppid !== node.pid) {
      byPid.get(node.ppid)!.children.push(node);
    } else {
      roots.push(node);
    }
  }
  // Sort each level by name for stable display.
  const sortAll = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => a.name.localeCompare(b.name) || a.pid - b.pid);
    nodes.forEach((n) => sortAll(n.children));
  };
  sortAll(roots);
  return { roots, totalNodes: byPid.size };
}

function filterTree(nodes: TreeNode[], predicate: (n: TreeNode) => boolean): TreeNode[] {
  const out: TreeNode[] = [];
  for (const n of nodes) {
    const kids = filterTree(n.children, predicate);
    if (predicate(n) || kids.length > 0) {
      out.push({ ...n, children: kids });
    }
  }
  return out;
}
