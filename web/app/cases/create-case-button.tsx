"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Route } from "next";
import { Loader2, Plus, X } from "lucide-react";

export function CreateCaseButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [priority, setPriority] = useState<"low" | "medium" | "high" | "critical">("medium");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (!title.trim()) {
      setError("Title is required.");
      return;
    }
    setPending(true);
    try {
      const res = await fetch("/api/cases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: title.trim(),
          summary: summary.trim() || null,
          priority,
        }),
      });
      const body = (await res.json().catch(() => null)) as { id?: number; error?: string } | null;
      if (!res.ok || !body || "error" in body) {
        throw new Error((body && "error" in body && body.error) || `Create failed with ${res.status}`);
      }
      setOpen(false);
      setTitle("");
      setSummary("");
      router.push((`/cases/${(body as { id: number }).id}`) as Route);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex min-h-10 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white"
      >
        <Plus size={14} /> New case
      </button>

      {open ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 px-4" role="dialog">
          <div className="grid w-full max-w-md gap-3 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">New case</h2>
              <button type="button" onClick={() => setOpen(false)} className="rounded-md p-1 hover:bg-[color:var(--color-muted)]">
                <X size={16} />
              </button>
            </div>

            <label className="grid gap-1 text-sm">
              <span className="font-medium">Title</span>
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
                placeholder="Possible C2 beaconing from db-01"
              />
            </label>

            <label className="grid gap-1 text-sm">
              <span className="font-medium">Summary</span>
              <textarea
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                className="min-h-20 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-2 text-sm"
                placeholder="What triggered the investigation, scope, owner, etc."
              />
            </label>

            <label className="grid gap-1 text-sm">
              <span className="font-medium">Priority</span>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as typeof priority)}
                className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm capitalize"
              >
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </label>

            {error ? (
              <p className="rounded-md border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 px-3 py-2 text-sm text-[color:var(--color-danger)]">
                {error}
              </p>
            ) : null}

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="inline-flex min-h-9 items-center rounded-md border border-[color:var(--color-border)] px-3 text-sm hover:bg-[color:var(--color-muted)]"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={submit}
                disabled={pending}
                className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-60"
              >
                {pending ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
                Create
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
