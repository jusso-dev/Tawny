"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { CheckCircle2, Loader2, MessageSquarePlus, Trash2 } from "lucide-react";

export type CaseDetail = {
  id: number;
  title: string;
  summary: string | null;
  status: "open" | "investigating" | "contained" | "resolved" | "closed";
  priority: "low" | "medium" | "high" | "critical";
  assigned_to_user_id: string | null;
  created_by_user_id: string | null;
  mitre_techniques: string[];
  alerts: Array<{
    id: number;
    alert_id: number;
    alert_title: string;
    alert_hostname: string;
    alert_severity: string;
    alert_created_at: string;
    added_at: string;
  }>;
  notes: Array<{
    id: number;
    author_user_id: string | null;
    body: string;
    created_at: string;
  }>;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
};

const STATUS_OPTIONS: CaseDetail["status"][] = ["open", "investigating", "contained", "resolved", "closed"];
const PRIORITY_OPTIONS: CaseDetail["priority"][] = ["low", "medium", "high", "critical"];

export function CaseDetailPanel({ initial, role }: { initial: CaseDetail; role: "Admin" | "Viewer" }) {
  const router = useRouter();
  const [caseDetail, setCaseDetail] = useState(initial);
  const [editing, setEditing] = useState(false);
  const [savingMeta, setSavingMeta] = useState(false);
  const [noteBody, setNoteBody] = useState("");
  const [addingNote, setAddingNote] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [title, setTitle] = useState(caseDetail.title);
  const [summary, setSummary] = useState(caseDetail.summary ?? "");
  const [status, setStatus] = useState(caseDetail.status);
  const [priority, setPriority] = useState(caseDetail.priority);
  const [techniques, setTechniques] = useState(caseDetail.mitre_techniques.join(", "));

  async function saveMeta() {
    setError(null);
    setSavingMeta(true);
    try {
      const techList = techniques
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0);
      const res = await fetch(`/api/cases/${caseDetail.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: title.trim(),
          summary: summary.trim() || null,
          status,
          priority,
          assigned_to_user_id: caseDetail.assigned_to_user_id,
          mitre_techniques: techList,
        }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? `Save failed with ${res.status}`);
      }
      setEditing(false);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed.");
    } finally {
      setSavingMeta(false);
    }
  }

  async function addNote() {
    if (!noteBody.trim()) return;
    setError(null);
    setAddingNote(true);
    try {
      const res = await fetch(`/api/cases/${caseDetail.id}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: noteBody.trim() }),
      });
      const body = (await res.json().catch(() => null)) as
        | { id: number; author_user_id: string | null; body: string; created_at: string; error?: string }
        | null;
      if (!res.ok || !body || "error" in body) {
        throw new Error((body && "error" in body && body.error) || `Add note failed with ${res.status}`);
      }
      setNoteBody("");
      setCaseDetail((current) => ({
        ...current,
        notes: [
          {
            id: body.id,
            author_user_id: body.author_user_id,
            body: body.body,
            created_at: body.created_at,
          },
          ...current.notes,
        ],
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Add note failed.");
    } finally {
      setAddingNote(false);
    }
  }

  async function removeAlert(alertId: number) {
    if (!window.confirm("Unlink this alert from the case?")) return;
    const res = await fetch(`/api/cases/${caseDetail.id}/alerts/${alertId}`, { method: "DELETE" });
    if (res.ok) {
      setCaseDetail((current) => ({
        ...current,
        alerts: current.alerts.filter((a) => a.alert_id !== alertId),
      }));
      router.refresh();
    }
  }

  return (
    <div className="mt-4 grid gap-5">
      {editing ? (
        <section className="grid gap-3 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-5">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Title</span>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Summary</span>
            <textarea
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              className="min-h-20 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-2 text-sm"
            />
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Status</span>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as CaseDetail["status"])}
                className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm capitalize"
              >
                {STATUS_OPTIONS.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Priority</span>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as CaseDetail["priority"])}
                className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm capitalize"
              >
                {PRIORITY_OPTIONS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">MITRE techniques (comma separated)</span>
            <input
              value={techniques}
              onChange={(e) => setTechniques(e.target.value)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
              placeholder="T1059.003, T1071.004"
            />
          </label>
          {error ? (
            <p className="rounded-md border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 px-3 py-2 text-sm text-[color:var(--color-danger)]">
              {error}
            </p>
          ) : null}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setEditing(false)}
              className="inline-flex min-h-9 items-center rounded-md border border-[color:var(--color-border)] px-3 text-sm hover:bg-[color:var(--color-muted)]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={saveMeta}
              disabled={savingMeta}
              className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white disabled:opacity-60"
            >
              {savingMeta ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
              Save
            </button>
          </div>
        </section>
      ) : (
        <header className="flex flex-col gap-3 border-b border-[color:var(--color-border)] pb-6 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">{caseDetail.title}</h1>
            {caseDetail.summary ? (
              <p className="mt-2 max-w-2xl text-sm text-[color:var(--color-muted-foreground)]">
                {caseDetail.summary}
              </p>
            ) : null}
            <p className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[color:var(--color-muted-foreground)]">
              <span className="rounded-full bg-[color:var(--color-muted)] px-2.5 py-1 capitalize">
                {caseDetail.status}
              </span>
              <span className="rounded-full bg-[color:var(--color-muted)] px-2.5 py-1 capitalize">
                {caseDetail.priority}
              </span>
              {caseDetail.mitre_techniques.map((t) => (
                <span
                  key={t}
                  className="rounded-full bg-[color:var(--color-muted)] px-2.5 py-1 font-mono"
                >
                  {t}
                </span>
              ))}
            </p>
          </div>
          {role === "Admin" ? (
            <button
              type="button"
              onClick={() => setEditing(true)}
              className="inline-flex min-h-9 items-center rounded-md border border-[color:var(--color-border)] px-3 text-sm hover:bg-[color:var(--color-muted)]"
            >
              Edit
            </button>
          ) : null}
        </header>
      )}

      <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <div className="flex items-center justify-between border-b border-[color:var(--color-border)] px-5 py-3">
          <h2 className="text-sm font-semibold">Linked alerts</h2>
          <span className="text-xs text-[color:var(--color-muted-foreground)]">{caseDetail.alerts.length} total</span>
        </div>
        {caseDetail.alerts.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-[color:var(--color-muted-foreground)]">
            Use <code className="font-mono text-xs">POST /api/cases/{caseDetail.id}/alerts</code> to link existing alert IDs.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-[color:var(--color-muted)] text-left">
              <tr>
                <th className="px-4 py-3 font-medium">Alert</th>
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Linked</th>
                <th className="px-4 py-3 font-medium" />
              </tr>
            </thead>
            <tbody>
              {caseDetail.alerts.map((a) => (
                <tr key={a.id} className="border-t border-[color:var(--color-border)]">
                  <td className="px-4 py-3 font-medium">{a.alert_title}</td>
                  <td className="px-4 py-3 text-[color:var(--color-muted-foreground)]">{a.alert_hostname}</td>
                  <td className="px-4 py-3 capitalize text-[color:var(--color-muted-foreground)]">{a.alert_severity}</td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {new Date(a.added_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => removeAlert(a.alert_id)}
                      className="inline-flex min-h-8 items-center gap-1 rounded-md border border-[color:var(--color-danger)]/40 px-2 text-xs text-[color:var(--color-danger)] hover:bg-[color:var(--color-danger)]/10"
                    >
                      <Trash2 size={12} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <div className="flex items-center justify-between border-b border-[color:var(--color-border)] px-5 py-3">
          <h2 className="text-sm font-semibold">Notes</h2>
          <span className="text-xs text-[color:var(--color-muted-foreground)]">{caseDetail.notes.length} total</span>
        </div>

        <div className="grid gap-3 border-b border-[color:var(--color-border)] px-5 py-4">
          <textarea
            value={noteBody}
            onChange={(e) => setNoteBody(e.target.value)}
            className="min-h-16 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-2 text-sm"
            placeholder="Append a note: what you checked, what you found, next step..."
          />
          <div className="flex justify-end">
            <button
              type="button"
              onClick={addNote}
              disabled={addingNote || noteBody.trim().length === 0}
              className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-3 text-sm font-medium text-white disabled:opacity-50"
            >
              {addingNote ? <Loader2 size={14} className="animate-spin" /> : <MessageSquarePlus size={14} />}
              Add note
            </button>
          </div>
        </div>

        {caseDetail.notes.length === 0 ? (
          <p className="px-5 py-8 text-center text-sm text-[color:var(--color-muted-foreground)]">
            No notes yet.
          </p>
        ) : (
          <ul className="divide-y divide-[color:var(--color-border)]">
            {caseDetail.notes.map((n) => (
              <li key={n.id} className="px-5 py-4">
                <p className="whitespace-pre-wrap text-sm">{n.body}</p>
                <p className="mt-2 text-xs text-[color:var(--color-muted-foreground)]">
                  {n.author_user_id ? `by ${n.author_user_id.slice(0, 8)}…, ` : ""}
                  {new Date(n.created_at).toLocaleString()}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
