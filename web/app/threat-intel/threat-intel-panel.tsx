"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, PlayCircle, Plus, Radio, Trash2, X } from "lucide-react";

export type TiFeed = {
  id: string;
  name: string;
  kind: "urlhaus_csv" | "urlhaus_json" | "otx_pulse" | "misp_events" | "taxii21" | "generic_csv";
  url: string;
  auth_header_name: string | null;
  default_severity: "low" | "medium" | "high" | "critical";
  interval_minutes: number;
  is_enabled: boolean;
  status: "healthy" | "degraded" | "failed" | "never_run";
  last_run_at: string | null;
  last_success_at: string | null;
  last_imported_count: number;
  last_skipped_count: number;
  last_error: string | null;
  created_at: string;
  updated_at: string;
};

const FEED_KINDS: TiFeed["kind"][] = ["urlhaus_csv", "urlhaus_json", "otx_pulse", "misp_events", "taxii21", "generic_csv"];

const STATUS_TONE: Record<TiFeed["status"], string> = {
  healthy: "bg-[color:var(--color-success)]/15 text-[color:var(--color-success)]",
  degraded: "bg-[color:var(--color-warning)]/15 text-[color:var(--color-warning)]",
  failed: "bg-[color:var(--color-danger)]/15 text-[color:var(--color-danger)]",
  never_run: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)]",
};

export function ThreatIntelPanel({ initial, role }: { initial: TiFeed[]; role: "Admin" | "Viewer" }) {
  const router = useRouter();
  const [feeds, setFeeds] = useState<TiFeed[]>(initial);
  const [creating, setCreating] = useState(false);
  const [running, setRunning] = useState<string | null>(null);
  const canEdit = role === "Admin";

  async function deleteFeed(id: string) {
    if (!window.confirm("Delete this feed? Existing imported IoCs will stay as alert rules.")) return;
    const res = await fetch(`/api/threat-intel-feeds/${id}`, { method: "DELETE" });
    if (res.ok) {
      setFeeds((current) => current.filter((f) => f.id !== id));
      router.refresh();
    }
  }

  async function runFeed(id: string) {
    setRunning(id);
    try {
      const res = await fetch(`/api/threat-intel-feeds/${id}/run`, { method: "POST" });
      const body = (await res.json().catch(() => null)) as TiFeed | { error?: string } | null;
      if (res.ok && body && !("error" in body)) {
        setFeeds((current) => current.map((f) => (f.id === id ? (body as TiFeed) : f)));
        router.refresh();
      }
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="mt-6 grid gap-5">
      {canEdit ? (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-3 text-sm font-medium text-white"
          >
            <Plus size={14} /> New feed
          </button>
        </div>
      ) : null}

      <section className="overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <table className="w-full text-sm">
          <thead className="bg-[color:var(--color-muted)] text-left">
            <tr>
              <th className="px-4 py-3 font-medium">Feed</th>
              <th className="px-4 py-3 font-medium">Kind</th>
              <th className="px-4 py-3 font-medium">Interval</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Last run</th>
              <th className="px-4 py-3 font-medium" />
            </tr>
          </thead>
          <tbody>
            {feeds.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                  No TI feeds configured yet.
                </td>
              </tr>
            ) : (
              feeds.map((f) => (
                <tr key={f.id} className="border-t border-[color:var(--color-border)] align-top">
                  <td className="px-4 py-3">
                    <p className="font-medium">{f.name}</p>
                    <p className="mt-1 truncate font-mono text-[10px] text-[color:var(--color-muted-foreground)]">
                      {f.url}
                    </p>
                    {f.last_error ? (
                      <p className="mt-1 truncate text-xs text-[color:var(--color-danger)]" title={f.last_error}>
                        {f.last_error}
                      </p>
                    ) : null}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                    {f.kind}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {f.interval_minutes}m
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    <span className={`rounded-full px-2 py-1 text-xs font-medium ${STATUS_TONE[f.status]}`}>
                      {f.status.replace("_", " ")}
                    </span>
                    {!f.is_enabled ? (
                      <span className="ml-2 rounded-full bg-[color:var(--color-muted)] px-2 py-1 text-[10px] text-[color:var(--color-muted-foreground)]">
                        disabled
                      </span>
                    ) : null}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {f.last_run_at ? (
                      <>
                        <p>{new Date(f.last_run_at).toLocaleString()}</p>
                        <p className="text-xs">
                          +{f.last_imported_count} new
                          {f.last_skipped_count > 0 ? `, ${f.last_skipped_count} skipped` : ""}
                        </p>
                      </>
                    ) : (
                      "Never"
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {canEdit ? (
                      <div className="flex justify-end gap-1">
                        <button
                          type="button"
                          onClick={() => runFeed(f.id)}
                          disabled={running === f.id}
                          className="inline-flex min-h-8 items-center gap-1 rounded-md border border-[color:var(--color-border)] px-2 text-xs hover:bg-[color:var(--color-muted)] disabled:opacity-60"
                          title="Run now"
                        >
                          {running === f.id ? <Loader2 size={12} className="animate-spin" /> : <PlayCircle size={12} />}
                        </button>
                        <button
                          type="button"
                          onClick={() => deleteFeed(f.id)}
                          className="inline-flex min-h-8 items-center gap-1 rounded-md border border-[color:var(--color-danger)]/40 px-2 text-xs text-[color:var(--color-danger)] hover:bg-[color:var(--color-danger)]/10"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>

      {creating ? (
        <CreateFeedDialog
          onClose={() => setCreating(false)}
          onCreated={(feed) => {
            setFeeds((current) => [feed, ...current]);
            setCreating(false);
            router.refresh();
          }}
        />
      ) : null}
    </div>
  );
}

function CreateFeedDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (feed: TiFeed) => void;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<TiFeed["kind"]>("urlhaus_csv");
  const [url, setUrl] = useState("https://urlhaus.abuse.ch/downloads/csv_recent/");
  const [authHeaderName, setAuthHeaderName] = useState("");
  const [authHeaderValue, setAuthHeaderValue] = useState("");
  const [severity, setSeverity] = useState<TiFeed["default_severity"]>("high");
  const [interval, setInterval] = useState("60");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    setPending(true);
    try {
      const res = await fetch("/api/threat-intel-feeds", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          kind,
          url: url.trim(),
          auth_header_name: authHeaderName.trim() || null,
          auth_header_value: authHeaderValue.trim() || null,
          default_severity: severity,
          interval_minutes: parseInt(interval, 10) || 60,
          is_enabled: true,
        }),
      });
      const body = (await res.json().catch(() => null)) as TiFeed | { error?: string } | null;
      if (!res.ok || !body || "error" in body) {
        throw new Error((body && "error" in body && body.error) || `Create failed with ${res.status}`);
      }
      onCreated(body as TiFeed);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 px-4" role="dialog">
      <div className="grid w-full max-w-lg gap-3 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">New threat intel feed</h2>
          <button type="button" onClick={onClose} className="rounded-md p-1 hover:bg-[color:var(--color-muted)]">
            <X size={16} />
          </button>
        </div>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
            placeholder="abuse.ch URLhaus"
          />
        </label>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Kind</span>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as TiFeed["kind"])}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          >
            {FEED_KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">URL</span>
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
          />
        </label>

        <div className="grid gap-2 sm:grid-cols-2">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Auth header name (optional)</span>
            <input
              value={authHeaderName}
              onChange={(e) => setAuthHeaderName(e.target.value)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
              placeholder="X-OTX-API-KEY"
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Auth header value</span>
            <input
              value={authHeaderValue}
              onChange={(e) => setAuthHeaderValue(e.target.value)}
              type="password"
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
            />
          </label>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Default severity</span>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as TiFeed["default_severity"])}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm capitalize"
            >
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Interval (minutes)</span>
            <input
              value={interval}
              onChange={(e) => setInterval(e.target.value)}
              type="number"
              min="5"
              max="10080"
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
            />
          </label>
        </div>

        {error ? (
          <p className="rounded-md border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 px-3 py-2 text-sm text-[color:var(--color-danger)]">
            {error}
          </p>
        ) : null}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="inline-flex min-h-9 items-center rounded-md border border-[color:var(--color-border)] px-3 text-sm hover:bg-[color:var(--color-muted)]"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={pending}
            className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white disabled:opacity-60"
          >
            {pending ? <Loader2 size={14} className="animate-spin" /> : <Radio size={14} />}
            Create
          </button>
        </div>
      </div>
    </div>
  );
}
