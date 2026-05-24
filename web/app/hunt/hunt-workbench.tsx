"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, BookmarkPlus, Calendar, Lock, Loader2, Pencil, Play, Save, Trash2, X } from "lucide-react";

export type SavedHunt = {
  id: string;
  name: string;
  description: string | null;
  query: string;
  is_scheduled: boolean;
  schedule_cron: string | null;
  alert_on_match: boolean;
  alert_severity: "low" | "medium" | "high" | "critical";
  mitre_techniques: string[];
  is_shared: boolean;
  created_by_user_id: string | null;
  last_run_at: string | null;
  last_match_count: number | null;
  created_at: string;
  updated_at: string;
};

type HuntMatch = {
  event_id: number;
  agent_id: string;
  hostname: string;
  event_type: string;
  occurred_at: string;
  received_at: string;
  payload: unknown;
};

type RunResponse = {
  match_count: number;
  matches: HuntMatch[];
  warnings: string[];
};

const STARTER_QUERIES: { label: string; query: string }[] = [
  {
    label: "PowerShell with EncodedCommand",
    query: 'event_type:process_snapshot AND processes.command_line:"-EncodedCommand"',
  },
  {
    label: "Connections to 1.1.1.1 in last 6h",
    query: "last:6h AND event_type:network_snapshot AND connections.remote_address:1.1.1.1",
  },
  {
    label: "Any cmd.exe or powershell.exe lineage",
    query: "processes.name:[cmd.exe, powershell.exe]",
  },
  {
    label: "FIM events on /etc/ in last 24h",
    query: "event_type:file_integrity AND path:/etc/",
  },
];

const SEVERITY_OPTIONS: SavedHunt["alert_severity"][] = ["low", "medium", "high", "critical"];

export function HuntWorkbench({
  initialHunts,
  role,
}: {
  initialHunts: SavedHunt[];
  role: "Admin" | "Viewer";
}) {
  const router = useRouter();
  const [query, setQuery] = useState<string>(initialHunts[0]?.query ?? STARTER_QUERIES[0]!.query);
  const [selectedHuntId, setSelectedHuntId] = useState<string | null>(initialHunts[0]?.id ?? null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RunResponse | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [hunts, setHunts] = useState<SavedHunt[]>(initialHunts);

  const selectedHunt = useMemo(
    () => hunts.find((h) => h.id === selectedHuntId) ?? null,
    [hunts, selectedHuntId],
  );

  const canEdit = role === "Admin";

  function selectHunt(hunt: SavedHunt) {
    setSelectedHuntId(hunt.id);
    setQuery(hunt.query);
    setResult(null);
    setRunError(null);
  }

  async function runQuery() {
    setRunning(true);
    setRunError(null);
    try {
      const res = await fetch("/api/hunts/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, limit: 200 }),
      });
      const body = (await res.json().catch(() => null)) as RunResponse | { error?: string } | null;
      if (!res.ok || !body || "error" in body) {
        throw new Error((body && "error" in body && body.error) || `Run failed with ${res.status}`);
      }
      setResult(body as RunResponse);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : "Hunt failed.");
      setResult(null);
    } finally {
      setRunning(false);
    }
  }

  async function deleteHunt(id: string) {
    if (!canEdit) return;
    if (!window.confirm("Delete this saved hunt?")) return;
    const res = await fetch(`/api/hunts/${id}`, { method: "DELETE" });
    if (res.ok) {
      setHunts((current) => current.filter((h) => h.id !== id));
      if (selectedHuntId === id) {
        setSelectedHuntId(null);
      }
      router.refresh();
    }
  }

  return (
    <div className="mt-6 grid gap-5 lg:grid-cols-[18rem_1fr]">
      <aside className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <div className="border-b border-[color:var(--color-border)] px-4 py-3">
          <h2 className="text-sm font-semibold">Saved hunts</h2>
          <p className="mt-1 text-xs text-[color:var(--color-muted-foreground)]">{hunts.length} saved</p>
        </div>
        <div className="grid max-h-[36rem] gap-1 overflow-y-auto p-2">
          {hunts.length === 0 ? (
            <p className="rounded-md px-3 py-6 text-center text-xs text-[color:var(--color-muted-foreground)]">
              No saved hunts yet. Run a query and click Save.
            </p>
          ) : (
            hunts.map((hunt) => (
              <button
                key={hunt.id}
                type="button"
                onClick={() => selectHunt(hunt)}
                className={`grid gap-1 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                  selectedHuntId === hunt.id
                    ? "bg-[color:var(--color-muted)]"
                    : "hover:bg-[color:var(--color-muted)]/60"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium">{hunt.name}</span>
                  <span className="flex items-center gap-1">
                    {!hunt.is_shared ? (
                      <span title="Private to you" aria-label="Private">
                        <Lock size={12} className="shrink-0 text-[color:var(--color-muted-foreground)]" />
                      </span>
                    ) : null}
                    {hunt.is_scheduled ? (
                      <span title="Scheduled" aria-label="Scheduled">
                        <Calendar size={13} className="shrink-0 text-[color:var(--color-accent)]" />
                      </span>
                    ) : null}
                  </span>
                </div>
                <span className="truncate font-mono text-[10px] text-[color:var(--color-muted-foreground)]">
                  {hunt.query}
                </span>
                {hunt.last_run_at ? (
                  <span className="text-[10px] text-[color:var(--color-muted-foreground)]">
                    last run {new Date(hunt.last_run_at).toLocaleString()}, {hunt.last_match_count ?? 0} matches
                  </span>
                ) : null}
              </button>
            ))
          )}
        </div>
      </aside>

      <section className="grid gap-5">
        <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--color-border)] px-5 py-4">
            <div>
              <h2 className="font-semibold">Query</h2>
              <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
                Fields like <code className="font-mono text-xs">event_type</code>, <code className="font-mono text-xs">agent</code>,
                or any <code className="font-mono text-xs">payload.path</code>. Combine with <code className="font-mono text-xs">AND</code>,
                <code className="font-mono text-xs">OR</code>, <code className="font-mono text-xs">NOT</code>.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={runQuery}
                disabled={running || query.trim().length === 0}
                className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-3 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
              >
                {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                {running ? "Running" : "Run"}
              </button>
              <button
                type="button"
                onClick={() => setSaveOpen(true)}
                disabled={!canEdit || query.trim().length === 0}
                className="inline-flex min-h-9 items-center gap-2 rounded-md border border-[color:var(--color-border)] px-3 text-sm hover:bg-[color:var(--color-muted)] disabled:cursor-not-allowed disabled:opacity-50"
              >
                <Save size={14} /> Save
              </button>
              {selectedHunt && canEdit ? (
                <>
                  <button
                    type="button"
                    onClick={() => setSaveOpen(true)}
                    className="inline-flex min-h-9 items-center gap-2 rounded-md border border-[color:var(--color-border)] px-3 text-sm hover:bg-[color:var(--color-muted)]"
                    title="Edit"
                  >
                    <Pencil size={14} /> Edit
                  </button>
                  <button
                    type="button"
                    onClick={() => deleteHunt(selectedHunt.id)}
                    className="inline-flex min-h-9 items-center gap-2 rounded-md border border-[color:var(--color-danger)]/40 px-3 text-sm text-[color:var(--color-danger)] hover:bg-[color:var(--color-danger)]/10"
                    title="Delete"
                  >
                    <Trash2 size={14} />
                  </button>
                </>
              ) : null}
            </div>
          </div>

          <div className="space-y-3 p-5">
            <textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              spellCheck={false}
              className="min-h-[8rem] w-full resize-y rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-3 font-mono text-xs leading-6 outline-none focus:ring-2 focus:ring-[color:var(--color-accent)]"
              placeholder='e.g. event_type:process_snapshot AND processes.name:"cmd.exe"'
            />
            <div className="flex flex-wrap gap-1.5">
              {STARTER_QUERIES.map((s) => (
                <button
                  key={s.label}
                  type="button"
                  onClick={() => setQuery(s.query)}
                  className="rounded-full border border-[color:var(--color-border)] bg-[color:var(--color-muted)] px-3 py-1 text-xs text-[color:var(--color-muted-foreground)] hover:bg-[color:var(--color-muted)]/80"
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {runError ? (
          <div className="rounded-md border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 px-4 py-3 text-sm text-[color:var(--color-danger)]">
            <div className="flex items-center gap-2 font-medium">
              <AlertTriangle size={15} /> Query did not run
            </div>
            <p className="mt-1 font-mono text-xs">{runError}</p>
          </div>
        ) : null}

        {result && result.warnings.length > 0 ? (
          <div className="rounded-md border border-[color:var(--color-warning)]/35 bg-[color:var(--color-warning)]/10 px-4 py-3 text-sm text-[color:var(--color-warning)]">
            {result.warnings.map((w) => (
              <p key={w} className="text-xs">
                {w}
              </p>
            ))}
          </div>
        ) : null}

        {result ? <ResultsTable result={result} /> : null}
      </section>

      {saveOpen ? (
        <SaveHuntDialog
          hunt={selectedHunt && selectedHunt.query === query ? selectedHunt : null}
          query={query}
          onClose={() => setSaveOpen(false)}
          onSaved={(saved) => {
            setHunts((current) => {
              const without = current.filter((h) => h.id !== saved.id);
              return [...without, saved].sort((a, b) => a.name.localeCompare(b.name));
            });
            setSelectedHuntId(saved.id);
            setSaveOpen(false);
            router.refresh();
          }}
        />
      ) : null}
    </div>
  );
}

function ResultsTable({ result }: { result: RunResponse }) {
  return (
    <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
      <div className="flex items-center justify-between border-b border-[color:var(--color-border)] px-5 py-3">
        <h3 className="text-sm font-semibold">
          {result.match_count} {result.match_count === 1 ? "match" : "matches"}
        </h3>
      </div>
      {result.matches.length === 0 ? (
        <p className="px-5 py-10 text-center text-sm text-[color:var(--color-muted-foreground)]">
          No telemetry matched this query in the current time window.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-[color:var(--color-muted)] text-left">
              <tr>
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Payload</th>
              </tr>
            </thead>
            <tbody>
              {result.matches.map((m) => (
                <tr key={m.event_id} className="border-t border-[color:var(--color-border)] align-top">
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {new Date(m.occurred_at).toLocaleString()}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 font-medium">{m.hostname}</td>
                  <td className="whitespace-nowrap px-4 py-3">{m.event_type.replace(/_/g, " ")}</td>
                  <td className="px-4 py-3">
                    <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-md bg-[color:var(--color-muted)] p-2 font-mono text-[11px] leading-5 text-[color:var(--color-muted-foreground)]">
                      {JSON.stringify(m.payload, null, 2)}
                    </pre>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function SaveHuntDialog({
  hunt,
  query,
  onClose,
  onSaved,
}: {
  hunt: SavedHunt | null;
  query: string;
  onClose: () => void;
  onSaved: (saved: SavedHunt) => void;
}) {
  const [name, setName] = useState(hunt?.name ?? "");
  const [description, setDescription] = useState(hunt?.description ?? "");
  const [isScheduled, setIsScheduled] = useState(hunt?.is_scheduled ?? false);
  const [scheduleCron, setScheduleCron] = useState(hunt?.schedule_cron ?? "1h");
  const [alertOnMatch, setAlertOnMatch] = useState(hunt?.alert_on_match ?? false);
  const [severity, setSeverity] = useState<SavedHunt["alert_severity"]>(hunt?.alert_severity ?? "medium");
  const [techniques, setTechniques] = useState((hunt?.mitre_techniques ?? []).join(", "));
  const [isShared, setIsShared] = useState(hunt?.is_shared ?? true);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    function onEscape(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onEscape);
    return () => window.removeEventListener("keydown", onEscape);
  }, [onClose]);

  async function submit() {
    setError(null);
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    const techniqueList = techniques
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
    const body = {
      name: name.trim(),
      description: description.trim() || null,
      query,
      is_scheduled: isScheduled,
      schedule_cron: isScheduled ? scheduleCron.trim() || null : null,
      alert_on_match: alertOnMatch,
      alert_severity: severity,
      mitre_techniques: techniqueList,
      is_shared: isShared,
    };
    setPending(true);
    try {
      const path = hunt ? `/api/hunts/${hunt.id}` : "/api/hunts";
      const method = hunt ? "PUT" : "POST";
      const res = await fetch(path, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = (await res.json().catch(() => null)) as SavedHunt | { error?: string } | null;
      if (!res.ok || !data || "error" in data) {
        throw new Error((data && "error" in data && data.error) || `Save failed with ${res.status}`);
      }
      onSaved(data as SavedHunt);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 px-4" role="dialog">
      <div className="grid w-full max-w-lg gap-4 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{hunt ? "Update saved hunt" : "Save hunt"}</h2>
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
            placeholder="EncodedCommand PowerShell"
          />
        </label>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Description (optional)</span>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="min-h-16 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-2 text-sm"
            placeholder="Why this hunt matters and what it catches."
          />
        </label>

        <div className="grid gap-1 text-sm">
          <span className="font-medium">Query</span>
          <pre className="overflow-auto rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-muted)] px-3 py-2 font-mono text-xs">
            {query}
          </pre>
        </div>

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={isScheduled}
            onChange={(e) => setIsScheduled(e.target.checked)}
            className="h-4 w-4 accent-[color:var(--color-accent)]"
          />
          <span className="font-medium">Run on a schedule</span>
        </label>

        {isScheduled ? (
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Cadence</span>
            <input
              value={scheduleCron}
              onChange={(e) => setScheduleCron(e.target.value)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
              placeholder="15m, 1h, 6h, 1d"
            />
            <span className="text-xs text-[color:var(--color-muted-foreground)]">
              The scheduler runs every 5 minutes and triggers this hunt when its cadence is due.
            </span>
          </label>
        ) : null}

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={alertOnMatch}
            onChange={(e) => setAlertOnMatch(e.target.checked)}
            className="h-4 w-4 accent-[color:var(--color-accent)]"
          />
          <span className="font-medium">Create an alert for each match (scheduled runs only)</span>
        </label>

        {alertOnMatch ? (
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Alert severity</span>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as SavedHunt["alert_severity"])}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm capitalize"
            >
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        <label className="grid gap-1 text-sm">
          <span className="font-medium">MITRE ATT&CK techniques (optional)</span>
          <input
            value={techniques}
            onChange={(e) => setTechniques(e.target.value)}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
            placeholder="T1059.003, T1071.004"
          />
        </label>

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={isShared}
            onChange={(e) => setIsShared(e.target.checked)}
            className="h-4 w-4 accent-[color:var(--color-accent)]"
          />
          <span className="font-medium">Share with everyone in this tenant</span>
          <span className="text-xs text-[color:var(--color-muted-foreground)]">
            (uncheck to keep this hunt private to you)
          </span>
        </label>

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
            className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-60"
          >
            {pending ? <Loader2 size={14} className="animate-spin" /> : <BookmarkPlus size={14} />}
            {hunt ? "Update" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
