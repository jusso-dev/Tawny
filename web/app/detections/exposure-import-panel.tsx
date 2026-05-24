"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, PackageOpen, Upload } from "lucide-react";

const SAMPLE = `{
  "id": "GHSA-example",
  "summary": "Example compromise of left-pad",
  "affected": [
    {
      "package": { "ecosystem": "npm", "name": "left-pad" },
      "ranges": [
        { "type": "ECOSYSTEM", "events": [{ "introduced": "1.0.0" }, { "fixed": "1.3.1" }] }
      ]
    },
    {
      "package": { "ecosystem": "editor-extension", "name": "evil.publisher.bad-ext" },
      "versions": ["0.5.7"]
    }
  ],
  "references": [{ "type": "ADVISORY", "url": "https://example.com/advisory" }]
}`;

const SEVERITY_OPTIONS = ["low", "medium", "high", "critical"] as const;
type Severity = (typeof SEVERITY_OPTIONS)[number];

export function ExposureImportPanel() {
  const router = useRouter();
  const [definition, setDefinition] = useState(SAMPLE);
  const [severity, setSeverity] = useState<Severity>("high");
  const [enabled, setEnabled] = useState(true);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSuccess(null);
    setPending(true);
    try {
      const res = await fetch("/api/alert-rules/exposures", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ definition, severity, is_enabled: enabled }),
      });
      const body = (await res.json().catch(() => null)) as
        | { rules: Array<{ name: string }>; skipped_entries: string[]; error?: string }
        | null;
      if (!res.ok || !body || "error" in body) {
        throw new Error((body && "error" in body && body.error) || `Import failed with ${res.status}`);
      }
      const skippedNote = body.skipped_entries.length > 0
        ? ` (${body.skipped_entries.length} skipped)`
        : "";
      setSuccess(`Imported ${body.rules.length} package exposure rule(s)${skippedNote}.`);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import exposures.");
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
      <div className="flex items-start justify-between gap-3 border-b border-[color:var(--color-border)] px-5 py-4">
        <div>
          <h2 className="font-semibold">Import package exposures</h2>
          <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
            Paste an OSV advisory or a simple <code className="font-mono text-xs">[{`{ecosystem, name, version_pattern}`}]</code> list.
            Each affected package becomes a rule that matches against agent inventory events (npm, pypi, editor / browser extensions, MCP configs).
          </p>
        </div>
        <PackageOpen size={20} className="text-[color:var(--color-muted-foreground)]" />
      </div>

      <form onSubmit={submit} className="space-y-4 p-5">
        <textarea
          value={definition}
          onChange={(e) => setDefinition(e.target.value)}
          spellCheck={false}
          className="min-h-[20rem] w-full resize-y rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-3 font-mono text-xs leading-6 outline-none focus:ring-2 focus:ring-[color:var(--color-accent)]"
        />

        <div className="flex flex-wrap items-center gap-4 text-sm">
          <label className="flex items-center gap-2">
            <span className="font-medium">Severity</span>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 capitalize"
            >
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 accent-[color:var(--color-accent)]"
            />
            Enable after import
          </label>
        </div>

        {error ? (
          <p className="rounded-md border border-[color:var(--color-danger)]/40 bg-[color:var(--color-danger)]/10 px-3 py-2 text-sm text-[color:var(--color-danger)]">
            {error}
          </p>
        ) : null}
        {success ? (
          <p className="rounded-md border border-[color:var(--color-success)]/40 bg-[color:var(--color-success)]/10 px-3 py-2 text-sm text-[color:var(--color-success)]">
            {success}
          </p>
        ) : null}

        <button
          type="submit"
          disabled={pending || definition.trim().length === 0}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
        >
          {pending ? <Loader2 size={16} className="animate-spin" /> : <Upload size={16} />}
          {pending ? "Importing..." : "Import exposures"}
        </button>
      </form>
    </section>
  );
}
