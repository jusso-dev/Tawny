"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, CheckCircle2, FileSearch, Loader2, Upload } from "lucide-react";

type SourceFormat = "auto" | "stix" | "openioc" | "raw";
type Severity = "low" | "medium" | "high" | "critical";

type IocSummary = {
  sha256: number;
  sha1: number;
  ips: number;
  domains: number;
  md5: number;
};

const sampleStix = `{
  "type": "bundle",
  "id": "bundle--9b1ad7d3-c5f3-4b2c-91c8-cb5a8912e7e1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--9fe9d1b7-27e6-4a78-836f-3358e08b1f0d",
      "name": "Advisory IoCs",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '203.0.113.44'] OR [domain-name:value = 'payload.example.com'] OR [file:hashes.'SHA-256' = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']"
    }
  ]
}
`;

const sampleRaw = `# Paste hashes, IPs, domains, CSV exports, or advisory text
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
203.0.113.44
payload.example.com
`;

const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,}:[0-9a-fA-F:]{2,}\b/g;
const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b/g;

function countMatches(value: string, regex: RegExp) {
  return new Set(value.match(regex)?.map((match) => match.toLowerCase()) ?? []).size;
}

function summarize(definition: string): IocSummary {
  return {
    sha256: countMatches(definition, sha256Regex),
    sha1: countMatches(definition, sha1Regex),
    ips: countMatches(definition, ipRegex),
    domains: countMatches(definition, domainRegex),
    md5: countMatches(definition, md5Regex),
  };
}

export function IocImportPanel() {
  const router = useRouter();
  const [definition, setDefinition] = useState(sampleStix);
  const [sourceFormat, setSourceFormat] = useState<SourceFormat>("auto");
  const [severity, setSeverity] = useState<Severity>("high");
  const [enabled, setEnabled] = useState(true);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const summary = useMemo(() => summarize(definition), [definition]);
  const supportedCount = summary.sha256 + summary.sha1 + summary.ips + summary.domains;
  const canSubmit = definition.trim().length > 0 && supportedCount > 0 && !pending;

  function load(value: string, format: SourceFormat) {
    setDefinition(value);
    setSourceFormat(format);
    setError(null);
    setSuccess(null);
  }

  async function importIocs(event: React.FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;

    setPending(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await fetch("/api/alert-rules/iocs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          definition,
          source_format: sourceFormat,
          severity,
          is_enabled: enabled,
        }),
      });
      const body = (await res.json().catch(() => null)) as
        | { rules?: unknown[]; skipped_indicators?: string[]; error?: string }
        | null;
      if (!res.ok) {
        throw new Error(body?.error ?? `Import failed with ${res.status}`);
      }

      const count = body?.rules?.length ?? 0;
      const skipped = body?.skipped_indicators?.length ?? 0;
      setSuccess(`Imported ${count} IoC ${count === 1 ? "rule" : "rules"}${skipped ? `, skipped ${skipped}` : ""}.`);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import IoCs.");
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
      <div className="border-b border-[color:var(--color-border)] px-5 py-4">
        <div className="flex items-center gap-2">
          <FileSearch size={17} className="text-[color:var(--color-accent)]" />
          <h2 className="font-semibold">Import threat intel IoCs</h2>
        </div>
        <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
          STIX 2.1, OpenIOC, CSV, and advisory text become endpoint hunt rules for SHA-1, SHA-256, domains, and IPs.
        </p>
      </div>

      <form onSubmit={importIocs} className="space-y-4 p-5">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => load(sampleStix, "stix")}
            className="inline-flex min-h-8 items-center rounded-md border border-[color:var(--color-border)] px-2.5 text-xs hover:bg-[color:var(--color-muted)]"
          >
            STIX sample
          </button>
          <button
            type="button"
            onClick={() => load(sampleRaw, "raw")}
            className="inline-flex min-h-8 items-center rounded-md border border-[color:var(--color-border)] px-2.5 text-xs hover:bg-[color:var(--color-muted)]"
          >
            Raw IoCs
          </button>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Format</span>
            <select
              value={sourceFormat}
              onChange={(event) => setSourceFormat(event.target.value as SourceFormat)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-2"
            >
              <option value="auto">Auto-detect</option>
              <option value="stix">STIX 2.1 JSON</option>
              <option value="openioc">OpenIOC XML</option>
              <option value="raw">Raw text or CSV</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Severity</span>
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value as Severity)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-2 capitalize"
            >
              {(["low", "medium", "high", "critical"] as Severity[]).map((level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-end gap-3 pb-2 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) => setEnabled(event.target.checked)}
              className="h-4 w-4 accent-[color:var(--color-accent)]"
            />
            Enable after import
          </label>
        </div>

        <textarea
          value={definition}
          onChange={(event) => {
            setDefinition(event.target.value);
            setError(null);
            setSuccess(null);
          }}
          spellCheck={false}
          className="min-h-[18rem] w-full resize-y rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-3 font-mono text-xs leading-6 outline-none focus:ring-2 focus:ring-[color:var(--color-accent)]"
        />

        <div className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-muted)] p-3">
          <div className="flex items-center gap-2">
            {supportedCount > 0 ? (
              <CheckCircle2 size={16} className="text-[color:var(--color-success)]" />
            ) : (
              <AlertTriangle size={16} className="text-[color:var(--color-warning)]" />
            )}
            <p className="text-sm font-medium">
              {supportedCount > 0 ? `${supportedCount} supported IoCs detected` : "No supported IoCs detected yet"}
            </p>
          </div>
          <p className="mt-2 font-mono text-xs text-[color:var(--color-muted-foreground)]">
            sha256 {summary.sha256} | sha1 {summary.sha1} | ip {summary.ips} | domain {summary.domains}
            {summary.md5 ? ` | md5 skipped ${summary.md5}` : ""}
          </p>
        </div>

        {error && (
          <p className="rounded-md border border-[color:var(--color-danger)]/35 bg-[color:var(--color-danger)]/10 px-3 py-2 text-sm text-[color:var(--color-danger)]">
            {error}
          </p>
        )}
        {success && (
          <p className="rounded-md border border-[color:var(--color-success)]/35 bg-[color:var(--color-success)]/10 px-3 py-2 text-sm text-[color:var(--color-success)]">
            {success}
          </p>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
        >
          {pending ? <Loader2 size={16} className="animate-spin" /> : <Upload size={16} />}
          {pending ? "Importing..." : "Import IoCs"}
        </button>
      </form>
    </section>
  );
}
