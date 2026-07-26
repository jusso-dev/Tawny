"use client";

import { useState } from "react";
import {
  CheckCircle2,
  KeyRound,
  LoaderCircle,
  Network,
  ShieldAlert,
  TestTube2,
} from "lucide-react";

export type UniFiIntegration = {
  id: string;
  base_url: string;
  events_url: string;
  api_key_header: string;
  has_api_key: boolean;
  records_path: string;
  verify_tls: boolean;
  is_enabled: boolean;
  interval_minutes: number;
  network_version: string | null;
  last_test_at: string | null;
  last_run_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  last_records_checked: number;
  last_indicators_checked: number;
  last_matching_events: number;
  last_cases_created: number;
  created_at: string;
  updated_at: string;
};

type FormState = {
  baseUrl: string;
  eventsUrl: string;
  apiKeyHeader: string;
  apiKey: string;
  recordsPath: string;
  verifyTls: boolean;
  isEnabled: boolean;
  intervalMinutes: string;
};

export function UniFiIntegrationPanel({
  initial,
  isAdmin,
}: {
  initial: UniFiIntegration | null;
  isAdmin: boolean;
}) {
  const [integration, setIntegration] = useState(initial);
  const [form, setForm] = useState<FormState>(() => toForm(initial));
  const [pending, setPending] = useState<"save" | "test" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function save(testAfterSave: boolean) {
    if (!isAdmin || pending) return;
    setPending(testAfterSave ? "test" : "save");
    setMessage(null);
    setError(null);

    try {
      const response = await fetch("/api/integrations/unifi", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          base_url: form.baseUrl.trim(),
          events_url: form.eventsUrl.trim(),
          api_key_header: form.apiKeyHeader.trim(),
          api_key: form.apiKey.trim() || null,
          records_path: form.recordsPath.trim(),
          verify_tls: form.verifyTls,
          is_enabled: form.isEnabled,
          interval_minutes: Number.parseInt(form.intervalMinutes, 10),
        }),
      });
      const saved = await readResponse<UniFiIntegration>(response, "Save failed.");
      setIntegration(saved);
      setForm((current) => ({ ...current, apiKey: "" }));

      if (!testAfterSave) {
        setMessage("UniFi configuration saved.");
        return;
      }

      const testResponse = await fetch("/api/integrations/unifi/test", { method: "POST" });
      const tested = await readResponse<{
        application_version: string;
        records_found: number;
        tested_at: string;
      }>(
        testResponse,
        "Connection test failed.",
      );
      setIntegration((current) =>
        current
          ? {
              ...current,
              network_version: tested.application_version,
              last_test_at: tested.tested_at,
              last_error: null,
            }
          : current,
      );
      setMessage(
        `Connected to UniFi Network ${tested.application_version}; read ${tested.records_found.toLocaleString()} event records.`,
      );
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "UniFi configuration failed.");
    } finally {
      setPending(null);
    }
  }

  return (
    <section className="mt-6 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
      <div className="flex flex-col gap-3 border-b border-[color:var(--color-border)] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Network size={18} className="text-[color:var(--color-accent)]" />
            <h2 className="font-semibold">UniFi Network</h2>
          </div>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[color:var(--color-muted-foreground)]">
            Pull local event records, match IPs and domains against Tawny threat intelligence, then create deduplicated Kelpie cases.
          </p>
        </div>
        <StatusPill integration={integration} />
      </div>

      <div className="grid gap-6 p-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <form
          className="grid min-w-0 gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            void save(false);
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Controller URL" hint="Private IP for your UniFi console.">
              <input
                type="text"
                inputMode="url"
                autoCapitalize="none"
                spellCheck={false}
                required
                value={form.baseUrl}
                onChange={(event) => setForm({ ...form, baseUrl: event.target.value })}
                placeholder="https://192.168.1.1"
                disabled={!isAdmin || pending !== null}
                className={inputClass}
              />
            </Field>
            <Field label="Events URL" hint="GET endpoint from Network > Integrations.">
              <input
                type="text"
                inputMode="url"
                autoCapitalize="none"
                spellCheck={false}
                required
                value={form.eventsUrl}
                onChange={(event) => setForm({ ...form, eventsUrl: event.target.value })}
                placeholder="https://192.168.1.1/proxy/network/integration/v1/…"
                disabled={!isAdmin || pending !== null}
                className={inputClass}
              />
            </Field>
            <Field label="API key header" hint="UniFi local API default is X-API-Key.">
              <input
                required
                value={form.apiKeyHeader}
                onChange={(event) => setForm({ ...form, apiKeyHeader: event.target.value })}
                disabled={!isAdmin || pending !== null}
                className={inputClass}
              />
            </Field>
            <Field
              label="API key"
              hint={integration?.has_api_key ? "Leave blank to keep saved key." : "Stored encrypted after save."}
            >
              <div className="relative">
                <KeyRound
                  size={15}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-muted-foreground)]"
                />
                <input
                  type="password"
                  required={!integration?.has_api_key}
                  value={form.apiKey}
                  onChange={(event) => setForm({ ...form, apiKey: event.target.value })}
                  placeholder={integration?.has_api_key ? "Saved key" : "Paste UniFi API key"}
                  autoComplete="new-password"
                  disabled={!isAdmin || pending !== null}
                  className={`${inputClass} pl-9`}
                />
              </div>
            </Field>
            <Field label="Records path" hint="Dot path to array; blank for top-level arrays.">
              <input
                value={form.recordsPath}
                onChange={(event) => setForm({ ...form, recordsPath: event.target.value })}
                placeholder="data"
                disabled={!isAdmin || pending !== null}
                className={inputClass}
              />
            </Field>
            <Field label="Check every" hint="Scheduler polls once per minute and runs when due.">
              <div className="relative">
                <input
                  type="number"
                  min={1}
                  max={1440}
                  required
                  value={form.intervalMinutes}
                  onChange={(event) => setForm({ ...form, intervalMinutes: event.target.value })}
                  disabled={!isAdmin || pending !== null}
                  className={`${inputClass} pr-20`}
                />
                <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-sm text-[color:var(--color-muted-foreground)]">
                  minutes
                </span>
              </div>
            </Field>
          </div>

          <div className="flex flex-col gap-3 rounded-md bg-[color:var(--color-muted)] p-3 sm:flex-row sm:items-center sm:justify-between">
            <Checkbox
              checked={form.isEnabled}
              onChange={(checked) => setForm({ ...form, isEnabled: checked })}
              disabled={!isAdmin || pending !== null}
              label="Enable scheduled matching"
            />
            <Checkbox
              checked={form.verifyTls}
              onChange={(checked) => setForm({ ...form, verifyTls: checked })}
              disabled={!isAdmin || pending !== null}
              label="Verify TLS certificate"
            />
          </div>

          {error ? (
            <div
              className="flex items-start gap-2 rounded-md border border-[color:var(--color-danger)]/35 bg-[color:var(--color-danger)]/10 px-3 py-2 text-sm text-[color:var(--color-danger)]"
              role="alert"
            >
              <ShieldAlert size={16} className="mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          ) : null}
          {message ? (
            <div
              className="flex items-center gap-2 rounded-md border border-[color:var(--color-success)]/30 bg-[color:var(--color-success)]/10 px-3 py-2 text-sm text-[color:var(--color-success)]"
              role="status"
            >
              <CheckCircle2 size={16} className="shrink-0" />
              <span>{message}</span>
            </div>
          ) : null}

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={!isAdmin || pending !== null}
              className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-[color:var(--color-accent-foreground)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pending === "save" ? <LoaderCircle size={16} className="mr-2 animate-spin" /> : null}
              Save configuration
            </button>
            <button
              type="button"
              disabled={!isAdmin || pending !== null}
              onClick={() => void save(true)}
              className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-4 text-sm font-medium transition-colors hover:bg-[color:var(--color-muted)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pending === "test" ? (
                <LoaderCircle size={16} className="mr-2 animate-spin" />
              ) : (
                <TestTube2 size={16} className="mr-2" />
              )}
              Save and test
            </button>
            {!isAdmin ? (
              <span className="text-sm text-[color:var(--color-muted-foreground)]">
                Admin access required to change integration settings.
              </span>
            ) : null}
          </div>
        </form>

        <aside className="min-w-0 border-t border-[color:var(--color-border)] pt-5 xl:border-l xl:border-t-0 xl:pl-5 xl:pt-0">
          <h3 className="text-sm font-semibold">Latest scheduled run</h3>
          <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-3 text-sm">
            <Metric label="Records" value={integration?.last_records_checked ?? 0} />
            <Metric label="Indicators" value={integration?.last_indicators_checked ?? 0} />
            <Metric label="Matches" value={integration?.last_matching_events ?? 0} />
            <Metric label="Cases" value={integration?.last_cases_created ?? 0} />
          </dl>
          <div className="mt-5 space-y-3 text-sm">
            <StatusLine label="Network" value={integration?.network_version ?? "Not tested"} />
            <StatusLine label="Last test" value={formatDate(integration?.last_test_at)} />
            <StatusLine label="Last run" value={formatDate(integration?.last_run_at)} />
            <StatusLine label="Last success" value={formatDate(integration?.last_success_at)} />
          </div>
          {integration?.last_error ? (
            <div className="mt-5 rounded-md bg-[color:var(--color-danger)]/10 p-3 text-sm text-[color:var(--color-danger)]">
              <p className="font-medium">Last error</p>
              <p className="mt-1 break-words leading-5">{integration.last_error}</p>
            </div>
          ) : null}
          <p className="mt-5 text-xs leading-5 text-[color:var(--color-muted-foreground)]">
            API key stays server-side and encrypted. Tawny never returns it after save.
          </p>
        </aside>
      </div>
    </section>
  );
}

const inputClass =
  "min-h-11 w-full rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm outline-2 outline-transparent focus-visible:outline-[color:var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-55";

function toForm(integration: UniFiIntegration | null): FormState {
  return {
    baseUrl: integration?.base_url ?? "https://192.168.1.1",
    eventsUrl: integration?.events_url ?? "",
    apiKeyHeader: integration?.api_key_header ?? "X-API-Key",
    apiKey: "",
    recordsPath: integration?.records_path ?? "data",
    verifyTls: integration?.verify_tls ?? true,
    isEnabled: integration?.is_enabled ?? false,
    intervalMinutes: String(integration?.interval_minutes ?? 5),
  };
}

async function readResponse<T>(response: Response, fallback: string): Promise<T> {
  const body = (await response.json().catch(() => null)) as T | { error?: string; detail?: string } | null;
  if (!response.ok || body === null) {
    const error = body && typeof body === "object" && ("error" in body || "detail" in body)
      ? body.error ?? body.detail
      : null;
    throw new Error(error || `${fallback} HTTP ${response.status}`);
  }
  return body as T;
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: React.ReactNode;
}) {
  return (
    <label className="grid gap-1.5">
      <span className="text-sm font-medium">{label}</span>
      {children}
      <span className="min-h-[1lh] text-xs leading-5 text-[color:var(--color-muted-foreground)]">
        {hint}
      </span>
    </label>
  );
}

function Checkbox({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled: boolean;
  label: string;
}) {
  return (
    <label className="flex min-h-11 cursor-pointer items-center gap-2 text-sm font-medium has-disabled:cursor-not-allowed has-disabled:opacity-55">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        disabled={disabled}
        className="size-4 accent-[color:var(--color-accent)]"
      />
      <span>{label}</span>
    </label>
  );
}

function StatusPill({ integration }: { integration: UniFiIntegration | null }) {
  const enabled = integration?.is_enabled;
  return (
    <span
      className={`inline-flex min-h-8 shrink-0 items-center gap-2 whitespace-nowrap rounded-full px-3 text-xs font-medium ring-1 ${
        enabled
          ? "bg-[color:var(--color-success)]/12 text-[color:var(--color-success)] ring-[color:var(--color-success)]/25"
          : "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)] ring-[color:var(--color-border)]"
      }`}
    >
      <span className="size-1.5 rounded-full bg-current" />
      {enabled ? "Scheduled" : integration ? "Saved, disabled" : "Not configured"}
    </span>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <dt className="text-xs text-[color:var(--color-muted-foreground)]">{label}</dt>
      <dd className="mt-1 text-xl font-semibold" data-tabular>
        {value}
      </dd>
    </div>
  );
}

function StatusLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-[color:var(--color-border)] pb-2">
      <dt className="text-[color:var(--color-muted-foreground)]">{label}</dt>
      <dd className="min-w-0 text-right">{value}</dd>
    </div>
  );
}

function formatDate(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "Never";
}
