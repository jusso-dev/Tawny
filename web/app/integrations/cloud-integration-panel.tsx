"use client";

import { useMemo, useState } from "react";
import { CheckCircle2, Cloud, LoaderCircle, Play, ShieldAlert, TestTube2 } from "lucide-react";

export type CloudConnection = {
  id: string;
  name: string;
  provider: "aws" | "azure";
  external_account_id: string;
  credential_mode: "aws_assume_role" | "azure_managed_identity" | "azure_client_secret";
  configuration: Record<string, unknown>;
  has_credential: boolean;
  is_enabled: boolean;
  last_test_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
};

export type CloudHunt = {
  id: string;
  cloud_connection_id: string;
  connection_name: string;
  name: string;
  source:
    | "aws_cloud_trail"
    | "aws_guard_duty"
    | "azure_activity_log"
    | "azure_entra_audit_log"
    | "azure_entra_sign_in_log";
  query: Record<string, unknown>;
  is_enabled: boolean;
  interval_minutes: number;
  lookback_minutes: number;
  severity: "low" | "medium" | "high" | "critical";
  last_run_at: string | null;
  last_success_at: string | null;
  last_match_count: number;
  last_error: string | null;
};

export type CloudFinding = {
  id: number;
  hunt_name: string;
  provider: "aws" | "azure";
  source: CloudHunt["source"];
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "acknowledged" | "resolved";
  actor: string | null;
  resource: string | null;
  occurred_at: string;
};

export function CloudIntegrationPanel({
  initialConnections,
  initialHunts,
  initialFindings,
  isAdmin,
}: {
  initialConnections: CloudConnection[];
  initialHunts: CloudHunt[];
  initialFindings: CloudFinding[];
  isAdmin: boolean;
}) {
  const [connections, setConnections] = useState(initialConnections);
  const [hunts, setHunts] = useState(initialHunts);
  const [findings, setFindings] = useState(initialFindings);
  const [provider, setProvider] = useState<"aws" | "azure">("aws");
  const [name, setName] = useState("");
  const [accountId, setAccountId] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [regions, setRegions] = useState("ap-southeast-2");
  const [externalId, setExternalId] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [managedIdentity, setManagedIdentity] = useState(true);
  const [huntConnectionId, setHuntConnectionId] = useState(initialConnections[0]?.id ?? "");
  const [huntName, setHuntName] = useState("");
  const [source, setSource] = useState<CloudHunt["source"]>("aws_cloud_trail");
  const [query, setQuery] = useState("{}");
  const [interval, setInterval] = useState("15");
  const [lookback, setLookback] = useState("15");
  const [severity, setSeverity] = useState<CloudHunt["severity"]>("medium");
  const [pending, setPending] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedConnection = useMemo(
    () => connections.find((item) => item.id === huntConnectionId),
    [connections, huntConnectionId],
  );

  async function saveConnection() {
    if (!isAdmin || pending) return;
    setPending("connection");
    setMessage(null);
    setError(null);
    try {
      const body = provider === "aws"
        ? {
            name,
            provider,
            external_account_id: accountId,
            credential_mode: "aws_assume_role",
            configuration: {
              role_arn: roleArn,
              regions: regions.split(",").map((value) => value.trim()).filter(Boolean),
            },
            credential: { external_id: externalId },
            is_enabled: true,
          }
        : {
            name,
            provider,
            external_account_id: accountId,
            credential_mode: managedIdentity ? "azure_managed_identity" : "azure_client_secret",
            configuration: {
              workspace_id: workspaceId,
              tenant_id: tenantId || null,
              client_id: clientId || null,
            },
            credential: managedIdentity ? null : { client_secret: clientSecret },
            is_enabled: true,
          };
      const response = await fetch("/api/cloud-connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const saved = await readResponse<CloudConnection>(response, "Connection save failed.");
      setConnections((current) => [...current, saved]);
      setHuntConnectionId(saved.id);
      const testSource: CloudHunt["source"] = provider === "aws" ? "aws_cloud_trail" : "azure_activity_log";
      const tested = await readResponse<{ records_read: number }>(await fetch(
        "/api/cloud-connections/" + saved.id + "/test",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source: testSource }),
        },
      ), "Connection test failed.");
      setMessage("Connection saved and verified; read " + tested.records_read.toLocaleString() + " recent records.");
      setExternalId("");
      setClientSecret("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Connection failed.");
    } finally {
      setPending(null);
    }
  }

  async function saveHunt() {
    if (!isAdmin || pending || !selectedConnection) return;
    setPending("hunt");
    setMessage(null);
    setError(null);
    try {
      const parsedQuery = JSON.parse(query) as Record<string, unknown>;
      const response = await fetch("/api/cloud-hunts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cloud_connection_id: selectedConnection.id,
          name: huntName,
          description: null,
          source,
          query: parsedQuery,
          is_enabled: true,
          interval_minutes: Number.parseInt(interval, 10),
          lookback_minutes: Number.parseInt(lookback, 10),
          severity,
          mitre_techniques: [],
        }),
      });
      const saved = await readResponse<CloudHunt>(response, "Hunt save failed.");
      setHunts((current) => [...current, saved]);
      setHuntName("");
      setMessage("Cloud hunt saved. Scheduler will run it when due.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Hunt save failed.");
    } finally {
      setPending(null);
    }
  }

  async function runHunt(hunt: CloudHunt) {
    if (!isAdmin || pending) return;
    setPending(hunt.id);
    setMessage(null);
    setError(null);
    try {
      const result = await readResponse<{ records_read: number; findings_created: number }>(
        await fetch("/api/cloud-hunts/" + hunt.id + "/run", { method: "POST" }),
        "Cloud hunt failed.",
      );
      setHunts((current) => current.map((item) => item.id === hunt.id
        ? { ...item, last_run_at: new Date().toISOString(), last_error: null }
        : item));
      const latest = await readResponse<CloudFinding[]>(
        await fetch("/api/cloud-findings?limit=20"),
        "Finding refresh failed.",
      );
      setFindings(latest);
      setMessage("Hunt read " + result.records_read.toLocaleString() + " records and created " + result.findings_created.toLocaleString() + " findings.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Cloud hunt failed.");
    } finally {
      setPending(null);
    }
  }

  function chooseHuntConnection(id: string) {
    setHuntConnectionId(id);
    const connection = connections.find((item) => item.id === id);
    setSource(connection?.provider === "azure" ? "azure_activity_log" : "aws_cloud_trail");
    setQuery("{}");
  }

  return (
    <section className="mt-6 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
      <div className="flex flex-col gap-3 border-b border-[color:var(--color-border)] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Cloud size={18} className="text-[color:var(--color-accent)]" />
            <h2 className="font-semibold">Cloud hunting</h2>
          </div>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-[color:var(--color-muted-foreground)]">
            Query AWS CloudTrail and GuardDuty or Azure Activity Logs. Tawny stores bounded, deduplicated findings—not a second cloud log archive or CSPM inventory.
          </p>
        </div>
        <span className="rounded-full bg-[color:var(--color-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--color-muted-foreground)]">
          {connections.length} connections · {hunts.length} hunts
        </span>
      </div>

      <div className="grid gap-8 p-5 xl:grid-cols-2">
        <form className="grid content-start gap-4" onSubmit={(event) => { event.preventDefault(); void saveConnection(); }}>
          <div>
            <h3 className="font-semibold">Add least-privilege connection</h3>
            <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">AWS uses AssumeRole. Azure uses managed identity or an encrypted client secret.</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Provider">
              <select value={provider} onChange={(event) => setProvider(event.target.value as "aws" | "azure")} className={inputClass}>
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
              </select>
            </Field>
            <Field label="Display name"><input required value={name} onChange={(event) => setName(event.target.value)} className={inputClass} /></Field>
            <Field label={provider === "aws" ? "AWS account ID" : "Azure subscription ID"}>
              <input required value={accountId} onChange={(event) => setAccountId(event.target.value)} className={inputClass} />
            </Field>
            {provider === "aws" ? (
              <>
                <Field label="Read-only role ARN"><input required value={roleArn} onChange={(event) => setRoleArn(event.target.value)} className={inputClass} /></Field>
                <Field label="Regions (comma separated)"><input required value={regions} onChange={(event) => setRegions(event.target.value)} className={inputClass} /></Field>
                <Field label="External ID"><input type="password" required value={externalId} onChange={(event) => setExternalId(event.target.value)} className={inputClass} /></Field>
              </>
            ) : (
              <>
                <Field label="Log Analytics workspace ID"><input required value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)} className={inputClass} /></Field>
                <Field label="Tenant ID"><input required={!managedIdentity} value={tenantId} onChange={(event) => setTenantId(event.target.value)} className={inputClass} /></Field>
                <Field label="Client ID"><input value={clientId} onChange={(event) => setClientId(event.target.value)} className={inputClass} /></Field>
                <label className="flex min-h-11 items-center gap-2 text-sm font-medium sm:col-span-2"><input type="checkbox" checked={managedIdentity} onChange={(event) => setManagedIdentity(event.target.checked)} /> Use managed/workload identity</label>
                {!managedIdentity ? <Field label="Client secret"><input type="password" required value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} className={inputClass} /></Field> : null}
              </>
            )}
          </div>
          <button disabled={!isAdmin || pending !== null} className={primaryButton}>
            {pending === "connection" ? <LoaderCircle size={16} className="mr-2 animate-spin" /> : <TestTube2 size={16} className="mr-2" />}
            Save and test
          </button>
        </form>

        <form className="grid content-start gap-4" onSubmit={(event) => { event.preventDefault(); void saveHunt(); }}>
          <div><h3 className="font-semibold">Create monitoring hunt</h3><p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">Manual runs and minute scheduler share same watermark and dedupe path.</p></div>
          {connections.length === 0 ? (
            <div className="rounded-md bg-[color:var(--color-muted)] p-4 text-sm text-[color:var(--color-muted-foreground)]">Add a connection first.</div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Connection"><select value={huntConnectionId} onChange={(event) => chooseHuntConnection(event.target.value)} className={inputClass}>{connections.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
              <Field label="Source"><select value={source} onChange={(event) => setSource(event.target.value as CloudHunt["source"])} className={inputClass}>{selectedConnection?.provider === "azure" ? <><option value="azure_activity_log">Azure Activity Log</option><option value="azure_entra_audit_log">Microsoft Entra audit log</option><option value="azure_entra_sign_in_log">Microsoft Entra sign-in log</option></> : <><option value="aws_cloud_trail">AWS CloudTrail</option><option value="aws_guard_duty">AWS GuardDuty</option></>}</select></Field>
              <Field label="Hunt name"><input required value={huntName} onChange={(event) => setHuntName(event.target.value)} className={inputClass} /></Field>
              <Field label="Severity"><select value={severity} onChange={(event) => setSeverity(event.target.value as CloudHunt["severity"])} className={inputClass}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></Field>
              <Field label="Interval (minutes)"><input type="number" min="1" max="1440" value={interval} onChange={(event) => setInterval(event.target.value)} className={inputClass} /></Field>
              <Field label="Initial lookback (minutes)"><input type="number" min="1" max="43200" value={lookback} onChange={(event) => setLookback(event.target.value)} className={inputClass} /></Field>
              <label className="grid gap-1.5 sm:col-span-2"><span className="text-sm font-medium">Query JSON</span><textarea rows={5} value={query} onChange={(event) => setQuery(event.target.value)} className={inputClass + " py-2 font-mono"} /><span className="text-xs text-[color:var(--color-muted-foreground)]">CloudTrail: attribute_key/value, source_ip, error_code. Azure: kql. GuardDuty: use {"{}"}.</span></label>
            </div>
          )}
          <button disabled={!isAdmin || pending !== null || connections.length === 0} className={primaryButton}>{pending === "hunt" ? <LoaderCircle size={16} className="mr-2 animate-spin" /> : null}Save monitoring hunt</button>
        </form>
      </div>

      {error ? <div role="alert" className="mx-5 mb-5 flex gap-2 rounded-md bg-[color:var(--color-danger)]/10 p-3 text-sm text-[color:var(--color-danger)]"><ShieldAlert size={16} className="mt-0.5 shrink-0" />{error}</div> : null}
      {message ? <div role="status" className="mx-5 mb-5 flex gap-2 rounded-md bg-[color:var(--color-success)]/10 p-3 text-sm text-[color:var(--color-success)]"><CheckCircle2 size={16} className="shrink-0" />{message}</div> : null}

      {hunts.length > 0 ? (
        <div className="border-t border-[color:var(--color-border)] p-5">
          <h3 className="font-semibold">Saved cloud hunts</h3>
          <div className="mt-3 grid gap-3">
            {hunts.map((hunt) => <div key={hunt.id} className="flex flex-col gap-3 rounded-md border border-[color:var(--color-border)] p-3 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-sm font-medium">{hunt.name}</p><p className="mt-1 text-xs text-[color:var(--color-muted-foreground)]">{hunt.connection_name} · {hunt.source.replaceAll("_", " ")} · every {hunt.interval_minutes}m · last {hunt.last_match_count} matches</p>{hunt.last_error ? <p className="mt-1 text-xs text-[color:var(--color-danger)]">{hunt.last_error}</p> : null}</div><button type="button" onClick={() => void runHunt(hunt)} disabled={!isAdmin || pending !== null} className="inline-flex min-h-10 items-center justify-center rounded-md border border-[color:var(--color-border)] px-3 text-sm font-medium disabled:opacity-50">{pending === hunt.id ? <LoaderCircle size={15} className="mr-2 animate-spin" /> : <Play size={15} className="mr-2" />}Run now</button></div>)}
          </div>
        </div>
      ) : null}

      {findings.length > 0 ? (
        <div className="border-t border-[color:var(--color-border)] p-5">
          <h3 className="font-semibold">Recent cloud findings</h3>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[48rem] text-left text-sm">
              <thead className="text-xs text-[color:var(--color-muted-foreground)]"><tr><th className="pb-2 pr-4 font-medium">Occurred</th><th className="pb-2 pr-4 font-medium">Finding</th><th className="pb-2 pr-4 font-medium">Actor / resource</th><th className="pb-2 font-medium">State</th></tr></thead>
              <tbody>{findings.map((finding) => <tr key={finding.id} className="border-t border-[color:var(--color-border)]"><td className="py-3 pr-4 whitespace-nowrap">{new Date(finding.occurred_at).toLocaleString()}</td><td className="py-3 pr-4"><p className="font-medium">{finding.title}</p><p className="mt-1 text-xs text-[color:var(--color-muted-foreground)]">{finding.hunt_name} · {finding.provider.toUpperCase()} · {finding.severity}</p></td><td className="max-w-md py-3 pr-4 text-xs"><p className="truncate">{finding.actor ?? "Unknown actor"}</p><p className="mt-1 truncate text-[color:var(--color-muted-foreground)]">{finding.resource ?? "No resource"}</p></td><td className="py-3"><span className="rounded-full bg-[color:var(--color-muted)] px-2 py-1 text-xs">{finding.status}</span></td></tr>)}</tbody>
            </table>
          </div>
        </div>
      ) : null}
    </section>
  );
}

const inputClass = "min-h-11 w-full rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm outline-2 outline-transparent focus-visible:outline-[color:var(--color-accent)] disabled:opacity-55";
const primaryButton = "inline-flex min-h-11 w-fit items-center justify-center rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-[color:var(--color-accent-foreground)] disabled:opacity-50";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="grid gap-1.5"><span className="text-sm font-medium">{label}</span>{children}</label>;
}

async function readResponse<T>(response: Response, fallback: string): Promise<T> {
  const body = await response.json().catch(() => null) as T | { error?: string; detail?: string } | null;
  if (!response.ok || body === null) {
    const problem = body && typeof body === "object" && ("error" in body || "detail" in body)
      ? body.error ?? body.detail
      : null;
    throw new Error(problem || fallback + " HTTP " + response.status);
  }
  return body as T;
}
