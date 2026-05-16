import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";
import { IocImportPanel } from "./ioc-import-panel";
import { SigmaImportPanel } from "./sigma-import-panel";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

type AlertRule = {
  id: string;
  name: string;
  format: "tawny_predicate" | "sigma" | "ioc";
  external_id: string | null;
  description: string | null;
  event_type: string | null;
  severity: "low" | "medium" | "high" | "critical";
  operator: "exists" | "equals" | "contains" | "greater_than" | "less_than";
  payload_path: string | null;
  match_value: string | null;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
};

const severityTone: Record<AlertRule["severity"], string> = {
  low: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)] ring-[color:var(--color-border)]",
  medium: "bg-[color:var(--color-accent)]/12 text-[color:var(--color-accent)] ring-[color:var(--color-accent)]/25",
  high: "bg-[color:var(--color-warning)]/12 text-[color:var(--color-warning)] ring-[color:var(--color-warning)]/25",
  critical: "bg-[color:var(--color-danger)]/12 text-[color:var(--color-danger)] ring-[color:var(--color-danger)]/25",
};

export default async function DetectionsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const [rules, agents] = await Promise.all([
    apiGet<AlertRule[]>("/api/alert-rules", session.user.id, role),
    apiGet<Agent[]>("/api/agents", session.user.id, role),
  ]);

  return (
    <AppShell agents={agents} active="detections">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Detections"
          title="Detection imports"
          description="Import Sigma rules and threat intel IoCs, review compiled predicates, and hunt across enrolled endpoints."
        />

        <div className="mt-6 grid gap-5 xl:grid-cols-2">
          <SigmaImportPanel />
          <IocImportPanel />
        </div>

        <div className="mt-5 grid gap-5 lg:grid-cols-2">
          <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <div className="border-b border-[color:var(--color-border)] px-5 py-4">
              <h2 className="font-semibold">Accepted Sigma subset</h2>
              <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
                One selection, one condition, simple field matches.
              </p>
            </div>
            <div className="grid gap-3 p-5 text-sm">
              <SubsetItem label="Required" value="title, detection, condition" />
              <SubsetItem label="Optional metadata" value="id, description, logsource, level" />
              <SubsetItem label="Condition" value="Must be the exact selection name, for example selection" />
              <SubsetItem label="Values" value="One scalar value or a YAML list of scalar values" />
              <SubsetItem label="Modifiers" value="contains, exists, gt, lt" />
              <SubsetItem label="Common fields" value="processes.name, processes.command_line, connections.remote_address, path, username" />
            </div>
          </section>
          <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <div className="border-b border-[color:var(--color-border)] px-5 py-4">
              <h2 className="font-semibold">Accepted IoC sources</h2>
              <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
                Common advisory formats compile into normal Tawny alert rules.
              </p>
            </div>
            <div className="grid gap-3 p-5 text-sm">
              <SubsetItem label="Formats" value="STIX 2.1 indicators, OpenIOC XML, CSV, raw advisory text" />
              <SubsetItem label="File hashes" value="SHA-256 and SHA-1 match file integrity telemetry" />
              <SubsetItem label="Network" value="IPv4 and IPv6 match remote connection addresses" />
              <SubsetItem label="Domains" value="Domain IoCs match process command lines until DNS telemetry is added" />
              <SubsetItem label="Skipped" value="MD5 is reported but not imported because agents do not emit MD5" />
            </div>
          </section>
        </div>

        <section className="mt-8">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold uppercase text-[color:var(--color-muted-foreground)]">
              Imported rules
            </h2>
            <span className="text-sm text-[color:var(--color-muted-foreground)]">{rules.length} total</span>
          </div>

          <div className="mt-3 overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <table className="w-full text-sm">
              <thead className="bg-[color:var(--color-muted)] text-left">
                <tr>
                  <th className="px-4 py-3 font-medium">Rule</th>
                  <th className="px-4 py-3 font-medium">Format</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Predicate</th>
                  <th className="px-4 py-3 font-medium">State</th>
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                      No detection rules have been imported yet.
                    </td>
                  </tr>
                )}
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-t border-[color:var(--color-border)] align-top">
                    <td className="max-w-sm px-4 py-3">
                      <p className="font-medium">{rule.name}</p>
                      <p className="mt-1 truncate font-mono text-xs text-[color:var(--color-muted-foreground)]">
                        {rule.external_id ?? rule.id}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded-full bg-[color:var(--color-muted)] px-2.5 py-1 text-xs font-medium uppercase text-[color:var(--color-muted-foreground)]">
                        {rule.format === "sigma" ? "Sigma" : rule.format === "ioc" ? "IoC" : "Tawny"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full px-2.5 py-1 text-xs font-medium capitalize ring-1 ${severityTone[rule.severity]}`}>
                        {rule.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                      {rule.event_type ?? "any"} | {rule.payload_path ?? "event"} {rule.operator}
                      {rule.match_value ? ` ${rule.match_value}` : ""}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-[color:var(--color-muted-foreground)]">
                        {rule.is_enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </AppShell>
  );
}

function SubsetItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 rounded-md bg-[color:var(--color-muted)] px-3 py-2 sm:grid-cols-[9rem_1fr] sm:gap-4">
      <span className="font-medium">{label}</span>
      <span className="text-[color:var(--color-muted-foreground)]">{value}</span>
    </div>
  );
}
