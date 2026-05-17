import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { AlertTriangle, CheckCircle2, KeyRound, PlugZap, ServerCog, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiGet } from "@/lib/api";
import { AppShell, PageHeader } from "@/components/app-shell";

type Agent = {
  id: string;
  hostname: string;
  status: string;
};

const sentinelFields = [
  ["Tenant ID", "Tawny__Sentinel__TenantId"],
  ["Client ID", "Tawny__Sentinel__ClientId"],
  ["Client secret", "Tawny__Sentinel__ClientSecret"],
  ["DCR endpoint URL", "Tawny__Sentinel__EndpointUrl"],
  ["DCR immutable ID", "Tawny__Sentinel__DcrImmutableId"],
  ["Alert stream", "Tawny__Sentinel__AlertStreamName"],
  ["Telemetry stream", "Tawny__Sentinel__TelemetryStreamName"],
] as const;

const envLines = [
  "TAWNY_SENTINEL_ENABLED=true",
  "TAWNY_SENTINEL_ALERTS_ENABLED=true",
  "TAWNY_SENTINEL_TELEMETRY_ENABLED=false",
  "TAWNY_SENTINEL_AUTHENTICATION_MODE=client_secret",
  "TAWNY_SENTINEL_TENANT_ID=00000000-0000-0000-0000-000000000000",
  "TAWNY_SENTINEL_CLIENT_ID=00000000-0000-0000-0000-000000000000",
  "TAWNY_SENTINEL_CLIENT_SECRET=...",
  "TAWNY_SENTINEL_ENDPOINT_URL=https://<dcr>.<region>.ingest.monitor.azure.com",
  "TAWNY_SENTINEL_DCR_IMMUTABLE_ID=dcr-00000000000000000000000000000000",
  "TAWNY_SENTINEL_ALERT_STREAM_NAME=Custom-TawnyAlert_CL",
  "TAWNY_SENTINEL_TELEMETRY_STREAM_NAME=Custom-TawnyTelemetry_CL",
];

export default async function IntegrationsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  const role = authRole(session.user);
  const agents = await apiGet<Agent[]>("/api/agents", session.user.id, role);

  return (
    <AppShell agents={agents} active="integrations">
      <main className="mx-auto max-w-6xl px-6 py-8">
        <PageHeader
          eyebrow="Integrations"
          title="SIEM and notification sinks"
          description="Configure alert delivery destinations and decide whether full telemetry should leave Tawny."
        />

        <section className="mt-6 grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <div className="flex flex-col gap-3 border-b border-[color:var(--color-border)] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldCheck size={18} className="text-[color:var(--color-accent)]" />
                  <h2 className="font-semibold">Microsoft Sentinel</h2>
                </div>
                <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
                  Azure Monitor Logs Ingestion API with Microsoft Entra OAuth and DCR streams.
                </p>
              </div>
              <span className="inline-flex min-h-8 items-center rounded-full bg-[color:var(--color-success)]/12 px-3 text-xs font-medium text-[color:var(--color-success)] ring-1 ring-[color:var(--color-success)]/25">
                OAuth + DCR
              </span>
            </div>

            <div className="grid gap-5 p-5">
              <div className="grid gap-3 md:grid-cols-3">
                <StatusTile icon={CheckCircle2} label="Alerts" value="Enabled by default" tone="success" />
                <StatusTile icon={AlertTriangle} label="Telemetry" value="Off until enabled" tone="warning" />
                <StatusTile icon={KeyRound} label="Auth" value="Secret or identity" tone="accent" />
              </div>

              <div>
                <h3 className="text-sm font-semibold">Connection fields</h3>
                <div className="mt-3 grid gap-2">
                  {sentinelFields.map(([label, key]) => (
                    <div
                      key={key}
                      className="grid gap-1 rounded-md bg-[color:var(--color-muted)] px-3 py-2 sm:grid-cols-[10rem_1fr] sm:gap-4"
                    >
                      <span className="text-sm font-medium">{label}</span>
                      <span className="min-w-0 break-words font-mono text-xs text-[color:var(--color-muted-foreground)]">
                        {key}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold">Azure requirements</h3>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  <Requirement label="Tables" value="TawnyAlert_CL and TawnyTelemetry_CL" />
                  <Requirement label="Streams" value="Custom-TawnyAlert_CL and Custom-TawnyTelemetry_CL" />
                  <Requirement label="Role" value="Monitoring Metrics Publisher on the DCR" />
                  <Requirement label="Endpoint" value="DCR direct ingestion, DCE only for Private Link" />
                </div>
              </div>
            </div>
          </div>

          <aside className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
            <div className="border-b border-[color:var(--color-border)] px-5 py-4">
              <div className="flex items-center gap-2">
                <ServerCog size={18} className="text-[color:var(--color-accent)]" />
                <h2 className="font-semibold">Environment template</h2>
              </div>
            </div>
            <pre className="max-h-[34rem] overflow-auto p-5 text-xs leading-6 text-[color:var(--color-muted-foreground)]">
              {envLines.join("\n")}
            </pre>
          </aside>
        </section>

        <section className="mt-5 grid gap-5 lg:grid-cols-2">
          <SinkCard
            title="Slack"
            icon={PlugZap}
            status="Webhook"
            items={[
              ["Delivery", "New generated alerts"],
              ["State", "Stored on each alert row"],
              ["Config", "Tawny__Slack__WebhookUrl"],
            ]}
          />
          <SinkCard
            title="Wazuh"
            icon={ServerCog}
            status="Syslog"
            items={[
              ["Delivery", "One JSON syslog event per alert"],
              ["Protocol", "UDP or TCP"],
              ["Config", "Tawny__Wazuh__Host"],
            ]}
          />
        </section>
      </main>
    </AppShell>
  );
}

function StatusTile({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  tone: "success" | "warning" | "accent";
}) {
  const toneClass = {
    success: "text-[color:var(--color-success)] bg-[color:var(--color-success)]/12",
    warning: "text-[color:var(--color-warning)] bg-[color:var(--color-warning)]/12",
    accent: "text-[color:var(--color-accent)] bg-[color:var(--color-accent)]/12",
  }[tone];

  return (
    <div className="rounded-md border border-[color:var(--color-border)] p-3">
      <div className={`grid size-8 place-items-center rounded-md ${toneClass}`}>
        <Icon size={16} />
      </div>
      <p className="mt-3 text-sm font-medium">{label}</p>
      <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">{value}</p>
    </div>
  );
}

function Requirement({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-[color:var(--color-muted)] px-3 py-2">
      <p className="text-sm font-medium">{label}</p>
      <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">{value}</p>
    </div>
  );
}

function SinkCard({
  title,
  icon: Icon,
  status,
  items,
}: {
  title: string;
  icon: LucideIcon;
  status: string;
  items: Array<[string, string]>;
}) {
  return (
    <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
      <div className="flex items-center justify-between gap-3 border-b border-[color:var(--color-border)] px-5 py-4">
        <div className="flex items-center gap-2">
          <Icon size={18} className="text-[color:var(--color-accent)]" />
          <h2 className="font-semibold">{title}</h2>
        </div>
        <span className="rounded-full bg-[color:var(--color-muted)] px-2.5 py-1 text-xs font-medium text-[color:var(--color-muted-foreground)]">
          {status}
        </span>
      </div>
      <div className="grid gap-2 p-5">
        {items.map(([label, value]) => (
          <Requirement key={label} label={label} value={value} />
        ))}
      </div>
    </section>
  );
}
