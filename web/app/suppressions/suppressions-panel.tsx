"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Plus, ShieldOff, Trash2, X } from "lucide-react";

export type SuppressionRule = {
  id: string;
  name: string;
  reason: string | null;
  scope: "all_rules" | "specific_rule";
  alert_rule_id: string | null;
  alert_rule_name: string | null;
  agent_id: string | null;
  agent_hostname: string | null;
  payload_path: string | null;
  operator: "exists" | "equals" | "contains" | "greater_than" | "less_than";
  match_value: string | null;
  is_enabled: boolean;
  expires_at: string | null;
  suppressed_count: number;
  last_suppressed_at: string | null;
  created_at: string;
  updated_at: string;
};

type AlertRuleStub = { id: string; name: string };
type AgentStub = { id: string; hostname: string };

const OPERATORS: SuppressionRule["operator"][] = ["contains", "equals", "exists", "greater_than", "less_than"];

export function SuppressionsPanel({
  initialRules,
  alertRules,
  agents,
  role,
}: {
  initialRules: SuppressionRule[];
  alertRules: AlertRuleStub[];
  agents: AgentStub[];
  role: "Admin" | "Viewer";
}) {
  const router = useRouter();
  const [rules, setRules] = useState<SuppressionRule[]>(initialRules);
  const [creating, setCreating] = useState(false);
  const canEdit = role === "Admin";

  async function deleteRule(id: string) {
    if (!window.confirm("Delete this suppression?")) return;
    const res = await fetch(`/api/suppression-rules/${id}`, { method: "DELETE" });
    if (res.ok) {
      setRules((current) => current.filter((r) => r.id !== id));
      router.refresh();
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
            <Plus size={14} /> New suppression
          </button>
        </div>
      ) : null}

      <section className="overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <table className="w-full text-sm">
          <thead className="bg-[color:var(--color-muted)] text-left">
            <tr>
              <th className="px-4 py-3 font-medium">Name</th>
              <th className="px-4 py-3 font-medium">Scope</th>
              <th className="px-4 py-3 font-medium">Predicate</th>
              <th className="px-4 py-3 font-medium">Suppressed</th>
              <th className="px-4 py-3 font-medium">State</th>
              <th className="px-4 py-3 font-medium" />
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                  No suppression rules configured.
                </td>
              </tr>
            ) : (
              rules.map((r) => (
                <tr key={r.id} className="border-t border-[color:var(--color-border)] align-top">
                  <td className="px-4 py-3">
                    <p className="font-medium">{r.name}</p>
                    {r.reason ? (
                      <p className="mt-1 text-xs text-[color:var(--color-muted-foreground)]">{r.reason}</p>
                    ) : null}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {r.scope === "specific_rule" ? (
                      <span>
                        Rule: <span className="font-medium text-[color:var(--color-foreground)]">{r.alert_rule_name ?? "—"}</span>
                      </span>
                    ) : (
                      <span>All rules</span>
                    )}
                    {r.agent_hostname ? (
                      <span className="ml-2 rounded-full bg-[color:var(--color-muted)] px-2 py-0.5 text-xs">
                        on {r.agent_hostname}
                      </span>
                    ) : null}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                    {r.payload_path ? `${r.payload_path} ${r.operator}${r.match_value ? ` ${r.match_value}` : ""}` : "match any payload"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {r.suppressed_count.toLocaleString()}
                    {r.last_suppressed_at ? (
                      <p className="text-xs">
                        last {new Date(r.last_suppressed_at).toLocaleString()}
                      </p>
                    ) : null}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    {r.is_enabled ? (
                      <span className="rounded-full bg-[color:var(--color-success)]/15 px-2 py-1 text-xs font-medium text-[color:var(--color-success)]">
                        Enabled
                      </span>
                    ) : (
                      <span className="rounded-full bg-[color:var(--color-muted)] px-2 py-1 text-xs text-[color:var(--color-muted-foreground)]">
                        Disabled
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {canEdit ? (
                      <button
                        type="button"
                        onClick={() => deleteRule(r.id)}
                        className="inline-flex min-h-8 items-center gap-1 rounded-md border border-[color:var(--color-danger)]/40 px-2 text-xs text-[color:var(--color-danger)] hover:bg-[color:var(--color-danger)]/10"
                      >
                        <Trash2 size={12} />
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>

      {creating ? (
        <CreateSuppressionDialog
          alertRules={alertRules}
          agents={agents}
          onClose={() => setCreating(false)}
          onCreated={(rule) => {
            setRules((current) => [rule, ...current]);
            setCreating(false);
            router.refresh();
          }}
        />
      ) : null}
    </div>
  );
}

function CreateSuppressionDialog({
  alertRules,
  agents,
  onClose,
  onCreated,
}: {
  alertRules: AlertRuleStub[];
  agents: AgentStub[];
  onClose: () => void;
  onCreated: (rule: SuppressionRule) => void;
}) {
  const [name, setName] = useState("");
  const [reason, setReason] = useState("");
  const [scope, setScope] = useState<"all_rules" | "specific_rule">("specific_rule");
  const [alertRuleId, setAlertRuleId] = useState<string>(alertRules[0]?.id ?? "");
  const [agentId, setAgentId] = useState<string>("");
  const [payloadPath, setPayloadPath] = useState("");
  const [operator, setOperator] = useState<SuppressionRule["operator"]>("contains");
  const [matchValue, setMatchValue] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    if (scope === "specific_rule" && !alertRuleId) {
      setError("Pick an alert rule when scope is a specific rule.");
      return;
    }
    setPending(true);
    try {
      const res = await fetch("/api/suppression-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          reason: reason.trim() || null,
          scope,
          alert_rule_id: scope === "specific_rule" ? alertRuleId : null,
          agent_id: agentId || null,
          payload_path: payloadPath.trim() || null,
          operator,
          match_value: operator === "exists" ? null : matchValue.trim() || null,
          is_enabled: true,
          expires_at: null,
        }),
      });
      const data = (await res.json().catch(() => null)) as SuppressionRule | { error?: string } | null;
      if (!res.ok || !data || "error" in data) {
        throw new Error((data && "error" in data && data.error) || `Create failed with ${res.status}`);
      }
      onCreated(data as SuppressionRule);
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
          <h2 className="text-lg font-semibold">New suppression rule</h2>
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
            placeholder="Backup job spike on db-01"
          />
        </label>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Reason</span>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="min-h-16 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-2 text-sm"
            placeholder="Why this is expected behavior, ticket links, etc."
          />
        </label>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Scope</span>
          <select
            value={scope}
            onChange={(e) => setScope(e.target.value as "all_rules" | "specific_rule")}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          >
            <option value="specific_rule">Specific detection rule</option>
            <option value="all_rules">All rules (broad payload match)</option>
          </select>
        </label>

        {scope === "specific_rule" ? (
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Alert rule</span>
            <select
              value={alertRuleId}
              onChange={(e) => setAlertRuleId(e.target.value)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
            >
              {alertRules.length === 0 ? (
                <option value="">No alert rules</option>
              ) : (
                alertRules.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))
              )}
            </select>
          </label>
        ) : null}

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Restrict to agent (optional)</span>
          <select
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          >
            <option value="">Any agent</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.hostname}
              </option>
            ))}
          </select>
        </label>

        <div className="grid gap-2 sm:grid-cols-[1fr_8rem]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Payload path (optional)</span>
            <input
              value={payloadPath}
              onChange={(e) => setPayloadPath(e.target.value)}
              placeholder="processes.command_line"
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Operator</span>
            <select
              value={operator}
              onChange={(e) => setOperator(e.target.value as SuppressionRule["operator"])}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
            >
              {OPERATORS.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </select>
          </label>
        </div>

        {operator !== "exists" ? (
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Match value</span>
            <input
              value={matchValue}
              onChange={(e) => setMatchValue(e.target.value)}
              className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm font-mono"
              placeholder="known-good-backup.exe"
            />
          </label>
        ) : null}

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
            {pending ? <Loader2 size={14} className="animate-spin" /> : <ShieldOff size={14} />}
            Create
          </button>
        </div>
      </div>
    </div>
  );
}
