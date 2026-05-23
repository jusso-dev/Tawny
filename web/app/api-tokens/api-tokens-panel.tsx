"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { CheckCircle2, Copy, KeyRound, Loader2, Plus, Trash2, X } from "lucide-react";

export type ApiToken = {
  id: string;
  name: string;
  token_prefix: string;
  role: "admin" | "viewer";
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
};

type CreatedToken = ApiToken & { token: string };

export function ApiTokensPanel({ initialTokens }: { initialTokens: ApiToken[] }) {
  const router = useRouter();
  const [tokens, setTokens] = useState<ApiToken[]>(initialTokens);
  const [createOpen, setCreateOpen] = useState(false);
  const [createdToken, setCreatedToken] = useState<CreatedToken | null>(null);

  async function revoke(id: string) {
    if (!window.confirm("Revoke this token? Any clients using it will stop working.")) return;
    const res = await fetch(`/api/api-tokens/${id}`, { method: "DELETE" });
    if (res.ok) {
      setTokens((current) =>
        current.map((t) => (t.id === id ? { ...t, revoked_at: new Date().toISOString() } : t)),
      );
      router.refresh();
    }
  }

  function onCreated(token: CreatedToken) {
    setTokens((current) => [
      {
        id: token.id,
        name: token.name,
        token_prefix: token.token_prefix,
        role: token.role,
        created_at: token.created_at,
        expires_at: token.expires_at,
        last_used_at: null,
        revoked_at: null,
      },
      ...current,
    ]);
    setCreateOpen(false);
    setCreatedToken(token);
    router.refresh();
  }

  return (
    <div className="mt-6 grid gap-5">
      <div className="flex justify-end">
        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex min-h-9 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-3 text-sm font-medium text-white"
        >
          <Plus size={14} /> Create token
        </button>
      </div>

      {createdToken ? <CreatedTokenBanner token={createdToken} onDismiss={() => setCreatedToken(null)} /> : null}

      <section className="overflow-hidden rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
        <table className="w-full text-sm">
          <thead className="bg-[color:var(--color-muted)] text-left">
            <tr>
              <th className="px-4 py-3 font-medium">Name</th>
              <th className="px-4 py-3 font-medium">Prefix</th>
              <th className="px-4 py-3 font-medium">Role</th>
              <th className="px-4 py-3 font-medium">Created</th>
              <th className="px-4 py-3 font-medium">Last used</th>
              <th className="px-4 py-3 font-medium">Expires</th>
              <th className="px-4 py-3 font-medium">State</th>
              <th className="px-4 py-3 font-medium" />
            </tr>
          </thead>
          <tbody>
            {tokens.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-[color:var(--color-muted-foreground)]">
                  No API tokens yet.
                </td>
              </tr>
            ) : (
              tokens.map((t) => (
                <tr key={t.id} className="border-t border-[color:var(--color-border)] align-top">
                  <td className="px-4 py-3 font-medium">{t.name}</td>
                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-[color:var(--color-muted-foreground)]">
                    {t.token_prefix}…
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 capitalize">{t.role}</td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {new Date(t.created_at).toLocaleDateString()}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {t.last_used_at ? new Date(t.last_used_at).toLocaleString() : "Never"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-[color:var(--color-muted-foreground)]">
                    {t.expires_at ? new Date(t.expires_at).toLocaleDateString() : "—"}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3">
                    {t.revoked_at ? (
                      <span className="rounded-full bg-[color:var(--color-danger)]/15 px-2 py-1 text-xs font-medium text-[color:var(--color-danger)]">
                        Revoked
                      </span>
                    ) : (
                      <span className="rounded-full bg-[color:var(--color-success)]/15 px-2 py-1 text-xs font-medium text-[color:var(--color-success)]">
                        Active
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {!t.revoked_at && (
                      <button
                        type="button"
                        onClick={() => revoke(t.id)}
                        className="inline-flex min-h-8 items-center gap-1 rounded-md border border-[color:var(--color-danger)]/40 px-2 text-xs text-[color:var(--color-danger)] hover:bg-[color:var(--color-danger)]/10"
                      >
                        <Trash2 size={12} /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>

      {createOpen ? <CreateTokenDialog onClose={() => setCreateOpen(false)} onCreated={onCreated} /> : null}
    </div>
  );
}

function CreatedTokenBanner({ token, onDismiss }: { token: CreatedToken; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(token.token);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="rounded-md border border-[color:var(--color-warning)]/40 bg-[color:var(--color-warning)]/10 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <KeyRound size={16} className="mt-0.5 text-[color:var(--color-warning)]" />
          <div>
            <h3 className="text-sm font-semibold">Token created — copy it now</h3>
            <p className="mt-1 text-xs text-[color:var(--color-muted-foreground)]">
              Tawny only shows this once. Save it in your secrets manager before closing this banner.
            </p>
          </div>
        </div>
        <button type="button" onClick={onDismiss} className="rounded-md p-1 hover:bg-[color:var(--color-muted)]">
          <X size={14} />
        </button>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded-md bg-[color:var(--color-background)] px-3 py-2 font-mono text-xs">
          {token.token}
        </code>
        <button
          type="button"
          onClick={copy}
          className="inline-flex min-h-9 items-center gap-2 rounded-md border border-[color:var(--color-border)] px-3 text-xs hover:bg-[color:var(--color-muted)]"
        >
          {copied ? <CheckCircle2 size={13} /> : <Copy size={13} />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

function CreateTokenDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (token: CreatedToken) => void;
}) {
  const [name, setName] = useState("");
  const [role, setRole] = useState<"admin" | "viewer">("viewer");
  const [expiresInDays, setExpiresInDays] = useState<string>("90");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    let expiresAt: string | null = null;
    const days = parseInt(expiresInDays, 10);
    if (Number.isFinite(days) && days > 0) {
      const d = new Date();
      d.setDate(d.getDate() + days);
      expiresAt = d.toISOString();
    }
    setPending(true);
    try {
      const res = await fetch("/api/api-tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim(), role, expires_at: expiresAt }),
      });
      const data = (await res.json().catch(() => null)) as CreatedToken | { error?: string } | null;
      if (!res.ok || !data || "error" in data) {
        throw new Error((data && "error" in data && data.error) || `Create failed with ${res.status}`);
      }
      onCreated(data as CreatedToken);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed.");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 px-4" role="dialog">
      <div className="grid w-full max-w-md gap-4 rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-6">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Create API token</h2>
          <button type="button" onClick={onClose} className="rounded-md p-1 hover:bg-[color:var(--color-muted)]">
            <X size={16} />
          </button>
        </div>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="ci-pipeline"
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          />
        </label>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Role</span>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as "admin" | "viewer")}
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          >
            <option value="viewer">Viewer (read-only)</option>
            <option value="admin">Admin (full access)</option>
          </select>
        </label>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Expires in (days)</span>
          <input
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(e.target.value)}
            placeholder="leave blank for no expiry"
            className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 text-sm"
          />
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
            {pending ? <Loader2 size={14} className="animate-spin" /> : <KeyRound size={14} />}
            Create
          </button>
        </div>
      </div>
    </div>
  );
}
