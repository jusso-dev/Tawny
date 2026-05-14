"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Check, Copy, Plus, X } from "lucide-react";

type CreatedToken = {
  id: string;
  token: string;
  expires_at: string;
};

type Props = {
  backendUrl: string;
};

const installBase = "https://raw.githubusercontent.com/jusso-dev/Tawny/main/agent/install";

function quotePowerShell(value: string) {
  return value.replace(/'/g, "''");
}

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <button
      type="button"
      onClick={copy}
      className="inline-flex items-center gap-2 rounded-md border border-[color:var(--color-border)] px-3 py-2 text-sm hover:bg-[color:var(--color-muted)]"
    >
      {copied ? <Check size={16} /> : <Copy size={16} />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function EnrollmentActions({ backendUrl }: Props) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [lifetimeHours, setLifetimeHours] = useState(24);
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const tokenForCommands = created?.token ?? "<token shown once after creation>";
  const windowsCommand = useMemo(
    () =>
      `irm ${installBase}/install.ps1 | iex; Install-TawnyAgent -BackendUrl '${quotePowerShell(
        backendUrl,
      )}' -EnrollmentToken '${quotePowerShell(tokenForCommands)}'`,
    [backendUrl, tokenForCommands],
  );
  const macCommand = useMemo(
    () =>
      `curl -fsSL ${installBase}/install.sh | sudo bash -s -- --backend-url '${backendUrl.replace(
        /'/g,
        "'\\''",
      )}' --enrollment-token '${tokenForCommands.replace(/'/g, "'\\''")}'`,
    [backendUrl, tokenForCommands],
  );

  async function createToken(e: React.FormEvent) {
    e.preventDefault();
    setPending(true);
    setError(null);
    try {
      const res = await fetch("/api/enrollment-tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lifetime_hours: lifetimeHours }),
      });
      if (!res.ok) throw new Error(`Create failed with ${res.status}`);
      const token = (await res.json()) as CreatedToken;
      setCreated(token);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create token.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="mt-6 inline-flex min-h-10 items-center justify-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white hover:opacity-90"
      >
        <Plus size={16} />
        Create token
      </button>

      <section className="mt-8 border-t border-[color:var(--color-border)] pt-8">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold">How to install</h2>
            <p className="mt-1 max-w-2xl text-sm text-[color:var(--color-muted-foreground)]">
              Create a token first, then run the command for the target endpoint. The raw token is only shown once.
            </p>
          </div>
          <span className="text-xs text-[color:var(--color-muted-foreground)]">
            Backend URL: {backendUrl}
          </span>
        </div>

        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="font-medium">Windows PowerShell</h3>
              <CopyButton value={windowsCommand} />
            </div>
            <pre className="mt-4 overflow-x-auto rounded-md bg-[color:var(--color-muted)] p-3 text-xs leading-6">
              <code>{windowsCommand}</code>
            </pre>
          </div>
          <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="font-medium">macOS shell</h3>
              <CopyButton value={macCommand} />
            </div>
            <pre className="mt-4 overflow-x-auto rounded-md bg-[color:var(--color-muted)] p-3 text-xs leading-6">
              <code>{macCommand}</code>
            </pre>
          </div>
        </div>
      </section>

      {open && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/45 px-4">
          <div className="w-full max-w-xl rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-6 shadow-xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold">Create enrollment token</h2>
                <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
                  Copy the value before closing this dialog. It will not be shown again.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded-md p-2 hover:bg-[color:var(--color-muted)]"
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>

            {created ? (
              <div className="mt-6">
                <label className="text-sm font-medium">One-time token</label>
                <div className="mt-2 flex flex-col gap-3 sm:flex-row">
                  <code className="min-w-0 flex-1 overflow-x-auto rounded-md bg-[color:var(--color-muted)] px-3 py-2 text-sm">
                    {created.token}
                  </code>
                  <CopyButton value={created.token} label="Copy token" />
                </div>
                <p className="mt-3 text-sm text-[color:var(--color-muted-foreground)]">
                  Expires {new Date(created.expires_at).toLocaleString()}.
                </p>
              </div>
            ) : (
              <form onSubmit={createToken} className="mt-6 space-y-5">
                <label className="block">
                  <span className="text-sm font-medium">Lifetime, hours</span>
                  <input
                    type="number"
                    min={1}
                    max={168}
                    value={lifetimeHours}
                    onChange={(e) => setLifetimeHours(Number(e.target.value))}
                    className="mt-2 w-full rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-2"
                  />
                </label>
                {error && <p className="text-sm text-[color:var(--color-danger)]">{error}</p>}
                <button
                  type="submit"
                  disabled={pending}
                  className="inline-flex min-h-10 items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
                >
                  <Plus size={16} />
                  {pending ? "Creating..." : "Create token"}
                </button>
              </form>
            )}
          </div>
        </div>
      )}
    </>
  );
}
