"use client";

import { useState } from "react";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { authClient } from "@/lib/auth-client";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPending(true);
    setError(null);
    const { error: authError } = await authClient.signIn.email({ email, password });
    setPending(false);
    if (authError) {
      setError(authError.message ?? "Sign-in failed.");
      return;
    }
    router.push("/agents");
  }

  async function onGithub() {
    await authClient.signIn.social({ provider: "github", callbackURL: "/agents" });
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-6">
      <Image
        src="/logo.jpg"
        alt="Tawny EDR"
        width={96}
        height={96}
        priority
        className="mb-6 rounded-md"
      />
      <h1 className="text-2xl font-semibold">Sign in</h1>
      <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
        Welcome back to Tawny.
      </p>

      <form onSubmit={onSubmit} className="mt-8 space-y-4">
        <label className="block">
          <span className="text-sm">Email</span>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded-md border border-[color:var(--color-border)] bg-transparent px-3 py-2"
          />
        </label>
        <label className="block">
          <span className="text-sm">Password</span>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-md border border-[color:var(--color-border)] bg-transparent px-3 py-2"
          />
        </label>
        {error && (
          <p className="text-sm text-[color:var(--color-danger)]">{error}</p>
        )}
        <button
          type="submit"
          disabled={pending}
          className="w-full rounded-md bg-[color:var(--color-accent)] py-2 text-sm font-medium text-black hover:opacity-90 disabled:opacity-50"
        >
          {pending ? "Signing in..." : "Sign in"}
        </button>
      </form>

      <button
        onClick={onGithub}
        className="mt-3 w-full rounded-md border border-[color:var(--color-border)] py-2 text-sm hover:bg-[color:var(--color-muted)]"
      >
        Continue with GitHub
      </button>
    </main>
  );
}
