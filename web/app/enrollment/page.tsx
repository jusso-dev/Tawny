import { headers } from "next/headers";
import { redirect } from "next/navigation";
import Link from "next/link";
import { auth } from "@/lib/auth";

export default async function EnrollmentPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login");

  return (
    <main className="mx-auto max-w-3xl px-6 py-10">
      <header>
        <h1 className="text-2xl font-semibold">Enrollment tokens</h1>
        <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
          One-shot tokens for onboarding new agents.
        </p>
      </header>

      <section className="mt-10 rounded-lg border border-[color:var(--color-border)] p-8 text-center">
        <p className="text-sm text-[color:var(--color-muted-foreground)]">
          Token management UI is not built yet.
        </p>
        <p className="mt-2 text-xs text-[color:var(--color-muted-foreground)]">
          For now, create tokens via the API:{" "}
          <code className="rounded bg-[color:var(--color-muted)] px-1.5 py-0.5">
            POST /api/enrollment-tokens
          </code>
          .
        </p>
        <Link
          href="/agents"
          className="mt-6 inline-block text-sm underline"
        >
          Back to agents
        </Link>
      </section>
    </main>
  );
}
