import Image from "next/image";
import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-24">
      <Image
        src="/logo.jpg"
        alt="Tawny EDR"
        width={160}
        height={160}
        priority
        className="mb-8 rounded-lg"
      />
      <h1 className="sr-only">Tawny</h1>
      <p className="mt-3 text-lg text-[color:var(--color-muted-foreground)]">
        Quiet eyes on every endpoint.
      </p>

      <div className="mt-10 flex gap-3">
        <Link
          href="/agents"
          className="rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-medium text-black hover:opacity-90"
        >
          View agents
        </Link>
        <Link
          href="/login"
          className="rounded-md border border-[color:var(--color-border)] px-4 py-2 text-sm font-medium hover:bg-[color:var(--color-muted)]"
        >
          Log in
        </Link>
      </div>
    </main>
  );
}
