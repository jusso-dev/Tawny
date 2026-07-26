import Link from "next/link";
import type { Route } from "next";
import { CommandPalette } from "@/components/command-palette";
import { AppNavigation, type AppSection } from "@/components/app-navigation";

type ShellAgent = {
  id: string;
  hostname: string;
  status: string;
};

type AppShellProps = {
  agents?: ShellAgent[];
  active: AppSection;
  children: React.ReactNode;
};

export function AppShell({ agents = [], active, children }: AppShellProps) {
  return (
    <div className="min-h-svh bg-[color:var(--color-background)]">
      <CommandPalette agents={agents} />
      <AppNavigation active={active}>{children}</AppNavigation>
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="flex min-w-0 flex-col gap-5 border-b border-[color:var(--color-border)] pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow ? (
          <p className="text-sm text-[color:var(--color-muted-foreground)]">{eyebrow}</p>
        ) : null}
        <h1 className="mt-1 min-w-0 [overflow-wrap:anywhere] text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
        {description ? (
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[color:var(--color-muted-foreground)]">
            {description}
          </p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-3">{actions}</div> : null}
    </header>
  );
}

export function PrimaryLink({
  href,
  children,
}: {
  href: Route;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-11 items-center justify-center whitespace-nowrap rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-[color:var(--color-accent-foreground)] transition-opacity hover:opacity-90"
    >
      {children}
    </Link>
  );
}
