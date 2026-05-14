import Image from "next/image";
import Link from "next/link";
import type { Route } from "next";
import { Activity, KeyRound, LayoutDashboard, ShieldCheck } from "lucide-react";
import { CommandPalette } from "@/components/command-palette";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/cn";

type ShellAgent = {
  id: string;
  hostname: string;
  status: string;
};

type AppShellProps = {
  agents?: ShellAgent[];
  active: "dashboard" | "agents" | "detections" | "enrollment";
  children: React.ReactNode;
};

type NavItem = {
  href: Route;
  label: string;
  key: AppShellProps["active"];
  icon: typeof LayoutDashboard;
};

const navItems: NavItem[] = [
  { href: "/", label: "Dashboard", key: "dashboard", icon: LayoutDashboard },
  { href: "/agents", label: "Agents", key: "agents", icon: Activity },
  { href: "/detections", label: "Detections", key: "detections", icon: ShieldCheck },
  { href: "/enrollment", label: "Enrollment", key: "enrollment", icon: KeyRound },
];

export function AppShell({ agents = [], active, children }: AppShellProps) {
  return (
    <div className="min-h-screen bg-[color:var(--color-background)]">
      <CommandPalette agents={agents} />
      <header className="sticky top-0 z-30 border-b border-[color:var(--color-border)] bg-[color:var(--color-background)]/95 backdrop-blur supports-[backdrop-filter]:bg-[color:var(--color-background)]/82">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-6 py-3">
          <div className="flex min-w-0 items-center gap-4">
            <Link href="/" className="flex shrink-0 items-center gap-2" aria-label="Tawny dashboard">
              <Image src="/logo.jpg" alt="" width={32} height={32} className="rounded" />
              <span className="font-semibold tracking-tight">Tawny</span>
            </Link>
            <nav className="hidden items-center gap-1 md:flex" aria-label="Primary navigation">
              {navItems.map((item) => {
                const Icon = item.icon;
                const selected = item.key === active;
                return (
                  <Link
                    key={item.key}
                    href={item.href}
                    className={cn(
                      "inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                      selected
                        ? "bg-[color:var(--color-muted)] text-[color:var(--color-foreground)]"
                        : "text-[color:var(--color-muted-foreground)] hover:bg-[color:var(--color-muted)]/70 hover:text-[color:var(--color-foreground)]",
                    )}
                    aria-current={selected ? "page" : undefined}
                  >
                    <Icon size={15} />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <span className="hidden rounded-md border border-[color:var(--color-border)] px-3 py-1.5 text-xs text-[color:var(--color-muted-foreground)] lg:inline-flex">
              Cmd+K
            </span>
            <ThemeToggle />
          </div>
        </div>
      </header>
      {children}
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
    <header className="flex flex-col gap-5 border-b border-[color:var(--color-border)] pb-6 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow ? (
          <p className="text-sm text-[color:var(--color-muted-foreground)]">{eyebrow}</p>
        ) : null}
        <h1 className="mt-1 text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
        {description ? (
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[color:var(--color-muted-foreground)]">
            {description}
          </p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-3">{actions}</div> : null}
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
      className="inline-flex min-h-10 items-center justify-center rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white transition-opacity hover:opacity-90"
    >
      {children}
    </Link>
  );
}
