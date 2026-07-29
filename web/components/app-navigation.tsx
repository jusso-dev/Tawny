"use client";

import { useEffect, useRef, useState } from "react";
import Image from "next/image";
import Link from "next/link";
import type { Route } from "next";
import {
  Activity,
  BellRing,
  Compass,
  FileClock,
  KeyRound,
  LayoutDashboard,
  Menu,
  Radar,
  ShieldCheck,
  ShieldOff,
  TerminalSquare,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/cn";

export type AppSection =
  | "dashboard"
  | "agents"
  | "alerts"
  | "detections"
  | "hunt"
  | "suppressions"
  | "threat-intel"
  | "audit"
  | "tokens"
  | "enrollment";

type NavItem = {
  href: Route;
  label: string;
  key: AppSection;
  icon: LucideIcon;
};

const navGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Operations",
    items: [
      { href: "/", label: "Dashboard", key: "dashboard", icon: LayoutDashboard },
      { href: "/agents", label: "Agents", key: "agents", icon: Activity },
      { href: "/alerts", label: "Alerts", key: "alerts", icon: BellRing },
    ],
  },
  {
    label: "Analysis",
    items: [
      { href: "/hunt" as Route, label: "Hunt", key: "hunt", icon: TerminalSquare },
    ],
  },
  {
    label: "Detection",
    items: [
      { href: "/detections", label: "Detections", key: "detections", icon: ShieldCheck },
      { href: "/threat-intel" as Route, label: "Threat intel", key: "threat-intel", icon: Radar },
      { href: "/suppressions" as Route, label: "Suppressions", key: "suppressions", icon: ShieldOff },
    ],
  },
  {
    label: "System",
    items: [
      { href: "/audit" as Route, label: "Audit", key: "audit", icon: FileClock },
      { href: "/api-tokens" as Route, label: "Tokens", key: "tokens", icon: Compass },
      { href: "/enrollment", label: "Enrollment", key: "enrollment", icon: KeyRound },
    ],
  },
];

const activeLabel = Object.fromEntries(
  navGroups.flatMap((group) => group.items.map((item) => [item.key, item.label])),
) as Record<AppSection, string>;

export function AppNavigation({
  active,
  children,
}: {
  active: AppSection;
  children: React.ReactNode;
}) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!mobileOpen) return;

    const previousOverflow = document.body.style.overflow;
    const trigger = triggerRef.current;
    document.body.style.overflow = "hidden";
    closeButtonRef.current?.focus();

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setMobileOpen(false);
    }

    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
      trigger?.focus();
    };
  }, [mobileOpen]);

  return (
    <div className="grid min-h-svh grid-cols-1 lg:grid-cols-[15.5rem_minmax(0,1fr)]">
      <aside className="sticky top-0 hidden h-svh min-w-0 flex-col border-r border-[color:var(--color-border)] bg-[color:var(--color-card)] lg:flex">
        <SidebarContent active={active} />
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Primary navigation">
          <button
            type="button"
            className="absolute inset-0 bg-[color:var(--color-overlay)]"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
          />
          <aside className="relative flex h-svh w-[min(20rem,calc(100%-3rem))] flex-col border-r border-[color:var(--color-border)] bg-[color:var(--color-card)] shadow-[var(--shadow-drawer)]">
            <button
              ref={closeButtonRef}
              type="button"
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-3 grid size-11 place-items-center rounded-md text-[color:var(--color-muted-foreground)] hover:bg-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)]"
              aria-label="Close navigation"
            >
              <X size={19} />
            </button>
            <SidebarContent active={active} onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      ) : null}

      <div className="min-w-0">
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-4 border-b border-[color:var(--color-border)] bg-[color:var(--color-background)]/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-[color:var(--color-background)]/82 sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <button
              ref={triggerRef}
              type="button"
              onClick={() => setMobileOpen(true)}
              className="grid size-11 shrink-0 place-items-center rounded-md text-[color:var(--color-muted-foreground)] hover:bg-[color:var(--color-muted)] hover:text-[color:var(--color-foreground)] lg:hidden"
              aria-label="Open navigation"
              aria-expanded={mobileOpen}
            >
              <Menu size={19} />
            </button>
            <Link href="/" className="flex shrink-0 items-center gap-2 lg:hidden" aria-label="Tawny dashboard">
              <Image src="/logo-mark.png" alt="" width={28} height={28} className="size-7 object-contain" />
              <span className="font-semibold tracking-tight">Tawny</span>
            </Link>
            <span className="hidden truncate text-sm font-medium text-[color:var(--color-muted-foreground)] lg:block">
              {activeLabel[active]}
            </span>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <kbd className="hidden min-h-9 items-center rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-3 text-xs text-[color:var(--color-muted-foreground)] sm:inline-flex">
              <span className="mr-1 text-[color:var(--color-foreground)]">⌘</span>K
            </kbd>
            <ThemeToggle />
          </div>
        </header>

        <div className="min-w-0">{children}</div>
      </div>
    </div>
  );
}

function SidebarContent({
  active,
  onNavigate,
}: {
  active: AppSection;
  onNavigate?: () => void;
}) {
  return (
    <>
      <div className="flex h-14 shrink-0 items-center border-b border-[color:var(--color-border)] px-4">
        <Link href="/" className="flex items-center gap-2.5" onClick={onNavigate} aria-label="Tawny dashboard">
          <Image src="/logo-mark.png" alt="" width={32} height={32} className="size-8 object-contain" />
          <span className="font-semibold tracking-tight">Tawny</span>
        </Link>
      </div>

      <nav className="min-h-0 flex-1 overflow-y-auto px-3 py-4" aria-label="Primary navigation">
        <div className="space-y-5">
          {navGroups.map((group) => (
            <section key={group.label} aria-labelledby={`nav-${group.label.toLowerCase()}`}>
              <h2
                id={`nav-${group.label.toLowerCase()}`}
                className="mb-1.5 px-2 text-[11px] font-medium uppercase tracking-[0.08em] text-[color:var(--color-muted-foreground)]"
              >
                {group.label}
              </h2>
              <ul className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const selected = item.key === active;
                  return (
                    <li key={item.key}>
                      <Link
                        href={item.href}
                        onClick={onNavigate}
                        className={cn(
                          "relative flex min-h-10 items-center gap-3 whitespace-nowrap rounded-md px-2.5 text-sm font-medium transition-colors",
                          selected
                            ? "bg-[color:var(--color-muted)] text-[color:var(--color-foreground)]"
                            : "text-[color:var(--color-muted-foreground)] hover:bg-[color:var(--color-muted)]/70 hover:text-[color:var(--color-foreground)]",
                        )}
                        aria-current={selected ? "page" : undefined}
                      >
                        <Icon size={16} className="shrink-0" />
                        <span className="truncate">{item.label}</span>
                        {selected ? (
                          <span
                            className="ml-auto size-1.5 shrink-0 rounded-full bg-[color:var(--color-accent)]"
                            aria-hidden="true"
                          />
                        ) : null}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </section>
          ))}
        </div>
      </nav>

      <div className="shrink-0 border-t border-[color:var(--color-border)] px-5 py-3">
        <p className="text-xs text-[color:var(--color-muted-foreground)]">Local-first endpoint security</p>
      </div>
    </>
  );
}
