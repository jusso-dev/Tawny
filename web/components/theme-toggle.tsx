"use client";

import { useEffect, useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";
import type { LucideIcon } from "lucide-react";

type Theme = "system" | "light" | "dark";

const storageKey = "tawny-theme";
const options: Array<[Theme, LucideIcon]> = [
  ["system", Monitor],
  ["light", Sun],
  ["dark", Moon],
];

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.dataset.theme = theme;
  }
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("system");

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const saved = window.localStorage.getItem(storageKey);
      setTheme(saved === "light" || saved === "dark" ? saved : "system");
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  function choose(next: Theme) {
    setTheme(next);
    if (next === "system") {
      window.localStorage.removeItem(storageKey);
    } else {
      window.localStorage.setItem(storageKey, next);
    }
  }

  return (
    <div className="inline-flex rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-1">
      {options.map(([value, Icon]) => (
        <button
          key={value}
          type="button"
          onClick={() => choose(value)}
          className={`min-h-8 rounded px-2.5 py-1.5 text-sm capitalize transition-colors ${
            theme === value
              ? "bg-[color:var(--color-muted)] text-[color:var(--color-foreground)]"
              : "text-[color:var(--color-muted-foreground)] hover:text-[color:var(--color-foreground)]"
          }`}
          aria-pressed={theme === value}
          title={`${value} theme`}
        >
          <Icon size={16} />
        </button>
      ))}
    </div>
  );
}
