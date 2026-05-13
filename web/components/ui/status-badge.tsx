import { cn } from "@/lib/cn";

type Status = "online" | "stale" | "offline" | "unknown";

const styles: Record<Status, string> = {
  online: "bg-[color:var(--color-success)]/15 text-[color:var(--color-success)]",
  stale: "bg-[color:var(--color-warning)]/15 text-[color:var(--color-warning)]",
  offline: "bg-[color:var(--color-danger)]/15 text-[color:var(--color-danger)]",
  unknown: "bg-[color:var(--color-muted)] text-[color:var(--color-muted-foreground)]",
};

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize",
        styles[status],
      )}
    >
      <span className="mr-1.5 inline-block size-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}
