"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { parse, YAMLParseError } from "yaml";
import { z } from "zod";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  FileCode2,
  Loader2,
  Search,
  Upload,
} from "lucide-react";
import {
  type SigmaCatalogCategory,
  type SigmaCatalogPlatform,
  sigmaCatalog,
} from "./sigma-rule-catalog";

type ValidationResult = {
  errors: string[];
  warnings: string[];
  summary: {
    title?: string;
    condition?: string;
    field?: string;
    modifier?: string;
    level?: string;
  };
};

const defaultYaml = `title: Suspicious Process Name
id: 8c6f0f07-5a44-4c41-83cc-2e0e0f6ef9f1
description: Detects a suspicious process name from Tawny process telemetry.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.name|contains: suspicious.exe
  condition: selection
level: high
`;

const blankYaml = `title: My Sigma Rule
description: Describe what this rule should detect.
logsource:
  category: process_creation
detection:
  selection:
    processes.name|contains: example
  condition: selection
level: medium
`;

const platforms: Array<SigmaCatalogPlatform | "any"> = ["any", "linux", "macos", "windows", "all"];
const categories: Array<SigmaCatalogCategory | "any"> = ["any", "process", "network", "file", "identity", "system"];

const supportedModifiers = new Set(["contains", "exists", "gt", "lt"]);
const displayedModifiers = "contains, exists, gt, lt";
const supportedLevels = new Set(["informational", "low", "medium", "high", "critical"]);

const scalarSchema = z.union([z.string(), z.number(), z.boolean()]).transform((value) => String(value).trim());

const requiredScalarSchema = scalarSchema.refine((value) => value.length > 0, {
  message: "Required value cannot be empty.",
});

const logsourceSchema = z.record(scalarSchema);

const sigmaRootSchema = z.object({
  title: requiredScalarSchema,
  id: scalarSchema.optional(),
  description: scalarSchema.optional(),
  logsource: logsourceSchema.optional(),
  detection: z.record(z.unknown()),
  level: scalarSchema.optional(),
});

const selectionValueSchema = z.union([requiredScalarSchema, z.array(requiredScalarSchema).min(1)]);
const selectionSchema = z.record(selectionValueSchema);

type SigmaRoot = z.infer<typeof sigmaRootSchema>;

function formatZodIssues(error: z.ZodError) {
  return error.issues.map((issue) => {
    const path = issue.path.length > 0 ? `${issue.path.join(".")}: ` : "";
    return `${path}${issue.message}`;
  });
}

function parseFieldPredicate(raw: string, errors: string[]) {
  const [field, ...modifiers] = raw.split("|");
  const modifier = modifiers.at(-1);

  if (!field) {
    errors.push("The selection field cannot be empty.");
  }

  if (modifiers.length > 1) {
    errors.push("Use at most one field modifier.");
  }

  if (modifier && !supportedModifiers.has(modifier.toLowerCase())) {
    errors.push(`Unsupported modifier "${modifier}". Use ${displayedModifiers}, or no modifier for equality.`);
  }

  return {
    field,
    modifier,
  };
}

function validateParsedSigmaRule(rule: SigmaRoot): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const summary: ValidationResult["summary"] = {
    title: rule.title,
  };

  if (rule.level) {
    const normalized = rule.level.toLowerCase();
    if (!supportedLevels.has(normalized)) {
      errors.push("Use one of these levels: informational, low, medium, high, critical.");
    } else {
      summary.level = normalized === "informational" ? "low" : normalized;
    }
  } else {
    warnings.push("No level set. Tawny will import the rule as medium severity.");
  }

  if (!rule.logsource) {
    warnings.push("No logsource set. The rule will evaluate against every telemetry event type.");
  }

  const conditionResult = requiredScalarSchema.safeParse(rule.detection.condition);
  if (!conditionResult.success) {
    errors.push("Add detection.condition and set it to the selection name.");
    return { errors, warnings, summary };
  }

  const condition = conditionResult.data;
  summary.condition = condition;
  if (condition.includes(" ")) {
    errors.push("Use a single selection name for condition, for example condition: selection.");
  }

  const selectionResult = selectionSchema.safeParse(rule.detection[condition]);
  if (!selectionResult.success) {
    errors.push(`Add a detection.${condition} selection block with scalar values or a YAML list.`);
    return { errors, warnings, summary };
  }

  const fieldNames = Object.keys(selectionResult.data);
  if (fieldNames.length === 0) {
    errors.push("Add exactly one field predicate inside the selection.");
    return { errors, warnings, summary };
  }

  if (fieldNames.length > 1) {
    errors.push("Only one field predicate per Sigma selection is supported right now.");
  }

  const fieldName = fieldNames[0];
  if (!fieldName) {
    errors.push("Add exactly one field predicate inside the selection.");
    return { errors, warnings, summary };
  }

  const { field, modifier } = parseFieldPredicate(fieldName, errors);
  summary.field = field;
  summary.modifier = modifier ?? "equals";

  return { errors, warnings, summary };
}

function validateSigmaRule(yaml: string): ValidationResult {
  const summary: ValidationResult["summary"] = {};

  if (yaml.trim().length === 0) {
    return {
      errors: ["Paste a Sigma YAML rule before importing."],
      warnings: [],
      summary,
    };
  }

  let parsed: unknown;
  try {
    parsed = parse(yaml);
  } catch (err) {
    const message =
      err instanceof YAMLParseError
        ? err.message.replace(/^.*?:\s*/, "")
        : "YAML could not be parsed.";
    return {
      errors: [message],
      warnings: [],
      summary,
    };
  }

  const rootResult = sigmaRootSchema.safeParse(parsed);
  if (!rootResult.success) {
    return {
      errors: formatZodIssues(rootResult.error),
      warnings: [],
      summary,
    };
  }

  return validateParsedSigmaRule(rootResult.data);
}

function CopyButton({ value }: { value: string }) {
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
      className="inline-flex min-h-9 items-center gap-2 rounded-md border border-[color:var(--color-border)] px-3 text-sm hover:bg-[color:var(--color-muted)]"
    >
      {copied ? <CheckCircle2 size={16} /> : <Copy size={16} />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function SigmaImportPanel() {
  const router = useRouter();
  const [ruleYaml, setRuleYaml] = useState(defaultYaml);
  const [enabled, setEnabled] = useState(true);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [platform, setPlatform] = useState<SigmaCatalogPlatform | "any">("any");
  const [category, setCategory] = useState<SigmaCatalogCategory | "any">("any");

  const validation = useMemo(() => validateSigmaRule(ruleYaml), [ruleYaml]);
  const filteredCatalog = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return sigmaCatalog.filter((rule) => {
      const platformMatch = platform === "any" || rule.platform === platform || rule.platform === "all";
      const categoryMatch = category === "any" || rule.category === category;
      const searchMatch =
        normalized.length === 0 ||
        `${rule.name} ${rule.description} ${rule.platform} ${rule.category}`.toLowerCase().includes(normalized);
      return platformMatch && categoryMatch && searchMatch;
    });
  }, [category, platform, query]);
  const canSubmit = validation.errors.length === 0 && ruleYaml.trim().length > 0 && !pending;

  function loadYaml(yaml: string) {
    setRuleYaml(yaml);
    setError(null);
    setSuccess(null);
  }

  async function importRule(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSuccess(null);

    if (!canSubmit) return;

    setPending(true);
    try {
      const res = await fetch("/api/alert-rules/sigma", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_yaml: ruleYaml, is_enabled: enabled }),
      });
      const body = (await res.json().catch(() => null)) as { name?: string; error?: string } | null;
      if (!res.ok) {
        throw new Error(body?.error ?? `Import failed with ${res.status}`);
      }

      setSuccess(`Imported ${body?.name ?? validation.summary.title ?? "Sigma rule"}.`);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import Sigma rule.");
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)]">
      <div className="flex flex-col gap-3 border-b border-[color:var(--color-border)] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="font-semibold">Import Sigma rule</h2>
          <p className="mt-1 text-sm text-[color:var(--color-muted-foreground)]">
            Paste a supported Sigma YAML rule and review the compiled predicate before importing.
          </p>
        </div>
        <CopyButton value={ruleYaml} />
      </div>

      <form onSubmit={importRule} className="space-y-5 p-5">
        <div className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-muted)] p-4">
          <div className="grid gap-3">
            <div className="max-w-2xl">
              <h3 className="text-sm font-medium">Detection catalog</h3>
              <p className="mt-1 text-xs text-[color:var(--color-muted-foreground)]">
                Load a supported Sigma starter rule, then tune the YAML before import.
              </p>
            </div>
            <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto_auto]">
              <label className="relative block">
                <Search
                  size={15}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--color-muted-foreground)]"
                />
                <input
                  type="search"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search detections"
                  className="min-h-9 w-full rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] pl-9 pr-3 text-sm"
                />
              </label>
              <select
                value={platform}
                onChange={(event) => setPlatform(event.target.value as SigmaCatalogPlatform | "any")}
                className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-2 text-sm capitalize"
                aria-label="Filter by operating system"
              >
                {platforms.map((item) => (
                  <option key={item} value={item}>
                    {item === "any" ? "Any OS" : item}
                  </option>
                ))}
              </select>
              <select
                value={category}
                onChange={(event) => setCategory(event.target.value as SigmaCatalogCategory | "any")}
                className="min-h-9 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-2 text-sm capitalize"
                aria-label="Filter by detection category"
              >
                {categories.map((item) => (
                  <option key={item} value={item}>
                    {item === "any" ? "Any category" : item}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="mt-4 grid max-h-80 gap-2 overflow-y-auto pr-1">
            {filteredCatalog.length === 0 ? (
              <p className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-3 py-4 text-center text-sm text-[color:var(--color-muted-foreground)]">
                No catalog detections match those filters.
              </p>
            ) : (
              filteredCatalog.map((rule) => (
                <button
                  key={rule.id}
                  type="button"
                  onClick={() => loadYaml(rule.yaml)}
                  className="grid gap-2 rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-3 py-3 text-left hover:border-[color:var(--color-accent)]/50 sm:grid-cols-[1fr_auto]"
                >
                  <span>
                    <span className="block text-sm font-medium">{rule.name}</span>
                    <span className="mt-1 block text-xs leading-5 text-[color:var(--color-muted-foreground)]">
                      {rule.description}
                    </span>
                  </span>
                  <span className="flex flex-wrap items-center gap-1.5 text-xs capitalize text-[color:var(--color-muted-foreground)]">
                    <span className="rounded-full bg-[color:var(--color-muted)] px-2 py-1">{rule.platform}</span>
                    <span className="rounded-full bg-[color:var(--color-muted)] px-2 py-1">{rule.category}</span>
                    <span className="rounded-full bg-[color:var(--color-muted)] px-2 py-1">{rule.severity}</span>
                  </span>
                </button>
              ))
            )}
          </div>
        </div>

        <div>
          <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
            <div>
              <label htmlFor="sigma-yaml" className="text-sm font-medium">
                Custom Sigma rule
              </label>
              <p className="mt-1 text-xs text-[color:var(--color-muted-foreground)]">
                Paste or write your own Sigma YAML. The same validation runs before import.
              </p>
            </div>
            <button
              type="button"
              onClick={() => loadYaml(blankYaml)}
              className="inline-flex min-h-8 items-center gap-2 rounded-md border border-[color:var(--color-border)] px-2.5 text-xs hover:bg-[color:var(--color-muted)]"
            >
              <FileCode2 size={14} />
              Start blank
            </button>
          </div>
          <textarea
            id="sigma-yaml"
            value={ruleYaml}
            onChange={(event) => {
              setRuleYaml(event.target.value);
              setError(null);
              setSuccess(null);
            }}
            spellCheck={false}
            className="min-h-[24rem] w-full resize-y rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-background)] px-3 py-3 font-mono text-xs leading-6 outline-none focus:ring-2 focus:ring-[color:var(--color-accent)]"
          />
        </div>

        <ValidationPanel validation={validation} />

        <label className="flex items-center gap-3 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
            className="h-4 w-4 accent-[color:var(--color-accent)]"
          />
          Enable after import
        </label>

        {error && (
          <p className="rounded-md border border-[color:var(--color-danger)]/35 bg-[color:var(--color-danger)]/10 px-3 py-2 text-sm text-[color:var(--color-danger)]">
            {error}
          </p>
        )}
        {success && (
          <p className="rounded-md border border-[color:var(--color-success)]/35 bg-[color:var(--color-success)]/10 px-3 py-2 text-sm text-[color:var(--color-success)]">
            {success}
          </p>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 text-sm font-medium text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
        >
          {pending ? <Loader2 size={16} className="animate-spin" /> : <Upload size={16} />}
          {pending ? "Importing..." : "Import rule"}
        </button>
      </form>
    </section>
  );
}

function ValidationPanel({ validation }: { validation: ValidationResult }) {
  const valid = validation.errors.length === 0;
  const hasSummary = Boolean(validation.summary.title || validation.summary.field);

  return (
    <div className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-muted)] p-4">
      <div className="flex items-center gap-2">
        {valid ? (
          <CheckCircle2 size={17} className="text-[color:var(--color-success)]" />
        ) : (
          <AlertTriangle size={17} className="text-[color:var(--color-danger)]" />
        )}
        <h3 className="text-sm font-medium">{valid ? "Ready to import" : "Fix validation issues"}</h3>
      </div>

      {hasSummary && (
        <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
          <SummaryItem label="Title" value={validation.summary.title} />
          <SummaryItem label="Condition" value={validation.summary.condition} />
          <SummaryItem label="Field" value={validation.summary.field} />
          <SummaryItem label="Modifier" value={validation.summary.modifier} />
          <SummaryItem label="Severity" value={validation.summary.level} />
        </dl>
      )}

      {(validation.errors.length > 0 || validation.warnings.length > 0) && (
        <div className="mt-3 space-y-2 text-sm">
          {validation.errors.map((message) => (
            <p key={message} className="text-[color:var(--color-danger)]">
              {message}
            </p>
          ))}
          {validation.warnings.map((message) => (
            <p key={message} className="text-[color:var(--color-muted-foreground)]">
              {message}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value?: string }) {
  if (!value) return null;

  return (
    <div>
      <dt className="text-[color:var(--color-muted-foreground)]">{label}</dt>
      <dd className="mt-0.5 break-words font-mono text-[color:var(--color-foreground)]">{value}</dd>
    </div>
  );
}
