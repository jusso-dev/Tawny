using System.Text.Json;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure.Hunting;

namespace Tawny.Api.Services;

public class ExposureRuleException(string message) : Exception(message);

public record ExposureImportResult(
    IReadOnlyList<AlertRule> Rules,
    IReadOnlyList<string> SkippedEntries);

/// <summary>
/// Imports package-exposure rules from supported advisory formats. The two
/// shapes we accept today are:
///
///   1. OSV (osv.dev / GitHub Advisory Database) — a JSON object with
///      `id`, `summary`, and an `affected[]` array whose entries carry
///      `package: {ecosystem, name}` plus `ranges[]` or `versions[]`.
///   2. Simple list — a JSON array of plain objects:
///      `[{ "ecosystem": "npm", "name": "x", "version_pattern": "<=1.2.3" }]`
///
/// Each affected (ecosystem, name, version_pattern) becomes a separate
/// AlertRule with Format = PackageExposure so the evaluator can short-circuit
/// after a single match.
/// </summary>
public class ExposureRuleImporter
{
    private const int MaxRulesPerImport = 1_000;

    public ExposureImportResult Import(
        string definition,
        AlertSeverity severity,
        bool isEnabled,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(definition))
        {
            throw new ExposureRuleException("Definition is empty.");
        }

        using var doc = ParseJson(definition);
        var root = doc.RootElement;
        var rules = new List<AlertRule>();
        var skipped = new List<string>();

        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in root.EnumerateArray())
            {
                if (rules.Count >= MaxRulesPerImport)
                {
                    skipped.Add($"Stopped at the import limit of {MaxRulesPerImport} rules.");
                    break;
                }
                var compiled = CompileSimpleEntry(entry, severity, isEnabled, now);
                if (compiled is null) skipped.Add(EntryFingerprint(entry));
                else rules.Add(compiled);
            }
        }
        else if (root.ValueKind == JsonValueKind.Object)
        {
            // OSV: top-level object with `affected[]`. Multiple advisories
            // bundled together as `{ "advisories": [...] }` are also accepted.
            if (root.TryGetProperty("advisories", out var bundle) && bundle.ValueKind == JsonValueKind.Array)
            {
                foreach (var advisory in bundle.EnumerateArray())
                {
                    AppendOsv(advisory, severity, isEnabled, now, rules, skipped);
                }
            }
            else
            {
                AppendOsv(root, severity, isEnabled, now, rules, skipped);
            }
        }
        else
        {
            throw new ExposureRuleException("Definition must be a JSON object (OSV) or an array of {ecosystem, name, version_pattern}.");
        }

        if (rules.Count == 0)
        {
            throw new ExposureRuleException("No exposure rules could be compiled. Check ecosystem/name fields.");
        }
        return new ExposureImportResult(rules, skipped);
    }

    private static JsonDocument ParseJson(string definition)
    {
        try { return JsonDocument.Parse(definition); }
        catch (JsonException ex)
        {
            throw new ExposureRuleException($"Could not parse JSON: {ex.Message}");
        }
    }

    private static void AppendOsv(
        JsonElement advisory,
        AlertSeverity severity,
        bool isEnabled,
        DateTimeOffset now,
        List<AlertRule> rules,
        List<string> skipped)
    {
        var id = advisory.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
            ? idEl.GetString()
            : null;
        var summary = advisory.TryGetProperty("summary", out var sEl) && sEl.ValueKind == JsonValueKind.String
            ? sEl.GetString()
            : null;
        var advisoryUrl = ExtractFirstUrl(advisory);

        if (!advisory.TryGetProperty("affected", out var affectedArray)
            || affectedArray.ValueKind != JsonValueKind.Array)
        {
            skipped.Add(id ?? "<no id>");
            return;
        }

        foreach (var affected in affectedArray.EnumerateArray())
        {
            if (!affected.TryGetProperty("package", out var pkg)) continue;
            if (!pkg.TryGetProperty("ecosystem", out var ecoEl) || !pkg.TryGetProperty("name", out var nameEl)) continue;

            var ecosystem = ecoEl.GetString();
            var name = nameEl.GetString();
            if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(name)) continue;

            var versionPattern = BuildOsvVersionPattern(affected);
            if (rules.Count >= MaxRulesPerImport) return;
            rules.Add(BuildRule(
                ecosystem: NormalizeEcosystem(ecosystem),
                name: name,
                versionPattern: versionPattern,
                advisoryId: id,
                advisoryUrl: advisoryUrl,
                summary: summary,
                severity: severity,
                isEnabled: isEnabled,
                now: now));
        }
    }

    private static string? BuildOsvVersionPattern(JsonElement affected)
    {
        // OSV `versions[]` is the cleanest signal — explicit list of affected versions.
        if (affected.TryGetProperty("versions", out var versions) && versions.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>();
            foreach (var v in versions.EnumerateArray())
            {
                if (v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()))
                {
                    list.Add(v.GetString()!);
                }
            }
            if (list.Count > 0) return string.Join(",", list);
        }

        // Fall back to ranges[].events[] -> compile {introduced, fixed} into >=X,<Y.
        if (affected.TryGetProperty("ranges", out var ranges) && ranges.ValueKind == JsonValueKind.Array)
        {
            var fragments = new List<string>();
            foreach (var range in ranges.EnumerateArray())
            {
                if (!range.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array) continue;
                string? introduced = null;
                string? fixedAt = null;
                foreach (var ev in events.EnumerateArray())
                {
                    if (ev.TryGetProperty("introduced", out var i) && i.ValueKind == JsonValueKind.String) introduced = i.GetString();
                    if (ev.TryGetProperty("fixed", out var f) && f.ValueKind == JsonValueKind.String) fixedAt = f.GetString();
                }
                // OSV "introduced: 0" means "from the beginning" — omit the lower bound.
                if (introduced is not null and not "0") fragments.Add($">={introduced}");
                if (fixedAt is not null) fragments.Add($"<{fixedAt}");
            }
            if (fragments.Count > 0) return string.Join(",", fragments);
        }

        return null; // No version constraint -> "any version of this package is affected."
    }

    private static string? ExtractFirstUrl(JsonElement advisory)
    {
        if (!advisory.TryGetProperty("references", out var refs) || refs.ValueKind != JsonValueKind.Array)
        {
            return null;
        }
        foreach (var r in refs.EnumerateArray())
        {
            if (r.TryGetProperty("url", out var u) && u.ValueKind == JsonValueKind.String)
            {
                return u.GetString();
            }
        }
        return null;
    }

    private static AlertRule? CompileSimpleEntry(
        JsonElement entry,
        AlertSeverity severity,
        bool isEnabled,
        DateTimeOffset now)
    {
        if (!entry.TryGetProperty("ecosystem", out var ecoEl) || ecoEl.ValueKind != JsonValueKind.String) return null;
        if (!entry.TryGetProperty("name", out var nameEl) || nameEl.ValueKind != JsonValueKind.String) return null;
        var ecosystem = ecoEl.GetString();
        var name = nameEl.GetString();
        if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(name)) return null;

        var versionPattern = entry.TryGetProperty("version_pattern", out var vp) && vp.ValueKind == JsonValueKind.String
            ? vp.GetString()
            : null;
        var advisoryId = entry.TryGetProperty("advisory_id", out var aid) && aid.ValueKind == JsonValueKind.String
            ? aid.GetString()
            : null;
        var advisoryUrl = entry.TryGetProperty("advisory_url", out var aurl) && aurl.ValueKind == JsonValueKind.String
            ? aurl.GetString()
            : null;

        return BuildRule(
            ecosystem: NormalizeEcosystem(ecosystem),
            name: name,
            versionPattern: versionPattern,
            advisoryId: advisoryId,
            advisoryUrl: advisoryUrl,
            summary: null,
            severity: severity,
            isEnabled: isEnabled,
            now: now);
    }

    private static AlertRule BuildRule(
        string ecosystem,
        string name,
        string? versionPattern,
        string? advisoryId,
        string? advisoryUrl,
        string? summary,
        AlertSeverity severity,
        bool isEnabled,
        DateTimeOffset now)
    {
        var definition = new PackageExposureDefinition(
            ecosystem,
            name,
            string.IsNullOrWhiteSpace(versionPattern) ? null : versionPattern,
            advisoryId,
            advisoryUrl);

        var eventType = ExposureEventType(ecosystem);
        var displayPattern = versionPattern ?? "any";
        var externalId = $"exposure:{ecosystem}:{name}:{displayPattern}";
        if (advisoryId is { Length: > 0 }) externalId = $"{externalId}:{advisoryId}";
        if (externalId.Length > 128) externalId = externalId[..128];

        return new AlertRule
        {
            Id = Guid.NewGuid(),
            Name = $"Exposed {ecosystem}/{name} {displayPattern}",
            Format = AlertRuleFormat.PackageExposure,
            ExternalId = externalId,
            Description = summary ?? $"Installed package {ecosystem}/{name} matches version pattern {displayPattern}.",
            EventType = eventType,
            Severity = severity,
            Operator = AlertRuleOperator.Exists,
            SourceDefinition = PackageExposureParser.Serialize(definition),
            IsEnabled = isEnabled,
            CreatedAt = now,
            UpdatedAt = now,
        };
    }

    /// <summary>
    /// Maps an ecosystem token to the telemetry event type it scopes against,
    /// so the evaluator only touches the relevant batch. Editor / browser /
    /// MCP "ecosystems" are first-class because Bumblebee shipped them that
    /// way and they map cleanly onto our new event types.
    /// </summary>
    private static TelemetryEventType ExposureEventType(string ecosystem) => ecosystem.ToLowerInvariant() switch
    {
        "editor-extension" or "editor_extension" => TelemetryEventType.EditorExtension,
        "browser-extension" or "browser_extension" => TelemetryEventType.BrowserExtension,
        "mcp" or "mcp_server" or "mcp-server" => TelemetryEventType.McpConfig,
        _ => TelemetryEventType.PackageInventory,
    };

    private static string NormalizeEcosystem(string ecosystem) => ecosystem.Trim().ToLowerInvariant() switch
    {
        // OSV uses TitleCase / mixed; we normalize so the evaluator can do a simple equals.
        "go" or "go modules" => "go",
        "npm" or "node" => "npm",
        "pypi" or "python" => "pypi",
        "rubygems" or "gem" => "rubygems",
        "packagist" or "composer" => "packagist",
        "crates.io" or "rust" => "crates.io",
        "maven" or "java" => "maven",
        "nuget" or ".net" => "nuget",
        var s => s,
    };

    private static string EntryFingerprint(JsonElement entry)
    {
        var eco = entry.TryGetProperty("ecosystem", out var e) && e.ValueKind == JsonValueKind.String
            ? e.GetString()
            : "?";
        var name = entry.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String
            ? n.GetString()
            : "?";
        return $"{eco}/{name}";
    }
}
