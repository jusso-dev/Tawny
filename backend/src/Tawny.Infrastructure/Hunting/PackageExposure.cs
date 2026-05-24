using System.Text.Json;
using System.Text.Json.Serialization;
using Tawny.Domain;

namespace Tawny.Infrastructure.Hunting;

public class PackageExposureException(string message) : Exception(message);

/// <summary>
/// JSON shape stored on AlertRule.SourceDefinition when Format = PackageExposure.
/// Inspired by Perplexity's Bumblebee scanner — the rule matches a (ecosystem,
/// name, version_pattern) triple against package_inventory events emitted by
/// the agent. Version patterns support exact match, comma-separated lists, or
/// simple npm-style range strings (^, ~, &gt;=, &lt;=, &lt;, &gt;).
/// </summary>
public record PackageExposureDefinition(
    [property: JsonPropertyName("ecosystem")] string Ecosystem,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("version_pattern")] string? VersionPattern,
    [property: JsonPropertyName("advisory_id")] string? AdvisoryId,
    [property: JsonPropertyName("advisory_url")] string? AdvisoryUrl);

public static class PackageExposureParser
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public static PackageExposureDefinition Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new PackageExposureException("Package exposure definition is empty.");
        }
        PackageExposureDefinition? def;
        try { def = JsonSerializer.Deserialize<PackageExposureDefinition>(json, JsonOptions); }
        catch (JsonException ex)
        {
            throw new PackageExposureException($"Invalid package exposure JSON: {ex.Message}");
        }
        if (def is null) throw new PackageExposureException("Definition deserialized to null.");
        if (string.IsNullOrWhiteSpace(def.Ecosystem))
        {
            throw new PackageExposureException("ecosystem is required (npm, pypi, go, rubygems, packagist, mcp, editor-extension, browser-extension).");
        }
        if (string.IsNullOrWhiteSpace(def.Name))
        {
            throw new PackageExposureException("name is required.");
        }
        return def;
    }

    public static string Serialize(PackageExposureDefinition def) => JsonSerializer.Serialize(def, JsonOptions);
}

public static class PackageExposureEvaluator
{
    /// <summary>
    /// Returns true if the supplied package_inventory / editor_extension /
    /// browser_extension / mcp_config payload matches this exposure
    /// definition. Caller is responsible for filtering by EventType before
    /// calling so we don't waste cycles on irrelevant events.
    /// </summary>
    public static bool Evaluate(PackageExposureDefinition definition, JsonElement payload)
    {
        if (!payload.TryGetProperty("ecosystem", out var ecosystem)
            || ecosystem.ValueKind != JsonValueKind.String) return false;
        if (!string.Equals(ecosystem.GetString(), definition.Ecosystem, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!payload.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String) return false;
        if (!string.Equals(name.GetString(), definition.Name, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(definition.VersionPattern))
        {
            // No version filter = "any installed version of this package is exposed".
            return true;
        }

        if (!payload.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.String)
        {
            // Pattern was specified but the event has no version — treat as no match.
            return false;
        }

        return VersionMatches(definition.VersionPattern, version.GetString() ?? "");
    }

    private static bool VersionMatches(string pattern, string actual)
    {
        if (string.IsNullOrWhiteSpace(actual)) return false;
        foreach (var raw in pattern.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (MatchesSingleRange(raw, actual)) return true;
        }
        return false;
    }

    private static bool MatchesSingleRange(string range, string actual)
    {
        if (range == "*") return true;
        if (range.StartsWith(">=")) return CompareVersion(actual, range[2..].Trim()) >= 0;
        if (range.StartsWith("<=")) return CompareVersion(actual, range[2..].Trim()) <= 0;
        if (range.StartsWith(">")) return CompareVersion(actual, range[1..].Trim()) > 0;
        if (range.StartsWith("<")) return CompareVersion(actual, range[1..].Trim()) < 0;
        if (range.StartsWith("="))
        {
            return string.Equals(range[1..].Trim(), actual, StringComparison.OrdinalIgnoreCase);
        }
        if (range.StartsWith("^"))
        {
            // ^1.2.3 means >=1.2.3 and <2.0.0 (caret pins the leftmost non-zero major).
            var anchor = ParseSemver(range[1..].Trim());
            var current = ParseSemver(actual);
            if (anchor is null || current is null) return false;
            if (current.Value.Major != anchor.Value.Major) return false;
            return CompareSemver(current.Value, anchor.Value) >= 0;
        }
        if (range.StartsWith("~"))
        {
            // ~1.2.3 means >=1.2.3 and <1.3.0 (tilde pins major.minor).
            var anchor = ParseSemver(range[1..].Trim());
            var current = ParseSemver(actual);
            if (anchor is null || current is null) return false;
            if (current.Value.Major != anchor.Value.Major
                || current.Value.Minor != anchor.Value.Minor) return false;
            return CompareSemver(current.Value, anchor.Value) >= 0;
        }
        // Default: exact string equality (case-insensitive). Covers commit hashes, named tags.
        return string.Equals(range, actual, StringComparison.OrdinalIgnoreCase);
    }

    private static int CompareVersion(string a, string b)
    {
        var sa = ParseSemver(a);
        var sb = ParseSemver(b);
        if (sa is not null && sb is not null) return CompareSemver(sa.Value, sb.Value);
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static (int Major, int Minor, int Patch)? ParseSemver(string raw)
    {
        // Strip leading "v" and any prerelease/build suffix (-alpha, +build).
        var stripped = raw.TrimStart('v', 'V');
        var split = stripped.IndexOfAny(new[] { '-', '+' });
        if (split >= 0) stripped = stripped[..split];
        var parts = stripped.Split('.');
        if (parts.Length == 0) return null;
        int major = 0, minor = 0, patch = 0;
        if (!int.TryParse(parts[0], out major)) return null;
        if (parts.Length > 1 && !int.TryParse(parts[1], out minor)) minor = 0;
        if (parts.Length > 2 && !int.TryParse(parts[2], out patch)) patch = 0;
        return (major, minor, patch);
    }

    private static int CompareSemver((int Major, int Minor, int Patch) a, (int Major, int Minor, int Patch) b)
    {
        if (a.Major != b.Major) return a.Major.CompareTo(b.Major);
        if (a.Minor != b.Minor) return a.Minor.CompareTo(b.Minor);
        return a.Patch.CompareTo(b.Patch);
    }
}
