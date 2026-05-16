using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public partial class IocRuleImporter
{
    private const int MaxIndicators = 500;

    public IocImportResult Import(
        string definition,
        string? sourceFormat,
        AlertSeverity severity,
        bool isEnabled,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(definition))
        {
            throw new IocRuleException("Threat intel definition is required.");
        }

        var normalizedFormat = NormalizeFormat(sourceFormat, definition);
        var parsed = normalizedFormat switch
        {
            "stix" => ParseStix(definition),
            "openioc" => ParseOpenIoc(definition),
            "raw" => ParseRaw(definition),
            _ => throw new IocRuleException("Use source_format auto, stix, openioc, or raw."),
        };

        var rules = new List<AlertRule>();
        var skipped = new List<string>(parsed.SkippedIndicators);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var indicator in parsed.Indicators)
        {
            var key = $"{indicator.Type}:{indicator.Value}";
            if (!seen.Add(key))
            {
                continue;
            }

            if (rules.Count >= MaxIndicators)
            {
                skipped.Add($"Reached the import limit of {MaxIndicators} indicators.");
                break;
            }

            var rule = CompileRule(indicator, normalizedFormat, severity, isEnabled, now);
            if (rule is null)
            {
                skipped.Add($"Skipped unsupported indicator {indicator.Type} {indicator.Value}.");
                continue;
            }

            rules.Add(rule);
        }

        if (rules.Count == 0)
        {
            throw new IocRuleException("No supported SHA-1, SHA-256, domain, IPv4, or IPv6 indicators were found.");
        }

        return new IocImportResult(rules, skipped);
    }

    private static AlertRule? CompileRule(
        IocIndicator indicator,
        string sourceFormat,
        AlertSeverity severity,
        bool isEnabled,
        DateTimeOffset now)
    {
        var compiled = indicator.Type switch
        {
            IocIndicatorType.Sha256 => (TelemetryEventType.FileIntegrity, "new_sha256", AlertRuleOperator.Equals),
            IocIndicatorType.Sha1 => (TelemetryEventType.FileIntegrity, "new_sha1", AlertRuleOperator.Equals),
            IocIndicatorType.IpAddress => (TelemetryEventType.NetworkSnapshot, "connections.remote_address", AlertRuleOperator.Equals),
            IocIndicatorType.Domain => (TelemetryEventType.ProcessSnapshot, "processes.command_line", AlertRuleOperator.Contains),
            _ => ((TelemetryEventType EventType, string PayloadPath, AlertRuleOperator Operator)?)null,
        };
        if (compiled is null)
        {
            return null;
        }

        var (eventType, payloadPath, op) = compiled.Value;
        var value = indicator.Type is IocIndicatorType.Domain
            ? indicator.Value.ToLowerInvariant()
            : indicator.Value;

        return new AlertRule
        {
            Id = Guid.NewGuid(),
            Name = BuildRuleName(indicator),
            Format = AlertRuleFormat.Ioc,
            ExternalId = ExternalId(indicator),
            Description = BuildDescription(indicator, sourceFormat),
            EventType = eventType,
            Severity = severity,
            Operator = op,
            PayloadPath = payloadPath,
            MatchValue = value,
            SourceDefinition = indicator.SourceDefinition,
            IsEnabled = isEnabled,
            CreatedAt = now,
            UpdatedAt = now,
        };
    }

    private static string BuildRuleName(IocIndicator indicator)
    {
        var label = indicator.Type switch
        {
            IocIndicatorType.Sha256 => "SHA-256",
            IocIndicatorType.Sha1 => "SHA-1",
            IocIndicatorType.IpAddress => "IP",
            IocIndicatorType.Domain => "domain",
            _ => "indicator",
        };
        var value = indicator.Value.Length > 72 ? $"{indicator.Value[..72]}..." : indicator.Value;
        return $"IoC {label}: {value}";
    }

    private static string BuildDescription(IocIndicator indicator, string sourceFormat)
    {
        var source = string.IsNullOrWhiteSpace(indicator.Title)
            ? $"{sourceFormat.ToUpperInvariant()} import"
            : indicator.Title.Trim();
        var note = indicator.Type is IocIndicatorType.Domain
            ? " Domain IoCs currently match process command lines that contain the domain."
            : "";
        return $"{source}: imported {indicator.Type} indicator {indicator.Value}.{note}".Trim();
    }

    private static string ExternalId(IocIndicator indicator)
    {
        if (!string.IsNullOrWhiteSpace(indicator.ExternalId))
        {
            return indicator.ExternalId.Length <= 128
                ? indicator.ExternalId
                : indicator.ExternalId[..128];
        }

        var externalId = indicator.Type switch
        {
            IocIndicatorType.Sha256 => $"sha256:{indicator.Value}",
            IocIndicatorType.Sha1 => $"sha1:{indicator.Value}",
            IocIndicatorType.IpAddress => $"ip:{indicator.Value}",
            IocIndicatorType.Domain => $"domain:{indicator.Value}",
            _ => Fingerprint(indicator.Value),
        };
        return externalId.Length <= 128 ? externalId : externalId[..128];
    }

    private static string Fingerprint(string value)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant()[..32];
    }

    private static IocParseResult ParseStix(string definition)
    {
        try
        {
            using var doc = JsonDocument.Parse(definition);
            var indicators = new List<IocIndicator>();
            var skipped = new List<string>();
            foreach (var item in StixObjects(doc.RootElement))
            {
                if (!item.TryGetProperty("type", out var type) ||
                    !string.Equals(type.GetString(), "indicator", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var pattern = StringProperty(item, "pattern");
                if (string.IsNullOrWhiteSpace(pattern))
                {
                    continue;
                }

                var title = StringProperty(item, "name");
                var description = StringProperty(item, "description");
                var externalId = StringProperty(item, "id");
                foreach (var indicator in ParseStixPattern(pattern, title, description, externalId, skipped))
                {
                    indicators.Add(indicator);
                }
            }

            return new IocParseResult(indicators, skipped);
        }
        catch (JsonException ex)
        {
            throw new IocRuleException($"STIX JSON could not be parsed: {ex.Message}");
        }
    }

    private static IEnumerable<JsonElement> StixObjects(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            yield break;
        }

        if (root.TryGetProperty("objects", out var objects) && objects.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in objects.EnumerateArray())
            {
                yield return item;
            }
            yield break;
        }

        yield return root;
    }

    private static IEnumerable<IocIndicator> ParseStixPattern(
        string pattern,
        string? title,
        string? description,
        string? externalId,
        List<string> skipped)
    {
        foreach (Match match in StixObservableRegex().Matches(pattern))
        {
            var objectType = match.Groups["object"].Value;
            var field = match.Groups["field"].Value;
            var value = match.Groups["value"].Value.Trim();
            var type = StixIndicatorType(objectType, field);
            if (type is null)
            {
                skipped.Add($"Skipped unsupported STIX observable {objectType}:{field}.");
                continue;
            }

            if (!TryNormalize(type.Value, value, out var normalized))
            {
                skipped.Add($"Skipped invalid {type} value {value}.");
                continue;
            }

            yield return new IocIndicator(
                type.Value,
                normalized,
                title,
                description,
                externalId,
                pattern);
        }
    }

    private static IocIndicatorType? StixIndicatorType(string objectType, string field)
    {
        if (string.Equals(objectType, "domain-name", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(field, "value", StringComparison.OrdinalIgnoreCase))
        {
            return IocIndicatorType.Domain;
        }

        if ((string.Equals(objectType, "ipv4-addr", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(objectType, "ipv6-addr", StringComparison.OrdinalIgnoreCase)) &&
            string.Equals(field, "value", StringComparison.OrdinalIgnoreCase))
        {
            return IocIndicatorType.IpAddress;
        }

        if (string.Equals(objectType, "file", StringComparison.OrdinalIgnoreCase) &&
            field.StartsWith("hashes.", StringComparison.OrdinalIgnoreCase))
        {
            var hashName = field["hashes.".Length..].Trim('\'', '"').Replace("-", "", StringComparison.Ordinal);
            return hashName.ToUpperInvariant() switch
            {
                "SHA256" => IocIndicatorType.Sha256,
                "SHA1" => IocIndicatorType.Sha1,
                _ => null,
            };
        }

        return null;
    }

    private static IocParseResult ParseOpenIoc(string definition)
    {
        try
        {
            var doc = XDocument.Parse(definition, LoadOptions.PreserveWhitespace);
            var indicators = new List<IocIndicator>();
            var skipped = new List<string>();
            foreach (var item in doc.Descendants().Where(e => e.Name.LocalName == "IndicatorItem"))
            {
                var context = item.Descendants().FirstOrDefault(e => e.Name.LocalName == "Context");
                var content = item.Descendants().FirstOrDefault(e => e.Name.LocalName == "Content");
                var value = content?.Value.Trim();
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                var contextText = string.Join(
                    ' ',
                    context?.Attributes().Select(a => a.Value) ?? Enumerable.Empty<string>());
                var type = OpenIocIndicatorType(contextText, value);
                if (type is null)
                {
                    skipped.Add($"Skipped unsupported OpenIOC context {contextText}.");
                    continue;
                }

                if (!TryNormalize(type.Value, value, out var normalized))
                {
                    skipped.Add($"Skipped invalid {type} value {value}.");
                    continue;
                }

                var title = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "short_description")?.Value.Trim();
                indicators.Add(new IocIndicator(type.Value, normalized, title, null, null, item.ToString(SaveOptions.DisableFormatting)));
            }

            return new IocParseResult(indicators, skipped);
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or InvalidOperationException)
        {
            throw new IocRuleException($"OpenIOC XML could not be parsed: {ex.Message}");
        }
    }

    private static IocIndicatorType? OpenIocIndicatorType(string context, string value)
    {
        if (context.Contains("Sha256", StringComparison.OrdinalIgnoreCase))
        {
            return IocIndicatorType.Sha256;
        }
        if (context.Contains("Sha1", StringComparison.OrdinalIgnoreCase))
        {
            return IocIndicatorType.Sha1;
        }
        if (context.Contains("DnsEntry", StringComparison.OrdinalIgnoreCase) ||
            context.Contains("Hostname", StringComparison.OrdinalIgnoreCase) ||
            context.Contains("Domain", StringComparison.OrdinalIgnoreCase))
        {
            return IocIndicatorType.Domain;
        }
        if (context.Contains("Address", StringComparison.OrdinalIgnoreCase) ||
            IPAddress.TryParse(value, out _))
        {
            return IocIndicatorType.IpAddress;
        }
        return null;
    }

    private static IocParseResult ParseRaw(string definition)
    {
        var indicators = new List<IocIndicator>();
        var skipped = new List<string>();
        var source = definition.Length <= 4096 ? definition : definition[..4096];

        foreach (Match match in Sha256Regex().Matches(definition))
        {
            indicators.Add(new IocIndicator(IocIndicatorType.Sha256, match.Value.ToLowerInvariant(), null, null, null, source));
        }
        foreach (Match match in Sha1Regex().Matches(definition))
        {
            indicators.Add(new IocIndicator(IocIndicatorType.Sha1, match.Value.ToLowerInvariant(), null, null, null, source));
        }
        foreach (Match match in IpCandidateRegex().Matches(definition))
        {
            if (IPAddress.TryParse(match.Value, out var address))
            {
                indicators.Add(new IocIndicator(IocIndicatorType.IpAddress, address.ToString(), null, null, null, source));
            }
        }
        foreach (Match match in DomainRegex().Matches(definition))
        {
            var value = match.Value.Trim('.').ToLowerInvariant();
            if (IPAddress.TryParse(value, out _) || value.Contains('@', StringComparison.Ordinal) || LooksLikeHash(value))
            {
                continue;
            }

            if (TryNormalize(IocIndicatorType.Domain, value, out var normalized))
            {
                indicators.Add(new IocIndicator(IocIndicatorType.Domain, normalized, null, null, null, source));
            }
        }
        foreach (Match match in Md5Regex().Matches(definition))
        {
            skipped.Add($"Skipped MD5 {match.Value}; Tawny agents currently emit SHA-1 and SHA-256 file hashes.");
        }

        return new IocParseResult(indicators, skipped);
    }

    private static bool TryNormalize(IocIndicatorType type, string raw, out string normalized)
    {
        normalized = raw.Trim().Trim('"', '\'');
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return false;
        }

        switch (type)
        {
            case IocIndicatorType.Sha256:
                normalized = normalized.ToLowerInvariant();
                return Sha256Regex().IsMatch(normalized);
            case IocIndicatorType.Sha1:
                normalized = normalized.ToLowerInvariant();
                return Sha1Regex().IsMatch(normalized);
            case IocIndicatorType.IpAddress:
                if (!IPAddress.TryParse(normalized, out var address))
                {
                    return false;
                }
                normalized = address.ToString();
                return true;
            case IocIndicatorType.Domain:
                normalized = normalized.Trim('.').ToLowerInvariant();
                return DomainOnlyRegex().IsMatch(normalized);
            default:
                return false;
        }
    }

    private static string NormalizeFormat(string? sourceFormat, string definition)
    {
        var requested = sourceFormat?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(requested) || requested == "auto")
        {
            var trimmed = definition.TrimStart();
            if (trimmed.StartsWith('{')) return "stix";
            if (trimmed.StartsWith('<')) return "openioc";
            return "raw";
        }

        return requested;
    }

    private static string? StringProperty(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static bool LooksLikeHash(string value)
    {
        return Sha256Regex().IsMatch(value) || Sha1Regex().IsMatch(value) || Md5Regex().IsMatch(value);
    }

    [GeneratedRegex(@"\[(?<object>file|domain-name|ipv4-addr|ipv6-addr):(?<field>[^\s=]+)\s*=\s*'(?<value>[^']+)'\]", RegexOptions.IgnoreCase)]
    private static partial Regex StixObservableRegex();

    [GeneratedRegex(@"\b[a-fA-F0-9]{64}\b")]
    private static partial Regex Sha256Regex();

    [GeneratedRegex(@"\b[a-fA-F0-9]{40}\b")]
    private static partial Regex Sha1Regex();

    [GeneratedRegex(@"\b[a-fA-F0-9]{32}\b")]
    private static partial Regex Md5Regex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,}:[0-9a-fA-F:]{2,}\b")]
    private static partial Regex IpCandidateRegex();

    [GeneratedRegex(@"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")]
    private static partial Regex DomainRegex();

    [GeneratedRegex(@"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", RegexOptions.IgnoreCase)]
    private static partial Regex DomainOnlyRegex();
}

public record IocImportResult(
    IReadOnlyList<AlertRule> Rules,
    IReadOnlyList<string> SkippedIndicators);

internal sealed record IocParseResult(
    IReadOnlyList<IocIndicator> Indicators,
    IReadOnlyList<string> SkippedIndicators);

internal sealed record IocIndicator(
    IocIndicatorType Type,
    string Value,
    string? Title,
    string? Description,
    string? ExternalId,
    string SourceDefinition);

internal enum IocIndicatorType
{
    Sha256,
    Sha1,
    IpAddress,
    Domain,
}

public class IocRuleException(string message) : Exception(message);
