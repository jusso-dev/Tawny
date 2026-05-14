using System.Text.Json;
using Tawny.Domain;
using Tawny.Domain.Entities;
using YamlDotNet.RepresentationModel;

namespace Tawny.Api.Services;

public class SigmaRuleImporter
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public AlertRule Import(string yaml, bool isEnabled, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(yaml))
        {
            throw new SigmaRuleException("Sigma rule YAML is required.");
        }

        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            throw new SigmaRuleException("Sigma rule must be a YAML mapping.");
        }

        var title = Scalar(root, "title");
        if (string.IsNullOrWhiteSpace(title))
        {
            throw new SigmaRuleException("Sigma rule title is required.");
        }

        var detection = Mapping(root, "detection")
            ?? throw new SigmaRuleException("Sigma rule detection block is required.");
        var condition = Scalar(detection, "condition");
        if (string.IsNullOrWhiteSpace(condition))
        {
            throw new SigmaRuleException("Sigma rule detection.condition is required.");
        }
        if (condition.Contains(' ', StringComparison.Ordinal))
        {
            throw new SigmaRuleException("Only a single Sigma selection condition is supported for now.");
        }

        var selection = Mapping(detection, condition)
            ?? throw new SigmaRuleException($"Sigma selection '{condition}' was not found.");
        var predicate = CompileSelection(selection);
        var logsource = Mapping(root, "logsource");

        return new AlertRule
        {
            Id = Guid.NewGuid(),
            Name = title.Trim(),
            Format = AlertRuleFormat.Sigma,
            ExternalId = Normalize(Scalar(root, "id")),
            Description = Normalize(Scalar(root, "description")),
            EventType = MapEventType(logsource),
            Severity = MapSeverity(Scalar(root, "level")),
            Operator = predicate.Operator,
            PayloadPath = predicate.PayloadPath,
            MatchValue = predicate.MatchValue,
            SourceDefinition = yaml,
            IsEnabled = isEnabled,
            CreatedAt = now,
            UpdatedAt = now,
        };
    }

    private static CompiledPredicate CompileSelection(YamlMappingNode selection)
    {
        if (selection.Children.Count != 1)
        {
            throw new SigmaRuleException("Only one field predicate per Sigma selection is supported for now.");
        }

        var pair = selection.Children.Single();
        if (pair.Key is not YamlScalarNode keyNode || string.IsNullOrWhiteSpace(keyNode.Value))
        {
            throw new SigmaRuleException("Sigma selection field must be a scalar.");
        }

        var (field, op) = ParseField(keyNode.Value);
        var values = Values(pair.Value);
        if (values.Count == 0)
        {
            throw new SigmaRuleException("Sigma selection value is required.");
        }

        return new CompiledPredicate(
            NormalizeField(field),
            op,
            values.Count == 1
                ? values[0]
                : JsonSerializer.Serialize(values, JsonOptions));
    }

    private static string NormalizeField(string field) => field switch
    {
        "Image" or "process.name" or "process.executable" => "processes.name",
        "CommandLine" or "process.command_line" => "processes.command_line",
        "ParentImage" or "process.parent.name" => "processes.parent_name",
        "DestinationIp" or "destination.ip" => "connections.remote_address",
        "DestinationPort" or "destination.port" => "connections.remote_port",
        "SourceIp" or "source.ip" => "connections.local_address",
        "SourcePort" or "source.port" => "connections.local_port",
        "TargetFilename" or "file.path" => "path",
        "User" or "user.name" => "username",
        _ => field,
    };

    private static (string Field, AlertRuleOperator Operator) ParseField(string raw)
    {
        var parts = raw.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var field = parts[0].Trim();
        var modifier = parts.Length > 1 ? parts[^1] : "";
        var op = modifier.ToLowerInvariant() switch
        {
            "exists" => AlertRuleOperator.Exists,
            "contains" => AlertRuleOperator.Contains,
            "startswith" => AlertRuleOperator.Contains,
            "endswith" => AlertRuleOperator.Contains,
            "gt" => AlertRuleOperator.GreaterThan,
            "lt" => AlertRuleOperator.LessThan,
            _ => AlertRuleOperator.Equals,
        };
        return (field, op);
    }

    private static List<string> Values(YamlNode node)
    {
        if (node is YamlScalarNode scalar)
        {
            return string.IsNullOrWhiteSpace(scalar.Value) ? [] : [scalar.Value];
        }

        if (node is YamlSequenceNode sequence)
        {
            return sequence.Children
                .OfType<YamlScalarNode>()
                .Select(v => v.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Cast<string>()
                .ToList();
        }

        return [];
    }

    private static AlertSeverity MapSeverity(string? level) => level?.Trim().ToLowerInvariant() switch
    {
        "critical" => AlertSeverity.Critical,
        "high" => AlertSeverity.High,
        "medium" => AlertSeverity.Medium,
        "low" => AlertSeverity.Low,
        "informational" => AlertSeverity.Low,
        _ => AlertSeverity.Medium,
    };

    private static TelemetryEventType? MapEventType(YamlMappingNode? logsource)
    {
        if (logsource is null) return null;
        var category = Scalar(logsource, "category")?.ToLowerInvariant();
        var product = Scalar(logsource, "product")?.ToLowerInvariant();
        var service = Scalar(logsource, "service")?.ToLowerInvariant();
        var source = string.Join(' ', new[] { category, product, service }.Where(v => !string.IsNullOrWhiteSpace(v)));

        if (source.Contains("process", StringComparison.Ordinal)) return TelemetryEventType.ProcessSnapshot;
        if (source.Contains("network", StringComparison.Ordinal)) return TelemetryEventType.NetworkSnapshot;
        if (source.Contains("file", StringComparison.Ordinal) || source.Contains("fim", StringComparison.Ordinal)) return TelemetryEventType.FileIntegrity;
        if (source.Contains("auth", StringComparison.Ordinal) || source.Contains("session", StringComparison.Ordinal)) return TelemetryEventType.UserSession;
        if (source.Contains("system", StringComparison.Ordinal)) return TelemetryEventType.SystemInfo;
        return null;
    }

    private static YamlMappingNode? Mapping(YamlMappingNode root, string key)
    {
        return root.Children.TryGetValue(new YamlScalarNode(key), out var node)
            ? node as YamlMappingNode
            : null;
    }

    private static string? Scalar(YamlMappingNode root, string key)
    {
        return root.Children.TryGetValue(new YamlScalarNode(key), out var node) && node is YamlScalarNode scalar
            ? scalar.Value
            : null;
    }

    private static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }

    private sealed record CompiledPredicate(
        string PayloadPath,
        AlertRuleOperator Operator,
        string MatchValue);
}

public class SigmaRuleException(string message) : Exception(message);
