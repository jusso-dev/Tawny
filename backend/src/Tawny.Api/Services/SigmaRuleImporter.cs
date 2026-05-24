using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure.Hunting;
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

        // Map every selection name (except `condition`) to its compiled SigmaNode.
        var selections = new Dictionary<string, SigmaNode>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in detection.Children)
        {
            if (pair.Key is not YamlScalarNode keyNode || keyNode.Value is null) continue;
            if (string.Equals(keyNode.Value, "condition", StringComparison.OrdinalIgnoreCase)) continue;
            if (pair.Value is not YamlMappingNode selectionMap)
            {
                throw new SigmaRuleException($"Selection '{keyNode.Value}' must be a mapping.");
            }
            selections[keyNode.Value] = CompileSelectionNode(selectionMap);
        }

        if (selections.Count == 0)
        {
            throw new SigmaRuleException("Sigma rule needs at least one named selection block.");
        }

        var logsource = Mapping(root, "logsource");
        var rule = new AlertRule
        {
            Id = Guid.NewGuid(),
            Name = title.Trim(),
            Format = AlertRuleFormat.Sigma,
            ExternalId = Normalize(Scalar(root, "id")),
            Description = Normalize(Scalar(root, "description")),
            EventType = MapEventType(logsource),
            Severity = MapSeverity(Scalar(root, "level")),
            SourceDefinition = yaml,
            IsEnabled = isEnabled,
            MitreTechniquesJson = ExtractMitreTechniques(root),
            CreatedAt = now,
            UpdatedAt = now,
        };

        // Fast path: single named selection referenced directly. Stays as a
        // single-predicate rule so the existing legacy fields and the existing
        // UI keep working without change.
        if (selections.Count == 1
            && selections.TryGetValue(condition.Trim(), out var solo)
            && solo is SigmaFieldPredicate predicate
            && predicate.Values.Count > 0)
        {
            rule.Operator = predicate.Operator;
            rule.PayloadPath = predicate.PayloadPath;
            rule.MatchValue = predicate.Values.Count == 1
                ? predicate.Values[0]
                : JsonSerializer.Serialize(predicate.Values, JsonOptions);
            return rule;
        }

        // General path: parse the condition into a SigmaNode tree by resolving
        // names + globs against the compiled selections.
        var tree = SigmaConditionParser.Parse(condition, selections);
        rule.CompiledExpressionJson = SigmaExpressionSerializer.Serialize(tree);
        // Leave legacy predicate fields null — the evaluator falls back to CompiledExpression.
        return rule;
    }

    private static SigmaNode CompileSelectionNode(YamlMappingNode selection)
    {
        if (selection.Children.Count == 0)
        {
            throw new SigmaRuleException("Selection must have at least one field predicate.");
        }
        var children = new List<SigmaNode>();
        foreach (var pair in selection.Children)
        {
            if (pair.Key is not YamlScalarNode keyNode || string.IsNullOrWhiteSpace(keyNode.Value))
            {
                throw new SigmaRuleException("Selection field name must be a scalar.");
            }
            var (fieldRaw, op) = ParseField(keyNode.Value);
            var field = NormalizeField(fieldRaw);
            var values = Values(pair.Value);
            if (values.Count == 0 && op != AlertRuleOperator.Exists)
            {
                throw new SigmaRuleException("Selection value is required.");
            }
            children.Add(new SigmaFieldPredicate(field, op, values));
        }
        // Multiple fields in the same selection mapping => AND across them (Sigma semantics).
        return children.Count == 1 ? children[0] : new SigmaAnd(children);
    }

    private static string? ExtractMitreTechniques(YamlMappingNode root)
    {
        // Sigma rules surface techniques via `tags:` like `attack.t1059.003`.
        // We extract everything that matches `attack.tNNNN(.NNN)?` and
        // uppercase to the canonical ATT&CK form (e.g. T1059.003).
        if (!root.Children.TryGetValue(new YamlScalarNode("tags"), out var tagsNode)
            || tagsNode is not YamlSequenceNode sequence)
        {
            return null;
        }

        var techniques = new List<string>();
        foreach (var item in sequence.Children.OfType<YamlScalarNode>())
        {
            var raw = item.Value;
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var trimmed = raw.Trim();
            if (!trimmed.StartsWith("attack.t", StringComparison.OrdinalIgnoreCase)) continue;
            var id = trimmed[(trimmed.IndexOf('.') + 1)..];
            techniques.Add(id.ToUpperInvariant());
        }

        if (techniques.Count == 0) return null;
        return JsonSerializer.Serialize(techniques.Distinct().ToList(), JsonOptions);
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
        if (parts.Length == 0 || string.IsNullOrWhiteSpace(parts[0]))
        {
            throw new SigmaRuleException("Sigma selection field is required.");
        }

        if (parts.Length > 2)
        {
            throw new SigmaRuleException("Only one Sigma field modifier is supported for now.");
        }

        var field = parts[0].Trim();
        var modifier = parts.Length > 1 ? parts[^1] : "";
        var op = modifier.ToLowerInvariant() switch
        {
            "" => AlertRuleOperator.Equals,
            "exists" => AlertRuleOperator.Exists,
            "contains" => AlertRuleOperator.Contains,
            "gt" => AlertRuleOperator.GreaterThan,
            "lt" => AlertRuleOperator.LessThan,
            _ => throw new SigmaRuleException($"Unsupported Sigma field modifier '{modifier}'."),
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
}

/// <summary>
/// Tiny recursive-descent parser for Sigma `condition:` strings.
/// Supports:  selection_name  |  not  |  and  |  or  |  ()  |  "1 of name_*"  |  "all of name_*"
/// Globs are resolved against the dictionary of compiled selections.
/// </summary>
internal static class SigmaConditionParser
{
    public static SigmaNode Parse(string condition, IReadOnlyDictionary<string, SigmaNode> selections)
    {
        var tokens = Tokenize(condition);
        var pos = 0;
        var node = ParseOr(tokens, ref pos, selections);
        if (pos < tokens.Count)
        {
            throw new SigmaRuleException($"Unexpected token '{tokens[pos]}' at end of condition.");
        }
        return node;
    }

    private static SigmaNode ParseOr(IReadOnlyList<string> tokens, ref int pos, IReadOnlyDictionary<string, SigmaNode> selections)
    {
        var left = ParseAnd(tokens, ref pos, selections);
        while (pos < tokens.Count && string.Equals(tokens[pos], "or", StringComparison.OrdinalIgnoreCase))
        {
            pos++;
            var right = ParseAnd(tokens, ref pos, selections);
            left = new SigmaOr(Flatten<SigmaOr>(left, right));
        }
        return left;
    }

    private static SigmaNode ParseAnd(IReadOnlyList<string> tokens, ref int pos, IReadOnlyDictionary<string, SigmaNode> selections)
    {
        var left = ParseUnary(tokens, ref pos, selections);
        while (pos < tokens.Count && string.Equals(tokens[pos], "and", StringComparison.OrdinalIgnoreCase))
        {
            pos++;
            var right = ParseUnary(tokens, ref pos, selections);
            left = new SigmaAnd(Flatten<SigmaAnd>(left, right));
        }
        return left;
    }

    private static SigmaNode ParseUnary(IReadOnlyList<string> tokens, ref int pos, IReadOnlyDictionary<string, SigmaNode> selections)
    {
        if (pos >= tokens.Count) throw new SigmaRuleException("Unexpected end of condition.");
        var token = tokens[pos];
        if (string.Equals(token, "not", StringComparison.OrdinalIgnoreCase))
        {
            pos++;
            return new SigmaNot(ParseUnary(tokens, ref pos, selections));
        }
        if (token == "(")
        {
            pos++;
            var inner = ParseOr(tokens, ref pos, selections);
            if (pos >= tokens.Count || tokens[pos] != ")")
            {
                throw new SigmaRuleException("Expected ')'.");
            }
            pos++;
            return inner;
        }
        if (string.Equals(token, "1", StringComparison.Ordinal)
            || string.Equals(token, "all", StringComparison.OrdinalIgnoreCase))
        {
            var quantifier = token;
            pos++;
            if (pos >= tokens.Count || !string.Equals(tokens[pos], "of", StringComparison.OrdinalIgnoreCase))
            {
                throw new SigmaRuleException("Expected 'of' after quantifier.");
            }
            pos++;
            if (pos >= tokens.Count) throw new SigmaRuleException("Expected pattern after 'of'.");
            var pattern = tokens[pos];
            pos++;
            var matched = ResolveGlob(pattern, selections);
            if (matched.Count == 0)
            {
                throw new SigmaRuleException($"No selections matched pattern '{pattern}'.");
            }
            return string.Equals(quantifier, "1", StringComparison.Ordinal)
                ? new SigmaAnyOf(matched)
                : new SigmaAllOf(matched);
        }
        // Bare selection name.
        pos++;
        if (!selections.TryGetValue(token, out var selection))
        {
            throw new SigmaRuleException($"Unknown selection '{token}' in condition.");
        }
        return selection;
    }

    private static List<SigmaNode> ResolveGlob(string pattern, IReadOnlyDictionary<string, SigmaNode> selections)
    {
        var matched = new List<SigmaNode>();
        var regex = new Regex("^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$",
            RegexOptions.IgnoreCase);
        foreach (var (name, node) in selections)
        {
            if (regex.IsMatch(name)) matched.Add(node);
        }
        return matched;
    }

    private static IReadOnlyList<SigmaNode> Flatten<T>(SigmaNode left, SigmaNode right) where T : SigmaNode
    {
        var list = new List<SigmaNode>();
        AddFlattened<T>(list, left);
        AddFlattened<T>(list, right);
        return list;
    }

    private static void AddFlattened<T>(List<SigmaNode> list, SigmaNode node) where T : SigmaNode
    {
        if (typeof(T) == typeof(SigmaAnd) && node is SigmaAnd and)
        {
            list.AddRange(and.Children);
            return;
        }
        if (typeof(T) == typeof(SigmaOr) && node is SigmaOr or)
        {
            list.AddRange(or.Children);
            return;
        }
        list.Add(node);
    }

    private static List<string> Tokenize(string condition)
    {
        var tokens = new List<string>();
        var i = 0;
        while (i < condition.Length)
        {
            var c = condition[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '(' || c == ')')
            {
                tokens.Add(c.ToString());
                i++;
                continue;
            }
            var start = i;
            while (i < condition.Length && !char.IsWhiteSpace(condition[i]) && condition[i] != '(' && condition[i] != ')')
            {
                i++;
            }
            tokens.Add(condition[start..i]);
        }
        return tokens;
    }
}

public class SigmaRuleException(string message) : Exception(message);
