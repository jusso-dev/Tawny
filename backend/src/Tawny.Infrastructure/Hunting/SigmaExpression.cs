using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Tawny.Domain;

namespace Tawny.Infrastructure.Hunting;

/// <summary>
/// Compiled Sigma rule tree, stored on AlertRule.CompiledExpressionJson when
/// the source rule has a non-trivial condition (AND/OR/NOT, "1 of selection_*",
/// "all of selection_*"). Single-selection rules continue to use the legacy
/// AlertRule.PayloadPath/Operator/MatchValue fields so the simple path stays simple.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(SigmaAnd), "and")]
[JsonDerivedType(typeof(SigmaOr), "or")]
[JsonDerivedType(typeof(SigmaNot), "not")]
[JsonDerivedType(typeof(SigmaAnyOf), "any_of")]
[JsonDerivedType(typeof(SigmaAllOf), "all_of")]
[JsonDerivedType(typeof(SigmaFieldPredicate), "field")]
public abstract record SigmaNode;

public sealed record SigmaAnd(IReadOnlyList<SigmaNode> Children) : SigmaNode;
public sealed record SigmaOr(IReadOnlyList<SigmaNode> Children) : SigmaNode;
public sealed record SigmaNot(SigmaNode Inner) : SigmaNode;
public sealed record SigmaAnyOf(IReadOnlyList<SigmaNode> Children) : SigmaNode;
public sealed record SigmaAllOf(IReadOnlyList<SigmaNode> Children) : SigmaNode;

public sealed record SigmaFieldPredicate(
    string PayloadPath,
    AlertRuleOperator Operator,
    IReadOnlyList<string> Values) : SigmaNode;

public static class SigmaExpressionEvaluator
{
    public static bool Evaluate(SigmaNode node, JsonElement payload)
    {
        return node switch
        {
            SigmaAnd and => and.Children.All(c => Evaluate(c, payload)),
            SigmaOr or => or.Children.Any(c => Evaluate(c, payload)),
            SigmaNot not => !Evaluate(not.Inner, payload),
            SigmaAnyOf anyOf => anyOf.Children.Any(c => Evaluate(c, payload)),
            SigmaAllOf allOf => allOf.Children.All(c => Evaluate(c, payload)),
            SigmaFieldPredicate p => EvaluatePredicate(p, payload),
            _ => false,
        };
    }

    private static bool EvaluatePredicate(SigmaFieldPredicate predicate, JsonElement payload)
    {
        var values = ResolvePath(payload, predicate.PayloadPath).ToList();
        if (values.Count == 0) return false;
        return predicate.Operator switch
        {
            AlertRuleOperator.Exists => true,
            AlertRuleOperator.Equals => values.Any(v => predicate.Values.Any(target => string.Equals(JsonScalar(v), target, StringComparison.OrdinalIgnoreCase))),
            AlertRuleOperator.Contains => values.Any(v => predicate.Values.Any(target => JsonScalar(v).Contains(target, StringComparison.OrdinalIgnoreCase))),
            AlertRuleOperator.GreaterThan => values.Any(v => predicate.Values.Any(target => CompareNumber(v, target, (a, b) => a > b))),
            AlertRuleOperator.LessThan => values.Any(v => predicate.Values.Any(target => CompareNumber(v, target, (a, b) => a < b))),
            _ => false,
        };
    }

    private static IEnumerable<JsonElement> ResolvePath(JsonElement root, string path)
    {
        var segments = path.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return ResolvePath(root, segments, 0);
    }

    private static IEnumerable<JsonElement> ResolvePath(JsonElement current, IReadOnlyList<string> segments, int index)
    {
        if (index >= segments.Count) { yield return current; yield break; }
        if (current.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in current.EnumerateArray())
            {
                foreach (var v in ResolvePath(item, segments, index)) yield return v;
            }
            yield break;
        }
        if (current.ValueKind != JsonValueKind.Object) yield break;
        if (!current.TryGetProperty(segments[index], out var child)) yield break;
        foreach (var v in ResolvePath(child, segments, index + 1)) yield return v;
    }

    private static string JsonScalar(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? "",
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "",
        _ => value.GetRawText(),
    };

    private static bool CompareNumber(JsonElement value, string? expected, Func<decimal, decimal, bool> cmp)
    {
        if (!decimal.TryParse(JsonScalar(value), NumberStyles.Float, CultureInfo.InvariantCulture, out var left)) return false;
        if (!decimal.TryParse(expected, NumberStyles.Float, CultureInfo.InvariantCulture, out var right)) return false;
        return cmp(left, right);
    }
}

public static class SigmaExpressionSerializer
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static string Serialize(SigmaNode node) => JsonSerializer.Serialize<SigmaNode>(node, Options);

    public static SigmaNode? Deserialize(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<SigmaNode>(json, Options); }
        catch { return null; }
    }
}
