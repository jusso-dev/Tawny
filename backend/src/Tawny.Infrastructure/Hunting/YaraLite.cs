using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Tawny.Infrastructure.Hunting;

public class YaraLiteException(string message) : Exception(message);

/// <summary>
/// YARA-lite: a JSON-defined string-match rule that evaluates against the
/// raw text of a telemetry payload. Not a full YARA implementation (no PE
/// parsing, no offsets, no XOR/wide modifiers) — those need libyara and a
/// way to ship file content from agents, which is Phase 2 territory.
///
/// What we do support:
///   strings: list of either { literal: "..." } or { regex: "..." } with a $name
///   condition: "any_of" | "all_of" | "n_of(K)"
/// </summary>
public record YaraLiteDefinition(
    [property: JsonPropertyName("strings")] IReadOnlyList<YaraLiteString> Strings,
    [property: JsonPropertyName("condition")] string Condition);

public record YaraLiteString(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("literal")] string? Literal,
    [property: JsonPropertyName("regex")] string? Regex,
    [property: JsonPropertyName("case_sensitive")] bool? CaseSensitive);

public static class YaraLiteParser
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public static YaraLiteDefinition Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new YaraLiteException("YARA rule definition is empty.");
        }
        YaraLiteDefinition? def;
        try { def = JsonSerializer.Deserialize<YaraLiteDefinition>(json, JsonOptions); }
        catch (JsonException ex)
        {
            throw new YaraLiteException($"Invalid YARA-lite JSON: {ex.Message}");
        }
        if (def is null || def.Strings is null || def.Strings.Count == 0)
        {
            throw new YaraLiteException("YARA-lite rule must define at least one string.");
        }
        foreach (var s in def.Strings)
        {
            if (string.IsNullOrWhiteSpace(s.Name))
            {
                throw new YaraLiteException("Each string needs a name (e.g. $cmd1).");
            }
            if (string.IsNullOrEmpty(s.Literal) && string.IsNullOrEmpty(s.Regex))
            {
                throw new YaraLiteException($"String {s.Name} needs either a literal or a regex.");
            }
            if (!string.IsNullOrEmpty(s.Regex))
            {
                try { _ = new Regex(s.Regex); }
                catch (ArgumentException ex)
                {
                    throw new YaraLiteException($"Invalid regex in {s.Name}: {ex.Message}");
                }
            }
        }
        if (string.IsNullOrWhiteSpace(def.Condition))
        {
            throw new YaraLiteException("YARA-lite rule must include a condition.");
        }
        return def;
    }

    public static string Serialize(YaraLiteDefinition def) => JsonSerializer.Serialize(def, JsonOptions);
}

public static class YaraLiteEvaluator
{
    private static readonly Regex NofRe = new(@"^\s*(?<n>\d+)_of\s*$", RegexOptions.Compiled);

    public static bool Evaluate(YaraLiteDefinition definition, string payloadText)
    {
        var matched = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in definition.Strings)
        {
            if (StringMatches(s, payloadText))
            {
                matched.Add(s.Name);
            }
        }
        var condition = definition.Condition.Trim().ToLowerInvariant();
        if (condition == "any_of" || condition == "any of them")
        {
            return matched.Count > 0;
        }
        if (condition == "all_of" || condition == "all of them")
        {
            return matched.Count == definition.Strings.Count;
        }
        var nofMatch = NofRe.Match(condition);
        if (nofMatch.Success && int.TryParse(nofMatch.Groups["n"].Value, out var n))
        {
            return matched.Count >= n;
        }
        // Specific names like "$a and $b": evaluate as token-replace -> boolean expression.
        var expr = condition;
        foreach (var s in definition.Strings)
        {
            var truthy = matched.Contains(s.Name) ? "true" : "false";
            expr = Regex.Replace(expr, Regex.Escape(s.Name.ToLowerInvariant()), truthy);
        }
        return EvalBoolean(expr);
    }

    private static bool StringMatches(YaraLiteString s, string payloadText)
    {
        if (!string.IsNullOrEmpty(s.Literal))
        {
            var comparison = s.CaseSensitive == true
                ? StringComparison.Ordinal
                : StringComparison.OrdinalIgnoreCase;
            return payloadText.Contains(s.Literal, comparison);
        }
        if (!string.IsNullOrEmpty(s.Regex))
        {
            var opts = s.CaseSensitive == true ? RegexOptions.None : RegexOptions.IgnoreCase;
            return Regex.IsMatch(payloadText, s.Regex, opts);
        }
        return false;
    }

    private static bool EvalBoolean(string expr)
    {
        // Cheap, safe boolean-expression evaluator for "true and false or not true" style strings.
        // Tokenize, then a tiny recursive-descent parser. We deliberately keep this minimal.
        var tokens = Tokenize(expr).ToList();
        var pos = 0;
        var result = ParseOr(tokens, ref pos);
        return result;
    }

    private static bool ParseOr(IReadOnlyList<string> tokens, ref int pos)
    {
        var left = ParseAnd(tokens, ref pos);
        while (pos < tokens.Count && tokens[pos] == "or")
        {
            pos++;
            var right = ParseAnd(tokens, ref pos);
            left = left || right;
        }
        return left;
    }

    private static bool ParseAnd(IReadOnlyList<string> tokens, ref int pos)
    {
        var left = ParseUnary(tokens, ref pos);
        while (pos < tokens.Count && tokens[pos] == "and")
        {
            pos++;
            var right = ParseUnary(tokens, ref pos);
            left = left && right;
        }
        return left;
    }

    private static bool ParseUnary(IReadOnlyList<string> tokens, ref int pos)
    {
        if (pos >= tokens.Count) return false;
        if (tokens[pos] == "not") { pos++; return !ParseUnary(tokens, ref pos); }
        if (tokens[pos] == "(") { pos++; var v = ParseOr(tokens, ref pos); if (pos < tokens.Count && tokens[pos] == ")") pos++; return v; }
        var t = tokens[pos++];
        return t == "true";
    }

    private static IEnumerable<string> Tokenize(string expr)
    {
        var i = 0;
        while (i < expr.Length)
        {
            var c = expr[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '(' || c == ')') { yield return c.ToString(); i++; continue; }
            var start = i;
            while (i < expr.Length && !char.IsWhiteSpace(expr[i]) && expr[i] != '(' && expr[i] != ')') i++;
            yield return expr[start..i];
        }
    }
}
