using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.Hunting;

public class SequenceRuleException(string message) : Exception(message);

/// <summary>
/// JSON shape stored on AlertRule.SourceDefinition when Format = Sequence.
/// Each step is a predicate that must match an event of the named type;
/// steps must occur in order on the same host, within the rule's time window.
/// </summary>
public record SequenceRuleDefinition(
    [property: JsonPropertyName("window_seconds")] int WindowSeconds,
    [property: JsonPropertyName("group_by")] string GroupBy,
    [property: JsonPropertyName("steps")] IReadOnlyList<SequenceStep> Steps);

public record SequenceStep(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("event_type")] TelemetryEventType EventType,
    [property: JsonPropertyName("payload_path")] string? PayloadPath,
    [property: JsonPropertyName("operator")] AlertRuleOperator Operator,
    [property: JsonPropertyName("match_value")] string? MatchValue);

public static class SequenceRuleParser
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static SequenceRuleDefinition Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new SequenceRuleException("Sequence rule definition is empty.");
        }
        SequenceRuleDefinition? def;
        try
        {
            def = JsonSerializer.Deserialize<SequenceRuleDefinition>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new SequenceRuleException($"Invalid sequence rule JSON: {ex.Message}");
        }
        if (def is null)
        {
            throw new SequenceRuleException("Sequence rule definition deserialized to null.");
        }
        if (def.WindowSeconds <= 0 || def.WindowSeconds > 86_400)
        {
            throw new SequenceRuleException("window_seconds must be between 1 and 86400.");
        }
        if (def.Steps is null || def.Steps.Count < 2)
        {
            throw new SequenceRuleException("A sequence rule needs at least two steps.");
        }
        if (def.Steps.Count > 8)
        {
            throw new SequenceRuleException("A sequence rule can have at most 8 steps.");
        }
        foreach (var step in def.Steps)
        {
            if (string.IsNullOrWhiteSpace(step.Name))
            {
                throw new SequenceRuleException("Each step needs a non-empty name.");
            }
            if (step.Operator != AlertRuleOperator.Exists && string.IsNullOrWhiteSpace(step.MatchValue))
            {
                throw new SequenceRuleException($"Step '{step.Name}' needs a match_value (or use the exists operator).");
            }
        }
        return def;
    }

    public static string Serialize(SequenceRuleDefinition def)
        => JsonSerializer.Serialize(def, JsonOptions);
}
