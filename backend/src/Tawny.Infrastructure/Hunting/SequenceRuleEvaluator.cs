using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.Hunting;

/// <summary>
/// Tracks in-flight sequence matches keyed by (rule, host). State is process-
/// local: we deliberately don't persist partial progress, because operators
/// expect EDR detections to fire when the *whole* sequence is observed within
/// the window, and survivability across restarts isn't worth the storage
/// churn. Rebuilds on the next matching event after a restart.
/// </summary>
public class SequenceRuleEvaluator
{
    private readonly ConcurrentDictionary<(Guid RuleId, Guid AgentId), SequenceState> _state = new();

    public IReadOnlyList<SequenceMatch> Evaluate(
        AlertRule rule,
        SequenceRuleDefinition definition,
        Agent agent,
        IReadOnlyList<TelemetryEvent> events,
        DateTimeOffset now)
    {
        var window = TimeSpan.FromSeconds(definition.WindowSeconds);
        var matches = new List<SequenceMatch>();
        var key = (rule.Id, agent.Id);
        var state = _state.GetOrAdd(key, _ => new SequenceState());

        foreach (var ev in events.OrderBy(e => e.OccurredAt))
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(ev.Payload); }
            catch { continue; }

            using (doc)
            {
                var nextStepIndex = state.MatchedSteps.Count;
                if (nextStepIndex >= definition.Steps.Count) continue;
                var step = definition.Steps[nextStepIndex];

                if (step.EventType != ev.EventType) continue;
                if (!StepMatches(step, doc.RootElement)) continue;

                // Reset if too far behind the first matched event.
                if (state.MatchedSteps.Count > 0
                    && (ev.OccurredAt - state.MatchedSteps[0].OccurredAt) > window)
                {
                    state.MatchedSteps.Clear();
                    nextStepIndex = 0;
                    step = definition.Steps[0];
                    if (step.EventType != ev.EventType || !StepMatches(step, doc.RootElement))
                    {
                        continue;
                    }
                }

                state.MatchedSteps.Add(new MatchedStep(step.Name, ev.Id, ev.OccurredAt));

                if (state.MatchedSteps.Count == definition.Steps.Count)
                {
                    matches.Add(new SequenceMatch(
                        rule.Id,
                        agent.Id,
                        state.MatchedSteps.Last().EventId,
                        state.MatchedSteps.ToList()));
                    state.MatchedSteps.Clear();
                }
            }
        }

        // Garbage-collect stale state per host: if oldest matched step is past window, drop progress.
        if (state.MatchedSteps.Count > 0 && (now - state.MatchedSteps[0].OccurredAt) > window)
        {
            state.MatchedSteps.Clear();
        }

        return matches;
    }

    public void ResetAll() => _state.Clear();

    private static bool StepMatches(SequenceStep step, JsonElement payload)
    {
        if (string.IsNullOrWhiteSpace(step.PayloadPath)) return true;
        var values = ResolvePath(payload, step.PayloadPath).ToList();
        if (values.Count == 0) return false;
        return step.Operator switch
        {
            AlertRuleOperator.Exists => true,
            AlertRuleOperator.Equals => values.Any(v => string.Equals(JsonScalar(v), step.MatchValue, StringComparison.OrdinalIgnoreCase)),
            AlertRuleOperator.Contains => values.Any(v => !string.IsNullOrEmpty(step.MatchValue) && JsonScalar(v).Contains(step.MatchValue, StringComparison.OrdinalIgnoreCase)),
            AlertRuleOperator.GreaterThan => values.Any(v => CompareNumber(v, step.MatchValue, (a, b) => a > b)),
            AlertRuleOperator.LessThan => values.Any(v => CompareNumber(v, step.MatchValue, (a, b) => a < b)),
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

    private sealed class SequenceState
    {
        public List<MatchedStep> MatchedSteps { get; } = [];
    }
}

public record MatchedStep(string Name, long EventId, DateTimeOffset OccurredAt);

public record SequenceMatch(
    Guid RuleId,
    Guid AgentId,
    long TriggeringEventId,
    IReadOnlyList<MatchedStep> Trail);
