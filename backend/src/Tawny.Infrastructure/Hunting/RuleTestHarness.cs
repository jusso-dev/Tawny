using System.Globalization;
using System.Text.Json;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.Hunting;

public record RuleTestEventInput(
    TelemetryEventType EventType,
    DateTimeOffset OccurredAt,
    JsonElement Payload);

public record RuleTestStepTrace(
    int Index,
    string Step,
    bool Matched,
    string? FailReason);

public record RuleTestResult(
    bool Matched,
    string? FailReason,
    IReadOnlyList<RuleTestStepTrace> Trace);

/// <summary>
/// Pure-function tester that runs an in-memory AlertRule (any format) against
/// supplied event(s). No DB writes, no broker publish, no sinks — used by the
/// /rule-test endpoint so detection authors can iterate on rules quickly.
/// </summary>
public class RuleTestHarness
{
    public RuleTestResult Test(AlertRule rule, IReadOnlyList<RuleTestEventInput> events)
    {
        if (events.Count == 0)
        {
            return new RuleTestResult(false, "no events supplied", []);
        }

        return rule.Format switch
        {
            AlertRuleFormat.Sequence => TestSequence(rule, events),
            _ => TestSinglePredicate(rule, events),
        };
    }

    private static RuleTestResult TestSinglePredicate(AlertRule rule, IReadOnlyList<RuleTestEventInput> events)
    {
        var trace = new List<RuleTestStepTrace>();
        for (var i = 0; i < events.Count; i++)
        {
            var ev = events[i];
            if (rule.EventType is not null && rule.EventType.Value != ev.EventType)
            {
                trace.Add(new RuleTestStepTrace(i, $"event[{i}] {ev.EventType}", false,
                    $"event_type {ev.EventType} does not match rule event_type {rule.EventType}"));
                continue;
            }
            if (string.IsNullOrWhiteSpace(rule.PayloadPath))
            {
                trace.Add(new RuleTestStepTrace(i, $"event[{i}]", true, null));
                return new RuleTestResult(true, null, trace);
            }
            var values = ResolvePath(ev.Payload, rule.PayloadPath).ToList();
            if (values.Count == 0)
            {
                trace.Add(new RuleTestStepTrace(i, $"event[{i}] {rule.PayloadPath}", false,
                    $"payload_path '{rule.PayloadPath}' was not found in the event payload"));
                continue;
            }
            if (RuleMatches(rule, values))
            {
                trace.Add(new RuleTestStepTrace(i, $"event[{i}] {rule.PayloadPath} {rule.Operator} {rule.MatchValue}", true, null));
                return new RuleTestResult(true, null, trace);
            }
            trace.Add(new RuleTestStepTrace(i, $"event[{i}] {rule.PayloadPath} {rule.Operator} {rule.MatchValue}", false,
                $"value(s) {string.Join(", ", values.Select(JsonScalar))} did not satisfy the predicate"));
        }
        return new RuleTestResult(false, "no event satisfied the predicate", trace);
    }

    private static RuleTestResult TestSequence(AlertRule rule, IReadOnlyList<RuleTestEventInput> events)
    {
        SequenceRuleDefinition definition;
        try { definition = SequenceRuleParser.Parse(rule.SourceDefinition ?? ""); }
        catch (SequenceRuleException ex)
        {
            return new RuleTestResult(false, ex.Message, []);
        }

        var trace = new List<RuleTestStepTrace>();
        var matched = 0;
        var firstMatchTime = DateTimeOffset.MinValue;
        var ordered = events.OrderBy(e => e.OccurredAt).ToList();
        foreach (var ev in ordered)
        {
            if (matched >= definition.Steps.Count) break;
            var step = definition.Steps[matched];
            if (step.EventType != ev.EventType)
            {
                trace.Add(new RuleTestStepTrace(matched, step.Name, false,
                    $"step expects {step.EventType} but event was {ev.EventType}"));
                continue;
            }
            if (!StepMatches(step, ev.Payload))
            {
                trace.Add(new RuleTestStepTrace(matched, step.Name, false,
                    $"payload did not satisfy step predicate"));
                continue;
            }
            if (matched > 0
                && (ev.OccurredAt - firstMatchTime).TotalSeconds > definition.WindowSeconds)
            {
                trace.Add(new RuleTestStepTrace(matched, step.Name, false,
                    $"step occurred {(ev.OccurredAt - firstMatchTime).TotalSeconds:F0}s after step 0, outside window_seconds={definition.WindowSeconds}"));
                continue;
            }
            if (matched == 0) firstMatchTime = ev.OccurredAt;
            trace.Add(new RuleTestStepTrace(matched, step.Name, true, null));
            matched += 1;
        }

        if (matched == definition.Steps.Count)
        {
            return new RuleTestResult(true, null, trace);
        }
        return new RuleTestResult(false, $"matched {matched} of {definition.Steps.Count} steps", trace);
    }

    private static bool RuleMatches(AlertRule rule, IEnumerable<JsonElement> values)
        => rule.Operator switch
        {
            AlertRuleOperator.Exists => true,
            AlertRuleOperator.Equals => values.Any(v => string.Equals(JsonScalar(v), rule.MatchValue, StringComparison.OrdinalIgnoreCase)),
            AlertRuleOperator.Contains => values.Any(v => !string.IsNullOrEmpty(rule.MatchValue) && JsonScalar(v).Contains(rule.MatchValue, StringComparison.OrdinalIgnoreCase)),
            AlertRuleOperator.GreaterThan => values.Any(v => CompareNumber(v, rule.MatchValue, (a, b) => a > b)),
            AlertRuleOperator.LessThan => values.Any(v => CompareNumber(v, rule.MatchValue, (a, b) => a < b)),
            _ => false,
        };

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
}
