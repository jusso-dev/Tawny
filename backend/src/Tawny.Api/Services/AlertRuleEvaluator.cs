using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Api.Services;

public class AlertRuleEvaluator(TawnyDbContext db)
{
    public async Task<IReadOnlyList<Alert>> EvaluateAsync(
        Agent agent,
        IReadOnlyList<TelemetryEvent> events,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (events.Count == 0)
        {
            return [];
        }

        var eventTypes = events.Select(e => e.EventType).Distinct().ToArray();
        var rules = await db.AlertRules
            .Where(r => r.IsEnabled && (r.EventType == null || eventTypes.Contains(r.EventType.Value)))
            .ToListAsync(ct);

        if (rules.Count == 0)
        {
            return [];
        }

        var alerts = new List<Alert>();
        foreach (var telemetryEvent in events)
        {
            using var payload = JsonDocument.Parse(telemetryEvent.Payload);
            foreach (var rule in rules)
            {
                if (rule.EventType is not null && rule.EventType.Value != telemetryEvent.EventType)
                {
                    continue;
                }

                if (!Matches(rule, payload.RootElement))
                {
                    continue;
                }

                alerts.Add(new Alert
                {
                    AlertRuleId = rule.Id,
                    AgentId = agent.Id,
                    TelemetryEventId = telemetryEvent.Id,
                    Severity = rule.Severity,
                    Title = $"{rule.Name} on {agent.Hostname}",
                    Description = BuildDescription(rule, telemetryEvent),
                    CreatedAt = now,
                });
            }
        }

        db.Alerts.AddRange(alerts);
        return alerts;
    }

    private static bool Matches(AlertRule rule, JsonElement payload)
    {
        if (string.IsNullOrWhiteSpace(rule.PayloadPath))
        {
            return true;
        }

        var values = ResolvePath(payload, rule.PayloadPath).ToList();
        if (values.Count == 0)
        {
            return false;
        }

        return rule.Operator switch
        {
            AlertRuleOperator.Exists => true,
            AlertRuleOperator.Equals => values.Any(value => MatchesAny(value, rule.MatchValue, static (left, right) =>
                string.Equals(left, right, StringComparison.OrdinalIgnoreCase))),
            AlertRuleOperator.Contains => values.Any(value => MatchesAny(value, rule.MatchValue, static (left, right) =>
                left.Contains(right, StringComparison.OrdinalIgnoreCase))),
            AlertRuleOperator.GreaterThan => values.Any(value => CompareNumber(value, rule.MatchValue, static (left, right) => left > right)),
            AlertRuleOperator.LessThan => values.Any(value => CompareNumber(value, rule.MatchValue, static (left, right) => left < right)),
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
        if (index >= segments.Count)
        {
            yield return current;
            yield break;
        }

        if (current.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in current.EnumerateArray())
            {
                foreach (var value in ResolvePath(item, segments, index))
                {
                    yield return value;
                }
            }
            yield break;
        }

        if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segments[index], out var child))
        {
            yield break;
        }

        foreach (var value in ResolvePath(child, segments, index + 1))
        {
            yield return value;
        }
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

    private static bool CompareNumber(JsonElement value, string? expected, Func<decimal, decimal, bool> compare)
    {
        var leftRaw = JsonScalar(value);
        return decimal.TryParse(leftRaw, NumberStyles.Float, CultureInfo.InvariantCulture, out var left)
            && decimal.TryParse(expected, NumberStyles.Float, CultureInfo.InvariantCulture, out var right)
            && compare(left, right);
    }

    private static bool MatchesAny(JsonElement value, string? expected, Func<string, string, bool> compare)
    {
        var left = JsonScalar(value);
        foreach (var candidate in MatchValues(expected))
        {
            if (compare(left, candidate))
            {
                return true;
            }
        }
        return false;
    }

    private static IReadOnlyList<string> MatchValues(string? expected)
    {
        if (string.IsNullOrWhiteSpace(expected))
        {
            return [""];
        }

        if (expected.TrimStart().StartsWith("[", StringComparison.Ordinal))
        {
            try
            {
                return JsonSerializer.Deserialize<List<string>>(expected) ?? [];
            }
            catch (JsonException)
            {
                return [expected];
            }
        }

        return [expected];
    }

    private static string BuildDescription(AlertRule rule, TelemetryEvent telemetryEvent)
    {
        var predicate = string.IsNullOrWhiteSpace(rule.PayloadPath)
            ? telemetryEvent.EventType.ToString()
            : $"{rule.PayloadPath} {rule.Operator} {rule.MatchValue}";
        return $"Matched {predicate} on telemetry event {telemetryEvent.Id}.";
    }
}
