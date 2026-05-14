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

        if (!TryGetPath(payload, rule.PayloadPath, out var value))
        {
            return false;
        }

        return rule.Operator switch
        {
            AlertRuleOperator.Exists => true,
            AlertRuleOperator.Equals => string.Equals(JsonScalar(value), rule.MatchValue ?? "", StringComparison.OrdinalIgnoreCase),
            AlertRuleOperator.Contains => JsonScalar(value).Contains(rule.MatchValue ?? "", StringComparison.OrdinalIgnoreCase),
            AlertRuleOperator.GreaterThan => CompareNumber(value, rule.MatchValue, static (left, right) => left > right),
            AlertRuleOperator.LessThan => CompareNumber(value, rule.MatchValue, static (left, right) => left < right),
            _ => false,
        };
    }

    private static bool TryGetPath(JsonElement root, string path, out JsonElement value)
    {
        value = root;
        foreach (var segment in path.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(segment, out value))
            {
                return false;
            }
        }
        return true;
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

    private static string BuildDescription(AlertRule rule, TelemetryEvent telemetryEvent)
    {
        var predicate = string.IsNullOrWhiteSpace(rule.PayloadPath)
            ? telemetryEvent.EventType.ToString()
            : $"{rule.PayloadPath} {rule.Operator} {rule.MatchValue}";
        return $"Matched {predicate} on telemetry event {telemetryEvent.Id}.";
    }
}
