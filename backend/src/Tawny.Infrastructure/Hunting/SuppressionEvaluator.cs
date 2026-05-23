using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.Hunting;

/// <summary>
/// Checks whether a candidate alert should be suppressed based on per-tenant
/// suppression rules. A suppression rule matches when:
///   - its scope is AllRules, or its AlertRuleId matches the candidate's rule, AND
///   - its AgentId is null, or it matches the candidate's agent, AND
///   - its PayloadPath/MatchValue predicate matches the telemetry payload.
/// Expired or disabled suppressions are skipped.
/// </summary>
public class SuppressionEvaluator(TawnyDbContext db)
{
    public async Task<IReadOnlyList<(Alert Alert, SuppressionRule Suppression)>> ApplyAsync(
        Guid tenantId,
        IReadOnlyList<Alert> candidates,
        IReadOnlyDictionary<long, TelemetryEvent> eventsById,
        DateTimeOffset now,
        CancellationToken ct)
    {
        if (candidates.Count == 0) return [];

        var rules = await db.SuppressionRules
            .Where(s => s.TenantId == tenantId && s.IsEnabled && (s.ExpiresAt == null || s.ExpiresAt > now))
            .ToListAsync(ct);
        if (rules.Count == 0) return [];

        var suppressed = new List<(Alert, SuppressionRule)>();
        foreach (var alert in candidates)
        {
            if (!eventsById.TryGetValue(alert.TelemetryEventId, out var telemetryEvent))
            {
                continue;
            }

            using var payload = JsonDocument.Parse(telemetryEvent.Payload);
            foreach (var rule in rules)
            {
                if (rule.Scope == SuppressionScope.SpecificRule && rule.AlertRuleId != alert.AlertRuleId)
                {
                    continue;
                }
                if (rule.AgentId is not null && rule.AgentId.Value != alert.AgentId)
                {
                    continue;
                }
                if (!MatchesPredicate(rule, payload.RootElement))
                {
                    continue;
                }

                suppressed.Add((alert, rule));
                rule.SuppressedCount += 1;
                rule.LastSuppressedAt = now;
                break;
            }
        }

        return suppressed;
    }

    private static bool MatchesPredicate(SuppressionRule rule, JsonElement payload)
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
            AlertRuleOperator.Equals => values.Any(v => string.Equals(JsonScalar(v), rule.MatchValue, StringComparison.OrdinalIgnoreCase)),
            AlertRuleOperator.Contains => values.Any(v => !string.IsNullOrEmpty(rule.MatchValue) && JsonScalar(v).Contains(rule.MatchValue, StringComparison.OrdinalIgnoreCase)),
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
}
