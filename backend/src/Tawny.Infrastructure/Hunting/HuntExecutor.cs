using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.Hunting;

public record HuntMatch(
    long EventId,
    Guid AgentId,
    string Hostname,
    TelemetryEventType EventType,
    DateTimeOffset OccurredAt,
    DateTimeOffset ReceivedAt,
    JsonElement Payload);

public record HuntResult(int MatchCount, IReadOnlyList<HuntMatch> Matches, IReadOnlyList<string> Warnings);

public class HuntExecutor(TawnyDbContext db)
{
    // Hard cap on the prefilter pull from SQL Server so a wide-open query
    // cannot drag the whole telemetry table back to memory.
    private const int PrefilterCap = 5_000;

    public async Task<HuntResult> ExecuteAsync(
        Guid tenantId,
        HuntQueryPlan plan,
        CancellationToken ct)
    {
        var warnings = new List<string>();
        var query = db.TelemetryEvents
            .AsNoTracking()
            .Where(e => e.TenantId == tenantId);

        if (plan.EventType is not null)
        {
            query = query.Where(e => e.EventType == plan.EventType.Value);
        }
        if (plan.AgentId is not null)
        {
            query = query.Where(e => e.AgentId == plan.AgentId.Value);
        }
        if (plan.From is not null)
        {
            query = query.Where(e => e.OccurredAt >= plan.From.Value);
        }
        if (plan.To is not null)
        {
            query = query.Where(e => e.OccurredAt <= plan.To.Value);
        }

        if (plan.AgentHostnameLike is { Length: > 0 } host)
        {
            var like = $"%{host}%";
            query = query.Where(e => EF.Functions.Like(e.Agent!.Hostname, like));
        }

        // Default to last 24h when no time bound is set, to keep wide-open queries cheap.
        if (plan.From is null && plan.To is null && plan.EventType is null && plan.AgentId is null)
        {
            var cutoff = DateTimeOffset.UtcNow.AddHours(-24);
            query = query.Where(e => e.OccurredAt >= cutoff);
            warnings.Add("No time window specified — restricted to the last 24h. Add 'last:7d' or 'from:...' to widen.");
        }

        var rows = await query
            .OrderByDescending(e => e.OccurredAt)
            .Take(PrefilterCap)
            .Select(e => new
            {
                e.Id,
                e.AgentId,
                Hostname = e.Agent!.Hostname,
                e.EventType,
                e.OccurredAt,
                e.ReceivedAt,
                e.Payload,
            })
            .ToListAsync(ct);

        if (rows.Count == PrefilterCap)
        {
            warnings.Add($"Hit prefilter cap of {PrefilterCap} events. Narrow the query with event_type, agent, or a tighter time window.");
        }

        var matches = new List<HuntMatch>(Math.Min(rows.Count, plan.Limit));
        foreach (var row in rows)
        {
            using var doc = JsonDocument.Parse(row.Payload);
            if (plan.Filter is null || Evaluate(plan.Filter, doc.RootElement))
            {
                matches.Add(new HuntMatch(
                    row.Id,
                    row.AgentId,
                    row.Hostname,
                    row.EventType,
                    row.OccurredAt,
                    row.ReceivedAt,
                    JsonSerializer.Deserialize<JsonElement>(row.Payload)));
                if (matches.Count >= plan.Limit) break;
            }
        }

        return new HuntResult(matches.Count, matches, warnings);
    }

    public static bool Evaluate(HuntNode node, JsonElement payload)
    {
        return node switch
        {
            HuntAnd and => Evaluate(and.Left, payload) && Evaluate(and.Right, payload),
            HuntOr or => Evaluate(or.Left, payload) || Evaluate(or.Right, payload),
            HuntNot not => !Evaluate(not.Inner, payload),
            HuntPredicate p => EvaluatePredicate(p, payload),
            _ => false,
        };
    }

    private static bool EvaluatePredicate(HuntPredicate predicate, JsonElement payload)
    {
        var path = predicate.Field;
        if (path.StartsWith("payload.", StringComparison.OrdinalIgnoreCase))
        {
            path = path[8..];
        }

        var values = ResolvePath(payload, path).ToList();
        if (values.Count == 0)
        {
            return predicate.Operator == HuntOperator.NotEquals;
        }

        return predicate.Operator switch
        {
            HuntOperator.Equals => values.Any(v => predicate.Values.Any(target => string.Equals(JsonScalar(v), target, StringComparison.OrdinalIgnoreCase))),
            HuntOperator.NotEquals => !values.Any(v => predicate.Values.Any(target => string.Equals(JsonScalar(v), target, StringComparison.OrdinalIgnoreCase))),
            HuntOperator.Contains => values.Any(v => predicate.Values.Any(target => JsonScalar(v).Contains(target, StringComparison.OrdinalIgnoreCase))),
            HuntOperator.In => values.Any(v => predicate.Values.Any(target => string.Equals(JsonScalar(v), target, StringComparison.OrdinalIgnoreCase))),
            HuntOperator.GreaterThan => values.Any(v => CompareNumber(v, predicate.Values, (a, b) => a > b)),
            HuntOperator.LessThan => values.Any(v => CompareNumber(v, predicate.Values, (a, b) => a < b)),
            HuntOperator.GreaterThanOrEqual => values.Any(v => CompareNumber(v, predicate.Values, (a, b) => a >= b)),
            HuntOperator.LessThanOrEqual => values.Any(v => CompareNumber(v, predicate.Values, (a, b) => a <= b)),
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

    private static bool CompareNumber(JsonElement value, IReadOnlyList<string> targets, Func<decimal, decimal, bool> cmp)
    {
        if (!decimal.TryParse(JsonScalar(value), NumberStyles.Float, CultureInfo.InvariantCulture, out var a)) return false;
        foreach (var raw in targets)
        {
            if (decimal.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var b) && cmp(a, b))
            {
                return true;
            }
        }
        return false;
    }
}
