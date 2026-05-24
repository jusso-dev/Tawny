using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.ThreatIntel;

namespace Tawny.Jobs;

/// <summary>
/// Walks recent unenriched alerts, extracts the matched IoC value from the
/// rule's payload_path, looks it up via reputation providers, and stores the
/// verdict on Alert.EnrichmentJson. Reputation is cached per tenant.
/// </summary>
public class ReputationEnrichmentJob(
    TawnyDbContext db,
    ReputationEnricher enricher,
    IOptions<ReputationOptions> options,
    ILogger<ReputationEnrichmentJob> log)
{
    private const int BatchSize = 100;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        if (!options.Value.EnrichAlertsAutomatically) return;

        var cutoff = DateTimeOffset.UtcNow.AddHours(-24);
        var alerts = await db.Alerts
            .Where(a => a.EnrichmentJson == null && a.CreatedAt >= cutoff)
            .OrderByDescending(a => a.CreatedAt)
            .Take(BatchSize)
            .Include(a => a.AlertRule)
            .Include(a => a.Agent)
            .Include(a => a.TelemetryEvent)
            .ToListAsync(ct);

        if (alerts.Count == 0) return;
        var enrichedCount = 0;

        foreach (var alert in alerts)
        {
            if (ct.IsCancellationRequested) break;
            var rule = alert.AlertRule;
            var telemetry = alert.TelemetryEvent;
            if (rule is null || telemetry is null) continue;

            var (kind, value) = ExtractIndicator(rule, telemetry);
            if (kind is null || string.IsNullOrEmpty(value))
            {
                alert.EnrichmentJson = "{\"enriched\":false,\"reason\":\"no_extractable_indicator\"}";
                continue;
            }

            try
            {
                var tenantId = alert.Agent?.TenantId ?? Tawny.Domain.TenantDefaults.DefaultTenantId;
                var lookups = await enricher.LookupAsync(tenantId, kind, value, ct);
                alert.EnrichmentJson = JsonSerializer.Serialize(new
                {
                    enriched = true,
                    indicator = new { kind, value },
                    lookups = lookups.Select(l => new
                    {
                        provider = l.Provider.ToString(),
                        verdict = l.Verdict.ToString(),
                        score = l.Score,
                        detail = l.Detail,
                    }),
                }, JsonOptions);
                enrichedCount += 1;
            }
            catch (Exception ex)
            {
                alert.EnrichmentJson = JsonSerializer.Serialize(new
                {
                    enriched = false,
                    reason = "lookup_failed",
                    error = ex.Message,
                }, JsonOptions);
                log.LogWarning(ex, "Reputation enrichment failed for alert {AlertId}", alert.Id);
            }
        }

        await db.SaveChangesAsync(ct);
        if (enrichedCount > 0)
        {
            log.LogInformation("Reputation enrichment completed: {Count} alerts enriched.", enrichedCount);
        }
    }

    private static (string? Kind, string? Value) ExtractIndicator(AlertRule rule, TelemetryEvent telemetryEvent)
    {
        // The cheapest path: if the rule is an IoC rule, the MatchValue is the indicator itself.
        if (rule.Format == AlertRuleFormat.Ioc && !string.IsNullOrEmpty(rule.MatchValue))
        {
            var kind = rule.PayloadPath switch
            {
                "new_sha256" => "sha256",
                "new_sha1" => "sha1",
                "connections.remote_address" => "ipv4",
                "processes.command_line" => "domain",
                _ => null,
            };
            if (kind is not null)
            {
                return (kind, rule.MatchValue);
            }
        }

        // Fallback: pull from the payload via rule.PayloadPath.
        if (string.IsNullOrWhiteSpace(rule.PayloadPath)) return (null, null);
        try
        {
            using var payload = JsonDocument.Parse(telemetryEvent.Payload);
            var segments = rule.PayloadPath.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var first = Resolve(payload.RootElement, segments).FirstOrDefault();
            if (first.ValueKind == JsonValueKind.Undefined) return (null, null);
            var scalar = first.ValueKind switch
            {
                JsonValueKind.String => first.GetString(),
                JsonValueKind.Number => first.GetRawText(),
                _ => null,
            };
            if (string.IsNullOrWhiteSpace(scalar)) return (null, null);
            var kind = rule.PayloadPath switch
            {
                "new_sha256" => "sha256",
                "new_sha1" => "sha1",
                _ when rule.PayloadPath.Contains("address", StringComparison.OrdinalIgnoreCase) => "ipv4",
                _ when rule.PayloadPath.Contains("domain", StringComparison.OrdinalIgnoreCase) => "domain",
                _ => null,
            };
            return (kind, scalar);
        }
        catch
        {
            return (null, null);
        }
    }

    private static IEnumerable<JsonElement> Resolve(JsonElement current, IReadOnlyList<string> segments, int index = 0)
    {
        if (index >= segments.Count) { yield return current; yield break; }
        if (current.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in current.EnumerateArray())
            {
                foreach (var v in Resolve(item, segments, index)) yield return v;
            }
            yield break;
        }
        if (current.ValueKind != JsonValueKind.Object) yield break;
        if (!current.TryGetProperty(segments[index], out var child)) yield break;
        foreach (var v in Resolve(child, segments, index + 1)) yield return v;
    }
}
