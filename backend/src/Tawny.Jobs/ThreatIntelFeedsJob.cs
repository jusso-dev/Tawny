using System.Net.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.Hunting;
using Tawny.Infrastructure.ThreatIntel;

namespace Tawny.Jobs;

/// <summary>
/// Walks every enabled ThreatIntelFeed whose interval has elapsed, pulls its
/// payload, and materialises new indicators as AlertRules (Format = Ioc) keyed
/// by ExternalId so re-imports are idempotent.
/// </summary>
public class ThreatIntelFeedsJob(
    TawnyDbContext db,
    TimeProvider timeProvider,
    ThreatIntelFetcher fetcher,
    ILogger<ThreatIntelFeedsJob> log)
{
    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var now = timeProvider.GetUtcNow();
        var due = await db.ThreatIntelFeeds
            .Where(f => f.IsEnabled
                && (f.LastRunAt == null
                    || EF.Functions.DateDiffMinute(f.LastRunAt!.Value, now) >= f.IntervalMinutes))
            .ToListAsync(ct);
        if (due.Count == 0) return;

        foreach (var feed in due)
        {
            if (ct.IsCancellationRequested) break;
            await RunOneAsync(feed, now, ct);
        }
    }

    private async Task RunOneAsync(ThreatIntelFeed feed, DateTimeOffset now, CancellationToken ct)
    {
        feed.LastRunAt = now;
        try
        {
            var result = await fetcher.FetchAsync(feed, ct);
            if (!result.Modified)
            {
                feed.Status = ThreatIntelFeedStatus.Healthy;
                feed.LastSuccessAt = now;
                feed.LastError = null;
                await db.SaveChangesAsync(ct);
                return;
            }
            feed.Etag = result.Etag;
            await MaterialiseAsync(feed, result, now, ct);
            feed.Status = ThreatIntelFeedStatus.Healthy;
            feed.LastSuccessAt = now;
            feed.LastImportedCount = result.Indicators.Count + (result.Exposures?.Count ?? 0);
            feed.LastSkippedCount = result.Skipped.Count;
            feed.LastError = null;
        }
        catch (Exception ex)
        {
            feed.Status = ThreatIntelFeedStatus.Failed;
            feed.LastError = ex.Message.Length > 2000 ? ex.Message[..2000] : ex.Message;
            log.LogError(ex, "TI feed {Name} ({Url}) failed", feed.Name, feed.Url);
        }
        await db.SaveChangesAsync(ct);
    }

    private async Task MaterialiseAsync(
        ThreatIntelFeed feed,
        FetchResult result,
        DateTimeOffset now,
        CancellationToken ct)
    {
        var externalIdPrefix = $"ti-feed:{feed.Id}:";
        var existingIds = await db.AlertRules
            .Where(r => r.TenantId == feed.TenantId
                && r.ExternalId != null
                && r.ExternalId.StartsWith(externalIdPrefix))
            .Select(r => r.ExternalId!)
            .ToListAsync(ct);
        var existing = new HashSet<string>(existingIds, StringComparer.OrdinalIgnoreCase);

        var newRules = new List<AlertRule>();
        foreach (var ind in result.Indicators)
        {
            var externalId = externalIdPrefix + ind.Kind + ":" + ind.Value.ToLowerInvariant();
            if (existing.Contains(externalId)) continue;

            (TelemetryEventType EventType, string PayloadPath, AlertRuleOperator Op)? compiled = ind.Kind switch
            {
                "sha256" => (TelemetryEventType.FileIntegrity, "new_sha256", AlertRuleOperator.Equals),
                "sha1" => (TelemetryEventType.FileIntegrity, "new_sha1", AlertRuleOperator.Equals),
                "ipv4" or "ipv6" => (TelemetryEventType.NetworkSnapshot, "connections.remote_address", AlertRuleOperator.Equals),
                "domain" => (TelemetryEventType.ProcessSnapshot, "processes.command_line", AlertRuleOperator.Contains),
                _ => null,
            };
            if (compiled is null) continue;
            var (eventType, payloadPath, op) = compiled.Value;

            newRules.Add(new AlertRule
            {
                Id = Guid.NewGuid(),
                TenantId = feed.TenantId,
                Name = $"TI feed {feed.Name}: {ind.Kind} {ind.Value}",
                Format = AlertRuleFormat.Ioc,
                ExternalId = externalId,
                Description = ind.Description,
                EventType = eventType,
                Severity = feed.DefaultSeverity,
                Operator = op,
                PayloadPath = payloadPath,
                MatchValue = ind.Value,
                IsEnabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
        }

        // OSV exposures coming from the feed get materialised as Format=PackageExposure
        // rules so the agent's inventory events can match them at ingest time.
        if (result.Exposures is { Count: > 0 })
        {
            foreach (var exposure in result.Exposures)
            {
                var pattern = exposure.VersionPattern ?? "any";
                var externalId = $"{externalIdPrefix}exposure:{exposure.Ecosystem}:{exposure.Name}:{pattern}";
                if (exposure.AdvisoryId is { Length: > 0 }) externalId = $"{externalId}:{exposure.AdvisoryId}";
                if (externalId.Length > 128) externalId = externalId[..128];
                if (existing.Contains(externalId)) continue;

                var definition = new PackageExposureDefinition(
                    exposure.Ecosystem,
                    exposure.Name,
                    exposure.VersionPattern,
                    exposure.AdvisoryId,
                    exposure.AdvisoryUrl);
                var eventType = exposure.Ecosystem switch
                {
                    "editor-extension" or "editor_extension" => TelemetryEventType.EditorExtension,
                    "browser-extension" or "browser_extension" => TelemetryEventType.BrowserExtension,
                    "mcp" or "mcp_server" or "mcp-server" => TelemetryEventType.McpConfig,
                    _ => TelemetryEventType.PackageInventory,
                };

                newRules.Add(new AlertRule
                {
                    Id = Guid.NewGuid(),
                    TenantId = feed.TenantId,
                    Name = $"OSV: {exposure.Ecosystem}/{exposure.Name} {pattern}",
                    Format = AlertRuleFormat.PackageExposure,
                    ExternalId = externalId,
                    Description = exposure.Summary
                        ?? $"OSV exposure from {feed.Name}: {exposure.Ecosystem}/{exposure.Name} {pattern}.",
                    EventType = eventType,
                    Severity = feed.DefaultSeverity,
                    Operator = AlertRuleOperator.Exists,
                    SourceDefinition = PackageExposureParser.Serialize(definition),
                    IsEnabled = true,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
            }
        }

        if (newRules.Count > 0)
        {
            db.AlertRules.AddRange(newRules);
            log.LogInformation("TI feed {Name} imported {Count} new rules ({Ioc} IoCs + {Exp} exposures).",
                feed.Name, newRules.Count,
                newRules.Count(r => r.Format == AlertRuleFormat.Ioc),
                newRules.Count(r => r.Format == AlertRuleFormat.PackageExposure));
        }
    }
}
