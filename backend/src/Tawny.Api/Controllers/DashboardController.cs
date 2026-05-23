using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/dashboard")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
public class DashboardController(TawnyDbContext db) : ControllerBase
{
    [HttpGet("summary")]
    public async Task<ActionResult<DashboardSummaryResponse>> Summary(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var agentQuery = db.Agents.Where(a => a.TenantId == tenantId);
        var eventQuery = db.TelemetryEvents.Where(e => e.TenantId == tenantId);

        var totalAgents = await agentQuery.CountAsync(ct);
        var onlineAgents = await agentQuery.CountAsync(a => a.Status == AgentStatus.Online, ct);
        var staleAgents = await agentQuery.CountAsync(a => a.Status == AgentStatus.Stale, ct);
        var offlineAgents = await agentQuery.CountAsync(a => a.Status == AgentStatus.Offline, ct);
        var unknownAgents = await agentQuery.CountAsync(a => a.Status == AgentStatus.Unknown, ct);

        var recentEvents = await eventQuery
            .OrderByDescending(e => e.ReceivedAt)
            .Take(12)
            .Select(e => new DashboardRecentEvent(
                e.Id,
                e.AgentId,
                e.Agent!.Hostname,
                e.EventType,
                e.OccurredAt,
                e.ReceivedAt))
            .ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        var currentHour = new DateTimeOffset(
            now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero);
        var firstBucket = currentHour.AddHours(-23);

        var receivedAtRows = await eventQuery
            .Where(e => e.ReceivedAt >= firstBucket)
            .Select(e => e.ReceivedAt)
            .ToListAsync(ct);

        var counts = receivedAtRows
            .GroupBy(HourBucket)
            .ToDictionary(g => g.Key, g => g.Count());

        var buckets = Enumerable.Range(0, 24)
            .Select(i =>
            {
                var start = firstBucket.AddHours(i);
                return new DashboardEventVolumeBucket(
                    start,
                    counts.TryGetValue(start, out var count) ? count : 0);
            })
            .ToList();

        var sevenDaysAgo = now.AddDays(-7);
        var taggedRules = await db.AlertRules
            .AsNoTracking()
            .Where(r => r.MitreTechniquesJson != null)
            .Select(r => new { r.Id, r.MitreTechniquesJson })
            .ToListAsync(ct);
        var techniqueByRule = new Dictionary<Guid, List<string>>();
        foreach (var row in taggedRules)
        {
            var techniques = ParseTechniques(row.MitreTechniquesJson);
            if (techniques.Count > 0)
            {
                techniqueByRule[row.Id] = techniques;
            }
        }

        var heatmap = new List<DashboardMitreHeatmapEntry>();
        if (techniqueByRule.Count > 0)
        {
            var ruleIds = techniqueByRule.Keys.ToList();
            var counts = await db.Alerts
                .AsNoTracking()
                .Where(a => a.CreatedAt >= sevenDaysAgo
                            && ruleIds.Contains(a.AlertRuleId)
                            && db.Agents.Any(ag => ag.Id == a.AgentId && ag.TenantId == tenantId))
                .GroupBy(a => a.AlertRuleId)
                .Select(g => new { RuleId = g.Key, Count = g.Count() })
                .ToListAsync(ct);

            var perTechnique = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in counts)
            {
                if (!techniqueByRule.TryGetValue(c.RuleId, out var techniques)) continue;
                foreach (var t in techniques)
                {
                    perTechnique[t] = perTechnique.GetValueOrDefault(t) + c.Count;
                }
            }
            heatmap = perTechnique
                .OrderByDescending(p => p.Value)
                .Take(20)
                .Select(p => new DashboardMitreHeatmapEntry(p.Key, p.Value))
                .ToList();
        }

        return Ok(new DashboardSummaryResponse(
            totalAgents,
            onlineAgents,
            offlineAgents,
            staleAgents,
            unknownAgents,
            recentEvents,
            buckets,
            heatmap));
    }

    private static List<string> ParseTechniques(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? []; }
        catch { return []; }
    }

    private static DateTimeOffset HourBucket(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(
            utc.Year, utc.Month, utc.Day, utc.Hour, 0, 0, TimeSpan.Zero);
    }
}
