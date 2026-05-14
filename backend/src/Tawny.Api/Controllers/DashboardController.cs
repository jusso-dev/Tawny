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

        return Ok(new DashboardSummaryResponse(
            totalAgents,
            onlineAgents,
            offlineAgents,
            staleAgents,
            unknownAgents,
            recentEvents,
            buckets));
    }

    private static DateTimeOffset HourBucket(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(
            utc.Year, utc.Month, utc.Day, utc.Hour, 0, 0, TimeSpan.Zero);
    }
}
