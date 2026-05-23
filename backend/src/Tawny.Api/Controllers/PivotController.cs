using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

public record PivotHostHit(
    Guid AgentId,
    string Hostname,
    int EventCount,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen);

public record PivotResponse(string Kind, string Value, int HostCount, IReadOnlyList<PivotHostHit> Hosts);

[ApiController]
[Route("api/pivot")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class PivotController(TawnyDbContext db) : ControllerBase
{
    /// <summary>
    /// Find every host that has telemetry referencing the given indicator
    /// (sha256, ipv4/ipv6, or domain). Defaults to the last 30 days.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PivotResponse>> Pivot(
        [FromQuery] string kind,
        [FromQuery] string value,
        [FromQuery] int days = 30,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Problem(statusCode: 400, title: "value is required.");
        }

        var normalizedKind = kind?.Trim().ToLowerInvariant() ?? "any";
        var needle = value.Trim();
        var clampedDays = Math.Clamp(days, 1, 365);
        var since = DateTimeOffset.UtcNow.AddDays(-clampedDays);
        var tenantId = User.GetTenantId();
        var like = $"%{needle}%";

        // Coarse JSON-payload LIKE filter — the payload is searchable text in SQL Server.
        // Cheap enough at 30d, and the result set is small (host aggregation).
        var rows = await db.TelemetryEvents
            .AsNoTracking()
            .Where(e => e.TenantId == tenantId && e.OccurredAt >= since && EF.Functions.Like(e.Payload, like))
            .GroupBy(e => new { e.AgentId, Hostname = e.Agent!.Hostname })
            .Select(g => new PivotHostHit(
                g.Key.AgentId,
                g.Key.Hostname,
                g.Count(),
                g.Min(e => e.OccurredAt),
                g.Max(e => e.OccurredAt)))
            .OrderByDescending(h => h.LastSeen)
            .Take(200)
            .ToListAsync(ct);

        return Ok(new PivotResponse(normalizedKind, needle, rows.Count, rows));
    }
}
