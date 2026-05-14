using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/alerts")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
public class AlertsController(TawnyDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<AlertResponse>>> List(
        [FromQuery] AlertStatus? status,
        [FromQuery] int limit = 50,
        CancellationToken ct = default)
    {
        var take = Math.Clamp(limit, 1, 200);
        var query = db.Alerts.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(a => a.Status == status.Value);
        }

        var rows = await query
            .OrderByDescending(a => a.CreatedAt)
            .ThenByDescending(a => a.Id)
            .Take(take)
            .Select(a => new AlertResponse(
                a.Id,
                a.AlertRuleId,
                a.AlertRule!.Name,
                a.AgentId,
                a.Agent!.Hostname,
                a.TelemetryEventId,
                a.Severity,
                a.Status,
                a.Title,
                a.Description,
                a.CreatedAt))
            .ToListAsync(ct);

        return Ok(rows);
    }
}
