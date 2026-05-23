using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/audit-logs")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class AuditLogController(TawnyDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<AuditLogResponse>>> List(
        [FromQuery] string? action,
        [FromQuery] DateTimeOffset? before,
        [FromQuery] int limit = 100,
        CancellationToken ct = default)
    {
        var take = Math.Clamp(limit, 1, 500);
        var tenantId = User.GetTenantId();
        var query = db.AuditLog.AsNoTracking().Where(a => a.TenantId == tenantId);
        if (!string.IsNullOrWhiteSpace(action))
        {
            var like = $"%{action.Trim()}%";
            query = query.Where(a => EF.Functions.Like(a.Action, like));
        }
        if (before is not null)
        {
            query = query.Where(a => a.OccurredAt < before.Value);
        }
        var rows = await query
            .OrderByDescending(a => a.OccurredAt)
            .ThenByDescending(a => a.Id)
            .Take(take)
            .ToListAsync(ct);

        return Ok(rows.Select(a => new AuditLogResponse(
            a.Id,
            a.UserId,
            a.Action,
            a.Target,
            string.IsNullOrEmpty(a.MetadataJson) ? null : JsonSerializer.Deserialize<JsonElement>(a.MetadataJson!),
            a.OccurredAt)).ToList());
    }
}
