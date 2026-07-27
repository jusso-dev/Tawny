using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/cloud-findings")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
public sealed class CloudFindingsController(
    TawnyDbContext db,
    AuditLogger audit,
    TimeProvider timeProvider) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<CloudFindingResponse>>> List(
        [FromQuery] CloudFindingStatus? status,
        [FromQuery] Guid? huntId,
        [FromQuery] int limit = 100,
        CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 500);
        var tenantId = User.GetTenantId();
        var query = db.CloudFindings.AsNoTracking()
            .Include(f => f.CloudHunt).ThenInclude(h => h!.CloudConnection)
            .Where(f => f.TenantId == tenantId);
        if (status is not null) query = query.Where(f => f.Status == status);
        if (huntId is not null) query = query.Where(f => f.CloudHuntId == huntId);
        var rows = await query.OrderByDescending(f => f.OccurredAt).Take(limit).ToListAsync(ct);
        return Ok(rows.Select(f => new CloudFindingResponse(
            f.Id,
            f.CloudHuntId,
            f.CloudHunt?.Name ?? "Unknown",
            f.CloudHunt?.CloudConnection?.Provider ?? CloudProvider.Aws,
            f.CloudHunt?.Source ?? CloudSourceKind.AwsCloudTrail,
            f.ProviderEventId,
            f.Title,
            f.Severity,
            f.Status,
            f.Actor,
            f.Resource,
            f.OccurredAt,
            JsonSerializer.Deserialize<JsonElement>(f.EvidenceJson),
            f.CreatedAt,
            f.UpdatedAt)).ToArray());
    }

    [HttpPut("{id:long}/status")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> UpdateStatus(
        long id,
        [FromBody] UpdateCloudFindingRequest request,
        CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var finding = await db.CloudFindings.SingleOrDefaultAsync(f => f.Id == id && f.TenantId == tenantId, ct);
        if (finding is null) return NotFound();
        finding.Status = request.Status;
        finding.UpdatedAt = timeProvider.GetUtcNow();
        audit.Add(User, "cloud.finding.status", finding.Id.ToString(), new { finding.Status });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}
