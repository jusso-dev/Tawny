using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Jobs.Cloud;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/cloud-hunts")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
public sealed class CloudHuntsController(
    TawnyDbContext db,
    CloudHuntCoordinator coordinator,
    AuditLogger audit,
    TimeProvider timeProvider) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<CloudHuntResponse>>> List(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var hunts = await db.CloudHunts.AsNoTracking()
            .Include(h => h.CloudConnection)
            .Where(h => h.TenantId == tenantId)
            .OrderBy(h => h.Name)
            .ToListAsync(ct);
        return Ok(hunts.Select(ToResponse).ToArray());
    }

    [HttpPost]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<CloudHuntResponse>> Create(
        [FromBody] UpsertCloudHuntRequest request,
        CancellationToken ct)
    {
        var error = Validate(request);
        if (error is not null) return Problem(statusCode: 400, title: error);
        var tenantId = User.GetTenantId();
        var connection = await db.CloudConnections
            .SingleOrDefaultAsync(c => c.Id == request.CloudConnectionId && c.TenantId == tenantId, ct);
        if (connection is null) return Problem(statusCode: 400, title: "Cloud connection was not found.");
        if (!SourceMatchesProvider(request.Source, connection.Provider))
            return Problem(statusCode: 400, title: "Hunt source does not match connection provider.");
        var now = timeProvider.GetUtcNow();
        var hunt = new CloudHunt
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            CloudConnectionId = connection.Id,
            CloudConnection = connection,
            Name = request.Name.Trim(),
            Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim(),
            Source = request.Source,
            QueryJson = request.Query.GetRawText(),
            IsEnabled = request.IsEnabled,
            IntervalMinutes = request.IntervalMinutes,
            LookbackMinutes = request.LookbackMinutes,
            Severity = request.Severity,
            MitreTechniquesJson = JsonSerializer.Serialize(request.MitreTechniques ?? []),
            CreatedByUserId = TryGetUserId(),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.CloudHunts.Add(hunt);
        audit.Add(User, "cloud.hunt.create", hunt.Id.ToString(), new
        {
            hunt.Name,
            hunt.Source,
            hunt.IsEnabled,
            hunt.IntervalMinutes,
            hunt.LookbackMinutes,
            hunt.Severity,
            hunt.CloudConnectionId,
        });
        await db.SaveChangesAsync(ct);
        return CreatedAtAction(nameof(List), new { id = hunt.Id }, ToResponse(hunt));
    }

    [HttpPut("{id:guid}")]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<CloudHuntResponse>> Update(
        Guid id,
        [FromBody] UpsertCloudHuntRequest request,
        CancellationToken ct)
    {
        var error = Validate(request);
        if (error is not null) return Problem(statusCode: 400, title: error);
        var tenantId = User.GetTenantId();
        var hunt = await db.CloudHunts.Include(h => h.CloudConnection)
            .SingleOrDefaultAsync(h => h.Id == id && h.TenantId == tenantId, ct);
        if (hunt is null) return NotFound();
        var connection = await db.CloudConnections
            .SingleOrDefaultAsync(c => c.Id == request.CloudConnectionId && c.TenantId == tenantId, ct);
        if (connection is null) return Problem(statusCode: 400, title: "Cloud connection was not found.");
        if (!SourceMatchesProvider(request.Source, connection.Provider))
            return Problem(statusCode: 400, title: "Hunt source does not match connection provider.");

        hunt.CloudConnectionId = connection.Id;
        hunt.CloudConnection = connection;
        hunt.Name = request.Name.Trim();
        hunt.Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();
        hunt.Source = request.Source;
        hunt.QueryJson = request.Query.GetRawText();
        hunt.IsEnabled = request.IsEnabled;
        hunt.IntervalMinutes = request.IntervalMinutes;
        hunt.LookbackMinutes = request.LookbackMinutes;
        hunt.Severity = request.Severity;
        hunt.MitreTechniquesJson = JsonSerializer.Serialize(request.MitreTechniques ?? []);
        hunt.UpdatedAt = timeProvider.GetUtcNow();
        audit.Add(User, "cloud.hunt.update", hunt.Id.ToString(), new
        {
            hunt.Name,
            hunt.Source,
            hunt.IsEnabled,
            hunt.IntervalMinutes,
            hunt.LookbackMinutes,
            hunt.Severity,
            hunt.CloudConnectionId,
        });
        await db.SaveChangesAsync(ct);
        return Ok(ToResponse(hunt));
    }

    [HttpPost("{id:guid}/run")]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<CloudRunResponse>> Run(Guid id, CancellationToken ct)
    {
        try
        {
            var result = await coordinator.RunAsync(User.GetTenantId(), id, TryGetUserId(), ct);
            audit.Add(User, "cloud.hunt.run", id.ToString(), new
            {
                result.RecordsRead,
                result.FindingsCreated,
            });
            await db.SaveChangesAsync(ct);
            return Ok(new CloudRunResponse(
                result.RunId,
                result.RecordsRead,
                result.FindingsCreated,
                result.WindowFrom,
                result.WindowTo));
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            return Problem(statusCode: 502, title: "Cloud hunt failed.", detail: ex.Message);
        }
    }

    [HttpGet("{id:guid}/runs")]
    public async Task<ActionResult<IReadOnlyList<CloudHuntRunResponse>>> Runs(
        Guid id,
        [FromQuery] int limit = 50,
        CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        var tenantId = User.GetTenantId();
        if (!await db.CloudHunts.AnyAsync(h => h.Id == id && h.TenantId == tenantId, ct)) return NotFound();
        var runs = await db.CloudHuntRuns.AsNoTracking()
            .Where(r => r.CloudHuntId == id && r.TenantId == tenantId)
            .OrderByDescending(r => r.StartedAt)
            .Take(limit)
            .Select(r => new CloudHuntRunResponse(
                r.Id,
                r.Status,
                r.WindowFrom,
                r.WindowTo,
                r.StartedAt,
                r.CompletedAt,
                r.RecordsRead,
                r.FindingsCreated,
                r.ErrorMessage))
            .ToListAsync(ct);
        return Ok(runs);
    }

    [HttpDelete("{id:guid}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var hunt = await db.CloudHunts.SingleOrDefaultAsync(h => h.Id == id && h.TenantId == tenantId, ct);
        if (hunt is null) return NotFound();
        db.CloudHunts.Remove(hunt);
        audit.Add(User, "cloud.hunt.delete", hunt.Id.ToString(), new { hunt.Name, hunt.Source });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private static string? Validate(UpsertCloudHuntRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length > 160)
            return "Name is required and must be 160 characters or fewer.";
        if (request.Description?.Length > 4000) return "Description must be 4000 characters or fewer.";
        if (request.Query.ValueKind != JsonValueKind.Object || request.Query.GetRawText().Length > 32_768)
            return "Query must be a JSON object no larger than 32 KiB.";
        if (request.IntervalMinutes is < 1 or > 1440)
            return "Interval must be between 1 and 1440 minutes.";
        if (request.LookbackMinutes is < 1 or > 43_200)
            return "Lookback must be between 1 minute and 30 days.";
        if (request.MitreTechniques?.Count > 64 || request.MitreTechniques?.Any(t => t.Length > 32) == true)
            return "MITRE technique list is too large.";
        return null;
    }

    private static bool SourceMatchesProvider(CloudSourceKind source, CloudProvider provider)
        => provider switch
        {
            CloudProvider.Aws => source is CloudSourceKind.AwsCloudTrail or CloudSourceKind.AwsGuardDuty,
            CloudProvider.Azure => source is CloudSourceKind.AzureActivityLog
                or CloudSourceKind.AzureEntraAuditLog
                or CloudSourceKind.AzureEntraSignInLog,
            _ => false,
        };

    private static CloudHuntResponse ToResponse(CloudHunt hunt)
        => new(
            hunt.Id,
            hunt.CloudConnectionId,
            hunt.CloudConnection?.Name ?? "Unknown",
            hunt.Name,
            hunt.Description,
            hunt.Source,
            JsonSerializer.Deserialize<JsonElement>(hunt.QueryJson),
            hunt.IsEnabled,
            hunt.IntervalMinutes,
            hunt.LookbackMinutes,
            hunt.Severity,
            JsonSerializer.Deserialize<string[]>(hunt.MitreTechniquesJson ?? "[]") ?? [],
            hunt.LastRunAt,
            hunt.LastSuccessAt,
            hunt.LastMatchCount,
            hunt.LastError,
            hunt.CreatedAt,
            hunt.UpdatedAt);

    private Guid? TryGetUserId()
        => Guid.TryParse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id) ? id : null;
}
