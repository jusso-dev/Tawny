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
using Tawny.Infrastructure.Hunting;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/hunts")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class HuntsController(
    TawnyDbContext db,
    AuditLogger audit,
    HuntQueryParser parser,
    HuntExecutor executor) : ControllerBase
{
    [HttpPost("run")]
    public async Task<ActionResult<RunHuntResponse>> Run(
        [FromBody] RunHuntRequest req,
        CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        HuntQueryPlan plan;
        try
        {
            plan = parser.Parse(req.Query, req.Limit);
        }
        catch (HuntQueryException ex)
        {
            return Problem(statusCode: 400, title: "Could not parse hunt query.", detail: ex.Message);
        }

        var result = await executor.ExecuteAsync(tenantId, plan, ct);
        return Ok(new RunHuntResponse(
            result.MatchCount,
            result.Matches.Select(m => new HuntMatchResponse(
                m.EventId, m.AgentId, m.Hostname, m.EventType, m.OccurredAt, m.ReceivedAt, m.Payload)).ToList(),
            result.Warnings));
    }

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<SavedHuntResponse>>> List(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var rows = await db.SavedHunts
            .AsNoTracking()
            .Where(h => h.TenantId == tenantId)
            .OrderBy(h => h.Name)
            .ToListAsync(ct);
        return Ok(rows.Select(ToResponse).ToList());
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<SavedHuntResponse>> Get(Guid id, CancellationToken ct)
    {
        var hunt = await db.SavedHunts.AsNoTracking()
            .FirstOrDefaultAsync(h => h.Id == id && h.TenantId == User.GetTenantId(), ct);
        if (hunt is null) return NotFound();
        return Ok(ToResponse(hunt));
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<SavedHuntResponse>> Create(
        [FromBody] CreateSavedHuntRequest req,
        CancellationToken ct)
    {
        var validation = ValidateRequest(req.Name, req.Query, req.ScheduleCron);
        if (validation is not null) return validation;

        try { parser.Parse(req.Query); }
        catch (HuntQueryException ex)
        {
            return Problem(statusCode: 400, title: "Saved hunt query did not parse.", detail: ex.Message);
        }

        var tenantId = User.GetTenantId();
        if (await db.SavedHunts.AnyAsync(h => h.TenantId == tenantId && h.Name == req.Name.Trim(), ct))
        {
            return Problem(statusCode: 409, title: "A saved hunt with this name already exists.");
        }

        var now = DateTimeOffset.UtcNow;
        var hunt = new SavedHunt
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            Name = req.Name.Trim(),
            Description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description.Trim(),
            Query = req.Query.Trim(),
            IsScheduled = req.IsScheduled ?? false,
            ScheduleCron = NormalizeCron(req.ScheduleCron),
            AlertOnMatch = req.AlertOnMatch ?? false,
            AlertSeverity = req.AlertSeverity ?? AlertSeverity.Medium,
            MitreTechniquesJson = SerializeTechniques(req.MitreTechniques),
            CreatedByUserId = TryGetUserId(),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.SavedHunts.Add(hunt);
        audit.Add(User, "saved_hunt.create", hunt.Id.ToString(), new
        {
            hunt.Name,
            hunt.IsScheduled,
            hunt.AlertOnMatch,
        });
        await db.SaveChangesAsync(ct);
        return CreatedAtAction(nameof(Get), new { id = hunt.Id }, ToResponse(hunt));
    }

    [HttpPut("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<SavedHuntResponse>> Update(
        Guid id,
        [FromBody] UpdateSavedHuntRequest req,
        CancellationToken ct)
    {
        var validation = ValidateRequest(req.Name, req.Query, req.ScheduleCron);
        if (validation is not null) return validation;

        try { parser.Parse(req.Query); }
        catch (HuntQueryException ex)
        {
            return Problem(statusCode: 400, title: "Saved hunt query did not parse.", detail: ex.Message);
        }

        var tenantId = User.GetTenantId();
        var hunt = await db.SavedHunts.FirstOrDefaultAsync(h => h.Id == id && h.TenantId == tenantId, ct);
        if (hunt is null) return NotFound();

        hunt.Name = req.Name.Trim();
        hunt.Description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description.Trim();
        hunt.Query = req.Query.Trim();
        hunt.IsScheduled = req.IsScheduled;
        hunt.ScheduleCron = NormalizeCron(req.ScheduleCron);
        hunt.AlertOnMatch = req.AlertOnMatch;
        hunt.AlertSeverity = req.AlertSeverity;
        hunt.MitreTechniquesJson = SerializeTechniques(req.MitreTechniques);
        hunt.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Add(User, "saved_hunt.update", hunt.Id.ToString(), new
        {
            hunt.Name,
            hunt.IsScheduled,
            hunt.AlertOnMatch,
        });
        await db.SaveChangesAsync(ct);
        return Ok(ToResponse(hunt));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var deleted = await db.SavedHunts
            .Where(h => h.Id == id && h.TenantId == tenantId)
            .ExecuteDeleteAsync(ct);
        if (deleted == 0) return NotFound();
        audit.Add(User, "saved_hunt.delete", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:guid}/run")]
    public async Task<ActionResult<RunHuntResponse>> RunSaved(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var hunt = await db.SavedHunts.FirstOrDefaultAsync(h => h.Id == id && h.TenantId == tenantId, ct);
        if (hunt is null) return NotFound();

        HuntQueryPlan plan;
        try { plan = parser.Parse(hunt.Query); }
        catch (HuntQueryException ex)
        {
            return Problem(statusCode: 400, title: "Saved hunt query did not parse.", detail: ex.Message);
        }

        var run = new HuntRun
        {
            TenantId = tenantId,
            SavedHuntId = hunt.Id,
            TriggeredByUserId = TryGetUserId(),
            StartedAt = DateTimeOffset.UtcNow,
            Status = HuntRunStatus.Running,
        };
        db.HuntRuns.Add(run);
        await db.SaveChangesAsync(ct);

        try
        {
            var result = await executor.ExecuteAsync(tenantId, plan, ct);
            run.MatchCount = result.MatchCount;
            run.CompletedAt = DateTimeOffset.UtcNow;
            run.Status = HuntRunStatus.Succeeded;
            hunt.LastRunAt = run.CompletedAt;
            hunt.LastMatchCount = result.MatchCount;
            audit.Add(User, "saved_hunt.run", hunt.Id.ToString(), new
            {
                match_count = result.MatchCount,
            });
            await db.SaveChangesAsync(ct);

            return Ok(new RunHuntResponse(
                result.MatchCount,
                result.Matches.Select(m => new HuntMatchResponse(
                    m.EventId, m.AgentId, m.Hostname, m.EventType, m.OccurredAt, m.ReceivedAt, m.Payload)).ToList(),
                result.Warnings));
        }
        catch (Exception ex)
        {
            run.Status = HuntRunStatus.Failed;
            run.CompletedAt = DateTimeOffset.UtcNow;
            run.ErrorMessage = ex.Message.Length > 1000 ? ex.Message[..1000] : ex.Message;
            await db.SaveChangesAsync(ct);
            return Problem(statusCode: 500, title: "Hunt execution failed.", detail: ex.Message);
        }
    }

    [HttpGet("{id:guid}/runs")]
    public async Task<ActionResult<IReadOnlyList<HuntRunResponse>>> Runs(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        if (!await db.SavedHunts.AnyAsync(h => h.Id == id && h.TenantId == tenantId, ct))
        {
            return NotFound();
        }

        var rows = await db.HuntRuns
            .AsNoTracking()
            .Where(r => r.TenantId == tenantId && r.SavedHuntId == id)
            .OrderByDescending(r => r.StartedAt)
            .Take(50)
            .Select(r => new HuntRunResponse(
                r.Id, r.SavedHuntId, r.Status, r.StartedAt, r.CompletedAt,
                r.MatchCount, r.AlertsCreated, r.ErrorMessage))
            .ToListAsync(ct);
        return Ok(rows);
    }

    private static SavedHuntResponse ToResponse(SavedHunt h) => new(
        h.Id,
        h.Name,
        h.Description,
        h.Query,
        h.IsScheduled,
        h.ScheduleCron,
        h.AlertOnMatch,
        h.AlertSeverity,
        DeserializeTechniques(h.MitreTechniquesJson),
        h.LastRunAt,
        h.LastMatchCount,
        h.CreatedAt,
        h.UpdatedAt);

    private static IReadOnlyList<string> DeserializeTechniques(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? []; }
        catch { return []; }
    }

    private static string? SerializeTechniques(IReadOnlyList<string>? techniques)
    {
        if (techniques is null || techniques.Count == 0) return null;
        var normalized = techniques
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.Trim().ToUpperInvariant())
            .Distinct()
            .ToList();
        return normalized.Count == 0 ? null : JsonSerializer.Serialize(normalized);
    }

    private static string? NormalizeCron(string? cron)
    {
        var trimmed = cron?.Trim();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }

    private ActionResult<SavedHuntResponse>? ValidateRequest(string name, string query, string? scheduleCron)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 160)
        {
            return Problem(statusCode: 400, title: "name is required and must be 160 characters or fewer.");
        }
        if (string.IsNullOrWhiteSpace(query))
        {
            return Problem(statusCode: 400, title: "query is required.");
        }
        if (!string.IsNullOrWhiteSpace(scheduleCron) && scheduleCron.Length > 64)
        {
            return Problem(statusCode: 400, title: "schedule_cron must be 64 characters or fewer.");
        }
        return null;
    }

    private Guid? TryGetUserId()
    {
        var raw = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
