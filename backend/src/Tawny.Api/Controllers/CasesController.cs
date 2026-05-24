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

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/cases")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class CasesController(TawnyDbContext db, AuditLogger audit) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<CaseResponse>>> List(
        [FromQuery] CaseStatus? status,
        [FromQuery] int limit = 50,
        CancellationToken ct = default)
    {
        var take = Math.Clamp(limit, 1, 200);
        var tenantId = User.GetTenantId();
        var query = db.Cases.AsNoTracking().Where(c => c.TenantId == tenantId);
        if (status is not null) query = query.Where(c => c.Status == status.Value);
        var rows = await query
            .OrderByDescending(c => c.UpdatedAt)
            .Take(take)
            .Select(c => new
            {
                c.Id, c.Title, c.Summary, c.Status, c.Priority,
                c.AssignedToUserId, c.CreatedByUserId, c.MitreTechniquesJson,
                AlertCount = c.CaseAlerts.Count,
                NoteCount = c.Notes.Count,
                c.CreatedAt, c.UpdatedAt, c.ClosedAt,
            })
            .ToListAsync(ct);
        return Ok(rows.Select(c => new CaseResponse(
            c.Id, c.Title, c.Summary, c.Status, c.Priority,
            c.AssignedToUserId, c.CreatedByUserId, c.AlertCount, c.NoteCount,
            DeserializeTechniques(c.MitreTechniquesJson),
            c.CreatedAt, c.UpdatedAt, c.ClosedAt)).ToList());
    }

    [HttpGet("{id:long}")]
    public async Task<ActionResult<CaseDetailResponse>> Get(long id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var caseRow = await db.Cases
            .Include(c => c.CaseAlerts).ThenInclude(ca => ca.Alert).ThenInclude(a => a!.Agent)
            .Include(c => c.Notes)
            .FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId, ct);
        if (caseRow is null) return NotFound();

        return Ok(new CaseDetailResponse(
            caseRow.Id,
            caseRow.Title,
            caseRow.Summary,
            caseRow.Status,
            caseRow.Priority,
            caseRow.AssignedToUserId,
            caseRow.CreatedByUserId,
            DeserializeTechniques(caseRow.MitreTechniquesJson),
            caseRow.CaseAlerts
                .OrderByDescending(ca => ca.AddedAt)
                .Select(ca => new CaseAlertResponse(
                    ca.Id, ca.AlertId,
                    ca.Alert?.Title ?? "",
                    ca.Alert?.Agent?.Hostname ?? "",
                    ca.Alert?.Severity.ToString().ToLowerInvariant() ?? "",
                    ca.Alert?.CreatedAt ?? DateTimeOffset.MinValue,
                    ca.AddedAt))
                .ToList(),
            caseRow.Notes
                .OrderByDescending(n => n.CreatedAt)
                .Select(n => new CaseNoteResponse(n.Id, n.AuthorUserId, n.Body, n.CreatedAt))
                .ToList(),
            caseRow.CreatedAt,
            caseRow.UpdatedAt,
            caseRow.ClosedAt));
    }

    [HttpPost]
    public async Task<ActionResult<CaseResponse>> Create(
        [FromBody] CreateCaseRequest req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Title) || req.Title.Length > 255)
        {
            return Problem(statusCode: 400, title: "title is required and must be 255 characters or fewer.");
        }
        var tenantId = User.GetTenantId();
        var now = DateTimeOffset.UtcNow;
        var newCase = new Case
        {
            TenantId = tenantId,
            Title = req.Title.Trim(),
            Summary = string.IsNullOrWhiteSpace(req.Summary) ? null : req.Summary.Trim(),
            Priority = req.Priority ?? CasePriority.Medium,
            CreatedByUserId = TryGetUserId(),
            MitreTechniquesJson = SerializeTechniques(req.MitreTechniques),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.Cases.Add(newCase);
        await db.SaveChangesAsync(ct);

        if (req.AlertIds is { Count: > 0 })
        {
            await LinkAlertsAsync(newCase.Id, tenantId, req.AlertIds, now, ct);
        }

        audit.Add(User, "case.create", newCase.Id.ToString(), new
        {
            newCase.Title,
            alert_count = req.AlertIds?.Count ?? 0,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(Get), new { id = newCase.Id }, new CaseResponse(
            newCase.Id, newCase.Title, newCase.Summary, newCase.Status, newCase.Priority,
            newCase.AssignedToUserId, newCase.CreatedByUserId,
            req.AlertIds?.Count ?? 0, 0,
            DeserializeTechniques(newCase.MitreTechniquesJson),
            newCase.CreatedAt, newCase.UpdatedAt, newCase.ClosedAt));
    }

    [HttpPut("{id:long}")]
    public async Task<ActionResult<CaseResponse>> Update(
        long id,
        [FromBody] UpdateCaseRequest req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Title) || req.Title.Length > 255)
        {
            return Problem(statusCode: 400, title: "title is required and must be 255 characters or fewer.");
        }
        var tenantId = User.GetTenantId();
        var caseRow = await db.Cases.FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId, ct);
        if (caseRow is null) return NotFound();

        caseRow.Title = req.Title.Trim();
        caseRow.Summary = string.IsNullOrWhiteSpace(req.Summary) ? null : req.Summary.Trim();
        var transitioningToClosed = req.Status is CaseStatus.Resolved or CaseStatus.Closed
            && caseRow.Status is not (CaseStatus.Resolved or CaseStatus.Closed);
        caseRow.Status = req.Status;
        caseRow.Priority = req.Priority;
        caseRow.AssignedToUserId = req.AssignedToUserId;
        caseRow.MitreTechniquesJson = SerializeTechniques(req.MitreTechniques);
        caseRow.UpdatedAt = DateTimeOffset.UtcNow;
        if (transitioningToClosed) caseRow.ClosedAt = caseRow.UpdatedAt;

        audit.Add(User, "case.update", caseRow.Id.ToString(), new
        {
            caseRow.Title, caseRow.Status, caseRow.Priority, caseRow.AssignedToUserId,
        });
        await db.SaveChangesAsync(ct);

        var alertCount = await db.CaseAlerts.CountAsync(ca => ca.CaseId == caseRow.Id, ct);
        var noteCount = await db.CaseNotes.CountAsync(n => n.CaseId == caseRow.Id, ct);
        return Ok(new CaseResponse(
            caseRow.Id, caseRow.Title, caseRow.Summary, caseRow.Status, caseRow.Priority,
            caseRow.AssignedToUserId, caseRow.CreatedByUserId, alertCount, noteCount,
            DeserializeTechniques(caseRow.MitreTechniquesJson),
            caseRow.CreatedAt, caseRow.UpdatedAt, caseRow.ClosedAt));
    }

    [HttpDelete("{id:long}")]
    public async Task<IActionResult> Delete(long id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var deleted = await db.Cases
            .Where(c => c.Id == id && c.TenantId == tenantId)
            .ExecuteDeleteAsync(ct);
        if (deleted == 0) return NotFound();
        audit.Add(User, "case.delete", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:long}/alerts")]
    public async Task<ActionResult<CaseDetailResponse>> AddAlerts(
        long id,
        [FromBody] AddCaseAlertRequest req,
        CancellationToken ct)
    {
        if (req.AlertIds is null || req.AlertIds.Count == 0)
        {
            return Problem(statusCode: 400, title: "alert_ids must contain at least one id.");
        }
        var tenantId = User.GetTenantId();
        var caseRow = await db.Cases.FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId, ct);
        if (caseRow is null) return NotFound();

        var now = DateTimeOffset.UtcNow;
        var linked = await LinkAlertsAsync(caseRow.Id, tenantId, req.AlertIds, now, ct);
        if (linked > 0)
        {
            caseRow.UpdatedAt = now;
            audit.Add(User, "case.alerts_add", caseRow.Id.ToString(), new { count = linked });
        }
        await db.SaveChangesAsync(ct);
        return await Get(id, ct);
    }

    [HttpDelete("{id:long}/alerts/{alertId:long}")]
    public async Task<IActionResult> RemoveAlert(long id, long alertId, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        if (!await db.Cases.AnyAsync(c => c.Id == id && c.TenantId == tenantId, ct))
        {
            return NotFound();
        }
        await db.CaseAlerts.Where(ca => ca.CaseId == id && ca.AlertId == alertId).ExecuteDeleteAsync(ct);
        audit.Add(User, "case.alert_remove", id.ToString(), new { alert_id = alertId });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:long}/notes")]
    public async Task<ActionResult<CaseNoteResponse>> AddNote(
        long id,
        [FromBody] AddCaseNoteRequest req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Body))
        {
            return Problem(statusCode: 400, title: "body is required.");
        }
        var tenantId = User.GetTenantId();
        var caseRow = await db.Cases.FirstOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId, ct);
        if (caseRow is null) return NotFound();

        var note = new CaseNote
        {
            CaseId = caseRow.Id,
            AuthorUserId = TryGetUserId(),
            Body = req.Body.Trim(),
            CreatedAt = DateTimeOffset.UtcNow,
        };
        db.CaseNotes.Add(note);
        caseRow.UpdatedAt = note.CreatedAt;
        audit.Add(User, "case.note_add", caseRow.Id.ToString());
        await db.SaveChangesAsync(ct);
        return Ok(new CaseNoteResponse(note.Id, note.AuthorUserId, note.Body, note.CreatedAt));
    }

    private async Task<int> LinkAlertsAsync(
        long caseId, Guid tenantId, IReadOnlyList<long> alertIds, DateTimeOffset now, CancellationToken ct)
    {
        var validAlertIds = await db.Alerts
            .Where(a => alertIds.Contains(a.Id) && a.Agent!.TenantId == tenantId)
            .Select(a => a.Id)
            .ToListAsync(ct);
        var existing = await db.CaseAlerts
            .Where(ca => ca.CaseId == caseId && validAlertIds.Contains(ca.AlertId))
            .Select(ca => ca.AlertId)
            .ToListAsync(ct);
        var existingSet = new HashSet<long>(existing);
        var toAdd = validAlertIds.Where(id => !existingSet.Contains(id)).ToList();
        var added = toAdd.Select(alertId => new CaseAlert
        {
            CaseId = caseId,
            AlertId = alertId,
            AddedAt = now,
            AddedByUserId = TryGetUserId(),
        }).ToList();
        if (added.Count > 0) db.CaseAlerts.AddRange(added);
        return added.Count;
    }

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

    private Guid? TryGetUserId()
    {
        var raw = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
