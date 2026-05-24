using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.Hunting;

namespace Tawny.Api.Controllers;

public record CreateYaraRuleRequest(
    string Name,
    string? Description,
    AlertSeverity Severity,
    TelemetryEventType? EventType,
    string Definition,
    bool? IsEnabled);

public record YaraRuleResponse(
    Guid Id,
    string Name,
    string? Description,
    AlertSeverity Severity,
    TelemetryEventType? EventType,
    string Definition,
    bool IsEnabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

[ApiController]
[Route("api/yara-rules")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class YaraRulesController(TawnyDbContext db, AuditLogger audit) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<YaraRuleResponse>>> List(CancellationToken ct)
    {
        var rows = await db.AlertRules
            .AsNoTracking()
            .Where(r => r.Format == AlertRuleFormat.Yara)
            .OrderBy(r => r.Name)
            .Select(r => new YaraRuleResponse(
                r.Id, r.Name, r.Description, r.Severity, r.EventType,
                r.SourceDefinition ?? "", r.IsEnabled, r.CreatedAt, r.UpdatedAt))
            .ToListAsync(ct);
        return Ok(rows);
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<YaraRuleResponse>> Create(
        [FromBody] CreateYaraRuleRequest req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Name) || req.Name.Length > 160)
        {
            return Problem(statusCode: 400, title: "name is required and must be 160 characters or fewer.");
        }
        try { YaraLiteParser.Parse(req.Definition); }
        catch (YaraLiteException ex)
        {
            return Problem(statusCode: 400, title: ex.Message);
        }

        var now = DateTimeOffset.UtcNow;
        var rule = new AlertRule
        {
            Id = Guid.NewGuid(),
            Name = req.Name.Trim(),
            Format = AlertRuleFormat.Yara,
            Description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description.Trim(),
            EventType = req.EventType,
            Severity = req.Severity,
            Operator = AlertRuleOperator.Exists,
            SourceDefinition = req.Definition.Trim(),
            IsEnabled = req.IsEnabled ?? true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.AlertRules.Add(rule);
        audit.Add(User, "yara_rule.create", rule.Id.ToString(), new { rule.Name });
        await db.SaveChangesAsync(ct);
        return CreatedAtAction(nameof(List), new { id = rule.Id },
            new YaraRuleResponse(rule.Id, rule.Name, rule.Description, rule.Severity, rule.EventType,
                rule.SourceDefinition!, rule.IsEnabled, rule.CreatedAt, rule.UpdatedAt));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        if (await db.Alerts.AnyAsync(a => a.AlertRuleId == id, ct))
        {
            return Problem(statusCode: 409, title: "Rule has alerts; disable it instead.");
        }
        var deleted = await db.AlertRules
            .Where(r => r.Id == id && r.Format == AlertRuleFormat.Yara)
            .ExecuteDeleteAsync(ct);
        if (deleted == 0) return NotFound();
        audit.Add(User, "yara_rule.delete", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}
