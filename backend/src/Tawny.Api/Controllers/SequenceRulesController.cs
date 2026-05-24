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
[Route("api/sequence-rules")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class SequenceRulesController(
    TawnyDbContext db,
    AuditLogger audit,
    SequenceRuleEvaluator sequences) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<SequenceRuleResponse>>> List(CancellationToken ct)
    {
        var rows = await db.AlertRules
            .AsNoTracking()
            .Where(r => r.Format == AlertRuleFormat.Sequence)
            .OrderBy(r => r.Name)
            .ToListAsync(ct);
        return Ok(rows.Select(ToResponse).ToList());
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<SequenceRuleResponse>> Create(
        [FromBody] CreateSequenceRuleRequest req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Name) || req.Name.Length > 160)
        {
            return Problem(statusCode: 400, title: "name is required and must be 160 characters or fewer.");
        }
        if (req.Steps is null || req.Steps.Count < 2)
        {
            return Problem(statusCode: 400, title: "A sequence rule needs at least two steps.");
        }
        if (req.WindowSeconds <= 0 || req.WindowSeconds > 86_400)
        {
            return Problem(statusCode: 400, title: "window_seconds must be between 1 and 86400.");
        }

        var definition = new SequenceRuleDefinition(
            req.WindowSeconds,
            "agent",
            req.Steps.Select(s => new SequenceStep(s.Name, s.EventType, s.PayloadPath, s.Operator, s.MatchValue)).ToList());

        try { SequenceRuleParser.Parse(SequenceRuleParser.Serialize(definition)); }
        catch (SequenceRuleException ex)
        {
            return Problem(statusCode: 400, title: ex.Message);
        }

        var now = DateTimeOffset.UtcNow;
        var rule = new AlertRule
        {
            Id = Guid.NewGuid(),
            Name = req.Name.Trim(),
            Format = AlertRuleFormat.Sequence,
            Description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description.Trim(),
            Severity = req.Severity,
            Operator = AlertRuleOperator.Exists,
            SourceDefinition = SequenceRuleParser.Serialize(definition),
            IsEnabled = req.IsEnabled ?? true,
            MitreTechniquesJson = SerializeTechniques(req.MitreTechniques),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.AlertRules.Add(rule);
        audit.Add(User, "sequence_rule.create", rule.Id.ToString(), new
        {
            rule.Name,
            step_count = req.Steps.Count,
            req.WindowSeconds,
        });
        await db.SaveChangesAsync(ct);
        sequences.ResetAll(); // wipe in-memory partial state so new rule starts cleanly
        return CreatedAtAction(nameof(List), new { id = rule.Id }, ToResponse(rule));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        if (await db.Alerts.AnyAsync(a => a.AlertRuleId == id, ct))
        {
            return Problem(statusCode: 409, title: "Sequence rule has alerts and cannot be deleted. Disable it instead.");
        }
        var deleted = await db.AlertRules
            .Where(r => r.Id == id && r.Format == AlertRuleFormat.Sequence)
            .ExecuteDeleteAsync(ct);
        if (deleted == 0) return NotFound();
        audit.Add(User, "sequence_rule.delete", id.ToString());
        await db.SaveChangesAsync(ct);
        sequences.ResetAll();
        return NoContent();
    }

    private static SequenceRuleResponse ToResponse(AlertRule rule)
    {
        SequenceRuleDefinition definition;
        try { definition = SequenceRuleParser.Parse(rule.SourceDefinition ?? ""); }
        catch
        {
            return new SequenceRuleResponse(
                rule.Id, rule.Name, rule.Description, rule.Severity, 0, [], [], rule.IsEnabled, rule.CreatedAt, rule.UpdatedAt);
        }
        return new SequenceRuleResponse(
            rule.Id,
            rule.Name,
            rule.Description,
            rule.Severity,
            definition.WindowSeconds,
            definition.Steps.Select(s => new SequenceStepInput(s.Name, s.EventType, s.PayloadPath, s.Operator, s.MatchValue)).ToList(),
            DeserializeTechniques(rule.MitreTechniquesJson),
            rule.IsEnabled,
            rule.CreatedAt,
            rule.UpdatedAt);
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
}
