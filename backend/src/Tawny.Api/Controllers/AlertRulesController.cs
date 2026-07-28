using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/alert-rules")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
[EnableRateLimiting("web-read")]
public class AlertRulesController(
    TawnyDbContext db,
    AuditLogger audit,
    SigmaRuleImporter sigma,
    IocRuleImporter iocs,
    ExposureRuleImporter exposures) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<AlertRuleResponse>>> List(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var rows = await db.AlertRules
            .AsNoTracking()
            .Where(r => r.TenantId == tenantId)
            .OrderBy(r => r.Name)
            .ToListAsync(ct);
        return Ok(rows.Select(ToResponse).ToList());
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
    public async Task<ActionResult<AlertRuleResponse>> Create(CreateAlertRuleRequest req, CancellationToken ct)
    {
        var validation = ValidateRule(req.Name, req.Operator, req.PayloadPath, req.MatchValue);
        if (validation is not null)
        {
            return validation;
        }

        var now = DateTimeOffset.UtcNow;
        var rule = new AlertRule
        {
            Id = Guid.NewGuid(),
            TenantId = User.GetTenantId(),
            Name = req.Name.Trim(),
            Format = AlertRuleFormat.TawnyPredicate,
            EventType = req.EventType,
            Severity = req.Severity,
            Operator = req.Operator,
            PayloadPath = Normalize(req.PayloadPath),
            MatchValue = Normalize(req.MatchValue),
            IsEnabled = req.IsEnabled ?? true,
            MitreTechniquesJson = SerializeTechniques(req.MitreTechniques),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.AlertRules.Add(rule);
        audit.Add(User, "alert_rule.create", rule.Id.ToString(), new
        {
            rule.Name,
            rule.EventType,
            rule.Severity,
            rule.Operator,
            rule.PayloadPath,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(List), new { id = rule.Id }, ToResponse(rule));
    }

    [HttpPost("sigma")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
    public async Task<ActionResult<AlertRuleResponse>> ImportSigma(
        ImportSigmaRuleRequest req,
        CancellationToken ct)
    {
        AlertRule rule;
        try
        {
            rule = sigma.Import(req.RuleYaml, req.IsEnabled ?? true, DateTimeOffset.UtcNow);
        }
        catch (SigmaRuleException ex)
        {
            return Problem(statusCode: 400, title: ex.Message);
        }

        rule.TenantId = User.GetTenantId();
        db.AlertRules.Add(rule);
        audit.Add(User, "alert_rule.import_sigma", rule.Id.ToString(), new
        {
            rule.Name,
            rule.ExternalId,
            rule.EventType,
            rule.Severity,
            rule.PayloadPath,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(List), new { id = rule.Id }, ToResponse(rule));
    }

    [HttpPost("iocs")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
    public async Task<ActionResult<ImportIocRulesResponse>> ImportIocs(
        ImportIocRulesRequest req,
        CancellationToken ct)
    {
        IocImportResult imported;
        try
        {
            imported = iocs.Import(
                req.Definition,
                req.SourceFormat,
                req.Severity ?? AlertSeverity.High,
                req.IsEnabled ?? true,
                DateTimeOffset.UtcNow);
        }
        catch (IocRuleException ex)
        {
            return Problem(statusCode: 400, title: ex.Message);
        }

        var tenantId = User.GetTenantId();
        foreach (var r in imported.Rules) r.TenantId = tenantId;
        db.AlertRules.AddRange(imported.Rules);
        audit.Add(User, "alert_rule.import_iocs", null, new
        {
            Count = imported.Rules.Count,
            SourceFormat = req.SourceFormat,
            Severity = req.Severity ?? AlertSeverity.High,
            SkippedCount = imported.SkippedIndicators.Count,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(
            nameof(List),
            new { count = imported.Rules.Count },
            new ImportIocRulesResponse(imported.Rules.Select(ToResponse).ToList(), imported.SkippedIndicators));
    }

    [HttpPost("exposures")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
    public async Task<ActionResult<ImportExposureRulesResponse>> ImportExposures(
        ImportExposureRulesRequest req,
        CancellationToken ct)
    {
        ExposureImportResult imported;
        try
        {
            imported = exposures.Import(
                req.Definition,
                req.Severity ?? AlertSeverity.High,
                req.IsEnabled ?? true,
                DateTimeOffset.UtcNow);
        }
        catch (ExposureRuleException ex)
        {
            return Problem(statusCode: 400, title: ex.Message);
        }

        var exposureTenantId = User.GetTenantId();
        foreach (var r in imported.Rules) r.TenantId = exposureTenantId;
        db.AlertRules.AddRange(imported.Rules);
        audit.Add(User, "alert_rule.import_exposures", null, new
        {
            Count = imported.Rules.Count,
            Severity = req.Severity ?? AlertSeverity.High,
            SkippedCount = imported.SkippedEntries.Count,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(
            nameof(List),
            new { count = imported.Rules.Count },
            new ImportExposureRulesResponse(imported.Rules.Select(ToResponse).ToList(), imported.SkippedEntries));
    }

    [HttpPut("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
    public async Task<ActionResult<AlertRuleResponse>> Update(Guid id, UpdateAlertRuleRequest req, CancellationToken ct)
    {
        var validation = ValidateRule(req.Name, req.Operator, req.PayloadPath, req.MatchValue);
        if (validation is not null)
        {
            return validation;
        }

        var tenantId = User.GetTenantId();
        var rule = await db.AlertRules.FirstOrDefaultAsync(r => r.Id == id && r.TenantId == tenantId, ct);
        if (rule is null)
        {
            return NotFound();
        }

        rule.Name = req.Name.Trim();
        rule.Format = AlertRuleFormat.TawnyPredicate;
        rule.ExternalId = null;
        rule.Description = null;
        rule.EventType = req.EventType;
        rule.Severity = req.Severity;
        rule.Operator = req.Operator;
        rule.PayloadPath = Normalize(req.PayloadPath);
        rule.MatchValue = Normalize(req.MatchValue);
        rule.SourceDefinition = null;
        rule.CompiledExpressionJson = null;
        rule.IsEnabled = req.IsEnabled;
        rule.MitreTechniquesJson = SerializeTechniques(req.MitreTechniques);
        rule.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Add(User, "alert_rule.update", rule.Id.ToString(), new
        {
            rule.Name,
            rule.EventType,
            rule.Severity,
            rule.Operator,
            rule.PayloadPath,
            rule.IsEnabled,
        });
        await db.SaveChangesAsync(ct);

        return Ok(ToResponse(rule));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        if (await db.Alerts.AnyAsync(a => a.AlertRuleId == id && a.TenantId == tenantId, ct))
        {
            return Problem(statusCode: 409, title: "Alert rule has alerts and cannot be deleted. Disable it instead.");
        }

        var rule = await db.AlertRules.FirstOrDefaultAsync(r => r.Id == id && r.TenantId == tenantId, ct);
        if (rule is null)
        {
            return NotFound();
        }

        db.AlertRules.Remove(rule);
        audit.Add(User, "alert_rule.delete", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private static AlertRuleResponse ToResponse(AlertRule r) => new(
        r.Id,
        r.Name,
        r.Format,
        r.ExternalId,
        r.Description,
        r.EventType,
        r.Severity,
        r.Operator,
        r.PayloadPath,
        r.MatchValue,
        r.SourceDefinition,
        r.IsEnabled,
        DeserializeTechniques(r.MitreTechniquesJson),
        r.CreatedAt,
        r.UpdatedAt);

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

    private ActionResult<AlertRuleResponse>? ValidateRule(
        string name,
        AlertRuleOperator op,
        string? payloadPath,
        string? matchValue)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 160)
        {
            return Problem(statusCode: 400, title: "Rule name is required and must be 160 characters or fewer.");
        }

        if (op != AlertRuleOperator.Exists && string.IsNullOrWhiteSpace(matchValue))
        {
            return Problem(statusCode: 400, title: "match_value is required unless the operator is exists.");
        }

        if (!string.IsNullOrWhiteSpace(payloadPath) && payloadPath.Length > 256)
        {
            return Problem(statusCode: 400, title: "payload_path must be 256 characters or fewer.");
        }

        return null;
    }

    private static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }
}
