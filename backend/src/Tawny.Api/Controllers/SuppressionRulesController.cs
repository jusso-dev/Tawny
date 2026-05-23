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
[Route("api/suppression-rules")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class SuppressionRulesController(
    TawnyDbContext db,
    AuditLogger audit) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<SuppressionRuleResponse>>> List(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var rows = await db.SuppressionRules
            .AsNoTracking()
            .Where(s => s.TenantId == tenantId)
            .OrderByDescending(s => s.CreatedAt)
            .Select(s => new
            {
                s.Id, s.Name, s.Reason, s.Scope, s.AlertRuleId,
                AlertRuleName = s.AlertRule != null ? s.AlertRule.Name : null,
                s.AgentId,
                AgentHostname = s.Agent != null ? s.Agent.Hostname : null,
                s.PayloadPath, s.Operator, s.MatchValue, s.IsEnabled,
                s.ExpiresAt, s.SuppressedCount, s.LastSuppressedAt,
                s.CreatedAt, s.UpdatedAt,
            })
            .ToListAsync(ct);
        return Ok(rows.Select(r => new SuppressionRuleResponse(
            r.Id, r.Name, r.Reason, r.Scope, r.AlertRuleId, r.AlertRuleName,
            r.AgentId, r.AgentHostname, r.PayloadPath, r.Operator, r.MatchValue,
            r.IsEnabled, r.ExpiresAt, r.SuppressedCount, r.LastSuppressedAt,
            r.CreatedAt, r.UpdatedAt)).ToList());
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<SuppressionRuleResponse>> Create(
        [FromBody] CreateSuppressionRuleRequest req,
        CancellationToken ct)
    {
        var validation = Validate(req.Name, req.Scope, req.AlertRuleId, req.Operator, req.MatchValue);
        if (validation is not null) return validation;

        var tenantId = User.GetTenantId();
        var now = DateTimeOffset.UtcNow;
        var rule = new SuppressionRule
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            Name = req.Name.Trim(),
            Reason = string.IsNullOrWhiteSpace(req.Reason) ? null : req.Reason.Trim(),
            Scope = req.Scope,
            AlertRuleId = req.Scope == SuppressionScope.SpecificRule ? req.AlertRuleId : null,
            AgentId = req.AgentId,
            PayloadPath = Normalize(req.PayloadPath),
            Operator = req.Operator,
            MatchValue = Normalize(req.MatchValue),
            IsEnabled = req.IsEnabled ?? true,
            ExpiresAt = req.ExpiresAt,
            CreatedByUserId = TryGetUserId(),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.SuppressionRules.Add(rule);
        audit.Add(User, "suppression_rule.create", rule.Id.ToString(), new
        {
            rule.Name, rule.Scope, rule.AlertRuleId, rule.AgentId, rule.IsEnabled,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(List), new { id = rule.Id }, await BuildResponse(rule.Id, ct));
    }

    [HttpPut("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<SuppressionRuleResponse>> Update(
        Guid id,
        [FromBody] UpdateSuppressionRuleRequest req,
        CancellationToken ct)
    {
        var validation = Validate(req.Name, req.Scope, req.AlertRuleId, req.Operator, req.MatchValue);
        if (validation is not null) return validation;

        var tenantId = User.GetTenantId();
        var rule = await db.SuppressionRules.FirstOrDefaultAsync(s => s.Id == id && s.TenantId == tenantId, ct);
        if (rule is null) return NotFound();

        rule.Name = req.Name.Trim();
        rule.Reason = string.IsNullOrWhiteSpace(req.Reason) ? null : req.Reason.Trim();
        rule.Scope = req.Scope;
        rule.AlertRuleId = req.Scope == SuppressionScope.SpecificRule ? req.AlertRuleId : null;
        rule.AgentId = req.AgentId;
        rule.PayloadPath = Normalize(req.PayloadPath);
        rule.Operator = req.Operator;
        rule.MatchValue = Normalize(req.MatchValue);
        rule.IsEnabled = req.IsEnabled;
        rule.ExpiresAt = req.ExpiresAt;
        rule.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Add(User, "suppression_rule.update", rule.Id.ToString(), new
        {
            rule.Name, rule.Scope, rule.IsEnabled,
        });
        await db.SaveChangesAsync(ct);
        return Ok(await BuildResponse(rule.Id, ct));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var deleted = await db.SuppressionRules
            .Where(s => s.Id == id && s.TenantId == tenantId)
            .ExecuteDeleteAsync(ct);
        if (deleted == 0) return NotFound();
        audit.Add(User, "suppression_rule.delete", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private ActionResult<SuppressionRuleResponse>? Validate(
        string name,
        SuppressionScope scope,
        Guid? alertRuleId,
        AlertRuleOperator op,
        string? matchValue)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 160)
        {
            return Problem(statusCode: 400, title: "name is required and must be 160 characters or fewer.");
        }
        if (scope == SuppressionScope.SpecificRule && alertRuleId is null)
        {
            return Problem(statusCode: 400, title: "alert_rule_id is required when scope is specific_rule.");
        }
        if (op != AlertRuleOperator.Exists && string.IsNullOrWhiteSpace(matchValue))
        {
            return Problem(statusCode: 400, title: "match_value is required unless the operator is exists.");
        }
        return null;
    }

    private async Task<SuppressionRuleResponse> BuildResponse(Guid id, CancellationToken ct)
    {
        var r = await db.SuppressionRules
            .Include(s => s.AlertRule)
            .Include(s => s.Agent)
            .FirstAsync(s => s.Id == id, ct);
        return new SuppressionRuleResponse(
            r.Id, r.Name, r.Reason, r.Scope, r.AlertRuleId, r.AlertRule?.Name,
            r.AgentId, r.Agent?.Hostname, r.PayloadPath, r.Operator, r.MatchValue,
            r.IsEnabled, r.ExpiresAt, r.SuppressedCount, r.LastSuppressedAt,
            r.CreatedAt, r.UpdatedAt);
    }

    private static string? Normalize(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }

    private Guid? TryGetUserId()
    {
        var raw = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
