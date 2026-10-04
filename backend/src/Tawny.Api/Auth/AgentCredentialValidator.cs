using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Auth;

/// <summary>
/// Rejects agent JWTs whose agent is unknown, revoked, or whose credential version
/// no longer matches the agent record.
/// </summary>
public static class AgentCredentialValidator
{
    public static async Task ValidateAsync(TokenValidatedContext context)
    {
        var principal = context.Principal;
        if (principal is null
            || !Guid.TryParse(principal.FindFirst("agent_id")?.Value, out var agentId)
            || !principal.TryGetTenantId(out var tenantId)
            || !int.TryParse(principal.FindFirst(AgentJwtService.CredentialVersionClaim)?.Value, out var tokenCv))
        {
            context.Fail("agent token is missing required claims");
            return;
        }

        var db = context.HttpContext.RequestServices.GetRequiredService<TawnyDbContext>();
        var agent = await db.Agents.AsNoTracking()
            .Where(a => a.Id == agentId && a.TenantId == tenantId)
            .Select(a => new { a.RevokedAt, a.Status, a.CredentialVersion })
            .FirstOrDefaultAsync(context.HttpContext.RequestAborted);

        if (agent is null)
        {
            context.Fail("agent not found");
            return;
        }

        string? reason = null;
        if (agent.RevokedAt is not null || agent.Status == AgentStatus.Revoked)
        {
            reason = "revoked";
        }
        else if (agent.CredentialVersion != tokenCv)
        {
            reason = "credential_version_mismatch";
        }
        if (reason is null) return;

        var audit = context.HttpContext.RequestServices.GetRequiredService<AuditLogger>();
        audit.Add((Guid?)null, tenantId, "agent.auth_failed", agentId.ToString(), new
        {
            reason,
            token_cv = tokenCv,
            agent_cv = agent.CredentialVersion,
            path = context.HttpContext.Request.Path.Value,
        });
        await db.SaveChangesAsync(context.HttpContext.RequestAborted);
        context.Fail(reason);
    }
}
