using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

public class EnrollmentOptions
{
    public int TokenLifetimeHours { get; set; } = 24;
}

[ApiController]
[Route("api/enrollment-tokens")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
public class EnrollmentTokensController(
    TawnyDbContext db,
    AuditLogger audit,
    IOptions<EnrollmentOptions> options) : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<CreateEnrollmentTokenResponse>> Create(
        [FromBody] CreateEnrollmentTokenRequest req,
        CancellationToken ct)
    {
        var userIdRaw = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        Guid.TryParse(userIdRaw, out var userId);
        var tenantId = User.GetTenantId();

        var raw = TokenHashing.NewToken();
        var token = new EnrollmentToken
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            TokenHash = TokenHashing.Hash(raw),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(req.LifetimeHours ?? options.Value.TokenLifetimeHours),
            CreatedAt = DateTimeOffset.UtcNow,
            CreatedByUserId = userId,
        };
        db.EnrollmentTokens.Add(token);
        audit.Add(User, "enrollment_token.create", token.Id.ToString(), new
        {
            token.ExpiresAt,
            token.CreatedByUserId,
            token.TenantId,
            req.LifetimeHours,
        });
        await db.SaveChangesAsync(ct);

        return Ok(new CreateEnrollmentTokenResponse(token.Id, raw, token.ExpiresAt));
    }

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<EnrollmentTokenSummary>>> List(CancellationToken ct)
    {
        var rows = await db.EnrollmentTokens
            .Where(t => t.TenantId == User.GetTenantId())
            .OrderByDescending(t => t.CreatedAt)
            .Select(t => new EnrollmentTokenSummary(
                t.Id, t.ExpiresAt, t.CreatedAt, t.UsedAt, t.UsedByAgentId))
            .ToListAsync(ct);
        return Ok(rows);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Revoke(Guid id, CancellationToken ct)
    {
        var deleted = await db.EnrollmentTokens
            .Where(t => t.Id == id && t.TenantId == User.GetTenantId() && t.UsedAt == null)
            .ExecuteDeleteAsync(ct);
        if (deleted == 0)
        {
            return NotFound();
        }

        audit.Add(User, "enrollment_token.revoke", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }
}
