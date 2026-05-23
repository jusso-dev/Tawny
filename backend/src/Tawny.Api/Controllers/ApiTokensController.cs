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
[Route("api/api-tokens")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
public class ApiTokensController(
    TawnyDbContext db,
    AuditLogger audit) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ApiTokenResponse>>> List(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var rows = await db.ApiTokens
            .AsNoTracking()
            .Where(t => t.TenantId == tenantId)
            .OrderByDescending(t => t.CreatedAt)
            .Select(t => new ApiTokenResponse(
                t.Id, t.Name, t.TokenPrefix, t.Role,
                t.CreatedAt, t.ExpiresAt, t.LastUsedAt, t.RevokedAt))
            .ToListAsync(ct);
        return Ok(rows);
    }

    [HttpPost]
    public async Task<ActionResult<CreatedApiTokenResponse>> Create(
        [FromBody] CreateApiTokenRequest req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Name) || req.Name.Length > 160)
        {
            return Problem(statusCode: 400, title: "name is required and must be 160 characters or fewer.");
        }

        var (token, prefix) = ApiTokenAuthHandler.Generate();
        var tenantId = User.GetTenantId();
        var record = new ApiToken
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            Name = req.Name.Trim(),
            TokenHash = ApiTokenAuthHandler.HashToken(token),
            TokenPrefix = prefix,
            Role = req.Role ?? UserRole.Viewer,
            CreatedByUserId = TryGetUserId(),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = req.ExpiresAt,
        };
        db.ApiTokens.Add(record);
        audit.Add(User, "api_token.create", record.Id.ToString(), new
        {
            record.Name, record.Role, record.ExpiresAt,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(List), new { id = record.Id },
            new CreatedApiTokenResponse(
                record.Id,
                record.Name,
                token,
                record.TokenPrefix,
                record.Role,
                record.CreatedAt,
                record.ExpiresAt));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Revoke(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var record = await db.ApiTokens.FirstOrDefaultAsync(t => t.Id == id && t.TenantId == tenantId, ct);
        if (record is null) return NotFound();
        if (record.RevokedAt is not null) return NoContent();

        record.RevokedAt = DateTimeOffset.UtcNow;
        audit.Add(User, "api_token.revoke", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private Guid? TryGetUserId()
    {
        var raw = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
