using System.Security.Claims;
using System.Text.Json;
using Tawny.Api.Auth;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Api.Services;

public class AuditLogger(TawnyDbContext db)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public void Add(ClaimsPrincipal user, string action, string? target = null, object? metadata = null)
    {
        var userIdRaw = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        Guid? userId = Guid.TryParse(userIdRaw, out var parsed) ? parsed : null;
        Add(userId, user.GetTenantId(), action, target, metadata);
    }

    public void Add(Guid? userId, string action, string? target = null, object? metadata = null)
        => Add(userId, TenantDefaults.DefaultTenantId, action, target, metadata);

    public void Add(Guid? userId, Guid tenantId, string action, string? target = null, object? metadata = null)
    {
        db.AuditLog.Add(new AuditLog
        {
            TenantId = tenantId,
            UserId = userId,
            Action = action,
            Target = target,
            MetadataJson = metadata is null ? null : JsonSerializer.Serialize(metadata, JsonOptions),
            OccurredAt = DateTimeOffset.UtcNow,
        });
    }
}
