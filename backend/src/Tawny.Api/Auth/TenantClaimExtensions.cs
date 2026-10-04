using System.Security.Claims;

namespace Tawny.Api.Auth;

public static class TenantClaimExtensions
{
    public const string TenantIdClaim = "tenant_id";
    public const string TenantHeader = "X-Tenant-Id";

    /// <summary>
    /// Tenant of an authenticated principal. Every auth handler issues this claim, so a
    /// missing or malformed value is a bug; fail closed rather than fall back to a tenant.
    /// </summary>
    public static Guid GetTenantId(this ClaimsPrincipal user)
    {
        if (user.TryGetTenantId(out var tenantId)) return tenantId;
        throw new InvalidOperationException("Authenticated principal has no valid tenant_id claim.");
    }

    public static bool TryGetTenantId(this ClaimsPrincipal user, out Guid tenantId)
    {
        var value = user.FindFirst(TenantIdClaim)?.Value;
        return Guid.TryParse(value, out tenantId);
    }
}
