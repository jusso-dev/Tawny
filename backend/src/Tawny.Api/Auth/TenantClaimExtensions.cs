using System.Security.Claims;
using Tawny.Domain;

namespace Tawny.Api.Auth;

public static class TenantClaimExtensions
{
    public const string TenantIdClaim = "tenant_id";
    public const string TenantHeader = "X-Tenant-Id";

    public static Guid GetTenantId(this ClaimsPrincipal user)
    {
        var value = user.FindFirst(TenantIdClaim)?.Value;
        return Guid.TryParse(value, out var tenantId)
            ? tenantId
            : TenantDefaults.DefaultTenantId;
    }

    public static bool TryGetTenantId(this ClaimsPrincipal user, out Guid tenantId)
    {
        var value = user.FindFirst(TenantIdClaim)?.Value;
        return Guid.TryParse(value, out tenantId);
    }
}
