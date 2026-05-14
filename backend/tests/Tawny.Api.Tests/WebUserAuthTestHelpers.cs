using System.Security.Cryptography;
using System.Text;
using Tawny.Domain;

namespace Tawny.Api.Tests;

public static class WebUserAuthTestHelpers
{
    public static void AddWebUserSignature(
        this HttpRequestMessage req,
        string path,
        string userId = "admin-user",
        string role = "Admin",
        Guid? tenantId = null,
        long? unix = null,
        string secret = TawnyWebApplicationFactory.HmacSecret)
    {
        var ts = (unix ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()).ToString();
        var resolvedTenantId = tenantId ?? TenantDefaults.DefaultTenantId;
        var canonical = string.Join('\n',
            req.Method.Method.ToUpperInvariant(),
            path,
            ts,
            userId,
            role,
            resolvedTenantId.ToString());
        var sig = Convert.ToHexString(
            HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(secret),
                Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();

        req.Headers.Add("X-User-Id", userId);
        req.Headers.Add("X-User-Role", role);
        req.Headers.Add("X-Tenant-Id", resolvedTenantId.ToString());
        req.Headers.Add("X-Timestamp", ts);
        req.Headers.Add("X-Signature", sig);
    }
}
