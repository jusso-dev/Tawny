using System.Security.Cryptography;
using System.Text;
using Tawny.Api.Auth;
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
        string secret = TawnyWebApplicationFactory.HmacSecret,
        string? nonce = null,
        string? bodyOverride = null)
    {
        var ts = (unix ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()).ToString();
        var resolvedTenantId = tenantId ?? TenantDefaults.DefaultTenantId;
        var nonceValue = nonce ?? Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

        byte[] bodyBytes;
        if (bodyOverride is not null)
        {
            bodyBytes = Encoding.UTF8.GetBytes(bodyOverride);
        }
        else if (req.Content is not null)
        {
            bodyBytes = req.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            // Re-attach content so the server can read it again.
            var contentType = req.Content.Headers.ContentType?.MediaType ?? "application/json";
            req.Content = new ByteArrayContent(bodyBytes);
            req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);
        }
        else
        {
            bodyBytes = [];
        }

        var contentTypeHeader = req.Content?.Headers.ContentType?.MediaType ?? "";
        var pathOnly = WebUserCanonical.PathOnly(path);
        var query = WebUserCanonical.CanonicalQueryFromRaw(path);
        var bodyHash = WebUserCanonical.HashBody(bodyBytes);
        var canonical = WebUserCanonical.Build(
            req.Method.Method,
            pathOnly,
            query,
            bodyHash,
            contentTypeHeader,
            userId,
            role,
            resolvedTenantId.ToString(),
            ts,
            nonceValue);
        var sig = WebUserCanonical.Sign(secret, canonical);

        req.Headers.Remove("X-User-Id");
        req.Headers.Remove("X-User-Role");
        req.Headers.Remove("X-Tenant-Id");
        req.Headers.Remove("X-Timestamp");
        req.Headers.Remove("X-Nonce");
        req.Headers.Remove("X-Signature");

        req.Headers.Add("X-User-Id", userId);
        req.Headers.Add("X-User-Role", role);
        req.Headers.Add("X-Tenant-Id", resolvedTenantId.ToString());
        req.Headers.Add("X-Timestamp", ts);
        req.Headers.Add("X-Nonce", nonceValue);
        req.Headers.Add("X-Signature", sig);
    }
}
