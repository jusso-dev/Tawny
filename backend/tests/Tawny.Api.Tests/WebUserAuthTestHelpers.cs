using System.Security.Cryptography;
using System.Text;

namespace Tawny.Api.Tests;

public static class WebUserAuthTestHelpers
{
    public static void AddWebUserSignature(
        this HttpRequestMessage req,
        string path,
        string userId = "admin-user",
        string role = "Admin",
        long? unix = null,
        string secret = TawnyWebApplicationFactory.HmacSecret)
    {
        var ts = (unix ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()).ToString();
        var canonical = string.Join('\n', req.Method.Method.ToUpperInvariant(), path, ts, userId, role);
        var sig = Convert.ToHexString(
            HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(secret),
                Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();

        req.Headers.Add("X-User-Id", userId);
        req.Headers.Add("X-User-Role", role);
        req.Headers.Add("X-Timestamp", ts);
        req.Headers.Add("X-Signature", sig);
    }
}
