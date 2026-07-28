using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Domain;

namespace Tawny.Api.Auth;

public class WebUserAuthOptions : AuthenticationSchemeOptions
{
    public string HmacSecret { get; set; } = "";
    public int ToleranceSeconds { get; set; } = 30;
}

public class WebUserAuthHandler(
    IOptionsMonitor<WebUserAuthOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IWebUserNonceStore nonceStore)
    : AuthenticationHandler<WebUserAuthOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var req = Request;
        if (!req.Headers.TryGetValue("X-User-Id", out var userId)
            || !req.Headers.TryGetValue("X-User-Role", out var role)
            || !req.Headers.TryGetValue("X-Timestamp", out var ts)
            || !req.Headers.TryGetValue("X-Nonce", out var nonce)
            || !req.Headers.TryGetValue("X-Signature", out var sig))
        {
            return AuthenticateResult.NoResult();
        }

        if (string.IsNullOrWhiteSpace(Options.HmacSecret))
        {
            return AuthenticateResult.Fail("Web user HMAC secret is not configured.");
        }

        if (!long.TryParse(ts.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix))
        {
            return AuthenticateResult.Fail("Invalid X-Timestamp.");
        }

        var skew = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - unix);
        if (skew > Options.ToleranceSeconds)
        {
            return AuthenticateResult.Fail("Stale request signature.");
        }

        var nonceValue = nonce.ToString();
        if (!nonceStore.TryAccept(nonceValue, TimeSpan.FromSeconds(Options.ToleranceSeconds * 2)))
        {
            return AuthenticateResult.Fail("Replayed or invalid nonce.");
        }

        if (!req.Headers.TryGetValue(TenantClaimExtensions.TenantHeader, out var tenantHeader)
            || !Guid.TryParse(tenantHeader.ToString(), out var tenantId))
        {
            return AuthenticateResult.Fail("Invalid or missing X-Tenant-Id.");
        }

        req.EnableBuffering();
        string bodyHash;
        try
        {
            if (req.Body.CanSeek)
            {
                req.Body.Position = 0;
            }

            using var ms = new MemoryStream();
            await req.Body.CopyToAsync(ms);
            bodyHash = WebUserCanonical.HashBody(ms.ToArray());
            if (req.Body.CanSeek)
            {
                req.Body.Position = 0;
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Failed to hash request body for web user auth");
            return AuthenticateResult.Fail("Unable to read request body for signature verification.");
        }

        var contentType = req.ContentType ?? "";
        // Sign only the media type portion (strip charset).
        var semi = contentType.IndexOf(';', StringComparison.Ordinal);
        if (semi >= 0)
        {
            contentType = contentType[..semi].Trim();
        }

        var path = req.Path.Value ?? "";
        var canonicalQuery = WebUserCanonical.CanonicalQuery(req.Query);
        var canonical = WebUserCanonical.Build(
            req.Method,
            path,
            canonicalQuery,
            bodyHash,
            contentType,
            userId.ToString(),
            role.ToString(),
            tenantId.ToString(),
            ts.ToString(),
            nonceValue);

        var expected = WebUserCanonical.Sign(Options.HmacSecret, canonical);
        var provided = sig.ToString().Trim().ToLowerInvariant();
        var expectedBytes = Encoding.ASCII.GetBytes(expected);
        var providedBytes = Encoding.ASCII.GetBytes(provided);
        if (expectedBytes.Length != providedBytes.Length
            || !CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes))
        {
            return AuthenticateResult.Fail("Bad signature.");
        }

        var identity = new ClaimsIdentity(TawnyAuthSchemes.WebUser);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));
        identity.AddClaim(new Claim(TenantClaimExtensions.TenantIdClaim, tenantId.ToString()));
        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity), TawnyAuthSchemes.WebUser);

        return AuthenticateResult.Success(ticket);
    }
}
