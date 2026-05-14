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
    UrlEncoder encoder)
    : AuthenticationHandler<WebUserAuthOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var req = Request;
        if (!req.Headers.TryGetValue("X-User-Id", out var userId)
            || !req.Headers.TryGetValue("X-User-Role", out var role)
            || !req.Headers.TryGetValue("X-Timestamp", out var ts)
            || !req.Headers.TryGetValue("X-Signature", out var sig))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!long.TryParse(ts.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid X-Timestamp."));
        }

        var skew = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - unix);
        if (skew > Options.ToleranceSeconds)
        {
            return Task.FromResult(AuthenticateResult.Fail("Stale request signature."));
        }

        var hasTenantHeader = req.Headers.TryGetValue(TenantClaimExtensions.TenantHeader, out var tenantHeader);
        var tenantId = TenantDefaults.DefaultTenantId;
        if (hasTenantHeader && !Guid.TryParse(tenantHeader.ToString(), out tenantId))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid X-Tenant-Id."));
        }

        var canonicalParts = new List<string>
        {
            req.Method.ToUpperInvariant(),
            req.Path.Value ?? "",
            ts.ToString(),
            userId.ToString(),
            role.ToString(),
        };
        if (hasTenantHeader)
        {
            canonicalParts.Add(tenantId.ToString());
        }
        var canonical = string.Join('\n', canonicalParts);

        var expected = Convert.ToHexString(
            HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(Options.HmacSecret),
                Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();

        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expected),
                Encoding.ASCII.GetBytes(sig.ToString().ToLowerInvariant())))
        {
            return Task.FromResult(AuthenticateResult.Fail("Bad signature."));
        }

        var identity = new ClaimsIdentity(TawnyAuthSchemes.WebUser);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));
        identity.AddClaim(new Claim(TenantClaimExtensions.TenantIdClaim, tenantId.ToString()));
        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity), TawnyAuthSchemes.WebUser);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
