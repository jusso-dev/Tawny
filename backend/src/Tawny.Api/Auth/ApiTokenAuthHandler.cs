using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Auth;

public class ApiTokenAuthOptions : AuthenticationSchemeOptions
{
}

public class ApiTokenAuthHandler(
    IOptionsMonitor<ApiTokenAuthOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    TawnyDbContext db)
    : AuthenticationHandler<ApiTokenAuthOptions>(options, logger, encoder)
{
    public const string TokenPrefix = "twny_";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            return AuthenticateResult.NoResult();
        }

        var raw = authHeader.ToString();
        if (string.IsNullOrEmpty(raw) || !raw.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var token = raw["Bearer ".Length..].Trim();
        if (!token.StartsWith(TokenPrefix, StringComparison.Ordinal))
        {
            // Not one of our API tokens — let the JWT scheme handle it.
            return AuthenticateResult.NoResult();
        }

        var hash = HashToken(token);
        var record = await db.ApiTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash);

        if (record is null || record.RevokedAt is not null)
        {
            return AuthenticateResult.Fail("Unknown or revoked API token.");
        }

        if (record.ExpiresAt is not null && record.ExpiresAt.Value <= DateTimeOffset.UtcNow)
        {
            return AuthenticateResult.Fail("API token expired.");
        }

        record.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();

        var identity = new ClaimsIdentity(TawnyAuthSchemes.ApiToken);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, record.CreatedByUserId?.ToString() ?? Guid.Empty.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Role, record.Role.ToString()));
        identity.AddClaim(new Claim(TenantClaimExtensions.TenantIdClaim, record.TenantId.ToString()));
        identity.AddClaim(new Claim("api_token_id", record.Id.ToString()));

        return AuthenticateResult.Success(new AuthenticationTicket(
            new ClaimsPrincipal(identity), TawnyAuthSchemes.ApiToken));
    }

    public static string HashToken(string token)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
    }

    public static (string Token, string Prefix) Generate()
    {
        // 32 random bytes, base64url-encoded — enough entropy to resist guessing.
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        var secret = Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
        var token = $"{TokenPrefix}{secret}";
        return (token, token[..12]);
    }
}
