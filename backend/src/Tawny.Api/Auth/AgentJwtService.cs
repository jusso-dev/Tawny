using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Tawny.Api.Auth;

public sealed class AgentJwtService(IOptions<AgentJwtOptions> options, IHostEnvironment env)
{
    public const string CredentialVersionClaim = "cv";

    private readonly AgentJwtOptions _opts = options.Value;
    private readonly Lazy<RsaSecurityKey> _signingKey = new(() =>
        LoadKey(options.Value, env.IsProduction() || options.Value.RequireConfiguredSigningKey));

    public (string Token, DateTimeOffset ExpiresAt, string Jti) Issue(
        Guid agentId,
        Guid tenantId,
        int credentialVersion)
    {
        var now = DateTimeOffset.UtcNow;
        var lifetime = TimeSpan.FromMinutes(Math.Clamp(_opts.LifetimeMinutes, 5, 24 * 60));
        var expires = now.Add(lifetime);
        var jti = Guid.NewGuid().ToString("N");

        var creds = new SigningCredentials(_signingKey.Value, SecurityAlgorithms.RsaSha256);
        var token = new JwtSecurityToken(
            issuer: _opts.Issuer,
            audience: _opts.Audience,
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, agentId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
                new Claim("agent_id", agentId.ToString()),
                new Claim(TenantClaimExtensions.TenantIdClaim, tenantId.ToString()),
                new Claim(CredentialVersionClaim, credentialVersion.ToString()),
            ],
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: creds);

        return (new JwtSecurityTokenHandler().WriteToken(token), expires, jti);
    }

    public bool ShouldRotate(DateTimeOffset? tokenExpiresAt)
    {
        if (tokenExpiresAt is null)
        {
            return true;
        }

        var rotateWithin = TimeSpan.FromMinutes(Math.Clamp(_opts.RotateWithinMinutes, 1, _opts.LifetimeMinutes));
        return tokenExpiresAt.Value <= DateTimeOffset.UtcNow.Add(rotateWithin);
    }

    public RsaSecurityKey GetValidationKey() => _signingKey.Value;

    private static RsaSecurityKey LoadKey(AgentJwtOptions opts, bool requireConfiguredKey)
    {
        var rsa = RSA.Create(2048);
        if (!string.IsNullOrWhiteSpace(opts.SigningKeyPem))
        {
            var pem = File.Exists(opts.SigningKeyPem)
                ? File.ReadAllText(opts.SigningKeyPem)
                : opts.SigningKeyPem;
            rsa.ImportFromPem(pem);
        }
        else if (requireConfiguredKey)
        {
            throw new InvalidOperationException(
                "Tawny:AgentJwt:SigningKeyPem must be configured with a stable RSA private key.");
        }

        return new RsaSecurityKey(rsa) { KeyId = "tawny-agent-key" };
    }
}
