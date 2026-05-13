using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Tawny.Api.Auth;

public sealed class AgentJwtService(IOptions<AgentJwtOptions> options)
{
    private readonly AgentJwtOptions _opts = options.Value;
    private readonly Lazy<RsaSecurityKey> _signingKey = new(() => LoadKey(options.Value));

    public (string Token, DateTimeOffset ExpiresAt) Issue(Guid agentId)
    {
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddDays(_opts.LifetimeDays);

        var creds = new SigningCredentials(_signingKey.Value, SecurityAlgorithms.RsaSha256);
        var token = new JwtSecurityToken(
            issuer: _opts.Issuer,
            audience: _opts.Audience,
            claims: [
                new Claim(JwtRegisteredClaimNames.Sub, agentId.ToString()),
                new Claim("agent_id", agentId.ToString()),
            ],
            notBefore: now.UtcDateTime,
            expires: expires.UtcDateTime,
            signingCredentials: creds);

        return (new JwtSecurityTokenHandler().WriteToken(token), expires);
    }

    public RsaSecurityKey GetValidationKey() => _signingKey.Value;

    private static RsaSecurityKey LoadKey(AgentJwtOptions opts)
    {
        var rsa = RSA.Create(2048);
        if (!string.IsNullOrWhiteSpace(opts.SigningKeyPem))
        {
            var pem = File.Exists(opts.SigningKeyPem)
                ? File.ReadAllText(opts.SigningKeyPem)
                : opts.SigningKeyPem;
            rsa.ImportFromPem(pem);
        }
        return new RsaSecurityKey(rsa) { KeyId = "tawny-agent-key" };
    }
}
