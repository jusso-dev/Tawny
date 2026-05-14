using System.IdentityModel.Tokens.Jwt;
using FluentAssertions;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Tawny.Api.Auth;
using Xunit;

namespace Tawny.Api.Tests;

public class AgentJwtServiceTests
{
    [Fact]
    public void IssuedToken_ValidatesWithServiceValidationKey()
    {
        var service = new AgentJwtService(
            Options.Create(new AgentJwtOptions()),
            new TestHostEnvironment());
        var agentId = Guid.NewGuid();

        var (token, expiresAt) = service.Issue(agentId);
        var principal = new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "tawny",
            ValidateAudience = true,
            ValidAudience = "tawny-agents",
            ValidateLifetime = true,
            IssuerSigningKey = service.GetValidationKey(),
            ValidateIssuerSigningKey = true,
        }, out _);

        principal.FindFirst("agent_id")!.Value.Should().Be(agentId.ToString());
        expiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Tawny.Api.Tests";
        public string ContentRootPath { get; set; } = Directory.GetCurrentDirectory();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
