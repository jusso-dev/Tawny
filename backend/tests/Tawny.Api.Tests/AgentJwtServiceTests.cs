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
            Options.Create(new AgentJwtOptions { LifetimeMinutes = 30 }),
            new TestHostEnvironment());
        var agentId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var (token, expiresAt, jti) = service.Issue(agentId, tenantId, credentialVersion: 3);
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
        principal.FindFirst(TenantClaimExtensions.TenantIdClaim)!.Value.Should().Be(tenantId.ToString());
        principal.FindFirst(AgentJwtService.CredentialVersionClaim)!.Value.Should().Be("3");
        principal.FindFirst(JwtRegisteredClaimNames.Jti)!.Value.Should().Be(jti);
        expiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
        expiresAt.Should().BeBefore(DateTimeOffset.UtcNow.AddHours(1));
    }

    [Fact]
    public void ShouldRotate_WhenNearExpiry()
    {
        var service = new AgentJwtService(
            Options.Create(new AgentJwtOptions { LifetimeMinutes = 60, RotateWithinMinutes = 15 }),
            new TestHostEnvironment());

        service.ShouldRotate(DateTimeOffset.UtcNow.AddMinutes(5)).Should().BeTrue();
        service.ShouldRotate(DateTimeOffset.UtcNow.AddMinutes(45)).Should().BeFalse();
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Tawny.Api.Tests";
        public string ContentRootPath { get; set; } = Directory.GetCurrentDirectory();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
