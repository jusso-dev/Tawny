using System.Security.Claims;
using FluentAssertions;
using Tawny.Api.Auth;
using Xunit;

namespace Tawny.Api.Tests;

public class TenantClaimExtensionsTests
{
    [Fact]
    public void GetTenantId_ReturnsClaimValue()
    {
        var tenant = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(TenantClaimExtensions.TenantIdClaim, tenant.ToString())], "test"));

        user.GetTenantId().Should().Be(tenant);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-guid")]
    public void GetTenantId_MissingOrInvalidClaim_FailsClosed(string? value)
    {
        var claims = value is null ? [] : new[] { new Claim(TenantClaimExtensions.TenantIdClaim, value) };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));

        var act = () => user.GetTenantId();

        act.Should().Throw<InvalidOperationException>();
    }
}
