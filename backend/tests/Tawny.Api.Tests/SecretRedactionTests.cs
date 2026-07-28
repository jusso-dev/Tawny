using FluentAssertions;
using Tawny.Api.Logging;
using Xunit;

namespace Tawny.Api.Tests;

public class SecretRedactionTests
{
    [Theory]
    [InlineData("password")]
    [InlineData("Authorization")]
    [InlineData("TAWNY_WEB_HMAC_SECRET")]
    [InlineData("client_secret")]
    [InlineData("X-Signature")]
    public void SensitiveNames_AreDetected(string name)
    {
        SecretRedactingEnricher.IsSensitiveName(name).Should().BeTrue();
    }

    [Fact]
    public void LooksLikeSecret_DetectsJwtAndBearer()
    {
        SecretRedactingEnricher.LooksLikeSecret("Bearer abcdefghijklmnop").Should().BeTrue();
        SecretRedactingEnricher.LooksLikeSecret("eyJhbGciOiJSUzI1NiJ9.aaa.bbb").Should().BeTrue();
        SecretRedactingEnricher.LooksLikeSecret("wte_abcdefghijklmnopqrstuv").Should().BeTrue();
        SecretRedactingEnricher.LooksLikeSecret("short").Should().BeFalse();
    }

    [Fact]
    public void RedactText_ScrubsTokens()
    {
        var input = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.aaa.bbb and wte_abc123def456ghi789";
        var redacted = SecretRedactingEnricher.RedactText(input);
        redacted.Should().NotContain("eyJ");
        redacted.Should().NotContain("wte_abc");
        redacted.Should().Contain("[REDACTED]");
    }
}
