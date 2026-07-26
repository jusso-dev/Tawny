using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Tawny.Infrastructure.Security;
using Tawny.Jobs;
using Xunit;

namespace Tawny.Api.Tests;

public class UniFiIntegrationSecurityTests
{
    [Fact]
    public void Protect_RoundTripsWithoutStoringPlaintext()
    {
        var protector = Protector("test-key-one");

        var first = protector.Protect("unifi-secret");
        var second = protector.Protect("unifi-secret");

        first.Should().StartWith("v1.");
        first.Should().NotContain("unifi-secret");
        first.Should().NotBe(second);
        protector.Unprotect(first).Should().Be("unifi-secret");
    }

    [Fact]
    public void Unprotect_WithDifferentKey_Fails()
    {
        var encrypted = Protector("test-key-one").Protect("unifi-secret");

        var action = () => Protector("test-key-two").Unprotect(encrypted);

        action.Should().Throw<CryptographicException>();
    }

    [Theory]
    [InlineData("https://192.168.1.1")]
    [InlineData("http://10.0.0.1:8443")]
    [InlineData("https://127.0.0.1")]
    public void RequirePrivateHttpUri_AcceptsPrivateAddresses(string value)
    {
        UniFiConnector.RequirePrivateHttpUri(value, "URL").Should().NotBeNull();
    }

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("https://8.8.8.8")]
    [InlineData("file:///etc/passwd")]
    [InlineData("https://user:password@192.168.1.1/events")]
    [InlineData("https://192.168.1.1/events#secret")]
    public void RequirePrivateHttpUri_RejectsNonLocalAddresses(string value)
    {
        var action = () => UniFiConnector.RequirePrivateHttpUri(value, "URL");

        action.Should().Throw<InvalidOperationException>();
    }

    private static IntegrationSecretProtector Protector(string key)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Tawny:IntegrationEncryptionKey"] = key,
            })
            .Build();
        return new IntegrationSecretProtector(configuration);
    }
}
