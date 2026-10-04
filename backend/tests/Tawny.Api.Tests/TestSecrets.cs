using Microsoft.Extensions.Configuration;
using Tawny.Infrastructure.Security;

namespace Tawny.Api.Tests;

internal static class TestSecrets
{
    public static IIntegrationSecretProtector Protector { get; } = new IntegrationSecretProtector(
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Tawny:IntegrationEncryptionKey"] = "test-integration-encryption-key",
            })
            .Build());
}
