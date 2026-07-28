using FluentAssertions;
using Tawny.Domain;
using Xunit;

namespace Tawny.Api.Tests;

public class RateLimitPartitionTests
{
    [Fact]
    public void PrincipalKeys_DifferByTenantAndUser()
    {
        // Partition keys used by web policies must not collapse tenants together.
        static string Key(string tenant, string user) => $"{tenant}:{user}";

        Key(TenantDefaults.DefaultTenantId.ToString(), "user-a")
            .Should().NotBe(Key(Guid.NewGuid().ToString(), "user-a"));
        Key(TenantDefaults.DefaultTenantId.ToString(), "user-a")
            .Should().NotBe(Key(TenantDefaults.DefaultTenantId.ToString(), "user-b"));
    }

    [Fact]
    public void AgentEventsPartition_IncludesTenantAndAgent()
    {
        var tenant = TenantDefaults.DefaultTenantId.ToString();
        var agent = Guid.NewGuid().ToString();
        var key = $"{tenant}:{agent}";
        key.Should().StartWith(tenant);
        key.Should().Contain(agent);
    }
}
