using FluentAssertions;
using Tawny.Api.Models;
using Xunit;

namespace Tawny.Api.Tests;

public class AgentRequestValidatorTests
{
    [Fact]
    public async Task EnrollValidator_AcceptsSupportedProductionAgent()
    {
        var validator = new EnrollRequestValidator();
        var request = new EnrollRequest(
            "enrollment-token",
            "prod-api-01",
            "linux",
            "6.12.0-aws",
            "arm64",
            "0.1.0");

        var result = await validator.ValidateAsync(request);

        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData("host\ninjected", "linux", "arm64")]
    [InlineData("host", "freebsd", "arm64")]
    [InlineData("host", "linux", "sparc")]
    public async Task EnrollValidator_RejectsUnsafeOrUnsupportedIdentity(
        string hostname,
        string os,
        string arch)
    {
        var validator = new EnrollRequestValidator();
        var request = new EnrollRequest(
            "enrollment-token",
            hostname,
            os,
            "1",
            arch,
            "0.1.0");

        var result = await validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task HeartbeatValidator_RejectsNegativeCounters()
    {
        var validator = new HeartbeatRequestValidator();
        var request = new HeartbeatRequest("0.1.0", -1, -1);

        var result = await validator.ValidateAsync(request);

        result.IsValid.Should().BeFalse();
    }
}
