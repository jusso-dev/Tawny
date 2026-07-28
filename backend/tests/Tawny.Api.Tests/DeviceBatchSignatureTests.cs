using System.Security.Cryptography;
using System.Text.Json;
using FluentAssertions;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Xunit;

namespace Tawny.Api.Tests;

public class DeviceBatchSignatureTests
{
    [Fact]
    public void SignAndVerify_RoundTrips()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        var pub = DeviceBatchSignature.PublicKeyFromSeed(seed);
        var agentId = Guid.NewGuid();
        var batchId = Guid.NewGuid();
        var events = new List<TelemetryEventIngest>
        {
            new(
                Guid.NewGuid(),
                TelemetryEventType.ProcessSnapshot,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                JsonDocument.Parse("""{"processes":[]}""").RootElement,
                Sequence: 1),
        };

        var canonical = DeviceBatchSignature.BuildCanonical(agentId, batchId, events);
        var sig = DeviceBatchSignature.Sign(seed, canonical);
        DeviceBatchSignature.TryVerify(pub, sig, canonical).Should().BeTrue();

        // Tamper
        DeviceBatchSignature.TryVerify(pub, sig, canonical + "x").Should().BeFalse();
    }

    [Fact]
    public void MissingSignature_FailsVerify()
    {
        DeviceBatchSignature.TryVerify("AAAA", null, "canonical").Should().BeFalse();
    }
}
