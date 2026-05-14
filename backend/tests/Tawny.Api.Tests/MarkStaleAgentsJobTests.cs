using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Jobs;
using Xunit;

namespace Tawny.Api.Tests;

public class MarkStaleAgentsJobTests
{
    [Fact]
    public async Task ExecuteAsync_TransitionsAtThreeAndFifteenMinuteBoundaries()
    {
        var options = new DbContextOptionsBuilder<TawnyDbContext>()
            .UseInMemoryDatabase($"mark-stale-{Guid.NewGuid()}")
            .Options;

        await using (var setup = new TawnyDbContext(options))
        {
            await setup.Database.EnsureCreatedAsync();
            var now = new DateTimeOffset(2026, 5, 14, 1, 0, 0, TimeSpan.Zero);
            setup.Agents.AddRange(
                Agent("fresh", AgentStatus.Online, now.AddMinutes(-2).AddSeconds(-59)),
                Agent("stale-boundary", AgentStatus.Online, now.AddMinutes(-3)),
                Agent("offline-boundary", AgentStatus.Online, now.AddMinutes(-15)));
            await setup.SaveChangesAsync();

            var job = new MarkStaleAgentsJob(
                setup,
                new FixedTimeProvider(now),
                NullLogger<MarkStaleAgentsJob>.Instance);
            await job.ExecuteAsync();
        }

        await using var verify = new TawnyDbContext(options);
        var statuses = await verify.Agents.ToDictionaryAsync(a => a.Hostname, a => a.Status);
        statuses["fresh"].Should().Be(AgentStatus.Online);
        statuses["stale-boundary"].Should().Be(AgentStatus.Stale);
        statuses["offline-boundary"].Should().Be(AgentStatus.Offline);
    }

    private static Agent Agent(string hostname, AgentStatus status, DateTimeOffset heartbeat) => new()
    {
        Id = Guid.NewGuid(),
        TenantId = TenantDefaults.DefaultTenantId,
        Hostname = hostname,
        OperatingSystem = AgentPlatform.Windows,
        OsVersion = "11",
        AgentVersion = "0.1.0",
        Architecture = AgentArchitecture.X64,
        EnrolledAt = heartbeat.AddMinutes(-1),
        LastHeartbeatAt = heartbeat,
        Status = status,
    };

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
