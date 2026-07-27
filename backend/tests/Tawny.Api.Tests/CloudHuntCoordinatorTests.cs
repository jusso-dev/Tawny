using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Jobs.Cloud;
using Xunit;

namespace Tawny.Api.Tests;

public sealed class CloudHuntCoordinatorTests
{
    [Fact]
    public async Task Run_deduplicates_provider_events_across_overlap_windows()
    {
        await using var db = CreateDb();
        var (tenantId, huntId) = await SeedAsync(db);
        var now = new DateTimeOffset(2026, 7, 27, 4, 0, 0, TimeSpan.Zero);
        var provider = new FakeProvider(new CloudLogRecord(
            "ap-southeast-2:event-1",
            now.AddMinutes(-1),
            "ConsoleLogin",
            "arn:aws:iam::123456789012:user/test",
            null,
            """{"eventName":"ConsoleLogin"}"""));
        var coordinator = new CloudHuntCoordinator(db, [provider], new FixedTimeProvider(now));

        var first = await coordinator.RunAsync(tenantId, huntId, null, default);
        var second = await coordinator.RunAsync(tenantId, huntId, null, default);

        first.FindingsCreated.Should().Be(1);
        second.FindingsCreated.Should().Be(0);
        (await db.CloudFindings.CountAsync()).Should().Be(1);
        (await db.CloudHuntRuns.CountAsync()).Should().Be(2);
        (await db.CloudHunts.SingleAsync()).WatermarkAt.Should().Be(now);
    }

    [Fact]
    public async Task Failed_run_does_not_advance_watermark()
    {
        await using var db = CreateDb();
        var (tenantId, huntId) = await SeedAsync(db);
        var now = new DateTimeOffset(2026, 7, 27, 4, 0, 0, TimeSpan.Zero);
        var coordinator = new CloudHuntCoordinator(
            db,
            [new FakeProvider(new InvalidOperationException("provider unavailable"))],
            new FixedTimeProvider(now));

        var action = () => coordinator.RunAsync(tenantId, huntId, null, default);

        await action.Should().ThrowAsync<InvalidOperationException>();
        var hunt = await db.CloudHunts.SingleAsync();
        hunt.WatermarkAt.Should().BeNull();
        hunt.LastError.Should().Be("provider unavailable");
        var run = await db.CloudHuntRuns.SingleAsync();
        run.Status.Should().Be(CloudRunStatus.Failed);
    }

    private static TawnyDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<TawnyDbContext>()
            .UseInMemoryDatabase($"cloud-hunt-{Guid.NewGuid()}")
            .Options;
        return new TawnyDbContext(options);
    }

    private static async Task<(Guid TenantId, Guid HuntId)> SeedAsync(TawnyDbContext db)
    {
        var tenantId = Guid.NewGuid();
        var connectionId = Guid.NewGuid();
        var huntId = Guid.NewGuid();
        db.Tenants.Add(new Tenant
        {
            Id = tenantId,
            Slug = $"tenant-{tenantId:N}",
            Name = "Cloud test",
            CreatedAt = DateTimeOffset.UtcNow,
        });
        db.CloudConnections.Add(new CloudConnection
        {
            Id = connectionId,
            TenantId = tenantId,
            Name = "AWS test",
            Provider = CloudProvider.Aws,
            ExternalAccountId = "123456789012",
            CredentialMode = CloudCredentialMode.AwsAssumeRole,
            ConfigurationJson = "{}",
            IsEnabled = true,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });
        db.CloudHunts.Add(new CloudHunt
        {
            Id = huntId,
            TenantId = tenantId,
            CloudConnectionId = connectionId,
            Name = "Console sign-ins",
            Source = CloudSourceKind.AwsCloudTrail,
            QueryJson = "{}",
            IsEnabled = true,
            IntervalMinutes = 5,
            LookbackMinutes = 15,
            Severity = AlertSeverity.High,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();
        return (tenantId, huntId);
    }

    private sealed class FakeProvider : ICloudLogProvider
    {
        private readonly CloudLogRecord? _record;
        private readonly Exception? _error;

        public FakeProvider(CloudLogRecord record) => _record = record;
        public FakeProvider(Exception error) => _error = error;

        public bool Supports(CloudSourceKind source) => source == CloudSourceKind.AwsCloudTrail;

        public Task<CloudQueryResult> QueryAsync(
            CloudConnection connection,
            CloudHunt hunt,
            DateTimeOffset from,
            DateTimeOffset to,
            int limit,
            CancellationToken ct)
        {
            if (_error is not null) throw _error;
            return Task.FromResult(new CloudQueryResult(1, [_record!]));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
