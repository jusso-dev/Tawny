using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.ThreatIntel;
using Tawny.Jobs;
using Xunit;

namespace Tawny.Api.Tests;

public class StarterThreatIntelFeedsTests
{
    [Fact]
    public async Task EnsureSeededAsync_InsertsKelpieStarterFeedsForDefaultTenant()
    {
        await using var db = CreateDb();
        db.Tenants.Add(new Tenant
        {
            Id = TenantDefaults.DefaultTenantId,
            Slug = TenantDefaults.DefaultTenantSlug,
            Name = TenantDefaults.DefaultTenantName,
            CreatedAt = DateTimeOffset.UtcNow,
        });
        await db.SaveChangesAsync();

        var added = await StarterThreatIntelFeeds.EnsureSeededAsync(db);
        var again = await StarterThreatIntelFeeds.EnsureSeededAsync(db);

        added.Should().Be(StarterThreatIntelFeeds.All.Count);
        again.Should().Be(0);

        var feeds = await db.ThreatIntelFeeds
            .Where(f => f.TenantId == TenantDefaults.DefaultTenantId)
            .OrderBy(f => f.Name)
            .ToListAsync();

        feeds.Select(f => f.Url).Should().BeEquivalentTo(StarterThreatIntelFeeds.All.Select(d => d.Url));
        feeds.Single(f => f.Url.Contains("feodotracker", StringComparison.OrdinalIgnoreCase))
            .IsEnabled.Should().BeTrue();
        feeds.Single(f => f.Url.Contains("openphish", StringComparison.OrdinalIgnoreCase))
            .IsEnabled.Should().BeTrue();
        feeds.Single(f => f.Url.Contains("phishtank", StringComparison.OrdinalIgnoreCase))
            .IsEnabled.Should().BeFalse();
    }

    [Fact]
    public async Task ThreatIntelFeedsJob_MaterialisesDomainIocAgainstDnsQuery()
    {
        await using var db = CreateDb();
        var now = DateTimeOffset.UtcNow;
        var feedId = Guid.NewGuid();
        db.Tenants.Add(new Tenant
        {
            Id = TenantDefaults.DefaultTenantId,
            Slug = TenantDefaults.DefaultTenantSlug,
            Name = TenantDefaults.DefaultTenantName,
            CreatedAt = now,
        });
        db.ThreatIntelFeeds.Add(new ThreatIntelFeed
        {
            Id = feedId,
            TenantId = TenantDefaults.DefaultTenantId,
            Name = "Test phishing domains",
            Kind = ThreatIntelFeedKind.GenericCsv,
            Url = "https://feed.example/domains.txt",
            DefaultSeverity = AlertSeverity.High,
            IntervalMinutes = 60,
            IsEnabled = true,
            Status = ThreatIntelFeedStatus.NeverRun,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();

        var http = new HttpClient(new StaticResponseHandler("https://evil.example/phish\n203.0.113.9\n"));
        var fetcher = new ThreatIntelFetcher(
            http,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ThreatIntelFetcher>.Instance);
        var job = new ThreatIntelFeedsJob(
            db,
            TimeProvider.System,
            fetcher,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ThreatIntelFeedsJob>.Instance);

        await job.ExecuteAsync();

        var rules = await db.AlertRules
            .Where(r => r.TenantId == TenantDefaults.DefaultTenantId && r.Format == AlertRuleFormat.Ioc)
            .ToListAsync();

        rules.Should().Contain(r =>
            r.MatchValue == "evil.example"
            && r.EventType == TelemetryEventType.DnsQuery
            && r.PayloadPath == "qname"
            && r.Operator == AlertRuleOperator.Equals
            && r.IsEnabled);
        rules.Should().Contain(r =>
            r.MatchValue == "203.0.113.9"
            && r.EventType == TelemetryEventType.NetworkSnapshot
            && r.PayloadPath == "connections.remote_address"
            && r.IsEnabled);
    }

    private static TawnyDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<TawnyDbContext>()
            .UseInMemoryDatabase($"starter-ti-{Guid.NewGuid()}")
            .Options;
        return new TawnyDbContext(options);
    }

    private sealed class StaticResponseHandler(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            });
    }
}
