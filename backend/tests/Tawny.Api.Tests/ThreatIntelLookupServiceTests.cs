using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public class ThreatIntelLookupServiceTests
{
    [Fact]
    public async Task LookupAsync_ReturnsOnlyFeedBackedRulesForTenant()
    {
        var options = new DbContextOptionsBuilder<TawnyDbContext>()
            .UseInMemoryDatabase($"ti-lookup-{Guid.NewGuid()}")
            .Options;
        await using var db = new TawnyDbContext(options);
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var feedId = Guid.NewGuid();
        var otherFeedId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        db.ThreatIntelFeeds.AddRange(
            Feed(feedId, tenantId, "Tenant feed", now),
            Feed(otherFeedId, otherTenantId, "Other feed", now));
        db.AlertRules.AddRange(
            Rule(tenantId, feedId, "ipv4", "203.0.113.20", now),
            Rule(otherTenantId, otherFeedId, "ipv4", "203.0.113.20", now),
            new AlertRule
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId,
                Name = "Manual global rule",
                Format = AlertRuleFormat.Ioc,
                ExternalId = "ioc:ipv4:203.0.113.20",
                EventType = TelemetryEventType.NetworkSnapshot,
                Operator = AlertRuleOperator.Equals,
                MatchValue = "203.0.113.20",
                IsEnabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
        await db.SaveChangesAsync();

        var matches = await new ThreatIntelLookupService(db).LookupAsync(
            tenantId,
            [" 203.0.113.20 "],
            CancellationToken.None);

        matches.Should().ContainSingle();
        matches[0].FeedId.Should().Be(feedId);
        matches[0].FeedName.Should().Be("Tenant feed");
        matches[0].Kind.Should().Be("ipv4");
        matches[0].Value.Should().Be("203.0.113.20");
    }

    private static ThreatIntelFeed Feed(
        Guid id,
        Guid tenantId,
        string name,
        DateTimeOffset now) => new()
    {
        Id = id,
        TenantId = tenantId,
        Name = name,
        Url = "https://feed.example/indicators.csv",
        CreatedAt = now,
        UpdatedAt = now,
    };

    private static AlertRule Rule(Guid tenantId, Guid feedId, string kind, string value, DateTimeOffset now) => new()
    {
        Id = Guid.NewGuid(),
        TenantId = tenantId,
        Name = $"Feed rule {value}",
        Format = AlertRuleFormat.Ioc,
        ExternalId = $"ti-feed:{feedId}:{kind}:{value}",
        EventType = TelemetryEventType.NetworkSnapshot,
        Severity = AlertSeverity.High,
        Operator = AlertRuleOperator.Equals,
        MatchValue = value,
        IsEnabled = true,
        CreatedAt = now,
        UpdatedAt = now,
    };
}
