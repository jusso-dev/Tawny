using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Api.Auth;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public class ThreatIntelLookupEndpointTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    [Fact]
    public async Task Lookup_WithApiToken_ReturnsTenantFeedMatch()
    {
        await factory.ResetDatabaseAsync();
        const string rawToken = "twny_test-lookup-token";
        var feedId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.ApiTokens.Add(new ApiToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                Name = "Personal agent",
                TokenHash = ApiTokenAuthHandler.HashToken(rawToken),
                TokenPrefix = rawToken[..12],
                Role = UserRole.Viewer,
                CreatedAt = now,
            });
            db.ThreatIntelFeeds.Add(new ThreatIntelFeed
            {
                Id = feedId,
                TenantId = TenantDefaults.DefaultTenantId,
                Name = "Local test feed",
                Url = "https://feed.example/indicators.csv",
                CreatedAt = now,
                UpdatedAt = now,
            });
            db.AlertRules.Add(new AlertRule
            {
                Id = Guid.NewGuid(),
                Name = "Known malicious IP",
                Format = AlertRuleFormat.Ioc,
                ExternalId = $"ti-feed:{feedId}:ipv4:203.0.113.20",
                EventType = TelemetryEventType.NetworkSnapshot,
                Severity = AlertSeverity.High,
                Operator = AlertRuleOperator.Equals,
                MatchValue = "203.0.113.20",
                IsEnabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", rawToken);
        var response = await client.PostAsJsonAsync(
            "/api/threat-intel/lookup",
            new { values = new[] { "203.0.113.20" } });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var match = body.RootElement.GetProperty("matches").EnumerateArray().Single();
        match.GetProperty("value").GetString().Should().Be("203.0.113.20");
        match.GetProperty("kind").GetString().Should().Be("ipv4");
        match.GetProperty("feed_name").GetString().Should().Be("Local test feed");
        match.GetProperty("severity").GetString().Should().Be("high");
    }
}
