using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Api.Auth;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public class CrossTenantIsolationTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    private static readonly Guid TenantA = TenantDefaults.DefaultTenantId;
    private static readonly Guid TenantB = Guid.Parse("00000000-0000-0000-0000-0000000000b2");

    [Fact]
    public async Task AgentsAndTelemetry_AreTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();

        var agentA = await EnrollInTenantAsync(TenantA, "host-a");
        var agentB = await EnrollInTenantAsync(TenantB, "host-b");

        // Tenant A cannot list tenant B agent events.
        using var listBAsA = new HttpRequestMessage(HttpMethod.Get, $"/api/agents/{agentB.Id}/events");
        listBAsA.AddWebUserSignature($"/api/agents/{agentB.Id}/events", tenantId: TenantA);
        (await factory.CreateClient().SendAsync(listBAsA)).StatusCode.Should().Be(HttpStatusCode.NotFound);

        // Tenant A cannot see tenant B agents.
        using var listAgents = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        listAgents.AddWebUserSignature("/api/agents", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(listAgents);
        res.EnsureSuccessStatusCode();
        var agents = await res.Content.ReadFromJsonAsync<JsonElement>();
        agents.GetArrayLength().Should().Be(1);
        agents[0].GetProperty("id").GetGuid().Should().Be(agentA.Id);
    }

    [Fact]
    public async Task AlertRules_AreTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.AlertRules.AddRange(
                NewRule(TenantA, "A-rule"),
                NewRule(TenantB, "B-rule"));
            await db.SaveChangesAsync();
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/alert-rules");
        req.AddWebUserSignature("/api/alert-rules", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(req);
        res.EnsureSuccessStatusCode();
        var body = await res.Content.ReadAsStringAsync();
        body.Should().Contain("A-rule");
        body.Should().NotContain("B-rule");

        // Tenant A cannot delete tenant B rule.
        using var scope2 = factory.Services.CreateScope();
        var db2 = scope2.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var bRuleId = await db2.AlertRules.Where(r => r.TenantId == TenantB).Select(r => r.Id).SingleAsync();
        using var del = new HttpRequestMessage(HttpMethod.Delete, $"/api/alert-rules/{bRuleId}");
        del.AddWebUserSignature($"/api/alert-rules/{bRuleId}", tenantId: TenantA);
        (await factory.CreateClient().SendAsync(del)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await db2.AlertRules.CountAsync(r => r.Id == bRuleId)).Should().Be(1);
    }

    [Fact]
    public async Task Alerts_AreTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();
        var agentA = await EnrollInTenantAsync(TenantA, "alert-a");
        var agentB = await EnrollInTenantAsync(TenantB, "alert-b");

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            var ruleA = NewRule(TenantA, "rule-a");
            var ruleB = NewRule(TenantB, "rule-b");
            db.AlertRules.AddRange(ruleA, ruleB);
            var teA = NewTelemetry(agentA.Id, TenantA);
            var teB = NewTelemetry(agentB.Id, TenantB);
            db.TelemetryEvents.AddRange(teA, teB);
            await db.SaveChangesAsync();
            db.Alerts.AddRange(
                new Alert
                {
                    TenantId = TenantA,
                    AlertRuleId = ruleA.Id,
                    AgentId = agentA.Id,
                    TelemetryEventId = teA.Id,
                    Severity = AlertSeverity.High,
                    Title = "alert-a",
                    CreatedAt = DateTimeOffset.UtcNow,
                },
                new Alert
                {
                    TenantId = TenantB,
                    AlertRuleId = ruleB.Id,
                    AgentId = agentB.Id,
                    TelemetryEventId = teB.Id,
                    Severity = AlertSeverity.High,
                    Title = "alert-b",
                    CreatedAt = DateTimeOffset.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/alerts");
        req.AddWebUserSignature("/api/alerts", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(req);
        res.EnsureSuccessStatusCode();
        var text = await res.Content.ReadAsStringAsync();
        text.Should().Contain("alert-a");
        text.Should().NotContain("alert-b");
    }

    [Fact]
    public async Task ResponseActions_RejectCrossTenantAgent()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();
        var agentB = await EnrollInTenantAsync(TenantB, "ra-b");

        var body = """{"action_type":"kill_process","payload":{"pid":1}}""";
        using var req = new HttpRequestMessage(HttpMethod.Post, $"/api/agents/{agentB.Id}/actions")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        req.AddWebUserSignature($"/api/agents/{agentB.Id}/actions", tenantId: TenantA);
        (await factory.CreateClient().SendAsync(req)).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task EnrollmentTokens_AreTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.AddRange(
                new EnrollmentToken
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantA,
                    TokenHash = TokenHashing.Hash("wte_a"),
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                    CreatedByUserId = Guid.Empty,
                },
                new EnrollmentToken
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantB,
                    TokenHash = TokenHashing.Hash("wte_b"),
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                    CreatedByUserId = Guid.Empty,
                });
            await db.SaveChangesAsync();
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/enrollment-tokens");
        req.AddWebUserSignature("/api/enrollment-tokens", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(req);
        res.EnsureSuccessStatusCode();
        var arr = await res.Content.ReadFromJsonAsync<JsonElement>();
        arr.GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task ThreatIntelFeeds_AreTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.ThreatIntelFeeds.AddRange(
                new ThreatIntelFeed
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantA,
                    Name = "feed-a",
                    Kind = ThreatIntelFeedKind.GenericCsv,
                    Url = "https://example.com/a.csv",
                    CreatedAt = DateTimeOffset.UtcNow,
                    UpdatedAt = DateTimeOffset.UtcNow,
                },
                new ThreatIntelFeed
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantB,
                    Name = "feed-b",
                    Kind = ThreatIntelFeedKind.GenericCsv,
                    Url = "https://example.com/b.csv",
                    CreatedAt = DateTimeOffset.UtcNow,
                    UpdatedAt = DateTimeOffset.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/threat-intel-feeds");
        req.AddWebUserSignature("/api/threat-intel-feeds", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(req);
        res.EnsureSuccessStatusCode();
        var text = await res.Content.ReadAsStringAsync();
        text.Should().Contain("feed-a");
        text.Should().NotContain("feed-b");
    }

    [Fact]
    public async Task ApiTokens_AreTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.ApiTokens.AddRange(
                new ApiToken
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantA,
                    Name = "token-a",
                    TokenHash = ApiTokenAuthHandler.HashToken("twny_aaaaaaaaaaaa"),
                    TokenPrefix = "twny_aaaaaaaa",
                    Role = UserRole.Admin,
                    CreatedAt = DateTimeOffset.UtcNow,
                },
                new ApiToken
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantB,
                    Name = "token-b",
                    TokenHash = ApiTokenAuthHandler.HashToken("twny_bbbbbbbbbbbb"),
                    TokenPrefix = "twny_bbbbbbbb",
                    Role = UserRole.Admin,
                    CreatedAt = DateTimeOffset.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/api-tokens");
        req.AddWebUserSignature("/api/api-tokens", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(req);
        res.EnsureSuccessStatusCode();
        var text = await res.Content.ReadAsStringAsync();
        text.Should().Contain("token-a");
        text.Should().NotContain("token-b");
    }

    [Fact]
    public async Task AuditLog_IsTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.AuditLog.AddRange(
                new AuditLog
                {
                    TenantId = TenantA,
                    Action = "test.a",
                    OccurredAt = DateTimeOffset.UtcNow,
                },
                new AuditLog
                {
                    TenantId = TenantB,
                    Action = "test.b",
                    OccurredAt = DateTimeOffset.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/audit-logs");
        req.AddWebUserSignature("/api/audit-logs", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(req);
        res.EnsureSuccessStatusCode();
        var text = await res.Content.ReadAsStringAsync();
        text.Should().Contain("test.a");
        text.Should().NotContain("test.b");
    }

    [Fact]
    public async Task Hunts_AreTenantIsolated()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.SavedHunts.AddRange(
                new SavedHunt
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantA,
                    Name = "hunt-a",
                    Query = "event_type:process_snapshot",
                    CreatedAt = DateTimeOffset.UtcNow,
                    UpdatedAt = DateTimeOffset.UtcNow,
                },
                new SavedHunt
                {
                    Id = Guid.NewGuid(),
                    TenantId = TenantB,
                    Name = "hunt-b",
                    Query = "event_type:process_snapshot",
                    CreatedAt = DateTimeOffset.UtcNow,
                    UpdatedAt = DateTimeOffset.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/hunts");
        req.AddWebUserSignature("/api/hunts", tenantId: TenantA);
        var res = await factory.CreateClient().SendAsync(req);
        res.EnsureSuccessStatusCode();
        var text = await res.Content.ReadAsStringAsync();
        text.Should().Contain("hunt-a");
        text.Should().NotContain("hunt-b");
    }

    [Fact]
    public async Task AgentCannotCompleteOtherAgentResponseAction()
    {
        await factory.ResetDatabaseAsync();
        await SeedTenantsAsync();
        var agentA = await EnrollInTenantAsync(TenantA, "act-a");
        var agentB = await EnrollInTenantAsync(TenantA, "act-b");

        Guid actionId;
        string token;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            token = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
            var action = new ResponseAction
            {
                Id = Guid.NewGuid(),
                AgentId = agentA.Id,
                TenantId = TenantA,
                ActionType = ResponseActionType.KillProcess,
                Status = ResponseActionStatus.Dispatched,
                RequestedAt = DateTimeOffset.UtcNow,
                DispatchedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
                PayloadJson = """{"pid":1}""",
                PayloadHash = "abc",
                ExecutionTokenHash = TokenHashing.Hash(token),
            };
            db.ResponseActions.Add(action);
            await db.SaveChangesAsync();
            actionId = action.Id;
        }

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", agentB.Jwt);
        var res = await client.PostAsJsonAsync($"/api/agents/actions/{actionId}/result", new
        {
            status = "succeeded",
            execution_token = token,
            message = "nope",
            result = new { },
        });
        res.StatusCode.Should().BeOneOf(HttpStatusCode.NotFound, HttpStatusCode.Unauthorized);
    }

    private async Task SeedTenantsAsync()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        if (!await db.Tenants.AnyAsync(t => t.Id == TenantB))
        {
            db.Tenants.Add(new Tenant
            {
                Id = TenantB,
                Slug = "tenant-b",
                Name = "Tenant B",
                CreatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }
    }

    private async Task<(Guid Id, string Jwt)> EnrollInTenantAsync(Guid tenantId, string hostname)
    {
        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId,
                TokenHash = TokenHashing.Hash(enrollmentToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                CreatedByUserId = Guid.Empty,
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname,
            os = "linux",
            os_version = "6.1",
            arch = "x64",
            agent_version = "0.2.0",
        });
        enroll.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await enroll.Content.ReadAsStringAsync());
        return (
            doc.RootElement.GetProperty("agent_id").GetGuid(),
            doc.RootElement.GetProperty("jwt").GetString()!);
    }

    private static AlertRule NewRule(Guid tenantId, string name) => new()
    {
        Id = Guid.NewGuid(),
        TenantId = tenantId,
        Name = name,
        Format = AlertRuleFormat.TawnyPredicate,
        EventType = TelemetryEventType.ProcessSnapshot,
        Severity = AlertSeverity.Medium,
        Operator = AlertRuleOperator.Contains,
        PayloadPath = "processes",
        MatchValue = "x",
        IsEnabled = true,
        CreatedAt = DateTimeOffset.UtcNow,
        UpdatedAt = DateTimeOffset.UtcNow,
    };

    private static TelemetryEvent NewTelemetry(Guid agentId, Guid tenantId) => new()
    {
        TenantId = tenantId,
        AgentId = agentId,
        EventType = TelemetryEventType.ProcessSnapshot,
        OccurredAt = DateTimeOffset.UtcNow,
        ReceivedAt = DateTimeOffset.UtcNow,
        Confidence = EvidenceConfidence.AgentReported,
        Payload = "{}",
    };
}
