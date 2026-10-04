using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Api.Auth;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

/// <summary>Alert polling contract used by external SOC integrations (BlakSoc).</summary>
public class AlertsIntegrationApiTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    private const string ViewerToken = "twny_test-alerts-viewer-token";

    [Fact]
    public async Task ApiToken_CanPageAlertsForwardWithMitreAndAgentOs()
    {
        await factory.ResetDatabaseAsync();
        var agentId = Guid.NewGuid();
        var otherTenant = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.Tenants.Add(new Tenant { Id = otherTenant, Slug = "other", Name = "Other", CreatedAt = DateTimeOffset.UtcNow });
            db.ApiTokens.Add(new ApiToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                Name = "blaksoc",
                TokenHash = ApiTokenAuthHandler.HashToken(ViewerToken),
                TokenPrefix = ViewerToken[..12],
                Role = UserRole.Viewer,
                CreatedAt = DateTimeOffset.UtcNow,
            });
            var agent = new Agent
            {
                Id = agentId, TenantId = TenantDefaults.DefaultTenantId, Hostname = "laptop-042",
                OperatingSystem = AgentPlatform.Windows, OsVersion = "11", AgentVersion = "0.1.0",
                EnrolledAt = DateTimeOffset.UtcNow,
            };
            var otherAgent = new Agent
            {
                Id = Guid.NewGuid(), TenantId = otherTenant, Hostname = "other-host",
                OperatingSystem = AgentPlatform.Linux, OsVersion = "6", AgentVersion = "0.1.0",
                EnrolledAt = DateTimeOffset.UtcNow,
            };
            var rule = new AlertRule
            {
                Id = Guid.NewGuid(), TenantId = TenantDefaults.DefaultTenantId, Name = "Encoded PowerShell",
                MitreTechniquesJson = "[\"T1059.001\"]", CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
            };
            var otherRule = new AlertRule
            {
                Id = Guid.NewGuid(), TenantId = otherTenant, Name = "Other", CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
            };
            db.AddRange(agent, otherAgent, rule, otherRule);
            await db.SaveChangesAsync();

            TelemetryEvent Ev(Guid a, Guid t) => new()
            {
                AgentId = a, TenantId = t, EventType = TelemetryEventType.ProcessLaunch,
                OccurredAt = DateTimeOffset.UtcNow, ReceivedAt = DateTimeOffset.UtcNow, Payload = "{\"name\":\"powershell.exe\"}",
            };
            var events = Enumerable.Range(0, 3).Select(_ => Ev(agentId, TenantDefaults.DefaultTenantId)).ToList();
            var otherEvent = Ev(otherAgent.Id, otherTenant);
            db.TelemetryEvents.AddRange(events);
            db.TelemetryEvents.Add(otherEvent);
            await db.SaveChangesAsync();

            foreach (var e in events)
            {
                db.Alerts.Add(new Alert
                {
                    TenantId = TenantDefaults.DefaultTenantId, AlertRuleId = rule.Id, AgentId = agentId,
                    TelemetryEventId = e.Id, Severity = AlertSeverity.High, Title = "Encoded PowerShell on laptop-042",
                    CreatedAt = DateTimeOffset.UtcNow,
                });
            }
            db.Alerts.Add(new Alert
            {
                TenantId = otherTenant, AlertRuleId = otherRule.Id, AgentId = otherAgent.Id,
                TelemetryEventId = otherEvent.Id, Severity = AlertSeverity.Low, Title = "other", CreatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ViewerToken);

        var page1 = await client.GetFromJsonAsync<AlertBody[]>("/api/alerts?after_id=0&limit=2");
        page1.Should().HaveCount(2);
        page1![0].Id.Should().BeLessThan(page1[1].Id, "forward paging is oldest first");
        page1.Should().OnlyContain(a => a.AgentId == agentId);
        page1[0].MitreTechniques.Should().Equal("T1059.001");
        page1[0].AgentOs.Should().Be("windows");
        page1[0].Hostname.Should().Be("laptop-042");

        var page2 = await client.GetFromJsonAsync<AlertBody[]>($"/api/alerts?after_id={page1[1].Id}&limit=2");
        page2.Should().ContainSingle().Which.Id.Should().BeGreaterThan(page1[1].Id);

        var page3 = await client.GetFromJsonAsync<AlertBody[]>($"/api/alerts?after_id={page2![0].Id}&limit=2");
        page3.Should().BeEmpty();

        var single = await client.GetFromJsonAsync<AlertBody>($"/api/alerts/{page1[0].Id}");
        single!.Id.Should().Be(page1[0].Id);

        (await client.GetAsync($"/api/agents/{agentId}/actions")).StatusCode.Should().Be(HttpStatusCode.OK,
            "viewer tokens can read action history");
        var sigma = await client.PostAsJsonAsync("/api/alert-rules/sigma", new { rule_yaml = "title: x" });
        sigma.StatusCode.Should().Be(HttpStatusCode.Forbidden, "Sigma import needs an Admin token");
    }

    [Fact]
    public async Task AdminApiToken_CanImportSigmaAndReadSingleAction()
    {
        await factory.ResetDatabaseAsync();
        const string adminToken = "twny_test-alerts-admin-token";
        var agentId = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.ApiTokens.Add(new ApiToken
            {
                Id = Guid.NewGuid(), TenantId = TenantDefaults.DefaultTenantId, Name = "blaksoc-admin",
                TokenHash = ApiTokenAuthHandler.HashToken(adminToken), TokenPrefix = adminToken[..12],
                Role = UserRole.Admin, CreatedAt = DateTimeOffset.UtcNow,
            });
            db.Agents.Add(new Agent
            {
                Id = agentId, TenantId = TenantDefaults.DefaultTenantId, Hostname = "h",
                OperatingSystem = AgentPlatform.Windows, OsVersion = "11", AgentVersion = "0.1.0",
                EnrolledAt = DateTimeOffset.UtcNow, PublicIp = "198.51.100.7", TagsJson = "[\"finance\"]",
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var sigma = await client.PostAsJsonAsync("/api/alert-rules/sigma", new
        {
            rule_yaml = """
title: Encoded PowerShell
id: 11111111-2222-3333-4444-555555555555
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.command_line|contains: -enc
  condition: selection
level: high
""",
        });
        sigma.EnsureSuccessStatusCode();

        var created = await client.PostAsJsonAsync($"/api/agents/{agentId}/actions", new
        {
            action_type = "release_host",
            payload = new { },
            idempotency_key = "blaksoc-action-1",
        });
        created.EnsureSuccessStatusCode();
        var action = await created.Content.ReadFromJsonAsync<ActionBody>();
        var fetched = await client.GetFromJsonAsync<ActionBody>($"/api/agents/{agentId}/actions/{action!.Id}");
        fetched!.Id.Should().Be(action.Id);

        var agent = await client.GetFromJsonAsync<AgentBody>($"/api/agents/{agentId}");
        agent!.PublicIp.Should().Be("198.51.100.7");
        agent.Tags.Should().Equal("finance");
    }

    private sealed record ActionBody([property: JsonPropertyName("id")] Guid Id);

    private sealed record AgentBody(
        [property: JsonPropertyName("public_ip")] string? PublicIp,
        [property: JsonPropertyName("tags")] string[] Tags);

    private sealed record AlertBody(
        [property: JsonPropertyName("id")] long Id,
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("hostname")] string Hostname,
        [property: JsonPropertyName("mitre_techniques")] string[] MitreTechniques,
        [property: JsonPropertyName("agent_os")] string AgentOs);
}
