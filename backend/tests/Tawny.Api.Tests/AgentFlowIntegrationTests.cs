using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public class AgentFlowIntegrationTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    [Fact]
    public async Task EnrollHeartbeatAndEventsFlow_PersistsFirstEvent()
    {
        await factory.ResetDatabaseAsync();
        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
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
            hostname = "edr-host-01",
            os = "windows",
            os_version = "11",
            arch = "x64",
            agent_version = "0.1.0",
        });
        enroll.EnsureSuccessStatusCode();
        var enrollBody = await enroll.Content.ReadFromJsonAsync<EnrollBody>();
        enrollBody.Should().NotBeNull();
        enrollBody!.Jwt.Should().NotBeNullOrWhiteSpace();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", enrollBody.Jwt);
        var heartbeat = await client.PostAsJsonAsync("/api/agents/heartbeat", new
        {
            agent_version = "0.1.1",
            uptime_seconds = 42,
            buffer_depth = 0,
        });
        heartbeat.EnsureSuccessStatusCode();

        var events = await client.PostAsJsonAsync("/api/agents/events", new
        {
            events = new[]
            {
                new
                {
                    type = "process_snapshot",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    payload = new { processes = Array.Empty<object>() },
                },
            },
        });
        events.StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var readReq = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/agents/{enrollBody.AgentId}/events?type=process_snapshot");
        readReq.AddWebUserSignature($"/api/agents/{enrollBody.AgentId}/events");
        var read = await client.SendAsync(readReq);
        read.EnsureSuccessStatusCode();
        var stored = await read.Content.ReadFromJsonAsync<TelemetryEventBody[]>();

        stored.Should().ContainSingle();
        stored![0].AgentId.Should().Be(enrollBody.AgentId);
        stored[0].Type.Should().Be("process_snapshot");
    }

    [Fact]
    public async Task WebReads_AreScopedToSignedTenant()
    {
        await factory.ResetDatabaseAsync();
        var otherTenantId = Guid.NewGuid();
        var defaultAgentId = Guid.NewGuid();
        var otherAgentId = Guid.NewGuid();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.Tenants.Add(new Tenant
            {
                Id = otherTenantId,
                Slug = "other",
                Name = "Other",
                CreatedAt = DateTimeOffset.UtcNow,
            });
            db.Agents.AddRange(
                NewAgent(defaultAgentId, TenantDefaults.DefaultTenantId, "default-host"),
                NewAgent(otherAgentId, otherTenantId, "other-host"));
            db.TelemetryEvents.AddRange(
                NewEvent(defaultAgentId, TenantDefaults.DefaultTenantId),
                NewEvent(otherAgentId, otherTenantId));
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        using var defaultReq = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        defaultReq.AddWebUserSignature("/api/agents");
        var defaultRead = await client.SendAsync(defaultReq);
        defaultRead.EnsureSuccessStatusCode();
        var defaultAgents = await defaultRead.Content.ReadFromJsonAsync<AgentSummaryBody[]>();
        defaultAgents.Should().ContainSingle(a => a.Id == defaultAgentId);
        defaultAgents.Should().NotContain(a => a.Id == otherAgentId);

        using var otherReq = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        otherReq.AddWebUserSignature("/api/agents", tenantId: otherTenantId);
        var otherRead = await client.SendAsync(otherReq);
        otherRead.EnsureSuccessStatusCode();
        var otherAgents = await otherRead.Content.ReadFromJsonAsync<AgentSummaryBody[]>();
        otherAgents.Should().ContainSingle(a => a.Id == otherAgentId);
        otherAgents.Should().NotContain(a => a.Id == defaultAgentId);
    }

    private static Agent NewAgent(Guid id, Guid tenantId, string hostname) => new()
    {
        Id = id,
        TenantId = tenantId,
        Hostname = hostname,
        OperatingSystem = AgentPlatform.Windows,
        OsVersion = "11",
        Architecture = AgentArchitecture.X64,
        AgentVersion = "0.1.0",
        EnrolledAt = DateTimeOffset.UtcNow,
        LastHeartbeatAt = DateTimeOffset.UtcNow,
        Status = AgentStatus.Online,
    };

    private static TelemetryEvent NewEvent(Guid agentId, Guid tenantId) => new()
    {
        AgentId = agentId,
        TenantId = tenantId,
        EventType = TelemetryEventType.ProcessSnapshot,
        OccurredAt = DateTimeOffset.UtcNow,
        ReceivedAt = DateTimeOffset.UtcNow,
        Payload = "{}",
    };

    private sealed record EnrollBody(
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("jwt")] string Jwt);

    private sealed record AgentSummaryBody(
        [property: JsonPropertyName("id")] Guid Id);

    private sealed record TelemetryEventBody(
        [property: JsonPropertyName("id")] long Id,
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("type")] string Type);
}
