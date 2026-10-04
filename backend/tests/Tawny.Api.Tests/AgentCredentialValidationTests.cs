using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
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

public class AgentCredentialValidationTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    [Fact]
    public async Task StaleCredentialVersion_IsRejectedOnEveryAgentEndpoint()
    {
        await factory.ResetDatabaseAsync();
        var (client, agentId) = await EnrollAsync();

        await MutateAgentAsync(agentId, a => a.CredentialVersion += 1);

        (await PostEventsAsync(client)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await PostHeartbeatAsync(client)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var result = await client.PostAsJsonAsync($"/api/agents/actions/{Guid.NewGuid()}/result", new
        {
            status = "succeeded",
            execution_token = "x",
        });
        result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var failures = await db.AuditLog
            .Where(a => a.Action == "agent.auth_failed" && a.Target == agentId.ToString())
            .ToListAsync();
        failures.Should().HaveCount(3);
        failures.Should().OnlyContain(a => a.MetadataJson!.Contains("credential_version_mismatch"));
    }

    [Fact]
    public async Task RevokedAgent_CannotIngest()
    {
        await factory.ResetDatabaseAsync();
        var (client, agentId) = await EnrollAsync();
        (await PostEventsAsync(client)).StatusCode.Should().Be(HttpStatusCode.Accepted);

        await MutateAgentAsync(agentId, a =>
        {
            a.Status = AgentStatus.Revoked;
            a.RevokedAt = DateTimeOffset.UtcNow;
        });

        (await PostEventsAsync(client)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private async Task<(HttpClient Client, Guid AgentId)> EnrollAsync()
    {
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
            hostname = "cv-host",
            os = "windows",
            os_version = "11",
            arch = "x64",
            agent_version = "0.1.0",
        });
        enroll.EnsureSuccessStatusCode();
        var body = await enroll.Content.ReadFromJsonAsync<EnrollBody>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body!.Jwt);
        return (client, body.AgentId);
    }

    private async Task MutateAgentAsync(Guid agentId, Action<Agent> mutate)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var agent = await db.Agents.SingleAsync(a => a.Id == agentId);
        mutate(agent);
        await db.SaveChangesAsync();
    }

    private static Task<HttpResponseMessage> PostHeartbeatAsync(HttpClient client) =>
        client.PostAsJsonAsync("/api/agents/heartbeat", new
        {
            agent_version = "0.1.0",
            uptime_seconds = 1,
            buffer_depth = 0,
        });

    private static Task<HttpResponseMessage> PostEventsAsync(HttpClient client) =>
        client.PostAsJsonAsync("/api/agents/events", new
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

    private sealed record EnrollBody(
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("jwt")] string Jwt);
}
