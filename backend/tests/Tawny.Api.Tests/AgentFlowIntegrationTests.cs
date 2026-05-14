using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Api.Services;
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

    private sealed record EnrollBody(
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("jwt")] string Jwt);

    private sealed record TelemetryEventBody(
        [property: JsonPropertyName("id")] long Id,
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("type")] string Type);
}
