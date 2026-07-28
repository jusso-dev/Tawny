using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public class TelemetryIntegrityTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    [Fact]
    public async Task SequenceRollback_IsAuditedAndDoesNotAdvanceWatermark()
    {
        await factory.ResetDatabaseAsync();
        var (client, agentId, jwt) = await EnrollAsync("seq-host");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        (await client.PostAsJsonAsync("/api/agents/events", new
        {
            batch_id = Guid.NewGuid(),
            events = new[]
            {
                new
                {
                    client_event_id = Guid.NewGuid(),
                    type = "process_snapshot",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    sequence = 10,
                    payload = new { processes = Array.Empty<object>() },
                },
            },
        })).StatusCode.Should().Be(HttpStatusCode.Accepted);

        (await client.PostAsJsonAsync("/api/agents/events", new
        {
            batch_id = Guid.NewGuid(),
            events = new[]
            {
                new
                {
                    client_event_id = Guid.NewGuid(),
                    type = "process_snapshot",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    sequence = 5,
                    payload = new { processes = Array.Empty<object>() },
                },
            },
        })).StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var agent = await db.Agents.SingleAsync(a => a.Id == agentId);
        agent.LastTelemetrySequence.Should().Be(10);

        var audits = await db.AuditLog.Where(a => a.Action == "telemetry.sequence_rollback").ToListAsync();
        audits.Should().NotBeEmpty();
    }

    [Fact]
    public async Task FutureTimestamp_IsRejected()
    {
        await factory.ResetDatabaseAsync();
        var (client, _, jwt) = await EnrollAsync("future-host");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var farFuture = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds();
        var res = await client.PostAsJsonAsync("/api/agents/events", new
        {
            events = new[]
            {
                new
                {
                    type = "heartbeat",
                    occurred_at = farFuture,
                    payload = new { ok = true },
                },
            },
        });
        res.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ClientEventIdReplay_IsAcceptedWithoutDuplicate()
    {
        await factory.ResetDatabaseAsync();
        var (client, agentId, jwt) = await EnrollAsync("replay-host");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var id = Guid.NewGuid();
        var body = new
        {
            events = new[]
            {
                new
                {
                    client_event_id = id,
                    type = "system_info",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    sequence = 1,
                    payload = new { hostname = "replay-host" },
                },
            },
        };

        (await client.PostAsJsonAsync("/api/agents/events", body)).StatusCode.Should().Be(HttpStatusCode.Accepted);
        (await client.PostAsJsonAsync("/api/agents/events", body)).StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        (await db.TelemetryEvents.CountAsync(e => e.AgentId == agentId && e.ClientEventId == id)).Should().Be(1);
        var row = await db.TelemetryEvents.SingleAsync(e => e.ClientEventId == id);
        row.Confidence.Should().Be(EvidenceConfidence.AgentReported);
        row.BatchId.Should().NotBeNull();
        row.PayloadDigest.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Enroll_AcceptsDevicePublicKey()
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

        var pub = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var client = factory.CreateClient();
        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname = "device-key-host",
            os = "linux",
            os_version = "6.1",
            arch = "x64",
            agent_version = "0.2.0",
            device_public_key = pub,
        });
        enroll.EnsureSuccessStatusCode();
        var body = await enroll.Content.ReadFromJsonAsync<EnrollBody>();

        using var verify = factory.Services.CreateScope();
        var agent = await verify.ServiceProvider.GetRequiredService<TawnyDbContext>()
            .Agents.SingleAsync(a => a.Id == body!.AgentId);
        agent.DevicePublicKey.Should().Be(pub);
    }

    [Fact]
    public void IntegrityHelpers_DetectGapAndSpike()
    {
        var agent = new Agent
        {
            Hostname = "h",
            OsVersion = "1",
            AgentVersion = "1",
            LastTelemetrySequence = 10,
            LastIngestEventCount = 5,
        };
        var gap = TelemetryIntegrity.AssessSequence(agent, [12]);
        gap.Gap.Should().BeTrue();
        gap.Rollback.Should().BeFalse();

        TelemetryIntegrity.IsVolumeSpike(agent, 100, new TelemetryIntegrityOptions
        {
            VolumeSpikeMinEvents = 50,
            VolumeSpikeMultiplier = 10,
        }).Should().BeTrue();
    }

    private async Task<(HttpClient Client, Guid AgentId, string Jwt)> EnrollAsync(string hostname)
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
            hostname,
            os = "linux",
            os_version = "6.1",
            arch = "x64",
            agent_version = "0.2.0",
        });
        enroll.EnsureSuccessStatusCode();
        var body = await enroll.Content.ReadFromJsonAsync<EnrollBody>();
        return (client, body!.AgentId, body.Jwt);
    }

    private sealed record EnrollBody(
        [property: System.Text.Json.Serialization.JsonPropertyName("agent_id")] Guid AgentId,
        [property: System.Text.Json.Serialization.JsonPropertyName("jwt")] string Jwt);
}
