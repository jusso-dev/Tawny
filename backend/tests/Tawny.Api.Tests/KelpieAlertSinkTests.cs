using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Xunit;

namespace Tawny.Api.Tests;

public class KelpieAlertSinkTests
{
    [Fact]
    public async Task PublishAsync_CreatesDetailedCaseAndMarksAlertSent()
    {
        var now = DateTimeOffset.Parse("2026-07-26T04:00:00Z");
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Created)
        {
            Content = new StringContent("""{"id":"case_123","caseNumber":"KEL-42"}"""),
        });
        var sink = CreateSink(handler, now);
        var agent = CreateAgent();
        var telemetry = CreateTelemetry(agent);
        var alert = CreateAlert(agent, telemetry);

        await sink.PublishAsync(
            agent,
            [alert],
            new Dictionary<long, TelemetryEvent> { [telemetry.Id] = telemetry },
            CancellationToken.None);

        handler.RequestCount.Should().Be(1);
        handler.LastMethod.Should().Be(HttpMethod.Post);
        handler.LastUri.Should().Be("http://kelpie.local/api/v1/cases");
        handler.LastAuthorization.Should().Be("Bearer kelpie-token");
        handler.LastBody.Should().NotBeNull();
        using var body = JsonDocument.Parse(handler.LastBody!);
        body.RootElement.GetProperty("severity").GetString().Should().Be("high");
        body.RootElement.GetProperty("sourceSystem").GetString().Should().Be("tawny");
        body.RootElement.GetProperty("sourceReference").GetString().Should().Be("7");
        body.RootElement.GetProperty("summary").GetString().Should().Contain("203.0.113.20");
        body.RootElement.GetProperty("tags").EnumerateArray()
            .Select(value => value.GetString())
            .Should().Contain("tawny-alert-7");
        alert.KelpieNotificationStatus.Should().Be(AlertNotificationStatus.Sent);
        alert.KelpieNotifiedAt.Should().Be(now);
        alert.KelpieCaseId.Should().Be("case_123");
        alert.KelpieCaseNumber.Should().Be("KEL-42");
        alert.KelpieNotificationError.Should().BeNull();
    }

    [Fact]
    public async Task PublishAsync_MarksAlertFailedWhenKelpieRejectsCase()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("""{"error":"forbidden"}"""),
        });
        var sink = CreateSink(handler, DateTimeOffset.UtcNow);
        var agent = CreateAgent();
        var telemetry = CreateTelemetry(agent);
        var alert = CreateAlert(agent, telemetry);

        await sink.PublishAsync(
            agent,
            [alert],
            new Dictionary<long, TelemetryEvent> { [telemetry.Id] = telemetry },
            CancellationToken.None);

        alert.KelpieNotificationStatus.Should().Be(AlertNotificationStatus.Failed);
        alert.KelpieNotificationError.Should().Contain("403");
        alert.KelpieNotificationError.Should().Contain("forbidden");
    }

    private static KelpieAlertSink CreateSink(RecordingHandler handler, DateTimeOffset now)
    {
        var options = Options.Create(new KelpieSinkOptions
        {
            Enabled = true,
            BaseUrl = "http://kelpie.local",
            ApiToken = "kelpie-token",
        });
        return new KelpieAlertSink(
            new HttpClient(handler),
            options,
            new StaticTimeProvider(now),
            NullLogger<KelpieAlertSink>.Instance);
    }

    private static Agent CreateAgent() => new()
    {
        Id = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        TenantId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        Hostname = "gateway-sensor",
        OperatingSystem = AgentPlatform.Linux,
        OsVersion = "6.12",
        Architecture = AgentArchitecture.Arm64,
        AgentVersion = "0.1.0",
        EnrolledAt = DateTimeOffset.UtcNow,
    };

    private static TelemetryEvent CreateTelemetry(Agent agent) => new()
    {
        Id = 42,
        TenantId = agent.TenantId,
        AgentId = agent.Id,
        EventType = TelemetryEventType.NetworkSnapshot,
        OccurredAt = DateTimeOffset.Parse("2026-07-26T03:59:00Z"),
        ReceivedAt = DateTimeOffset.Parse("2026-07-26T03:59:02Z"),
        Payload = """{"connections":[{"remote_address":"203.0.113.20","remote_port":443}]}""",
    };

    private static Alert CreateAlert(Agent agent, TelemetryEvent telemetry) => new()
    {
        Id = 7,
        AgentId = agent.Id,
        AlertRuleId = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        TelemetryEventId = telemetry.Id,
        Severity = AlertSeverity.High,
        Title = "TI match on gateway-sensor",
        Description = "Matched known malicious IP.",
        CreatedAt = DateTimeOffset.Parse("2026-07-26T03:59:03Z"),
    };

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public HttpMethod? LastMethod { get; private set; }
        public string? LastUri { get; private set; }
        public string? LastAuthorization { get; private set; }
        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            LastMethod = request.Method;
            LastUri = request.RequestUri?.ToString();
            LastAuthorization = request.Headers.Authorization?.ToString();
            LastBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return responder(request);
        }
    }
}
