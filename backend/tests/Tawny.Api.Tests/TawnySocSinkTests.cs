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

public class TawnySocSinkTests
{
    [Fact]
    public async Task AlertSink_PostsBatchWithBearerToken()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var options = Options.Create(new TawnySocSinkOptions
        {
            Enabled = true,
            AlertsEnabled = true,
            EndpointUrl = "http://localhost:3001/api/ingest/tawny",
            ApiToken = "soc-token",
        });
        var sink = new TawnySocAlertSink(
            new HttpClient(handler),
            options,
            new StaticTimeProvider(DateTimeOffset.Parse("2026-05-27T08:00:00Z")),
            NullLogger<TawnySocAlertSink>.Instance);
        var agent = CreateAgent();
        var telemetry = CreateTelemetry(agent);
        var alert = CreateAlert(agent, telemetry);

        await sink.PublishAsync(
            agent,
            [alert],
            new Dictionary<long, TelemetryEvent> { [telemetry.Id] = telemetry },
            CancellationToken.None);

        handler.RequestCount.Should().Be(1);
        handler.LastUri.Should().Be("http://localhost:3001/api/ingest/tawny");
        handler.LastAuthorization.Should().Be("Bearer soc-token");
        handler.LastBody.Should().Contain("alert_batch");
        handler.LastBody.Should().Contain("Suspicious process");
        handler.LastBody.Should().Contain("linux-host-01");
    }

    [Fact]
    public void PayloadFormatter_IncludesRelatedTelemetryById()
    {
        var agent = CreateAgent();
        var telemetry = CreateTelemetry(agent);
        var alert = CreateAlert(agent, telemetry);

        var payload = TawnySocPayloadFormatter.FormatAlertBatch(
            agent,
            [alert],
            new Dictionary<long, TelemetryEvent> { [telemetry.Id] = telemetry },
            DateTimeOffset.Parse("2026-05-27T08:00:00Z"));
        var json = JsonSerializer.Serialize(payload, TawnySocPayloadFormatter.JsonOptions);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("kind").GetString().Should().Be("alert_batch");
        root.GetProperty("agent").GetProperty("hostname").GetString().Should().Be("linux-host-01");
        root.GetProperty("alerts")[0].GetProperty("alert_id").GetInt64().Should().Be(7);
        root.GetProperty("telemetry_events").GetProperty("42").GetProperty("payload").GetString()
            .Should().Contain("suspicious.exe");
    }

    [Fact]
    public void OptionsValidate_RequiresValidEndpointWhenEnabled()
    {
        var options = new TawnySocSinkOptions
        {
            Enabled = true,
            AlertsEnabled = false,
            TelemetryEnabled = false,
            EndpointUrl = "not-a-url",
            BatchSize = 0,
            TimeoutSeconds = 0,
        };

        var errors = options.Validate();

        errors.Should().Contain(e => e.Contains("AlertsEnabled or TelemetryEnabled", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("EndpointUrl", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("BatchSize", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("TimeoutSeconds", StringComparison.Ordinal));
    }

    [Fact]
    public void OptionsValidate_RequiresHttpsOutsideLoopbackByDefault()
    {
        var options = new TawnySocSinkOptions
        {
            Enabled = true,
            AlertsEnabled = true,
            EndpointUrl = "http://soc.example.com/api/ingest/tawny",
        };

        options.Validate().Should().ContainSingle(e => e.Contains("must use HTTPS", StringComparison.Ordinal));

        options.AllowInsecureHttp = true;
        options.Validate().Should().BeEmpty();
    }

    private static Agent CreateAgent() => new()
    {
        Id = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        TenantId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        Hostname = "linux-host-01",
        OperatingSystem = AgentPlatform.Linux,
        OsVersion = "6.12",
        Architecture = AgentArchitecture.Arm64,
        AgentVersion = "0.1.0",
        EnrolledAt = DateTimeOffset.UtcNow,
    };

    private static TelemetryEvent CreateTelemetry(Agent agent) => new()
    {
        Id = 42,
        AgentId = agent.Id,
        TenantId = agent.TenantId,
        EventType = TelemetryEventType.ProcessLaunch,
        OccurredAt = DateTimeOffset.Parse("2026-05-27T08:00:01Z"),
        ReceivedAt = DateTimeOffset.Parse("2026-05-27T08:00:02Z"),
        Payload = """{"process":{"name":"suspicious.exe","command_line":"powershell.exe -enc SQBFAFgA"}}""",
    };

    private static Alert CreateAlert(Agent agent, TelemetryEvent telemetry) => new()
    {
        Id = 7,
        AgentId = agent.Id,
        AlertRuleId = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        TelemetryEventId = telemetry.Id,
        Severity = AlertSeverity.High,
        Title = "Suspicious process",
        Description = "Matched suspicious.exe.",
        CreatedAt = DateTimeOffset.Parse("2026-05-27T08:00:03Z"),
    };

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public string? LastUri { get; private set; }
        public string? LastAuthorization { get; private set; }
        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            LastUri = request.RequestUri?.ToString();
            LastAuthorization = request.Headers.Authorization?.ToString();
            LastBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return responder(request);
        }
    }
}
