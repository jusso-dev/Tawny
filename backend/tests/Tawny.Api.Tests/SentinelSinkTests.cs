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

public class SentinelSinkTests
{
    [Fact]
    public async Task TokenProvider_RequestsClientCredentialsTokenAndCachesIt()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
                {"access_token":"token-123","expires_in":3600}
                """),
        });
        var options = Options.Create(ValidOptions());
        var provider = new AzureMonitorTokenProvider(
            new HttpClient(handler),
            options,
            new StaticTimeProvider(DateTimeOffset.Parse("2026-05-17T00:00:00Z")),
            NullLogger<AzureMonitorTokenProvider>.Instance);

        var first = await provider.GetAccessTokenAsync(CancellationToken.None);
        var second = await provider.GetAccessTokenAsync(CancellationToken.None);

        first.Should().Be("token-123");
        second.Should().Be("token-123");
        handler.RequestCount.Should().Be(1);
        handler.LastMethod.Should().Be(HttpMethod.Post);
        handler.LastUri.Should().Be("https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token");
        handler.LastBody.Should().Contain("grant_type=client_credentials");
        handler.LastBody.Should().Contain("scope=https%3A%2F%2Fmonitor.azure.com%2F.default");
    }

    [Fact]
    public void PayloadFormatter_MapsAlertToSentinelRecord()
    {
        var agent = CreateAgent();
        var telemetry = CreateTelemetry(agent);
        var alert = CreateAlert(agent, telemetry);

        var json = JsonSerializer.Serialize(SentinelPayloadFormatter.FormatAlert(agent, alert, telemetry));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        root.GetProperty("EventKind").GetString().Should().Be("alert");
        root.GetProperty("TawnyTenantId").GetString().Should().Be(agent.TenantId.ToString());
        root.GetProperty("AgentHostname").GetString().Should().Be("linux-host-01");
        root.GetProperty("AlertId").GetInt64().Should().Be(7);
        root.GetProperty("AlertSeverity").GetString().Should().Be("High");
        root.GetProperty("TelemetryEventType").GetString().Should().Be("ProcessSnapshot");
        root.GetProperty("TelemetryPayload").GetString().Should().Contain("suspicious.exe");
    }

    [Fact]
    public async Task UploadAsync_RetriesRetryableResponses()
    {
        var calls = 0;
        var handler = new RecordingHandler(_ =>
        {
            calls++;
            return calls == 1
                ? new HttpResponseMessage(HttpStatusCode.TooManyRequests)
                {
                    Content = new StringContent("try again"),
                }
                : new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        var options = ValidOptions();
        options.RetryBaseDelayMilliseconds = 0;
        var client = new AzureMonitorLogsIngestionClient(
            new HttpClient(handler),
            new StaticTokenProvider("monitor-token"),
            Options.Create(options));

        await client.UploadAsync("Custom-TawnyAlert_CL", new[] { new { Message = "hello" } }, CancellationToken.None);

        handler.RequestCount.Should().Be(2);
        handler.LastUri.Should().Be("https://dcr.example.monitor.azure.com/dataCollectionRules/dcr-abc/streams/Custom-TawnyAlert_CL?api-version=2023-01-01");
        handler.LastAuthorization.Should().Be("Bearer monitor-token");
    }

    [Fact]
    public async Task UploadAsync_DoesNotRetryNonRetryableResponses()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("bad stream"),
        });
        var options = ValidOptions();
        options.RetryBaseDelayMilliseconds = 0;
        var client = new AzureMonitorLogsIngestionClient(
            new HttpClient(handler),
            new StaticTokenProvider("monitor-token"),
            Options.Create(options));

        var act = () => client.UploadAsync("Custom-TawnyAlert_CL", new[] { new { Message = "hello" } }, CancellationToken.None);

        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*400 BadRequest*bad stream*");
        handler.RequestCount.Should().Be(1);
    }

    [Fact]
    public void OptionsValidate_RequiresEndpointDcrStreamAndCredentialsWhenEnabled()
    {
        var options = new SentinelSinkOptions
        {
            Enabled = true,
            AlertsEnabled = true,
            TelemetryEnabled = true,
            EndpointUrl = "http://not-https.example",
            DcrImmutableId = "",
            AlertStreamName = "",
            TelemetryStreamName = "",
            TenantId = "",
            ClientId = "",
            ClientSecret = "",
        };

        var errors = options.Validate();

        errors.Should().Contain(e => e.Contains("EndpointUrl", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("DcrImmutableId", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("AlertStreamName", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("TelemetryStreamName", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("TenantId", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("ClientId", StringComparison.Ordinal));
        errors.Should().Contain(e => e.Contains("ClientSecret", StringComparison.Ordinal));
    }

    private static SentinelSinkOptions ValidOptions() => new()
    {
        Enabled = true,
        AlertsEnabled = true,
        TenantId = "tenant-1",
        ClientId = "client-1",
        ClientSecret = "secret-1",
        EndpointUrl = "https://dcr.example.monitor.azure.com",
        DcrImmutableId = "dcr-abc",
        AlertStreamName = "Custom-TawnyAlert_CL",
        TelemetryStreamName = "Custom-TawnyTelemetry_CL",
        BatchSize = 100,
        MaxRetries = 3,
        RetryBaseDelayMilliseconds = 0,
    };

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
        EventType = TelemetryEventType.ProcessSnapshot,
        OccurredAt = DateTimeOffset.Parse("2026-05-17T00:00:01Z"),
        ReceivedAt = DateTimeOffset.Parse("2026-05-17T00:00:02Z"),
        Payload = """{"processes":[{"name":"suspicious.exe"}]}""",
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
        CreatedAt = DateTimeOffset.Parse("2026-05-17T00:00:03Z"),
    };

    private sealed class StaticTokenProvider(string token) : IAzureMonitorTokenProvider
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult(token);
    }

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public HttpMethod? LastMethod { get; private set; }
        public string? LastUri { get; private set; }
        public string? LastBody { get; private set; }
        public string? LastAuthorization { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
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
