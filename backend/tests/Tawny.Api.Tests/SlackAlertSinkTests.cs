using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Xunit;

namespace Tawny.Api.Tests;

public class SlackAlertSinkTests
{
    [Fact]
    public async Task PublishAsync_SendsWebhookAndMarksAlertSent()
    {
        var now = DateTimeOffset.Parse("2026-05-14T08:00:00Z");
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sink = CreateSink(handler, now);
        var agent = CreateAgent();
        var alert = CreateAlert(agent);

        await sink.PublishAsync(agent, [alert], new Dictionary<long, TelemetryEvent>(), CancellationToken.None);

        handler.RequestCount.Should().Be(1);
        handler.LastUri.Should().Be("https://hooks.slack.test/services/test");
        handler.LastBody.Should().Contain("Suspicious process");
        handler.LastBody.Should().Contain("linux-host-01");
        alert.SlackNotificationStatus.Should().Be(AlertNotificationStatus.Sent);
        alert.SlackNotifiedAt.Should().Be(now);
        alert.SlackNotificationError.Should().BeNull();
    }

    [Fact]
    public async Task PublishAsync_MarksAlertFailedWhenWebhookRejectsRequest()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests)
        {
            Content = new StringContent("rate limited"),
        });
        var sink = CreateSink(handler, DateTimeOffset.UtcNow);
        var agent = CreateAgent();
        var alert = CreateAlert(agent);

        await sink.PublishAsync(agent, [alert], new Dictionary<long, TelemetryEvent>(), CancellationToken.None);

        alert.SlackNotificationStatus.Should().Be(AlertNotificationStatus.Failed);
        alert.SlackNotificationError.Should().Contain("429");
        alert.SlackNotificationError.Should().Contain("rate limited");
    }

    private static SlackAlertSink CreateSink(RecordingHandler handler, DateTimeOffset now)
    {
        var http = new HttpClient(handler);
        var options = Options.Create(new SlackSinkOptions
        {
            Enabled = true,
            WebhookUrl = "https://hooks.slack.test/services/test",
        });
        return new SlackAlertSink(http, options, new StaticTimeProvider(now), NullLogger<SlackAlertSink>.Instance);
    }

    private static Agent CreateAgent() => new()
    {
        Id = Guid.NewGuid(),
        TenantId = Guid.NewGuid(),
        Hostname = "linux-host-01",
        OperatingSystem = AgentPlatform.Linux,
        OsVersion = "6.12",
        Architecture = AgentArchitecture.Arm64,
        AgentVersion = "0.1.0",
        EnrolledAt = DateTimeOffset.UtcNow,
    };

    private static Alert CreateAlert(Agent agent) => new()
    {
        Id = 7,
        AgentId = agent.Id,
        AlertRuleId = Guid.NewGuid(),
        TelemetryEventId = 42,
        Severity = AlertSeverity.High,
        Title = "Suspicious process",
        Description = "Matched suspicious.exe.",
        CreatedAt = DateTimeOffset.Parse("2026-05-14T08:00:02Z"),
    };

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public string? LastUri { get; private set; }
        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            LastUri = request.RequestUri?.ToString();
            LastBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return responder(request);
        }
    }
}
