using System.Text.Json;
using FluentAssertions;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Xunit;

namespace Tawny.Api.Tests;

public class WazuhSyslogFormatterTests
{
    [Fact]
    public void Format_EmitsSyslogWrappedJsonAlert()
    {
        var agentId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var alertRuleId = Guid.NewGuid();
        var options = new WazuhSinkOptions
        {
            Facility = 16,
            Hostname = "tawny-api",
            AppName = "tawny",
        };
        var agent = new Agent
        {
            Id = agentId,
            TenantId = tenantId,
            Hostname = "linux-host-01",
            OperatingSystem = AgentPlatform.Linux,
            OsVersion = "6.12",
            Architecture = AgentArchitecture.Arm64,
            AgentVersion = "0.1.0",
            EnrolledAt = DateTimeOffset.UtcNow,
        };
        var telemetryEvent = new TelemetryEvent
        {
            Id = 42,
            TenantId = tenantId,
            AgentId = agentId,
            EventType = TelemetryEventType.ProcessSnapshot,
            OccurredAt = DateTimeOffset.Parse("2026-05-14T08:00:00Z"),
            ReceivedAt = DateTimeOffset.Parse("2026-05-14T08:00:01Z"),
            Payload = """{"processes":[{"name":"suspicious.exe","pid":4242}]}""",
        };
        var alert = new Alert
        {
            Id = 7,
            AgentId = agentId,
            AlertRuleId = alertRuleId,
            TelemetryEventId = telemetryEvent.Id,
            Severity = AlertSeverity.High,
            Title = "Suspicious process on linux-host-01",
            Description = "Matched processes Contains suspicious.exe.",
            CreatedAt = DateTimeOffset.Parse("2026-05-14T08:00:02Z"),
        };

        var message = WazuhSyslogFormatter.Format(options, agent, alert, telemetryEvent);

        message.Should().StartWith("<131>May 14 08:00:02 tawny-api tawny: ");
        var jsonStart = message.IndexOf('{', StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(message[jsonStart..]);
        var root = doc.RootElement;
        root.GetProperty("integration").GetString().Should().Be("tawny");
        root.GetProperty("event_kind").GetString().Should().Be("alert");
        root.GetProperty("alert_id").GetInt64().Should().Be(7);
        root.GetProperty("tenant_id").GetGuid().Should().Be(tenantId);
        root.GetProperty("telemetry_type").GetString().Should().Be("process_snapshot");
        var payloadJson = root.GetProperty("telemetry_payload_json").GetString();
        payloadJson.Should().NotBeNullOrWhiteSpace();
        using var payloadDoc = JsonDocument.Parse(payloadJson!);
        payloadDoc.RootElement
            .GetProperty("processes")[0]
            .GetProperty("pid")
            .GetInt32()
            .Should().Be(4242);
    }

    [Fact]
    public void Format_OmitsTelemetryPayloadWhenMessageWouldExceedLimit()
    {
        var agent = new Agent
        {
            Id = Guid.NewGuid(),
            TenantId = Guid.NewGuid(),
            Hostname = "host-01",
            OperatingSystem = AgentPlatform.Windows,
            OsVersion = "11",
            Architecture = AgentArchitecture.X64,
            AgentVersion = "0.1.0",
            EnrolledAt = DateTimeOffset.UtcNow,
        };
        var telemetryEvent = new TelemetryEvent
        {
            Id = 99,
            TenantId = agent.TenantId,
            AgentId = agent.Id,
            EventType = TelemetryEventType.FileIntegrity,
            OccurredAt = DateTimeOffset.UtcNow,
            ReceivedAt = DateTimeOffset.UtcNow,
            Payload = $$"""{"blob":"{{new string('x', 12000)}}"}""",
        };
        var alert = new Alert
        {
            Id = 1,
            AgentId = agent.Id,
            AlertRuleId = Guid.NewGuid(),
            TelemetryEventId = telemetryEvent.Id,
            Severity = AlertSeverity.Low,
            Title = "Large payload",
            CreatedAt = DateTimeOffset.Parse("2026-05-14T08:00:02Z"),
        };

        var message = WazuhSyslogFormatter.Format(new WazuhSinkOptions { MaxMessageBytes = 1024 }, agent, alert, telemetryEvent);

        var jsonStart = message.IndexOf('{', StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(message[jsonStart..]);
        var root = doc.RootElement;
        root.GetProperty("telemetry_payload_omitted").GetBoolean().Should().BeTrue();
        root.GetProperty("telemetry_payload_json").ValueKind.Should().Be(JsonValueKind.Null);
    }
}
