using System.Globalization;
using System.Net.Sockets;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public sealed class WazuhSinkOptions
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; } = 514;
    public string Protocol { get; set; } = "udp";
    public int Facility { get; set; } = 16;
    public string AppName { get; set; } = "tawny";
    public string Hostname { get; set; } = "";
    public int MaxMessageBytes { get; set; } = 8192;
}

public sealed class WazuhAlertSink(
    IOptions<WazuhSinkOptions> options,
    ILogger<WazuhAlertSink> log) : IAlertSink
{
    private readonly WazuhSinkOptions _options = options.Value;

    public async Task PublishAsync(
        Agent agent,
        IReadOnlyList<Alert> alerts,
        IReadOnlyDictionary<long, TelemetryEvent> telemetryEvents,
        CancellationToken ct)
    {
        if (!_options.Enabled || alerts.Count == 0)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(_options.Host))
        {
            log.LogWarning("Wazuh sink is enabled but Tawny:Wazuh:Host is empty.");
            return;
        }
        if (_options.Port is < 1 or > 65535)
        {
            log.LogWarning("Wazuh sink is enabled but Tawny:Wazuh:Port is outside the valid range.");
            return;
        }
        if (!string.Equals(_options.Protocol, "udp", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(_options.Protocol, "tcp", StringComparison.OrdinalIgnoreCase))
        {
            log.LogWarning("Wazuh sink is enabled but Tawny:Wazuh:Protocol must be udp or tcp.");
            return;
        }

        foreach (var alert in alerts)
        {
            telemetryEvents.TryGetValue(alert.TelemetryEventId, out var telemetryEvent);
            var message = WazuhSyslogFormatter.Format(_options, agent, alert, telemetryEvent);
            try
            {
                await SendAsync(message, ct);
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                log.LogWarning(ex, "Failed to publish alert {AlertId} to Wazuh sink.", alert.Id);
            }
        }
        log.LogInformation(
            "Published {AlertCount} alert(s) to Wazuh sink {Host}:{Port}/{Protocol}.",
            alerts.Count,
            _options.Host,
            _options.Port,
            _options.Protocol);
    }

    private async Task SendAsync(string message, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(message);
        if (string.Equals(_options.Protocol, "tcp", StringComparison.OrdinalIgnoreCase))
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(_options.Host, _options.Port, ct);
            await using var stream = tcp.GetStream();
            await stream.WriteAsync(bytes, ct);
            await stream.WriteAsync("\n"u8.ToArray(), ct);
            return;
        }

        using var udp = new UdpClient();
        await udp.SendAsync(bytes, _options.Host, _options.Port, ct);
    }
}

public static class WazuhSyslogFormatter
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static string Format(
        WazuhSinkOptions options,
        Agent agent,
        Alert alert,
        TelemetryEvent? telemetryEvent)
    {
        var timestamp = alert.CreatedAt.ToUniversalTime().ToString("MMM dd HH:mm:ss", CultureInfo.InvariantCulture);
        var hostname = SanitizeSyslogToken(string.IsNullOrWhiteSpace(options.Hostname)
            ? Environment.MachineName
            : options.Hostname);
        var appName = SanitizeSyslogToken(options.AppName);
        var priority = Math.Clamp(options.Facility, 0, 23) * 8 + Severity(alert.Severity);

        var eventJson = BuildJson(agent, alert, telemetryEvent, includeTelemetryPayload: true);
        var message = $"<{priority}>{timestamp} {hostname} {appName}: {eventJson}";
        var maxBytes = Math.Max(options.MaxMessageBytes, 1024);
        if (Encoding.UTF8.GetByteCount(message) <= maxBytes)
        {
            return message;
        }

        eventJson = BuildJson(agent, alert, telemetryEvent, includeTelemetryPayload: false);
        return $"<{priority}>{timestamp} {hostname} {appName}: {eventJson}";
    }

    private static string BuildJson(
        Agent agent,
        Alert alert,
        TelemetryEvent? telemetryEvent,
        bool includeTelemetryPayload)
    {
        var payload = includeTelemetryPayload && telemetryEvent is not null
            ? telemetryEvent.Payload
            : null;

        return JsonSerializer.Serialize(new
        {
            integration = "tawny",
            event_kind = "alert",
            alert_id = alert.Id,
            alert_title = alert.Title,
            alert_description = alert.Description,
            alert_severity = alert.Severity,
            alert_status = alert.Status,
            alert_created_at = alert.CreatedAt,
            rule_id = alert.AlertRuleId,
            agent_id = agent.Id,
            tenant_id = agent.TenantId,
            agent_hostname = agent.Hostname,
            agent_os = agent.OperatingSystem,
            agent_os_version = agent.OsVersion,
            agent_architecture = agent.Architecture,
            agent_version = agent.AgentVersion,
            telemetry_id = telemetryEvent?.Id,
            telemetry_type = telemetryEvent?.EventType,
            telemetry_occurred_at = telemetryEvent?.OccurredAt,
            telemetry_received_at = telemetryEvent?.ReceivedAt,
            telemetry_payload_json = payload,
            telemetry_payload_omitted = telemetryEvent is not null && !includeTelemetryPayload,
        }, JsonOptions);
    }

    private static int Severity(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => 2,
        AlertSeverity.High => 3,
        AlertSeverity.Medium => 4,
        AlertSeverity.Low => 5,
        _ => 5,
    };

    private static string SanitizeSyslogToken(string value)
    {
        var token = string.IsNullOrWhiteSpace(value) ? "tawny" : value.Trim();
        var builder = new StringBuilder(token.Length);
        foreach (var c in token)
        {
            builder.Append(char.IsWhiteSpace(c) || c == ':' ? '-' : c);
        }
        return builder.ToString();
    }
}
