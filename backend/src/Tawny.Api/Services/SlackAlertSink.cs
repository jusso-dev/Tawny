using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public sealed class SlackSinkOptions
{
    public bool Enabled { get; set; }
    public string WebhookUrl { get; set; } = "";
    public string Username { get; set; } = "Tawny";
    public string IconEmoji { get; set; } = ":rotating_light:";
    public int TimeoutSeconds { get; set; } = 5;
}

public sealed class SlackAlertSink(
    HttpClient http,
    IOptions<SlackSinkOptions> options,
    TimeProvider timeProvider,
    ILogger<SlackAlertSink> log) : IAlertSink
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private readonly SlackSinkOptions _options = options.Value;

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

        if (!Uri.TryCreate(_options.WebhookUrl, UriKind.Absolute, out var webhookUri)
            || webhookUri.Scheme != Uri.UriSchemeHttps)
        {
            MarkFailed(alerts, "Slack sink is enabled but Tawny:Slack:WebhookUrl is not a valid HTTPS URL.");
            log.LogWarning("Slack sink is enabled but Tawny:Slack:WebhookUrl is not a valid HTTPS URL.");
            return;
        }

        foreach (var alert in alerts)
        {
            if (alert.SlackNotificationStatus == AlertNotificationStatus.Sent)
            {
                continue;
            }

            alert.SlackNotificationStatus = AlertNotificationStatus.Pending;
            alert.SlackNotificationError = null;
            telemetryEvents.TryGetValue(alert.TelemetryEventId, out var telemetryEvent);

            try
            {
                await SendAsync(webhookUri, agent, alert, telemetryEvent, ct);
                alert.SlackNotificationStatus = AlertNotificationStatus.Sent;
                alert.SlackNotifiedAt = timeProvider.GetUtcNow();
                alert.SlackNotificationError = null;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                alert.SlackNotificationStatus = AlertNotificationStatus.Failed;
                alert.SlackNotificationError = Truncate(ex.Message, 1024);
                log.LogWarning(ex, "Failed to publish alert {AlertId} to Slack sink.", alert.Id);
            }
        }
    }

    private async Task SendAsync(
        Uri webhookUri,
        Agent agent,
        Alert alert,
        TelemetryEvent? telemetryEvent,
        CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 1, 60)));

        var payload = SlackPayloadFormatter.Format(_options, agent, alert, telemetryEvent);
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await http.PostAsync(webhookUri, content, timeout.Token);
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(timeout.Token);
        throw new HttpRequestException(
            $"Slack webhook returned {(int)response.StatusCode} {response.StatusCode}: {Truncate(body, 300)}",
            null,
            response.StatusCode);
    }

    private static void MarkFailed(IReadOnlyList<Alert> alerts, string message)
    {
        foreach (var alert in alerts)
        {
            alert.SlackNotificationStatus = AlertNotificationStatus.Failed;
            alert.SlackNotificationError = Truncate(message, 1024);
        }
    }

    private static string Truncate(string value, int maxLength)
    {
        if (value.Length <= maxLength)
        {
            return value;
        }

        return value[..maxLength];
    }
}

public static class SlackPayloadFormatter
{
    public static object Format(
        SlackSinkOptions options,
        Agent agent,
        Alert alert,
        TelemetryEvent? telemetryEvent)
    {
        var severity = alert.Severity.ToString().ToLowerInvariant();
        var status = alert.Status.ToString().ToLowerInvariant();
        var eventType = telemetryEvent?.EventType.ToString() ?? "Unknown";
        var title = SlackEscape(alert.Title);
        var description = SlackEscape(alert.Description ?? "No alert description captured.");
        var hostname = SlackEscape(agent.Hostname);
        var createdAt = alert.CreatedAt.ToUniversalTime().ToString("u");

        return new
        {
            text = $"[{severity}] {alert.Title} on {agent.Hostname}",
            username = string.IsNullOrWhiteSpace(options.Username) ? "Tawny" : options.Username,
            icon_emoji = string.IsNullOrWhiteSpace(options.IconEmoji) ? ":rotating_light:" : options.IconEmoji,
            blocks = new object[]
            {
                new
                {
                    type = "section",
                    text = new
                    {
                        type = "mrkdwn",
                        text = $"*{title}*\n{Truncate(description, 1800)}",
                    },
                },
                new
                {
                    type = "section",
                    fields = new object[]
                    {
                        Field("Severity", severity),
                        Field("Status", status),
                        Field("Agent", hostname),
                        Field("Event", eventType),
                        Field("Alert ID", alert.Id.ToString()),
                        Field("Created", createdAt),
                    },
                },
            },
        };
    }

    private static object Field(string title, string value) => new
    {
        type = "mrkdwn",
        text = $"*{title}:*\n{SlackEscape(value)}",
    };

    private static string SlackEscape(string value) => value
        .Replace("&", "&amp;", StringComparison.Ordinal)
        .Replace("<", "&lt;", StringComparison.Ordinal)
        .Replace(">", "&gt;", StringComparison.Ordinal);

    private static string Truncate(string value, int maxLength)
    {
        if (value.Length <= maxLength)
        {
            return value;
        }

        return value[..maxLength];
    }
}
