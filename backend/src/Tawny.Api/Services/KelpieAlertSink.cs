using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public sealed class KelpieSinkOptions
{
    public bool Enabled { get; set; }
    public string BaseUrl { get; set; } = "";
    public string ApiToken { get; set; } = "";
    public bool IncludeTelemetryPayload { get; set; } = true;
    public int MaxSummaryCharacters { get; set; } = 24_000;
    public int TimeoutSeconds { get; set; } = 10;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (!Uri.TryCreate(BaseUrl, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            errors.Add("Tawny:Kelpie:BaseUrl must be an absolute HTTP or HTTPS URL.");
        }
        if (string.IsNullOrWhiteSpace(ApiToken))
        {
            errors.Add("Tawny:Kelpie:ApiToken is required.");
        }
        return errors;
    }
}

public sealed class KelpieAlertSink(
    HttpClient http,
    IOptions<KelpieSinkOptions> options,
    TimeProvider timeProvider,
    ILogger<KelpieAlertSink> log) : IAlertSink
{
    private readonly KelpieSinkOptions _options = options.Value;

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

        var validationErrors = _options.Validate();
        if (validationErrors.Count > 0)
        {
            MarkFailed(alerts, string.Join(" ", validationErrors));
            log.LogWarning("Kelpie sink is enabled but configuration is invalid: {Errors}", validationErrors);
            return;
        }

        var baseUri = new Uri(EnsureTrailingSlash(_options.BaseUrl));
        foreach (var alert in alerts.Where(a => a.KelpieNotificationStatus != AlertNotificationStatus.Sent))
        {
            alert.KelpieNotificationStatus = AlertNotificationStatus.Pending;
            alert.KelpieNotificationError = null;
            telemetryEvents.TryGetValue(alert.TelemetryEventId, out var telemetryEvent);

            try
            {
                var created = await CreateCaseAsync(baseUri, agent, alert, telemetryEvent, ct);
                alert.KelpieNotificationStatus = AlertNotificationStatus.Sent;
                alert.KelpieNotifiedAt = timeProvider.GetUtcNow();
                alert.KelpieNotificationError = null;
                alert.KelpieCaseId = created.Id;
                alert.KelpieCaseNumber = created.CaseNumber;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                alert.KelpieNotificationStatus = AlertNotificationStatus.Failed;
                alert.KelpieNotificationError = Truncate(ex.Message, 1024);
                log.LogWarning(ex, "Failed to create Kelpie case for Tawny alert {AlertId}.", alert.Id);
            }
        }
    }

    private async Task<KelpieCaseResponse> CreateCaseAsync(
        Uri baseUri,
        Agent agent,
        Alert alert,
        TelemetryEvent? telemetryEvent,
        CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 1, 60)));

        var payload = KelpieCaseFormatter.Format(_options, agent, alert, telemetryEvent);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "api/v1/cases"))
        {
            Content = JsonContent.Create(payload),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiToken.Trim());

        using var response = await http.SendAsync(request, timeout.Token);
        var body = await response.Content.ReadAsStringAsync(timeout.Token);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Kelpie API returned {(int)response.StatusCode} {response.StatusCode}: {Truncate(body, 500)}",
                null,
                response.StatusCode);
        }

        var created = JsonSerializer.Deserialize<KelpieCaseResponse>(
            body,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        if (created is null || string.IsNullOrWhiteSpace(created.Id))
        {
            throw new HttpRequestException("Kelpie API returned an invalid case response.");
        }
        return created;
    }

    private static void MarkFailed(IReadOnlyList<Alert> alerts, string message)
    {
        foreach (var alert in alerts)
        {
            alert.KelpieNotificationStatus = AlertNotificationStatus.Failed;
            alert.KelpieNotificationError = Truncate(message, 1024);
        }
    }

    private static string EnsureTrailingSlash(string value)
        => value.EndsWith("/", StringComparison.Ordinal) ? value : value + "/";

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    private sealed record KelpieCaseResponse(string Id, string? CaseNumber);
}

public static class KelpieCaseFormatter
{
    public static object Format(
        KelpieSinkOptions options,
        Agent agent,
        Alert alert,
        TelemetryEvent? telemetryEvent)
    {
        var summary = BuildSummary(options, agent, alert, telemetryEvent);
        return new
        {
            title = alert.Title,
            summary,
            severity = alert.Severity.ToString().ToLowerInvariant(),
            classification = "other",
            tags = new[]
            {
                "tawny",
                "tawny-alert",
                $"tawny-alert-{alert.Id}",
                $"agent-{TagValue(agent.Hostname)}",
            },
            sourceSystem = "tawny",
            sourceReference = alert.Id.ToString(),
        };
    }

    private static string BuildSummary(
        KelpieSinkOptions options,
        Agent agent,
        Alert alert,
        TelemetryEvent? telemetryEvent)
    {
        var text = new StringBuilder();
        text.AppendLine(alert.Description ?? "Tawny generated an alert.");
        text.AppendLine();
        text.AppendLine("## Detection");
        text.AppendLine($"- Tawny alert: {alert.Id}");
        text.AppendLine($"- Rule: {alert.AlertRuleId}");
        text.AppendLine($"- Severity: {alert.Severity.ToString().ToLowerInvariant()}");
        text.AppendLine($"- Status: {alert.Status.ToString().ToLowerInvariant()}");
        text.AppendLine($"- Created: {alert.CreatedAt:O}");
        text.AppendLine();
        text.AppendLine("## Endpoint");
        text.AppendLine($"- Hostname: {agent.Hostname}");
        text.AppendLine($"- Agent: {agent.Id}");
        text.AppendLine($"- OS: {agent.OperatingSystem} {agent.OsVersion}");
        text.AppendLine($"- Architecture: {agent.Architecture}");
        text.AppendLine($"- Agent version: {agent.AgentVersion}");

        if (telemetryEvent is not null)
        {
            text.AppendLine();
            text.AppendLine("## Evidence");
            text.AppendLine($"- Telemetry event: {telemetryEvent.Id}");
            text.AppendLine($"- Event type: {telemetryEvent.EventType}");
            text.AppendLine($"- Occurred: {telemetryEvent.OccurredAt:O}");
            text.AppendLine($"- Received: {telemetryEvent.ReceivedAt:O}");
            if (options.IncludeTelemetryPayload)
            {
                text.AppendLine();
                text.AppendLine("```json");
                text.AppendLine(telemetryEvent.Payload.Replace("```", "``\u200b`", StringComparison.Ordinal));
                text.AppendLine("```");
            }
        }

        if (!string.IsNullOrWhiteSpace(alert.EnrichmentJson))
        {
            text.AppendLine();
            text.AppendLine("## Enrichment");
            text.AppendLine("```json");
            text.AppendLine(alert.EnrichmentJson.Replace("```", "``\u200b`", StringComparison.Ordinal));
            text.AppendLine("```");
        }

        var maxLength = Math.Clamp(options.MaxSummaryCharacters, 2_000, 100_000);
        return text.Length <= maxLength
            ? text.ToString()
            : text.ToString(0, maxLength) + "\n\n[Summary truncated by Tawny]";
    }

    private static string TagValue(string value)
    {
        var tag = new string(value
            .Trim()
            .ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-')
            .ToArray());
        return string.IsNullOrEmpty(tag) ? "unknown" : tag;
    }
}
