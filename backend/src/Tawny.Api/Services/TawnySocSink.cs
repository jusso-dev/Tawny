using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public sealed class TawnySocSinkOptions
{
    public bool Enabled { get; set; }
    public bool AlertsEnabled { get; set; } = true;
    public bool TelemetryEnabled { get; set; }
    public string EndpointUrl { get; set; } = "http://localhost:3001/api/ingest/tawny";
    public string ApiToken { get; set; } = "";
    public int BatchSize { get; set; } = 100;
    public int TimeoutSeconds { get; set; } = 10;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (!Enabled)
        {
            return errors;
        }

        if (!AlertsEnabled && !TelemetryEnabled)
        {
            errors.Add("Tawny:TawnySoc requires AlertsEnabled or TelemetryEnabled when Enabled is true.");
        }

        if (!Uri.TryCreate(EndpointUrl, UriKind.Absolute, out var endpoint)
            || (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps))
        {
            errors.Add("Tawny:TawnySoc:EndpointUrl must be a valid HTTP or HTTPS URL.");
        }

        if (BatchSize is < 1 or > 1000)
        {
            errors.Add("Tawny:TawnySoc:BatchSize must be between 1 and 1000.");
        }

        if (TimeoutSeconds is < 1 or > 300)
        {
            errors.Add("Tawny:TawnySoc:TimeoutSeconds must be between 1 and 300.");
        }

        return errors;
    }
}

public sealed class TawnySocAlertSink(
    HttpClient http,
    IOptions<TawnySocSinkOptions> options,
    TimeProvider timeProvider,
    ILogger<TawnySocAlertSink> log) : IAlertSink
{
    private readonly TawnySocSinkOptions _options = options.Value;

    public async Task PublishAsync(
        Agent agent,
        IReadOnlyList<Alert> alerts,
        IReadOnlyDictionary<long, TelemetryEvent> telemetryEvents,
        CancellationToken ct)
    {
        if (!_options.Enabled || !_options.AlertsEnabled || alerts.Count == 0)
        {
            return;
        }

        var validationErrors = _options.Validate();
        if (validationErrors.Count > 0)
        {
            log.LogWarning("Tawny-SOC alert sink is enabled but configuration is invalid: {Errors}", validationErrors);
            return;
        }

        foreach (var batch in alerts.Chunk(Math.Clamp(_options.BatchSize, 1, 1000)))
        {
            try
            {
                var payload = TawnySocPayloadFormatter.FormatAlertBatch(
                    agent,
                    batch,
                    telemetryEvents,
                    timeProvider.GetUtcNow());
                await SendAsync(payload, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                log.LogWarning(ex, "Failed to publish {AlertCount} alert(s) to Tawny-SOC sink.", batch.Length);
            }
        }
    }

    private async Task SendAsync(object payload, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 1, 300)));

        var json = JsonSerializer.Serialize(payload, TawnySocPayloadFormatter.JsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, _options.EndpointUrl)
        {
            Content = content,
        };
        if (!string.IsNullOrWhiteSpace(_options.ApiToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiToken);
        }

        using var response = await http.SendAsync(request, timeout.Token);
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(timeout.Token);
        throw new HttpRequestException(
            $"Tawny-SOC sink returned {(int)response.StatusCode} {response.StatusCode}: {Truncate(body, 300)}",
            null,
            response.StatusCode);
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}

public sealed class CompositeTelemetrySink(
    SentinelTelemetrySink sentinel,
    TawnySocTelemetrySink tawnySoc) : ITelemetrySink
{
    public async Task PublishAsync(Agent agent, IReadOnlyList<TelemetryEvent> events, CancellationToken ct)
    {
        await sentinel.PublishAsync(agent, events, ct);
        await tawnySoc.PublishAsync(agent, events, ct);
    }
}

public sealed class TawnySocTelemetrySink(
    HttpClient http,
    IOptions<TawnySocSinkOptions> options,
    TimeProvider timeProvider,
    ILogger<TawnySocTelemetrySink> log) : ITelemetrySink
{
    private readonly TawnySocSinkOptions _options = options.Value;

    public async Task PublishAsync(Agent agent, IReadOnlyList<TelemetryEvent> events, CancellationToken ct)
    {
        if (!_options.Enabled || !_options.TelemetryEnabled || events.Count == 0)
        {
            return;
        }

        var validationErrors = _options.Validate();
        if (validationErrors.Count > 0)
        {
            log.LogWarning("Tawny-SOC telemetry sink is enabled but configuration is invalid: {Errors}", validationErrors);
            return;
        }

        foreach (var batch in events.Chunk(Math.Clamp(_options.BatchSize, 1, 1000)))
        {
            try
            {
                var payload = TawnySocPayloadFormatter.FormatTelemetryBatch(
                    agent,
                    batch,
                    timeProvider.GetUtcNow());
                await SendAsync(payload, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                log.LogWarning(
                    ex,
                    "Failed to publish {TelemetryCount} telemetry event(s) to Tawny-SOC sink for agent {AgentId}.",
                    batch.Length,
                    agent.Id);
            }
        }
    }

    private async Task SendAsync(object payload, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 1, 300)));

        var json = JsonSerializer.Serialize(payload, TawnySocPayloadFormatter.JsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, _options.EndpointUrl)
        {
            Content = content,
        };
        if (!string.IsNullOrWhiteSpace(_options.ApiToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiToken);
        }

        using var response = await http.SendAsync(request, timeout.Token);
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(timeout.Token);
        throw new HttpRequestException(
            $"Tawny-SOC sink returned {(int)response.StatusCode} {response.StatusCode}: {Truncate(body, 300)}",
            null,
            response.StatusCode);
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}

public static class TawnySocPayloadFormatter
{
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    public static object FormatAlertBatch(
        Agent agent,
        IReadOnlyList<Alert> alerts,
        IReadOnlyDictionary<long, TelemetryEvent> telemetryEvents,
        DateTimeOffset sentAt)
    {
        var relatedTelemetry = alerts
            .Select(alert => alert.TelemetryEventId)
            .Distinct()
            .Select(id => telemetryEvents.TryGetValue(id, out var telemetryEvent)
                ? new { Key = id.ToString(), Value = FormatTelemetry(telemetryEvent) }
                : null)
            .Where(item => item is not null)
            .ToDictionary(item => item!.Key, item => item!.Value);

        return new
        {
            Source = "tawny",
            Kind = "alert_batch",
            SentAt = sentAt,
            TenantId = agent.TenantId,
            Agent = FormatAgent(agent),
            Alerts = alerts.Select(FormatAlert).ToArray(),
            TelemetryEvents = relatedTelemetry,
        };
    }

    public static object FormatTelemetryBatch(
        Agent agent,
        IReadOnlyList<TelemetryEvent> events,
        DateTimeOffset sentAt)
        => new
        {
            Source = "tawny",
            Kind = "telemetry_batch",
            SentAt = sentAt,
            TenantId = agent.TenantId,
            Agent = FormatAgent(agent),
            Events = events.Select(FormatTelemetry).ToArray(),
        };

    private static object FormatAgent(Agent agent)
        => new
        {
            Id = agent.Id,
            TenantId = agent.TenantId,
            Hostname = agent.Hostname,
            OperatingSystem = agent.OperatingSystem,
            OsVersion = agent.OsVersion,
            Architecture = agent.Architecture,
            AgentVersion = agent.AgentVersion,
        };

    private static object FormatAlert(Alert alert)
        => new
        {
            AlertId = alert.Id,
            AlertRuleId = alert.AlertRuleId,
            AgentId = alert.AgentId,
            TelemetryEventId = alert.TelemetryEventId,
            Severity = alert.Severity,
            Status = alert.Status,
            Title = alert.Title,
            Description = alert.Description,
            EnrichmentJson = alert.EnrichmentJson,
            CreatedAt = alert.CreatedAt,
        };

    private static object FormatTelemetry(TelemetryEvent telemetryEvent)
        => new
        {
            TelemetryId = telemetryEvent.Id,
            TenantId = telemetryEvent.TenantId,
            AgentId = telemetryEvent.AgentId,
            EventType = telemetryEvent.EventType,
            OccurredAt = telemetryEvent.OccurredAt,
            ReceivedAt = telemetryEvent.ReceivedAt,
            Payload = telemetryEvent.Payload,
        };
}
