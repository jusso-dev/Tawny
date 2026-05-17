using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public sealed class SentinelSinkOptions
{
    public bool Enabled { get; set; }
    public bool AlertsEnabled { get; set; } = true;
    public bool TelemetryEnabled { get; set; }
    public string AuthenticationMode { get; set; } = "client_secret";
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string AuthorityHost { get; set; } = "https://login.microsoftonline.com";
    public string TokenAudience { get; set; } = "https://monitor.azure.com";
    public string ManagedIdentityEndpoint { get; set; } = "";
    public string EndpointUrl { get; set; } = "";
    public string DcrImmutableId { get; set; } = "";
    public string AlertStreamName { get; set; } = "Custom-TawnyAlert_CL";
    public string TelemetryStreamName { get; set; } = "Custom-TawnyTelemetry_CL";
    public string ApiVersion { get; set; } = "2023-01-01";
    public int BatchSize { get; set; } = 100;
    public int MaxRetries { get; set; } = 3;
    public int RetryBaseDelayMilliseconds { get; set; } = 250;
    public int TimeoutSeconds { get; set; } = 15;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (!Enabled)
        {
            return errors;
        }

        if (!AlertsEnabled && !TelemetryEnabled)
        {
            errors.Add("Tawny:Sentinel requires AlertsEnabled or TelemetryEnabled when Enabled is true.");
        }

        if (!Uri.TryCreate(EndpointUrl, UriKind.Absolute, out var endpoint)
            || endpoint.Scheme != Uri.UriSchemeHttps)
        {
            errors.Add("Tawny:Sentinel:EndpointUrl must be a valid HTTPS DCR or DCE logs ingestion endpoint.");
        }

        if (string.IsNullOrWhiteSpace(DcrImmutableId))
        {
            errors.Add("Tawny:Sentinel:DcrImmutableId is required.");
        }

        if (AlertsEnabled && string.IsNullOrWhiteSpace(AlertStreamName))
        {
            errors.Add("Tawny:Sentinel:AlertStreamName is required when alert delivery is enabled.");
        }

        if (TelemetryEnabled && string.IsNullOrWhiteSpace(TelemetryStreamName))
        {
            errors.Add("Tawny:Sentinel:TelemetryStreamName is required when telemetry delivery is enabled.");
        }

        if (BatchSize is < 1 or > 1000)
        {
            errors.Add("Tawny:Sentinel:BatchSize must be between 1 and 1000.");
        }

        if (MaxRetries is < 0 or > 10)
        {
            errors.Add("Tawny:Sentinel:MaxRetries must be between 0 and 10.");
        }

        if (TimeoutSeconds is < 1 or > 300)
        {
            errors.Add("Tawny:Sentinel:TimeoutSeconds must be between 1 and 300.");
        }

        if (string.IsNullOrWhiteSpace(TokenAudience)
            || !Uri.TryCreate(TokenAudience, UriKind.Absolute, out _))
        {
            errors.Add("Tawny:Sentinel:TokenAudience must be a valid absolute URI.");
        }

        if (IsClientSecretMode())
        {
            if (string.IsNullOrWhiteSpace(TenantId))
            {
                errors.Add("Tawny:Sentinel:TenantId is required for client_secret authentication.");
            }
            if (string.IsNullOrWhiteSpace(ClientId))
            {
                errors.Add("Tawny:Sentinel:ClientId is required for client_secret authentication.");
            }
            if (string.IsNullOrWhiteSpace(ClientSecret))
            {
                errors.Add("Tawny:Sentinel:ClientSecret is required for client_secret authentication.");
            }
            if (!Uri.TryCreate(AuthorityHost, UriKind.Absolute, out var authority)
                || authority.Scheme != Uri.UriSchemeHttps)
            {
                errors.Add("Tawny:Sentinel:AuthorityHost must be a valid HTTPS URI.");
            }
        }
        else if (!IsManagedIdentityMode())
        {
            errors.Add("Tawny:Sentinel:AuthenticationMode must be client_secret or managed_identity.");
        }

        return errors;
    }

    public bool IsClientSecretMode()
        => string.Equals(AuthenticationMode, "client_secret", StringComparison.OrdinalIgnoreCase);

    public bool IsManagedIdentityMode()
        => string.Equals(AuthenticationMode, "managed_identity", StringComparison.OrdinalIgnoreCase);
}

public interface ITelemetrySink
{
    Task PublishAsync(Agent agent, IReadOnlyList<TelemetryEvent> events, CancellationToken ct);
}

public sealed class NoopTelemetrySink : ITelemetrySink
{
    public Task PublishAsync(Agent agent, IReadOnlyList<TelemetryEvent> events, CancellationToken ct)
        => Task.CompletedTask;
}

public sealed class SentinelAlertSink(
    AzureMonitorLogsIngestionClient client,
    IOptions<SentinelSinkOptions> options,
    TimeProvider timeProvider,
    ILogger<SentinelAlertSink> log) : IAlertSink
{
    private readonly SentinelSinkOptions _options = options.Value;

    public async Task PublishAsync(
        Agent agent,
        IReadOnlyList<Alert> alerts,
        IReadOnlyDictionary<long, TelemetryEvent> telemetryEvents,
        CancellationToken ct)
    {
        if (!_options.Enabled || !_options.AlertsEnabled || alerts.Count == 0)
        {
            foreach (var alert in alerts)
            {
                if (alert.SentinelNotificationStatus == AlertNotificationStatus.Pending)
                {
                    alert.SentinelNotificationStatus = AlertNotificationStatus.NotConfigured;
                }
            }
            return;
        }

        var validationErrors = _options.Validate();
        if (validationErrors.Count > 0)
        {
            MarkFailed(alerts, string.Join(" ", validationErrors));
            log.LogWarning("Sentinel alert sink is enabled but configuration is invalid: {Errors}", validationErrors);
            return;
        }

        foreach (var batch in alerts
            .Where(a => a.SentinelNotificationStatus != AlertNotificationStatus.Sent)
            .Chunk(Math.Clamp(_options.BatchSize, 1, 1000)))
        {
            foreach (var alert in batch)
            {
                alert.SentinelNotificationStatus = AlertNotificationStatus.Pending;
                alert.SentinelNotificationError = null;
            }

            try
            {
                var records = batch
                    .Select(alert =>
                    {
                        telemetryEvents.TryGetValue(alert.TelemetryEventId, out var telemetryEvent);
                        return SentinelPayloadFormatter.FormatAlert(agent, alert, telemetryEvent);
                    })
                    .ToList();

                await client.UploadAsync(_options.AlertStreamName, records, ct);
                var now = timeProvider.GetUtcNow();
                foreach (var alert in batch)
                {
                    alert.SentinelNotificationStatus = AlertNotificationStatus.Sent;
                    alert.SentinelNotifiedAt = now;
                    alert.SentinelNotificationError = null;
                }
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                foreach (var alert in batch)
                {
                    alert.SentinelNotificationStatus = AlertNotificationStatus.Failed;
                    alert.SentinelNotificationError = Truncate(ex.Message, 1024);
                }
                log.LogWarning(ex, "Failed to publish {AlertCount} alert(s) to Sentinel sink.", batch.Length);
            }
        }
    }

    private static void MarkFailed(IReadOnlyList<Alert> alerts, string message)
    {
        foreach (var alert in alerts)
        {
            alert.SentinelNotificationStatus = AlertNotificationStatus.Failed;
            alert.SentinelNotificationError = Truncate(message, 1024);
        }
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}

public sealed class SentinelTelemetrySink(
    AzureMonitorLogsIngestionClient client,
    IOptions<SentinelSinkOptions> options,
    ILogger<SentinelTelemetrySink> log) : ITelemetrySink
{
    private readonly SentinelSinkOptions _options = options.Value;

    public async Task PublishAsync(Agent agent, IReadOnlyList<TelemetryEvent> events, CancellationToken ct)
    {
        if (!_options.Enabled || !_options.TelemetryEnabled || events.Count == 0)
        {
            return;
        }

        var validationErrors = _options.Validate();
        if (validationErrors.Count > 0)
        {
            log.LogWarning("Sentinel telemetry sink is enabled but configuration is invalid: {Errors}", validationErrors);
            return;
        }

        foreach (var batch in events.Chunk(Math.Clamp(_options.BatchSize, 1, 1000)))
        {
            try
            {
                var records = batch.Select(ev => SentinelPayloadFormatter.FormatTelemetry(agent, ev)).ToList();
                await client.UploadAsync(_options.TelemetryStreamName, records, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                log.LogWarning(
                    ex,
                    "Failed to publish {TelemetryCount} telemetry event(s) to Sentinel sink for agent {AgentId}.",
                    batch.Length,
                    agent.Id);
            }
        }
    }
}

public interface IAzureMonitorTokenProvider
{
    Task<string> GetAccessTokenAsync(CancellationToken ct);
}

public sealed class AzureMonitorTokenProvider(
    HttpClient http,
    IOptions<SentinelSinkOptions> options,
    TimeProvider timeProvider,
    ILogger<AzureMonitorTokenProvider> log) : IAzureMonitorTokenProvider
{
    private readonly SentinelSinkOptions _options = options.Value;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private string? _accessToken;
    private DateTimeOffset _expiresAt;

    public async Task<string> GetAccessTokenAsync(CancellationToken ct)
    {
        if (HasUsableCachedToken())
        {
            return _accessToken!;
        }

        await _lock.WaitAsync(ct);
        try
        {
            if (HasUsableCachedToken())
            {
                return _accessToken!;
            }

            var token = _options.IsManagedIdentityMode()
                ? await RequestManagedIdentityTokenAsync(ct)
                : await RequestClientSecretTokenAsync(ct);

            _accessToken = token.AccessToken;
            _expiresAt = token.ExpiresAt;
            return _accessToken;
        }
        finally
        {
            _lock.Release();
        }
    }

    private bool HasUsableCachedToken()
        => !string.IsNullOrWhiteSpace(_accessToken)
            && _expiresAt > timeProvider.GetUtcNow().AddMinutes(5);

    private async Task<TokenResponse> RequestClientSecretTokenAsync(CancellationToken ct)
    {
        var authorityHost = _options.AuthorityHost.TrimEnd('/');
        var uri = new Uri($"{authorityHost}/{Uri.EscapeDataString(_options.TenantId)}/oauth2/v2.0/token");
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = _options.ClientId,
                ["client_secret"] = _options.ClientSecret,
                ["grant_type"] = "client_credentials",
                ["scope"] = $"{_options.TokenAudience.TrimEnd('/')}/.default",
            }),
        };

        using var response = await http.SendAsync(request, ct);
        return await ReadTokenResponseAsync(response, ct);
    }

    private async Task<TokenResponse> RequestManagedIdentityTokenAsync(CancellationToken ct)
    {
        var endpoint = string.IsNullOrWhiteSpace(_options.ManagedIdentityEndpoint)
            ? "http://169.254.169.254/metadata/identity/oauth2/token"
            : _options.ManagedIdentityEndpoint;
        var separator = endpoint.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        var uri = $"{endpoint}{separator}api-version=2018-02-01&resource={Uri.EscapeDataString(_options.TokenAudience.TrimEnd('/'))}";
        if (!string.IsNullOrWhiteSpace(_options.ClientId))
        {
            uri += $"&client_id={Uri.EscapeDataString(_options.ClientId)}";
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Add("Metadata", "true");

        using var response = await http.SendAsync(request, ct);
        return await ReadTokenResponseAsync(response, ct);
    }

    private async Task<TokenResponse> ReadTokenResponseAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Azure Monitor token request returned {(int)response.StatusCode} {response.StatusCode}: {Truncate(body, 300)}",
                null,
                response.StatusCode);
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        if (!root.TryGetProperty("access_token", out var tokenProperty))
        {
            throw new InvalidOperationException("Azure Monitor token response did not include access_token.");
        }

        var accessToken = tokenProperty.GetString();
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new InvalidOperationException("Azure Monitor token response included an empty access_token.");
        }

        var expiresAt = timeProvider.GetUtcNow().AddMinutes(50);
        if (root.TryGetProperty("expires_in", out var expiresInProperty)
            && TryReadInt64(expiresInProperty, out var expiresIn))
        {
            expiresAt = timeProvider.GetUtcNow().AddSeconds(Math.Max(expiresIn, 60));
        }
        else if (root.TryGetProperty("expires_on", out var expiresOnProperty)
            && TryReadInt64(expiresOnProperty, out var expiresOn))
        {
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresOn);
        }
        else
        {
            log.LogDebug("Azure Monitor token response did not include expires_in or expires_on; using conservative cache lifetime.");
        }

        return new TokenResponse(accessToken, expiresAt);
    }

    private static bool TryReadInt64(JsonElement element, out long value)
    {
        if (element.ValueKind == JsonValueKind.Number)
        {
            return element.TryGetInt64(out value);
        }
        if (element.ValueKind == JsonValueKind.String)
        {
            return long.TryParse(element.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }
        value = 0;
        return false;
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    private readonly record struct TokenResponse(string AccessToken, DateTimeOffset ExpiresAt);
}

public sealed class AzureMonitorLogsIngestionClient(
    HttpClient http,
    IAzureMonitorTokenProvider tokenProvider,
    IOptions<SentinelSinkOptions> options)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = null,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly SentinelSinkOptions _options = options.Value;

    public async Task UploadAsync<T>(string streamName, IReadOnlyList<T> records, CancellationToken ct)
    {
        if (records.Count == 0)
        {
            return;
        }

        var endpoint = BuildUploadUri(streamName);
        var maxRetries = Math.Clamp(_options.MaxRetries, 0, 10);
        for (var attempt = 0; ; attempt++)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.TimeoutSeconds, 1, 300)));

            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                await tokenProvider.GetAccessTokenAsync(timeout.Token));
            request.Headers.Add("x-ms-client-request-id", Guid.NewGuid().ToString());
            request.Content = new StringContent(JsonSerializer.Serialize(records, JsonOptions), Encoding.UTF8, "application/json");

            using var response = await http.SendAsync(request, timeout.Token);
            if (response.IsSuccessStatusCode)
            {
                return;
            }

            var body = await response.Content.ReadAsStringAsync(timeout.Token);
            if (!IsRetryable(response.StatusCode) || attempt >= maxRetries)
            {
                throw new HttpRequestException(
                    $"Azure Monitor Logs Ingestion returned {(int)response.StatusCode} {response.StatusCode}: {Truncate(body, 500)}",
                    null,
                    response.StatusCode);
            }

            var delay = RetryDelay(response, attempt);
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, ct);
            }
        }
    }

    private Uri BuildUploadUri(string streamName)
    {
        var baseUri = new Uri(_options.EndpointUrl.TrimEnd('/') + "/");
        var path = $"dataCollectionRules/{Uri.EscapeDataString(_options.DcrImmutableId)}/streams/{Uri.EscapeDataString(streamName)}";
        return new Uri(baseUri, $"{path}?api-version={Uri.EscapeDataString(_options.ApiVersion)}");
    }

    private TimeSpan RetryDelay(HttpResponseMessage response, int attempt)
    {
        if (response.Headers.RetryAfter?.Delta is { } delta)
        {
            return delta;
        }

        var baseDelay = Math.Max(_options.RetryBaseDelayMilliseconds, 0);
        if (baseDelay == 0)
        {
            return TimeSpan.Zero;
        }

        var multiplier = Math.Pow(2, attempt);
        return TimeSpan.FromMilliseconds(Math.Min(baseDelay * multiplier, 10_000));
    }

    private static bool IsRetryable(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.RequestTimeout
            or HttpStatusCode.TooManyRequests
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}

public static class SentinelPayloadFormatter
{
    public static object FormatAlert(Agent agent, Alert alert, TelemetryEvent? telemetryEvent) => new
    {
        TimeGenerated = alert.CreatedAt.UtcDateTime,
        EventKind = "alert",
        TawnyTenantId = agent.TenantId.ToString(),
        AgentId = agent.Id.ToString(),
        AgentHostname = agent.Hostname,
        AgentOs = agent.OperatingSystem.ToString(),
        AgentOsVersion = agent.OsVersion,
        AgentArchitecture = agent.Architecture.ToString(),
        AgentVersion = agent.AgentVersion,
        AlertId = alert.Id,
        AlertRuleId = alert.AlertRuleId.ToString(),
        AlertTitle = alert.Title,
        AlertDescription = alert.Description,
        AlertSeverity = alert.Severity.ToString(),
        AlertStatus = alert.Status.ToString(),
        AlertCreatedAt = alert.CreatedAt.UtcDateTime,
        TelemetryEventId = telemetryEvent?.Id ?? alert.TelemetryEventId,
        TelemetryEventType = telemetryEvent?.EventType.ToString(),
        TelemetryOccurredAt = telemetryEvent?.OccurredAt.UtcDateTime,
        TelemetryReceivedAt = telemetryEvent?.ReceivedAt.UtcDateTime,
        TelemetryPayload = telemetryEvent?.Payload,
    };

    public static object FormatTelemetry(Agent agent, TelemetryEvent telemetryEvent) => new
    {
        TimeGenerated = telemetryEvent.OccurredAt.UtcDateTime,
        EventKind = "telemetry",
        TawnyTenantId = telemetryEvent.TenantId.ToString(),
        AgentId = agent.Id.ToString(),
        AgentHostname = agent.Hostname,
        AgentOs = agent.OperatingSystem.ToString(),
        AgentOsVersion = agent.OsVersion,
        AgentArchitecture = agent.Architecture.ToString(),
        AgentVersion = agent.AgentVersion,
        TelemetryEventId = telemetryEvent.Id,
        TelemetryEventType = telemetryEvent.EventType.ToString(),
        TelemetryOccurredAt = telemetryEvent.OccurredAt.UtcDateTime,
        TelemetryReceivedAt = telemetryEvent.ReceivedAt.UtcDateTime,
        TelemetryPayload = telemetryEvent.Payload,
    };
}
