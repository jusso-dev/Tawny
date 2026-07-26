using System.Net;
using System.Text.Json;
using Tawny.Domain.Entities;
using Tawny.Infrastructure.Security;

namespace Tawny.Jobs;

public sealed record UniFiApplicationInfo(string ApplicationVersion);

public sealed class UniFiConnector(IIntegrationSecretProtector secrets)
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    public async Task<UniFiApplicationInfo> FetchInfoAsync(
        UniFiIntegration integration,
        CancellationToken ct)
    {
        var baseUri = RequirePrivateHttpUri(integration.BaseUrl, "Controller URL");
        var infoUri = new Uri(baseUri, "/proxy/network/integration/v1/info");
        using var document = await GetJsonAsync(integration, infoUri, ct);
        if (!document.RootElement.TryGetProperty("applicationVersion", out var version)
            || version.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(version.GetString()))
        {
            throw new InvalidOperationException("UniFi info response has no applicationVersion.");
        }

        return new UniFiApplicationInfo(version.GetString()!);
    }

    public async Task<IReadOnlyList<JsonElement>> FetchRecordsAsync(
        UniFiIntegration integration,
        CancellationToken ct)
    {
        var eventsUri = RequirePrivateHttpUri(integration.EventsUrl, "Events URL");
        using var document = await GetJsonAsync(integration, eventsUri, ct);
        var records = document.RootElement;

        if (!string.IsNullOrWhiteSpace(integration.RecordsPath))
        {
            foreach (var segment in integration.RecordsPath.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                if (records.ValueKind != JsonValueKind.Object
                    || !records.TryGetProperty(segment, out records))
                {
                    throw new InvalidOperationException(
                        $"UniFi response has no records path '{integration.RecordsPath}'.");
                }
            }
        }

        if (records.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("UniFi event records must be a JSON array.");
        }

        return records.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.Object)
            .Select(item => item.Clone())
            .ToArray();
    }

    public static Uri RequirePrivateHttpUri(string value, string fieldName)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(
                $"{fieldName} must be an absolute HTTP or HTTPS URL without credentials or a fragment.");
        }

        if (!IPAddress.TryParse(uri.Host, out var address) || !IsPrivate(address))
        {
            throw new InvalidOperationException($"{fieldName} must use a loopback or private-LAN IP address.");
        }

        return uri;
    }

    private async Task<JsonDocument> GetJsonAsync(
        UniFiIntegration integration,
        Uri uri,
        CancellationToken ct)
    {
        using var handler = new HttpClientHandler();
        if (!integration.VerifyTls)
        {
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        using var http = new HttpClient(handler) { Timeout = RequestTimeout };
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.TryAddWithoutValidation(
            integration.ApiKeyHeader,
            secrets.Unprotect(integration.ApiKeyEncrypted));
        request.Headers.UserAgent.ParseAdd("Tawny-EDR/1.0");

        using var response = await http.SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"UniFi API returned {(int)response.StatusCode} {response.StatusCode}.",
                null,
                response.StatusCode);
        }

        try
        {
            return JsonDocument.Parse(body);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("UniFi API returned invalid JSON.", ex);
        }
    }

    private static bool IsPrivate(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return bytes[0] == 10
                || bytes[0] == 127
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254);
        }

        return address.IsIPv6LinkLocal
            || (bytes[0] & 0xfe) == 0xfc;
    }
}
