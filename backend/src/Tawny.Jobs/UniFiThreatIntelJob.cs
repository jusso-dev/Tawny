using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Jobs;

public sealed class UniFiKelpieOptions
{
    public bool Enabled { get; set; }
    public string BaseUrl { get; set; } = "";
    public string ApiToken { get; set; } = "";
    public int TimeoutSeconds { get; set; } = 10;
}

public sealed record UniFiHuntResult(
    int RecordsChecked,
    int IndicatorsChecked,
    int MatchingEvents,
    int CasesCreated);

public sealed partial class UniFiThreatIntelJob(
    TawnyDbContext db,
    UniFiConnector connector,
    IOptions<UniFiKelpieOptions> kelpieOptions,
    TimeProvider timeProvider,
    ILogger<UniFiThreatIntelJob> log)
{
    private const int MaxCaseSummaryCharacters = 24_000;
    private readonly UniFiKelpieOptions _kelpie = kelpieOptions.Value;

    [DisableConcurrentExecution(timeoutInSeconds: 300)]
    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var now = timeProvider.GetUtcNow();
        var integrations = await db.UniFiIntegrations
            .Where(i => i.IsEnabled)
            .ToListAsync(ct);

        foreach (var integration in integrations)
        {
            if (ct.IsCancellationRequested)
            {
                break;
            }

            var interval = TimeSpan.FromMinutes(Math.Clamp(integration.IntervalMinutes, 1, 1440));
            if (integration.LastRunAt is not null && now - integration.LastRunAt < interval)
            {
                continue;
            }

            try
            {
                await RunIntegrationAsync(integration, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                log.LogWarning(
                    ex,
                    "Scheduled UniFi integration hunt failed for tenant {TenantId}; continuing.",
                    integration.TenantId);
            }
        }
    }

    public async Task<UniFiHuntResult> RunIntegrationAsync(
        UniFiIntegration integration,
        CancellationToken ct)
    {
        var now = timeProvider.GetUtcNow();
        integration.LastRunAt = now;
        integration.LastError = null;

        try
        {
            var records = await connector.FetchRecordsAsync(integration, ct);
            var recordIndicators = records
                .Select(record => (Record: record, Indicators: ExtractIndicators(record)))
                .ToArray();
            var allIndicators = recordIndicators
                .SelectMany(item => item.Indicators)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var matches = await FindMatchesAsync(integration.TenantId, allIndicators, ct);
            var matchesByValue = matches
                .GroupBy(match => match.Value, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);

            var matchingEvents = 0;
            var casesCreated = 0;
            foreach (var (record, indicators) in recordIndicators)
            {
                var eventMatches = indicators
                    .SelectMany(value => matchesByValue.GetValueOrDefault(value, []))
                    .DistinctBy(match => match.RuleId)
                    .ToArray();
                if (eventMatches.Length == 0)
                {
                    continue;
                }

                matchingEvents++;
                var eventReference = EventReference(record);
                var matchedValues = eventMatches
                    .Select(match => match.Value)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var dedupeKey = Sha256($"{eventReference}:{string.Join(',', matchedValues)}");
                if (await db.UniFiEventMatches.AnyAsync(
                        match => match.TenantId == integration.TenantId
                            && match.DedupeKey == dedupeKey,
                        ct))
                {
                    continue;
                }

                var created = await CreateKelpieCaseAsync(
                    integration,
                    record,
                    eventReference,
                    eventMatches,
                    ct);
                db.UniFiEventMatches.Add(new UniFiEventMatch
                {
                    TenantId = integration.TenantId,
                    UniFiIntegrationId = integration.Id,
                    DedupeKey = dedupeKey,
                    EventReference = eventReference,
                    MatchedValuesJson = JsonSerializer.Serialize(matchedValues),
                    KelpieCaseId = created.Id,
                    KelpieCaseNumber = created.CaseNumber,
                    CreatedAt = now,
                });
                await db.SaveChangesAsync(ct);
                casesCreated++;
            }

            integration.LastSuccessAt = now;
            integration.LastRecordsChecked = records.Count;
            integration.LastIndicatorsChecked = allIndicators.Length;
            integration.LastMatchingEvents = matchingEvents;
            integration.LastCasesCreated = casesCreated;
            integration.LastError = null;
            await db.SaveChangesAsync(ct);

            return new UniFiHuntResult(
                records.Count,
                allIndicators.Length,
                matchingEvents,
                casesCreated);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            integration.LastError = Truncate(ex.Message, 2048);
            await db.SaveChangesAsync(ct);
            log.LogWarning(ex, "UniFi integration hunt failed for tenant {TenantId}.", integration.TenantId);
            throw;
        }
    }

    private async Task<IReadOnlyList<ThreatIntelMatch>> FindMatchesAsync(
        Guid tenantId,
        IReadOnlyList<string> indicators,
        CancellationToken ct)
    {
        if (indicators.Count == 0)
        {
            return [];
        }

        var feeds = await db.ThreatIntelFeeds
            .AsNoTracking()
            .Where(feed => feed.TenantId == tenantId)
            .Select(feed => new { feed.Id, feed.Name })
            .ToDictionaryAsync(feed => feed.Id, ct);
        if (feeds.Count == 0)
        {
            return [];
        }

        var normalised = indicators.Select(value => value.ToLowerInvariant()).ToArray();
        var rules = await db.AlertRules
            .AsNoTracking()
            .Where(rule => rule.TenantId == tenantId
                && rule.IsEnabled
                && rule.Format == AlertRuleFormat.Ioc
                && rule.MatchValue != null
                && normalised.Contains(rule.MatchValue.ToLower()))
            .Select(rule => new
            {
                rule.Id,
                rule.Name,
                rule.Description,
                rule.Severity,
                rule.MatchValue,
                rule.ExternalId,
            })
            .ToListAsync(ct);

        var matches = new List<ThreatIntelMatch>();
        foreach (var rule in rules)
        {
            if (!TryParseFeedExternalId(rule.ExternalId, out var feedId, out var kind)
                || !feeds.TryGetValue(feedId, out var feed))
            {
                continue;
            }

            matches.Add(new ThreatIntelMatch(
                rule.MatchValue!,
                kind,
                rule.Id,
                rule.Name,
                rule.Description,
                rule.Severity,
                feed.Name));
        }

        return matches;
    }

    private async Task<KelpieCaseResponse> CreateKelpieCaseAsync(
        UniFiIntegration integration,
        JsonElement record,
        string eventReference,
        IReadOnlyList<ThreatIntelMatch> matches,
        CancellationToken ct)
    {
        if (!_kelpie.Enabled
            || !Uri.TryCreate(_kelpie.BaseUrl, UriKind.Absolute, out var baseUri)
            || string.IsNullOrWhiteSpace(_kelpie.ApiToken))
        {
            throw new InvalidOperationException(
                "Kelpie case sink must be enabled and configured before UniFi matching can create cases.");
        }

        var values = matches
            .Select(match => match.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var details = string.Join(
            "\n",
            matches.Select(match =>
                $"- `{match.Value}`: {match.FeedName} ({match.Kind}, {match.Severity.ToString().ToLowerInvariant()})"));
        var summary = Truncate(
            $"UniFi network event matched Tawny threat intelligence.\n\n"
            + $"## Matches\n{details}\n\n"
            + $"## UniFi event\n```json\n{record.GetRawText().Replace("```", "``\u200b`", StringComparison.Ordinal)}\n```",
            MaxCaseSummaryCharacters);
        var payload = new
        {
            title = Truncate($"UniFi TI match: {string.Join(", ", values.Take(3))}", 255),
            summary,
            severity = matches.Max(match => match.Severity).ToString().ToLowerInvariant(),
            classification = "other",
            tags = new[]
            {
                "tawny",
                "unifi",
                "threat-intel",
                $"unifi-event-{TagValue(eventReference)}",
            },
            sourceSystem = "tawny-unifi",
            sourceReference = eventReference,
        };

        using var http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(Math.Clamp(_kelpie.TimeoutSeconds, 1, 60)),
        };
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(new Uri(EnsureTrailingSlash(baseUri.ToString())), "api/v1/cases"))
        {
            Content = JsonContent.Create(payload),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _kelpie.ApiToken.Trim());
        using var response = await http.SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Kelpie API returned {(int)response.StatusCode} {response.StatusCode}.",
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

    private static HashSet<string> ExtractIndicators(JsonElement record)
    {
        var indicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in StringValues(record))
        {
            foreach (Match token in IpTokenRegex().Matches(value))
            {
                var candidate = token.Value.Trim('[', ']', '(', ')', ',', ';');
                if (IPAddress.TryParse(candidate, out var address))
                {
                    indicators.Add(address.ToString().ToLowerInvariant());
                }
            }

            foreach (Match domain in DomainRegex().Matches(value))
            {
                indicators.Add(domain.Value.TrimEnd('.').ToLowerInvariant());
            }
        }

        return indicators;
    }

    private static IEnumerable<string> StringValues(JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                if (value.GetString() is { } text)
                {
                    yield return text;
                }
                break;
            case JsonValueKind.Object:
                foreach (var property in value.EnumerateObject())
                {
                    foreach (var nestedText in StringValues(property.Value))
                    {
                        yield return nestedText;
                    }
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray())
                {
                    foreach (var nestedText in StringValues(item))
                    {
                        yield return nestedText;
                    }
                }
                break;
        }
    }

    private static string EventReference(JsonElement record)
    {
        foreach (var name in new[] { "id", "_id", "event_id", "flow_id" })
        {
            foreach (var property in record.EnumerateObject())
            {
                if (!property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var value = property.Value.ToString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return Truncate(value, 255);
                }
            }
        }

        return Sha256(record.GetRawText())[..24];
    }

    private static bool TryParseFeedExternalId(string? externalId, out Guid feedId, out string kind)
    {
        const string prefix = "ti-feed:";
        feedId = default;
        kind = "";
        if (string.IsNullOrWhiteSpace(externalId)
            || !externalId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var feedEnd = externalId.IndexOf(':', prefix.Length);
        if (feedEnd < 0 || !Guid.TryParse(externalId[prefix.Length..feedEnd], out feedId))
        {
            return false;
        }

        var kindEnd = externalId.IndexOf(':', feedEnd + 1);
        if (kindEnd < 0)
        {
            return false;
        }

        kind = externalId[(feedEnd + 1)..kindEnd];
        return kind.Length > 0;
    }

    private static string Sha256(string value)
        => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string EnsureTrailingSlash(string value)
        => value.EndsWith("/", StringComparison.Ordinal) ? value : value + "/";

    private static string TagValue(string value)
    {
        var tag = new string(value
            .Trim()
            .ToLowerInvariant()
            .Select(character => char.IsLetterOrDigit(character) || character is '-' or '_'
                ? character
                : '-')
            .ToArray());
        return string.IsNullOrWhiteSpace(tag) ? "unknown" : tag;
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    [GeneratedRegex(@"[0-9A-Fa-f:.]{3,}", RegexOptions.CultureInvariant)]
    private static partial Regex IpTokenRegex();

    [GeneratedRegex(
        @"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w-])",
        RegexOptions.CultureInvariant)]
    private static partial Regex DomainRegex();

    private sealed record ThreatIntelMatch(
        string Value,
        string Kind,
        Guid RuleId,
        string RuleName,
        string? Description,
        AlertSeverity Severity,
        string FeedName);

    private sealed record KelpieCaseResponse(string Id, string? CaseNumber);
}
