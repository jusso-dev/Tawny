using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.ThreatIntel;

public record FetchedIndicator(string Kind, string Value, string? Description);

public record FetchResult(
    bool Modified,
    string? Etag,
    IReadOnlyList<FetchedIndicator> Indicators,
    IReadOnlyList<string> Skipped);

public class ThreatIntelFetchException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Pulls indicators from supported TI feed shapes. Returns raw FetchedIndicator
/// records — the caller decides which to turn into AlertRules.
/// </summary>
public class ThreatIntelFetcher(HttpClient http, ILogger<ThreatIntelFetcher> log)
{
    private static readonly Regex Sha256Re = new(@"\b[a-fA-F0-9]{64}\b", RegexOptions.Compiled);
    private static readonly Regex Sha1Re = new(@"\b[a-fA-F0-9]{40}\b", RegexOptions.Compiled);
    private static readonly Regex Ipv4Re = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);
    private static readonly Regex DomainRe = new(@"\b(?=.{4,253}\b)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b", RegexOptions.Compiled);
    private const int MaxIndicatorsPerFeed = 5_000;

    public async Task<FetchResult> FetchAsync(ThreatIntelFeed feed, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, feed.Url);
        if (!string.IsNullOrWhiteSpace(feed.AuthHeaderName) && !string.IsNullOrWhiteSpace(feed.AuthHeaderValueEncrypted))
        {
            // We're using the column name "Encrypted" defensively but storing plaintext here;
            // a real deployment would decrypt via DPAPI or the configured secret store.
            request.Headers.TryAddWithoutValidation(feed.AuthHeaderName, feed.AuthHeaderValueEncrypted);
        }
        if (!string.IsNullOrWhiteSpace(feed.Etag))
        {
            request.Headers.IfNoneMatch.Add(new EntityTagHeaderValue($"\"{feed.Etag}\""));
        }
        request.Headers.UserAgent.ParseAdd("Tawny-EDR/1.0 (+https://github.com/jusso-dev/Tawny)");

        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == System.Net.HttpStatusCode.NotModified)
        {
            return new FetchResult(false, feed.Etag, [], []);
        }
        if (!response.IsSuccessStatusCode)
        {
            throw new ThreatIntelFetchException($"Feed responded with {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        var body = await response.Content.ReadAsStringAsync(ct);
        var etag = response.Headers.ETag?.Tag?.Trim('"');
        var indicators = feed.Kind switch
        {
            ThreatIntelFeedKind.UrlhausCsv => ParseUrlhausCsv(body),
            ThreatIntelFeedKind.UrlhausJson => ParseUrlhausJson(body),
            ThreatIntelFeedKind.OtxPulse => ParseOtxPulse(body),
            ThreatIntelFeedKind.MispEvents => ParseMispEvents(body),
            ThreatIntelFeedKind.Taxii21 => ParseTaxii21(body),
            ThreatIntelFeedKind.GenericCsv => ParseGenericCsv(body),
            _ => throw new ThreatIntelFetchException($"Unsupported feed kind: {feed.Kind}"),
        };

        var (taken, skipped) = TakeWithBudget(indicators);
        if (skipped.Count > 0)
        {
            log.LogInformation("Feed {Feed} returned {Total} indicators, kept {Kept}, skipped {Skipped}.",
                feed.Name, indicators.Count, taken.Count, skipped.Count);
        }
        return new FetchResult(true, etag, taken, skipped);
    }

    // ---------- parsers ----------

    private static List<FetchedIndicator> ParseUrlhausCsv(string body)
    {
        // abuse.ch URLhaus CSV: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
        var result = new List<FetchedIndicator>();
        foreach (var rawLine in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var cols = SplitCsv(line);
            if (cols.Count < 3) continue;
            var url = cols[2].Trim('"');
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
            {
                result.Add(new FetchedIndicator("domain", uri.Host, $"URLhaus: {url}"));
            }
        }
        return result;
    }

    private static List<FetchedIndicator> ParseUrlhausJson(string body)
    {
        var result = new List<FetchedIndicator>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            // URLhaus JSON: { "1": { "url": "...", "host": "...", "tags": [...] }, ... }
            foreach (var entry in doc.RootElement.EnumerateObject())
            {
                if (entry.Value.ValueKind != JsonValueKind.Object) continue;
                if (entry.Value.TryGetProperty("host", out var host) && host.ValueKind == JsonValueKind.String)
                {
                    var value = host.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        result.Add(new FetchedIndicator("domain", value, "URLhaus host"));
                    }
                }
            }
        }
        catch (JsonException ex)
        {
            throw new ThreatIntelFetchException("URLhaus JSON parse failed", ex);
        }
        return result;
    }

    private static List<FetchedIndicator> ParseOtxPulse(string body)
    {
        // OTX pulse JSON: { "results": [ { "indicators": [ { "type": "IPv4", "indicator": "1.2.3.4" } ] } ] }
        var result = new List<FetchedIndicator>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("results", out var results)) return result;
            foreach (var pulse in results.EnumerateArray())
            {
                if (!pulse.TryGetProperty("indicators", out var indicators)) continue;
                foreach (var ind in indicators.EnumerateArray())
                {
                    var type = ind.GetProperty("type").GetString();
                    var value = ind.GetProperty("indicator").GetString();
                    if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(type)) continue;
                    var kind = type.ToLowerInvariant() switch
                    {
                        "ipv4" => "ipv4",
                        "ipv6" => "ipv6",
                        "domain" or "hostname" => "domain",
                        "filehash-sha256" => "sha256",
                        "filehash-sha1" => "sha1",
                        _ => null,
                    };
                    if (kind is not null)
                    {
                        result.Add(new FetchedIndicator(kind, value, $"OTX {type}"));
                    }
                }
            }
        }
        catch (JsonException ex)
        {
            throw new ThreatIntelFetchException("OTX pulse parse failed", ex);
        }
        return result;
    }

    private static List<FetchedIndicator> ParseMispEvents(string body)
    {
        // MISP /events/restSearch returns { "response": [{ "Event": { "Attribute": [{ "type": "...", "value": "..." }]}}]}
        var result = new List<FetchedIndicator>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("response", out var response)) return result;
            foreach (var entry in response.EnumerateArray())
            {
                if (!entry.TryGetProperty("Event", out var eventNode)) continue;
                if (!eventNode.TryGetProperty("Attribute", out var attributes)) continue;
                foreach (var attr in attributes.EnumerateArray())
                {
                    var type = attr.GetProperty("type").GetString();
                    var value = attr.GetProperty("value").GetString();
                    if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(type)) continue;
                    var kind = type switch
                    {
                        "ip-src" or "ip-dst" => "ipv4",
                        "domain" or "hostname" => "domain",
                        "sha256" => "sha256",
                        "sha1" => "sha1",
                        _ => null,
                    };
                    if (kind is not null)
                    {
                        result.Add(new FetchedIndicator(kind, value, $"MISP {type}"));
                    }
                }
            }
        }
        catch (JsonException ex)
        {
            throw new ThreatIntelFetchException("MISP parse failed", ex);
        }
        return result;
    }

    private static List<FetchedIndicator> ParseTaxii21(string body)
    {
        // TAXII 2.1 envelope: { "objects": [ STIX bundles... ] }
        var result = new List<FetchedIndicator>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("objects", out var objects)) return result;
            foreach (var obj in objects.EnumerateArray())
            {
                if (!obj.TryGetProperty("type", out var type) || type.GetString() != "indicator") continue;
                if (!obj.TryGetProperty("pattern", out var pattern)) continue;
                var raw = pattern.GetString() ?? "";
                // Reuse the same simple pattern shapes the existing IoC importer understands.
                foreach (var match in Regex.Matches(raw, @"\[(?<kind>file:hashes\.'SHA-256'|file:hashes\.'SHA-1'|ipv4-addr:value|ipv6-addr:value|domain-name:value)\s*=\s*'(?<value>[^']+)'\]").Cast<Match>())
                {
                    var k = match.Groups["kind"].Value;
                    var v = match.Groups["value"].Value;
                    var kind = k switch
                    {
                        "file:hashes.'SHA-256'" => "sha256",
                        "file:hashes.'SHA-1'" => "sha1",
                        "ipv4-addr:value" => "ipv4",
                        "ipv6-addr:value" => "ipv6",
                        "domain-name:value" => "domain",
                        _ => null,
                    };
                    if (kind is not null)
                    {
                        result.Add(new FetchedIndicator(kind, v, $"TAXII {k}"));
                    }
                }
            }
        }
        catch (JsonException ex)
        {
            throw new ThreatIntelFetchException("TAXII parse failed", ex);
        }
        return result;
    }

    private static List<FetchedIndicator> ParseGenericCsv(string body)
    {
        // One indicator per line (or first column of a CSV). Auto-detect kind by shape.
        var result = new List<FetchedIndicator>();
        foreach (var rawLine in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var cols = SplitCsv(line);
            var value = cols.Count == 0 ? line : cols[0].Trim('"');
            var kind = DetectKind(value);
            if (kind is not null)
            {
                result.Add(new FetchedIndicator(kind, value, "Generic CSV"));
            }
        }
        return result;
    }

    private static string? DetectKind(string value)
    {
        if (Sha256Re.IsMatch(value) && value.Length == 64) return "sha256";
        if (Sha1Re.IsMatch(value) && value.Length == 40) return "sha1";
        if (Ipv4Re.IsMatch(value)) return "ipv4";
        if (DomainRe.IsMatch(value)) return "domain";
        return null;
    }

    private static List<string> SplitCsv(string line)
    {
        return line.Split(',').Select(p => p.Trim()).ToList();
    }

    private static (List<FetchedIndicator> Taken, List<string> Skipped) TakeWithBudget(IReadOnlyList<FetchedIndicator> all)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var taken = new List<FetchedIndicator>();
        var skipped = new List<string>();
        foreach (var indicator in all)
        {
            var key = $"{indicator.Kind}:{indicator.Value}";
            if (!seen.Add(key)) continue;
            if (taken.Count >= MaxIndicatorsPerFeed)
            {
                skipped.Add(key);
                continue;
            }
            taken.Add(indicator);
        }
        return (taken, skipped);
    }
}
