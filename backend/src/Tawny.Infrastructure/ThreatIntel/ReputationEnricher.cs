using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.ThreatIntel;

public class ReputationOptions
{
    public string? VirusTotalApiKey { get; set; }
    public string? AbuseIpDbApiKey { get; set; }
    public string? GreyNoiseApiKey { get; set; }
    public int CacheTtlHours { get; set; } = 24;
    public int TimeoutSeconds { get; set; } = 10;
    public bool EnrichAlertsAutomatically { get; set; } = true;
}

public record ReputationLookup(
    ReputationProvider Provider,
    ReputationVerdict Verdict,
    int? Score,
    object Detail);

/// <summary>
/// Looks up reputation for IoCs (hashes, IPs, domains) from configured providers
/// and caches the result. Designed to be safe to call from the alert pipeline:
/// each provider is HTTP-bound, has a short timeout, and respects the cache.
/// </summary>
public class ReputationEnricher(
    TawnyDbContext db,
    HttpClient http,
    IOptions<ReputationOptions> options,
    TimeProvider timeProvider,
    ILogger<ReputationEnricher> log)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ReputationOptions _opts = options.Value;

    public async Task<IReadOnlyList<ReputationLookup>> LookupAsync(
        Guid tenantId,
        string kind,
        string value,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        var providers = ProvidersForKind(kind).ToList();
        if (providers.Count == 0) return [];

        var results = new List<ReputationLookup>();
        foreach (var provider in providers)
        {
            var cached = await TryCachedAsync(tenantId, provider, kind, value, ct);
            if (cached is not null)
            {
                results.Add(cached);
                continue;
            }
            try
            {
                var fresh = await ProbeAsync(provider, kind, value, ct);
                if (fresh is null) continue;
                results.Add(fresh);
                await db.ReputationCache.AddAsync(new ReputationCacheEntry
                {
                    TenantId = tenantId,
                    Provider = provider,
                    IndicatorKind = kind,
                    IndicatorValue = value,
                    Verdict = fresh.Verdict,
                    Score = fresh.Score,
                    DetailJson = JsonSerializer.Serialize(fresh.Detail, JsonOptions),
                    FetchedAt = timeProvider.GetUtcNow(),
                    ExpiresAt = timeProvider.GetUtcNow().AddHours(_opts.CacheTtlHours),
                }, ct);
                await db.SaveChangesAsync(ct);
            }
            catch (Exception ex)
            {
                log.LogWarning(ex, "Reputation probe for {Provider} {Kind} {Value} failed", provider, kind, value);
            }
        }
        return results;
    }

    private async Task<ReputationLookup?> TryCachedAsync(
        Guid tenantId, ReputationProvider provider, string kind, string value, CancellationToken ct)
    {
        var now = timeProvider.GetUtcNow();
        var entry = await db.ReputationCache.AsNoTracking()
            .FirstOrDefaultAsync(r => r.TenantId == tenantId
                && r.Provider == provider
                && r.IndicatorKind == kind
                && r.IndicatorValue == value
                && r.ExpiresAt > now, ct);
        if (entry is null) return null;
        object detail;
        try { detail = JsonSerializer.Deserialize<JsonElement>(entry.DetailJson); }
        catch { detail = new { cached = true }; }
        return new ReputationLookup(entry.Provider, entry.Verdict, entry.Score, detail);
    }

    private async Task<ReputationLookup?> ProbeAsync(ReputationProvider provider, string kind, string value, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_opts.TimeoutSeconds, 1, 60)));
        return provider switch
        {
            ReputationProvider.VirusTotal => await ProbeVirusTotalAsync(kind, value, timeoutCts.Token),
            ReputationProvider.AbuseIpDb => await ProbeAbuseIpDbAsync(kind, value, timeoutCts.Token),
            ReputationProvider.GreyNoise => await ProbeGreyNoiseAsync(kind, value, timeoutCts.Token),
            _ => null,
        };
    }

    private async Task<ReputationLookup?> ProbeVirusTotalAsync(string kind, string value, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_opts.VirusTotalApiKey)) return null;
        if (kind is not "sha256" and not "sha1" and not "ipv4" and not "domain") return null;
        var path = kind switch
        {
            "sha256" or "sha1" => $"https://www.virustotal.com/api/v3/files/{Uri.EscapeDataString(value)}",
            "ipv4" => $"https://www.virustotal.com/api/v3/ip_addresses/{Uri.EscapeDataString(value)}",
            "domain" => $"https://www.virustotal.com/api/v3/domains/{Uri.EscapeDataString(value)}",
            _ => throw new InvalidOperationException(),
        };
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("x-apikey", _opts.VirusTotalApiKey);
        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return new ReputationLookup(ReputationProvider.VirusTotal, ReputationVerdict.Unknown, null, new { not_found = true });
        }
        if (!response.IsSuccessStatusCode)
        {
            return new ReputationLookup(ReputationProvider.VirusTotal, ReputationVerdict.Error, null, new { http_status = (int)response.StatusCode });
        }
        var body = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        var stats = doc.RootElement
            .GetProperty("data")
            .GetProperty("attributes")
            .GetProperty("last_analysis_stats");
        var malicious = stats.GetProperty("malicious").GetInt32();
        var suspicious = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
        var verdict = malicious switch
        {
            >= 5 => ReputationVerdict.Malicious,
            >= 1 => ReputationVerdict.Suspicious,
            _ => suspicious > 0 ? ReputationVerdict.Suspicious : ReputationVerdict.Clean,
        };
        return new ReputationLookup(ReputationProvider.VirusTotal, verdict, malicious, new
        {
            malicious,
            suspicious,
            stats = stats.GetRawText(),
        });
    }

    private async Task<ReputationLookup?> ProbeAbuseIpDbAsync(string kind, string value, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_opts.AbuseIpDbApiKey)) return null;
        if (kind != "ipv4") return null;
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(value)}&maxAgeInDays=90");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.TryAddWithoutValidation("Key", _opts.AbuseIpDbApiKey);
        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            return new ReputationLookup(ReputationProvider.AbuseIpDb, ReputationVerdict.Error, null,
                new { http_status = (int)response.StatusCode });
        }
        var body = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        var data = doc.RootElement.GetProperty("data");
        var score = data.GetProperty("abuseConfidenceScore").GetInt32();
        var verdict = score switch
        {
            >= 75 => ReputationVerdict.Malicious,
            >= 25 => ReputationVerdict.Suspicious,
            _ => ReputationVerdict.Clean,
        };
        return new ReputationLookup(ReputationProvider.AbuseIpDb, verdict, score, new
        {
            confidence = score,
            usage_type = data.TryGetProperty("usageType", out var ut) ? ut.GetString() : null,
            country = data.TryGetProperty("countryCode", out var cc) ? cc.GetString() : null,
            total_reports = data.TryGetProperty("totalReports", out var tr) ? tr.GetInt32() : 0,
        });
    }

    private async Task<ReputationLookup?> ProbeGreyNoiseAsync(string kind, string value, CancellationToken ct)
    {
        // GreyNoise Community API works without a key (rate-limited); the key
        // unlocks higher quotas. Only IPv4 is supported.
        if (kind != "ipv4") return null;
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://api.greynoise.io/v3/community/{Uri.EscapeDataString(value)}");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrWhiteSpace(_opts.GreyNoiseApiKey))
        {
            request.Headers.TryAddWithoutValidation("key", _opts.GreyNoiseApiKey);
        }
        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return new ReputationLookup(ReputationProvider.GreyNoise, ReputationVerdict.Unknown, null, new { not_found = true });
        }
        if (!response.IsSuccessStatusCode)
        {
            return new ReputationLookup(ReputationProvider.GreyNoise, ReputationVerdict.Error, null,
                new { http_status = (int)response.StatusCode });
        }
        var body = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        var classification = root.TryGetProperty("classification", out var c) ? c.GetString() : null;
        var verdict = classification switch
        {
            "malicious" => ReputationVerdict.Malicious,
            "suspicious" => ReputationVerdict.Suspicious,
            "benign" => ReputationVerdict.Clean,
            _ => ReputationVerdict.Unknown,
        };
        return new ReputationLookup(ReputationProvider.GreyNoise, verdict, null, new
        {
            classification,
            noise = root.TryGetProperty("noise", out var n) && n.ValueKind == JsonValueKind.True,
            riot = root.TryGetProperty("riot", out var r) && r.ValueKind == JsonValueKind.True,
            name = root.TryGetProperty("name", out var nm) ? nm.GetString() : null,
        });
    }

    private IEnumerable<ReputationProvider> ProvidersForKind(string kind)
    {
        if (!string.IsNullOrWhiteSpace(_opts.VirusTotalApiKey)
            && kind is "sha256" or "sha1" or "ipv4" or "domain")
        {
            yield return ReputationProvider.VirusTotal;
        }
        if (!string.IsNullOrWhiteSpace(_opts.AbuseIpDbApiKey) && kind == "ipv4")
        {
            yield return ReputationProvider.AbuseIpDb;
        }
        if (kind == "ipv4")
        {
            yield return ReputationProvider.GreyNoise;
        }
    }
}
