using Microsoft.EntityFrameworkCore;
using Tawny.Api.Models;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Services;

public sealed class ThreatIntelLookupService(TawnyDbContext db)
{
    public async Task<IReadOnlyList<ThreatIntelMatchResponse>> LookupAsync(
        Guid tenantId,
        IReadOnlyList<string> values,
        CancellationToken ct)
    {
        var normalised = values
            .Select(Normalise)
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (normalised.Length == 0)
        {
            return [];
        }

        var feeds = await db.ThreatIntelFeeds
            .AsNoTracking()
            .Where(f => f.TenantId == tenantId)
            .Select(f => new { f.Id, f.Name })
            .ToDictionaryAsync(f => f.Id, ct);
        if (feeds.Count == 0)
        {
            return [];
        }

        var rules = await db.AlertRules
            .AsNoTracking()
            .Where(r => r.TenantId == tenantId
                && r.IsEnabled
                && r.Format == AlertRuleFormat.Ioc
                && r.MatchValue != null
                && normalised.Contains(r.MatchValue.ToLower()))
            .Select(r => new
            {
                r.Id,
                r.Name,
                r.Description,
                r.Severity,
                r.MatchValue,
                r.ExternalId,
            })
            .ToListAsync(ct);

        var matches = new List<ThreatIntelMatchResponse>();
        foreach (var rule in rules)
        {
            if (!TryParseFeedExternalId(rule.ExternalId, out var feedId, out var kind)
                || !feeds.TryGetValue(feedId, out var feed))
            {
                continue;
            }

            matches.Add(new ThreatIntelMatchResponse(
                rule.MatchValue!,
                kind,
                rule.Id,
                rule.Name,
                rule.Description,
                rule.Severity,
                feed.Id,
                feed.Name));
        }

        return matches;
    }

    private static string Normalise(string? value) => value?.Trim().ToLowerInvariant() ?? "";

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
}
