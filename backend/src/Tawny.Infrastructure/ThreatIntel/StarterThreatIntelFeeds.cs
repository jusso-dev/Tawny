using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure.ThreatIntel;

/// <summary>
/// Public starter TI sources kept in step with Kelpie's STARTER_TI_FEEDS.
/// Seeded for every tenant so IoC rules materialise without manual install.
/// </summary>
public static class StarterThreatIntelFeeds
{
    public sealed record Definition(
        string Name,
        string Url,
        ThreatIntelFeedKind Kind,
        AlertSeverity DefaultSeverity,
        int IntervalMinutes,
        bool IsEnabled);

    // Kelpie src/lib/ti/starter-feeds.ts — same URLs and default enabled flags.
    public static readonly IReadOnlyList<Definition> All =
    [
        new(
            "Feodo Tracker Botnet C2 IPs",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
            ThreatIntelFeedKind.GenericCsv,
            AlertSeverity.High,
            IntervalMinutes: 60,
            IsEnabled: true),
        new(
            "OpenPhish Community Phishing URLs",
            "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
            ThreatIntelFeedKind.GenericCsv,
            AlertSeverity.High,
            IntervalMinutes: 60,
            IsEnabled: true),
        new(
            "PhishTank Online Valid Phishing URLs",
            "https://data.phishtank.com/data/online-valid.csv",
            ThreatIntelFeedKind.GenericCsv,
            AlertSeverity.High,
            IntervalMinutes: 120,
            IsEnabled: false),
        new(
            "Emerging Threats Compromised IPs",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            ThreatIntelFeedKind.GenericCsv,
            AlertSeverity.Medium,
            IntervalMinutes: 120,
            IsEnabled: false),
        new(
            "Blocklist.de Recent Attackers",
            "https://lists.blocklist.de/lists/all.txt",
            ThreatIntelFeedKind.GenericCsv,
            AlertSeverity.Medium,
            IntervalMinutes: 60,
            IsEnabled: false),
    ];

    /// <summary>
    /// Insert any missing starter feeds for every tenant. Idempotent by URL.
    /// </summary>
    public static async Task<int> EnsureSeededAsync(TawnyDbContext db, CancellationToken ct = default)
    {
        var tenantIds = await db.Tenants.AsNoTracking().Select(t => t.Id).ToListAsync(ct);
        if (tenantIds.Count == 0)
        {
            return 0;
        }

        var now = DateTimeOffset.UtcNow;
        var added = 0;
        foreach (var tenantId in tenantIds)
        {
            var existingUrls = await db.ThreatIntelFeeds
                .AsNoTracking()
                .Where(f => f.TenantId == tenantId)
                .Select(f => f.Url)
                .ToListAsync(ct);
            var seen = new HashSet<string>(existingUrls, StringComparer.OrdinalIgnoreCase);

            foreach (var def in All)
            {
                if (!seen.Add(def.Url))
                {
                    continue;
                }

                db.ThreatIntelFeeds.Add(new ThreatIntelFeed
                {
                    Id = Guid.NewGuid(),
                    TenantId = tenantId,
                    Name = def.Name,
                    Kind = def.Kind,
                    Url = def.Url,
                    DefaultSeverity = def.DefaultSeverity,
                    IntervalMinutes = def.IntervalMinutes,
                    IsEnabled = def.IsEnabled,
                    Status = ThreatIntelFeedStatus.NeverRun,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                added++;
            }
        }

        if (added > 0)
        {
            await db.SaveChangesAsync(ct);
        }

        return added;
    }
}
