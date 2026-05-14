using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Jobs;

public partial class CheckAgentReleasesJob(
    TawnyDbContext db,
    HttpClient http,
    ILogger<CheckAgentReleasesJob> log)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(
            HttpMethod.Get,
            "https://api.github.com/repos/jusso-dev/tawny/releases/latest");
        req.Headers.UserAgent.ParseAdd("tawny-release-check/1.0");
        req.Headers.Accept.ParseAdd("application/vnd.github+json");

        using var res = await http.SendAsync(req, ct);
        res.EnsureSuccessStatusCode();

        await using var stream = await res.Content.ReadAsStreamAsync(ct);
        var release = await JsonSerializer.DeserializeAsync<GitHubRelease>(stream, JsonOptions, ct);
        if (release is null)
        {
            log.LogWarning("GitHub latest release response was empty.");
            return;
        }

        var shaAssets = release.Assets
            .Where(a => a.Name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(a => a.Name, StringComparer.OrdinalIgnoreCase);

        var rows = new List<AgentRelease>();
        foreach (var asset in release.Assets.Where(a => !a.Name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase)))
        {
            var match = AgentAssetRegex().Match(asset.Name);
            if (!match.Success) continue;

            var sidecarName = ShaSidecarName(asset.Name);
            if (!shaAssets.TryGetValue(sidecarName, out var shaAsset))
            {
                log.LogWarning("Skipping release asset {AssetName}: missing SHA-256 sidecar {SidecarName}",
                    asset.Name, sidecarName);
                continue;
            }

            var sha256 = await FetchSha256Async(shaAsset.BrowserDownloadUrl, ct);
            if (sha256 is null)
            {
                log.LogWarning("Skipping release asset {AssetName}: invalid SHA-256 sidecar", asset.Name);
                continue;
            }

            rows.Add(new AgentRelease
            {
                Version = match.Groups["version"].Value,
                Platform = match.Groups["platform"].Value,
                DownloadUrl = asset.BrowserDownloadUrl,
                Sha256 = sha256,
                ReleasedAt = release.PublishedAt ?? DateTimeOffset.UtcNow,
                IsLatest = true,
            });
        }

        if (rows.Count == 0)
        {
            log.LogInformation("No Tawny agent release assets found in {TagName}.", release.TagName);
            return;
        }

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var platforms = rows.Select(r => r.Platform).Distinct().ToArray();
        await db.AgentReleases
            .Where(r => platforms.Contains(r.Platform))
            .ExecuteUpdateAsync(setters => setters.SetProperty(r => r.IsLatest, false), ct);

        foreach (var row in rows)
        {
            var existing = await db.AgentReleases.FindAsync(
                new object?[] { row.Version, row.Platform }, ct);
            if (existing is null)
            {
                db.AgentReleases.Add(row);
            }
            else
            {
                existing.DownloadUrl = row.DownloadUrl;
                existing.Sha256 = row.Sha256;
                existing.ReleasedAt = row.ReleasedAt;
                existing.IsLatest = true;
            }
        }

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        log.LogInformation("Updated {Count} latest Tawny agent release rows from {TagName}.", rows.Count, release.TagName);
    }

    private async Task<string?> FetchSha256Async(string url, CancellationToken ct)
    {
        var content = await http.GetStringAsync(url, ct);
        var first = content
            .Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault();
        return first is { Length: 64 } && first.All(Uri.IsHexDigit)
            ? first.ToLowerInvariant()
            : null;
    }

    private static string ShaSidecarName(string assetName) =>
        assetName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? assetName[..^4] + ".sha256"
            : assetName + ".sha256";

    [GeneratedRegex(@"^tawny-agent-(?<version>.+)-(?<platform>windows-x64|macos-arm64|macos-x64)(?:\.exe)?$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AgentAssetRegex();

    private sealed record GitHubRelease(
        [property: JsonPropertyName("tag_name")] string TagName,
        [property: JsonPropertyName("published_at")] DateTimeOffset? PublishedAt,
        [property: JsonPropertyName("assets")] IReadOnlyList<GitHubAsset> Assets);

    private sealed record GitHubAsset(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("browser_download_url")] string BrowserDownloadUrl);
}
