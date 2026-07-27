using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Jobs.Cloud;

public sealed record CloudRunResult(
    long RunId,
    int RecordsRead,
    int FindingsCreated,
    DateTimeOffset WindowFrom,
    DateTimeOffset WindowTo);

public sealed class CloudHuntCoordinator(
    TawnyDbContext db,
    IEnumerable<ICloudLogProvider> providers,
    TimeProvider timeProvider)
{
    private const int ResultLimit = 500;
    private static readonly TimeSpan Overlap = TimeSpan.FromMinutes(2);
    private static readonly ConcurrentDictionary<Guid, SemaphoreSlim> HuntLocks = new();

    public async Task<CloudRunResult> RunAsync(
        Guid tenantId,
        Guid huntId,
        Guid? triggeredByUserId,
        CancellationToken ct)
    {
        var gate = HuntLocks.GetOrAdd(huntId, _ => new SemaphoreSlim(1, 1));
        if (!await gate.WaitAsync(0, ct))
            throw new InvalidOperationException("Cloud hunt is already running.");
        try
        {
            return await RunCoreAsync(tenantId, huntId, triggeredByUserId, ct);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<CloudRunResult> RunCoreAsync(
        Guid tenantId,
        Guid huntId,
        Guid? triggeredByUserId,
        CancellationToken ct)
    {
        var hunt = await db.CloudHunts
            .Include(h => h.CloudConnection)
            .SingleOrDefaultAsync(h => h.Id == huntId && h.TenantId == tenantId, ct)
            ?? throw new KeyNotFoundException("Cloud hunt was not found.");
        var connection = hunt.CloudConnection
            ?? throw new InvalidOperationException("Cloud connection was not found.");
        if (!connection.IsEnabled) throw new InvalidOperationException("Cloud connection is disabled.");

        var provider = providers.SingleOrDefault(p => p.Supports(hunt.Source))
            ?? throw new InvalidOperationException($"No provider supports {hunt.Source}.");
        var now = timeProvider.GetUtcNow();
        var from = hunt.WatermarkAt is not null
            ? hunt.WatermarkAt.Value - Overlap
            : now.AddMinutes(-hunt.LookbackMinutes);
        var run = new CloudHuntRun
        {
            TenantId = tenantId,
            CloudHuntId = hunt.Id,
            TriggeredByUserId = triggeredByUserId,
            Status = CloudRunStatus.Running,
            WindowFrom = from,
            WindowTo = now,
            StartedAt = now,
        };
        db.CloudHuntRuns.Add(run);
        hunt.LastRunAt = now;
        hunt.LastError = null;
        await db.SaveChangesAsync(ct);

        try
        {
            var result = await provider.QueryAsync(connection, hunt, from, now, ResultLimit, ct);
            var candidates = result.Matches
                .Select(record => new { Record = record, Key = DedupeKey(hunt.Id, record.ProviderEventId) })
                .ToArray();
            var keys = candidates.Select(item => item.Key).ToArray();
            var existing = keys.Length == 0
                ? new HashSet<string>(StringComparer.Ordinal)
                : (await db.CloudFindings
                    .Where(f => f.CloudHuntId == hunt.Id && keys.Contains(f.DedupeKey))
                    .Select(f => f.DedupeKey)
                    .ToListAsync(ct))
                    .ToHashSet(StringComparer.Ordinal);

            var created = 0;
            foreach (var item in candidates)
            {
                if (!existing.Add(item.Key)) continue;
                db.CloudFindings.Add(new CloudFinding
                {
                    TenantId = tenantId,
                    CloudHuntId = hunt.Id,
                    ProviderEventId = Truncate(item.Record.ProviderEventId, 512),
                    DedupeKey = item.Key,
                    Title = Truncate(item.Record.Title, 255),
                    Severity = hunt.Severity,
                    Actor = TruncateNullable(item.Record.Actor, 1024),
                    Resource = TruncateNullable(item.Record.Resource, 2048),
                    OccurredAt = item.Record.OccurredAt,
                    EvidenceJson = BoundEvidence(item.Record.EvidenceJson),
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                created++;
            }

            run.Status = CloudRunStatus.Succeeded;
            run.CompletedAt = timeProvider.GetUtcNow();
            run.RecordsRead = result.RecordsRead;
            run.FindingsCreated = created;
            hunt.LastSuccessAt = run.CompletedAt;
            hunt.WatermarkAt = now;
            hunt.LastMatchCount = result.Matches.Count;
            hunt.UpdatedAt = run.CompletedAt.Value;
            connection.LastSuccessAt = run.CompletedAt;
            connection.LastError = null;
            await db.SaveChangesAsync(ct);
            return new CloudRunResult(run.Id, result.RecordsRead, created, from, now);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            var completed = timeProvider.GetUtcNow();
            var message = Truncate(ex.Message, 2048);
            run.Status = CloudRunStatus.Failed;
            run.CompletedAt = completed;
            run.ErrorMessage = message;
            hunt.LastError = message;
            hunt.UpdatedAt = completed;
            connection.LastError = message;
            await db.SaveChangesAsync(ct);
            throw;
        }
    }

    private static string DedupeKey(Guid huntId, string providerEventId)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{huntId:N}:{providerEventId}"))).ToLowerInvariant();

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    private static string? TruncateNullable(string? value, int maxLength)
        => value is null ? null : Truncate(value, maxLength);

    private static string BoundEvidence(string evidence)
    {
        const int maxLength = 64 * 1024;
        if (evidence.Length <= maxLength) return evidence;
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidence))).ToLowerInvariant();
        return JsonSerializer.Serialize(new
        {
            truncated = true,
            original_length = evidence.Length,
            sha256 = digest,
            preview = evidence[..(32 * 1024)],
        });
    }
}
