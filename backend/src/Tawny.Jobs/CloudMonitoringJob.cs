using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tawny.Infrastructure;
using Tawny.Jobs.Cloud;

namespace Tawny.Jobs;

public sealed class CloudMonitoringJob(
    TawnyDbContext db,
    CloudHuntCoordinator coordinator,
    TimeProvider timeProvider,
    ILogger<CloudMonitoringJob> log)
{
    [DisableConcurrentExecution(timeoutInSeconds: 300)]
    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var now = timeProvider.GetUtcNow();
        var hunts = await db.CloudHunts
            .AsNoTracking()
            .Where(h => h.IsEnabled && h.CloudConnection!.IsEnabled)
            .Select(h => new { h.Id, h.TenantId, h.IntervalMinutes, h.LastRunAt })
            .ToListAsync(ct);

        foreach (var hunt in hunts)
        {
            if (ct.IsCancellationRequested) break;
            if (hunt.LastRunAt is not null && now - hunt.LastRunAt.Value < TimeSpan.FromMinutes(hunt.IntervalMinutes)) continue;
            try
            {
                await coordinator.RunAsync(hunt.TenantId, hunt.Id, null, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                log.LogError(ex, "Cloud hunt {HuntId} failed", hunt.Id);
            }
        }
    }
}
