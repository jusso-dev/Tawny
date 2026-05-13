using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Infrastructure;

namespace Tawny.Jobs;

public class RetentionOptions
{
    public int EventRetentionDays { get; set; } = 30;
}

public class PurgeOldEventsJob(
    TawnyDbContext db,
    IOptions<RetentionOptions> options,
    ILogger<PurgeOldEventsJob> log)
{
    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-options.Value.EventRetentionDays);
        var deleted = await db.TelemetryEvents
            .Where(e => e.ReceivedAt < cutoff)
            .ExecuteDeleteAsync(ct);

        log.LogInformation("Purged {Count} telemetry events older than {Cutoff:o}", deleted, cutoff);
    }
}
