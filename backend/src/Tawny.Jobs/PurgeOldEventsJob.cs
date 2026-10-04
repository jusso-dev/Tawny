using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Infrastructure;

namespace Tawny.Jobs;

public class RetentionOptions
{
    public int EventRetentionDays { get; set; } = 30;
    public int AlertRetentionDays { get; set; } = 365;
}

public class PurgeOldEventsJob(
    TawnyDbContext db,
    IOptions<RetentionOptions> options,
    ILogger<PurgeOldEventsJob> log)
{
    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var alertCutoff = now.AddDays(-Math.Max(options.Value.AlertRetentionDays, options.Value.EventRetentionDays));
        var eventCutoff = now.AddDays(-options.Value.EventRetentionDays);

        var alertsDeleted = await db.Alerts
            .Where(a => a.CreatedAt < alertCutoff)
            .ExecuteDeleteAsync(ct);

        // Events that are evidence for a surviving alert are kept until the alert ages out.
        var eventsDeleted = await db.TelemetryEvents
            .Where(e => e.ReceivedAt < eventCutoff && !db.Alerts.Any(a => a.TelemetryEventId == e.Id))
            .ExecuteDeleteAsync(ct);

        log.LogInformation(
            "Purged {Alerts} alerts older than {AlertCutoff:o} and {Events} unreferenced telemetry events older than {EventCutoff:o}",
            alertsDeleted, alertCutoff, eventsDeleted, eventCutoff);
    }
}
