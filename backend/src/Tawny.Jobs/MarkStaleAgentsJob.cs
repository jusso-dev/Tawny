using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Jobs;

public class MarkStaleAgentsJob(TawnyDbContext db, ILogger<MarkStaleAgentsJob> log)
{
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan OfflineAfter = TimeSpan.FromMinutes(15);

    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var staleCutoff = now - StaleAfter;
        var offlineCutoff = now - OfflineAfter;

        var stale = await db.Agents
            .Where(a => a.Status == AgentStatus.Online
                && a.LastHeartbeatAt != null
                && a.LastHeartbeatAt <= staleCutoff
                && a.LastHeartbeatAt > offlineCutoff)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, AgentStatus.Stale), ct);

        var offline = await db.Agents
            .Where(a => a.Status != AgentStatus.Offline
                && a.LastHeartbeatAt != null
                && a.LastHeartbeatAt <= offlineCutoff)
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, AgentStatus.Offline), ct);

        if (stale > 0 || offline > 0)
        {
            log.LogInformation("Agent status sweep: stale={Stale} offline={Offline}", stale, offline);
        }
    }
}
