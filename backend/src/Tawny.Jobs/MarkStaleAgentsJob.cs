using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Jobs;

public class MarkStaleAgentsJob(
    TawnyDbContext db,
    TimeProvider timeProvider,
    ILogger<MarkStaleAgentsJob> log)
{
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan OfflineAfter = TimeSpan.FromMinutes(15);

    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var now = timeProvider.GetUtcNow();
        var staleCutoff = now - StaleAfter;
        var offlineCutoff = now - OfflineAfter;

        var staleAgents = await db.Agents
            .Where(a => a.Status == AgentStatus.Online
                && a.LastHeartbeatAt != null
                && a.LastHeartbeatAt <= staleCutoff
                && a.LastHeartbeatAt > offlineCutoff)
            .ToListAsync(ct);

        var offlineAgents = await db.Agents
            .Where(a => a.Status != AgentStatus.Offline
                && a.LastHeartbeatAt != null
                && a.LastHeartbeatAt <= offlineCutoff)
            .ToListAsync(ct);

        foreach (var agent in staleAgents)
        {
            agent.Status = AgentStatus.Stale;
        }

        foreach (var agent in offlineAgents)
        {
            agent.Status = AgentStatus.Offline;
        }

        await db.SaveChangesAsync(ct);

        if (staleAgents.Count > 0 || offlineAgents.Count > 0)
        {
            log.LogInformation("Agent status sweep: stale={Stale} offline={Offline}",
                staleAgents.Count, offlineAgents.Count);
        }
    }
}
