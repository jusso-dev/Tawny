using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.Hunting;

namespace Tawny.Jobs;

/// <summary>
/// Runs every 5 minutes. For each enabled scheduled saved hunt whose last run
/// is older than its cadence (parsed from a simple "Nm" / "Nh" cron-ish string),
/// executes the query and, when AlertOnMatch is true and there are matches,
/// emits alerts attached to the matched telemetry events.
/// </summary>
public class ScheduledHuntsJob(
    TawnyDbContext db,
    TimeProvider timeProvider,
    HuntQueryParser parser,
    HuntExecutor executor,
    ILogger<ScheduledHuntsJob> log)
{
    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var now = timeProvider.GetUtcNow();
        var due = await db.SavedHunts
            .Where(h => h.IsScheduled && h.ScheduleCron != null)
            .ToListAsync(ct);

        if (due.Count == 0) return;

        foreach (var hunt in due)
        {
            if (ct.IsCancellationRequested) break;
            if (!IsDue(hunt, now)) continue;

            var run = new HuntRun
            {
                TenantId = hunt.TenantId,
                SavedHuntId = hunt.Id,
                StartedAt = now,
                Status = HuntRunStatus.Running,
            };
            db.HuntRuns.Add(run);
            await db.SaveChangesAsync(ct);

            try
            {
                var plan = parser.Parse(hunt.Query);
                var result = await executor.ExecuteAsync(hunt.TenantId, plan, ct);

                var alertsCreated = 0;
                if (hunt.AlertOnMatch && result.Matches.Count > 0)
                {
                    // Manufacture a synthetic alert rule placeholder so the alert FK is satisfiable.
                    // We use an "always-on" rule per saved hunt, created on the fly.
                    var ruleId = await EnsureHuntRuleAsync(hunt, ct);
                    foreach (var match in result.Matches)
                    {
                        db.Alerts.Add(new Alert
                        {
                            AlertRuleId = ruleId,
                            AgentId = match.AgentId,
                            TelemetryEventId = match.EventId,
                            Severity = hunt.AlertSeverity,
                            Title = $"Scheduled hunt: {hunt.Name}",
                            Description = $"Matched by saved hunt '{hunt.Name}'.",
                            CreatedAt = now,
                        });
                        alertsCreated += 1;
                    }
                }

                run.Status = HuntRunStatus.Succeeded;
                run.CompletedAt = timeProvider.GetUtcNow();
                run.MatchCount = result.MatchCount;
                run.AlertsCreated = alertsCreated;
                hunt.LastRunAt = run.CompletedAt;
                hunt.LastMatchCount = result.MatchCount;

                await db.SaveChangesAsync(ct);
                log.LogInformation("Scheduled hunt {HuntId} ran with {Matches} matches, {Alerts} alerts created.",
                    hunt.Id, result.MatchCount, alertsCreated);
            }
            catch (Exception ex)
            {
                run.Status = HuntRunStatus.Failed;
                run.CompletedAt = timeProvider.GetUtcNow();
                run.ErrorMessage = ex.Message.Length > 1000 ? ex.Message[..1000] : ex.Message;
                await db.SaveChangesAsync(ct);
                log.LogError(ex, "Scheduled hunt {HuntId} failed", hunt.Id);
            }
        }
    }

    private async Task<Guid> EnsureHuntRuleAsync(SavedHunt hunt, CancellationToken ct)
    {
        var externalId = $"saved-hunt:{hunt.Id}";
        var existing = await db.AlertRules.FirstOrDefaultAsync(r => r.ExternalId == externalId, ct);
        if (existing is not null) return existing.Id;

        var now = DateTimeOffset.UtcNow;
        var rule = new AlertRule
        {
            Id = Guid.NewGuid(),
            Name = $"Hunt: {hunt.Name}",
            Format = AlertRuleFormat.TawnyPredicate,
            ExternalId = externalId,
            Description = $"Auto-generated rule backing saved hunt {hunt.Id}.",
            Severity = hunt.AlertSeverity,
            Operator = AlertRuleOperator.Exists,
            IsEnabled = false, // we only emit via scheduled hunt, not via ingest evaluation
            MitreTechniquesJson = hunt.MitreTechniquesJson,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.AlertRules.Add(rule);
        await db.SaveChangesAsync(ct);
        return rule.Id;
    }

    private static bool IsDue(SavedHunt hunt, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(hunt.ScheduleCron)) return false;

        // Accept the simple "Nm" / "Nh" / "Nd" form so users don't need full cron semantics.
        var trimmed = hunt.ScheduleCron.Trim();
        if (trimmed.Length >= 2
            && int.TryParse(trimmed[..^1], out var amount)
            && amount > 0)
        {
            var span = char.ToLowerInvariant(trimmed[^1]) switch
            {
                'm' => TimeSpan.FromMinutes(amount),
                'h' => TimeSpan.FromHours(amount),
                'd' => TimeSpan.FromDays(amount),
                _ => TimeSpan.Zero,
            };
            if (span > TimeSpan.Zero)
            {
                return hunt.LastRunAt is null || (now - hunt.LastRunAt.Value) >= span;
            }
        }

        // Anything else (e.g. classic cron) -> run at most every 15 minutes;
        // a real cron parser is out of scope here.
        return hunt.LastRunAt is null || (now - hunt.LastRunAt.Value) >= TimeSpan.FromMinutes(15);
    }
}
