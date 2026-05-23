namespace Tawny.Domain.Entities;

public class HuntRun
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid SavedHuntId { get; set; }
    public Guid? TriggeredByUserId { get; set; }
    public HuntRunStatus Status { get; set; } = HuntRunStatus.Running;
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public int MatchCount { get; set; }
    public int AlertsCreated { get; set; }
    public string? ErrorMessage { get; set; }

    public SavedHunt? SavedHunt { get; set; }
}
