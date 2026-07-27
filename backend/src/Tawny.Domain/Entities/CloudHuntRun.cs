namespace Tawny.Domain.Entities;

public class CloudHuntRun
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid CloudHuntId { get; set; }
    public Guid? TriggeredByUserId { get; set; }
    public CloudRunStatus Status { get; set; } = CloudRunStatus.Running;
    public DateTimeOffset WindowFrom { get; set; }
    public DateTimeOffset WindowTo { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public int RecordsRead { get; set; }
    public int FindingsCreated { get; set; }
    public string? ErrorMessage { get; set; }

    public CloudHunt? CloudHunt { get; set; }
}
