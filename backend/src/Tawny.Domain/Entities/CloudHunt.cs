namespace Tawny.Domain.Entities;

public class CloudHunt
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid CloudConnectionId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public CloudSourceKind Source { get; set; }
    public required string QueryJson { get; set; }
    public bool IsEnabled { get; set; }
    public int IntervalMinutes { get; set; } = 15;
    public int LookbackMinutes { get; set; } = 15;
    public AlertSeverity Severity { get; set; } = AlertSeverity.Medium;
    public string? MitreTechniquesJson { get; set; }
    public DateTimeOffset? LastRunAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public DateTimeOffset? WatermarkAt { get; set; }
    public int LastMatchCount { get; set; }
    public string? LastError { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Tenant? Tenant { get; set; }
    public CloudConnection? CloudConnection { get; set; }
    public List<CloudHuntRun> Runs { get; set; } = [];
    public List<CloudFinding> Findings { get; set; } = [];
}
