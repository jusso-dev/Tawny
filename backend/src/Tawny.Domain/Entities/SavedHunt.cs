namespace Tawny.Domain.Entities;

public class SavedHunt
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public required string Query { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public bool IsScheduled { get; set; }
    public string? ScheduleCron { get; set; }
    public bool AlertOnMatch { get; set; }
    public AlertSeverity AlertSeverity { get; set; } = AlertSeverity.Medium;
    public string? MitreTechniquesJson { get; set; }
    public DateTimeOffset? LastRunAt { get; set; }
    public int? LastMatchCount { get; set; }
    public bool IsShared { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Tenant? Tenant { get; set; }
    public List<HuntRun> Runs { get; set; } = [];
}
