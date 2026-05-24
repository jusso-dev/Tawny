namespace Tawny.Domain.Entities;

public enum CaseStatus
{
    Open = 0,
    Investigating = 1,
    Contained = 2,
    Resolved = 3,
    Closed = 4,
}

public enum CasePriority
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

public class Case
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public required string Title { get; set; }
    public string? Summary { get; set; }
    public CaseStatus Status { get; set; } = CaseStatus.Open;
    public CasePriority Priority { get; set; } = CasePriority.Medium;
    public Guid? AssignedToUserId { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? ClosedAt { get; set; }
    public string? MitreTechniquesJson { get; set; }

    public Tenant? Tenant { get; set; }
    public List<CaseAlert> CaseAlerts { get; set; } = [];
    public List<CaseNote> Notes { get; set; } = [];
}

public class CaseAlert
{
    public long Id { get; set; }
    public long CaseId { get; set; }
    public long AlertId { get; set; }
    public DateTimeOffset AddedAt { get; set; }
    public Guid? AddedByUserId { get; set; }

    public Case? Case { get; set; }
    public Alert? Alert { get; set; }
}

public class CaseNote
{
    public long Id { get; set; }
    public long CaseId { get; set; }
    public Guid? AuthorUserId { get; set; }
    public required string Body { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public Case? Case { get; set; }
}
