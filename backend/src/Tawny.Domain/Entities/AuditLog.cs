namespace Tawny.Domain.Entities;

public class AuditLog
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid? UserId { get; set; }
    public required string Action { get; set; }
    public string? Target { get; set; }
    public string? MetadataJson { get; set; }
    public DateTimeOffset OccurredAt { get; set; }

    public Tenant? Tenant { get; set; }
}
