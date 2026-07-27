namespace Tawny.Domain.Entities;

public class CloudFinding
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid CloudHuntId { get; set; }
    public required string ProviderEventId { get; set; }
    public required string DedupeKey { get; set; }
    public required string Title { get; set; }
    public AlertSeverity Severity { get; set; }
    public CloudFindingStatus Status { get; set; } = CloudFindingStatus.Open;
    public string? Actor { get; set; }
    public string? Resource { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public required string EvidenceJson { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public CloudHunt? CloudHunt { get; set; }
}
