namespace Tawny.Domain.Entities;

public class UniFiEventMatch
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid UniFiIntegrationId { get; set; }
    public required string DedupeKey { get; set; }
    public required string EventReference { get; set; }
    public required string MatchedValuesJson { get; set; }
    public required string KelpieCaseId { get; set; }
    public string? KelpieCaseNumber { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public Tenant? Tenant { get; set; }
    public UniFiIntegration? UniFiIntegration { get; set; }
}
