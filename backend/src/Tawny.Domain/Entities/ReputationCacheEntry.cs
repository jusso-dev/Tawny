namespace Tawny.Domain.Entities;

public class ReputationCacheEntry
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public ReputationProvider Provider { get; set; }
    public required string IndicatorKind { get; set; }
    public required string IndicatorValue { get; set; }
    public ReputationVerdict Verdict { get; set; }
    public int? Score { get; set; }
    public required string DetailJson { get; set; }
    public DateTimeOffset FetchedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}
