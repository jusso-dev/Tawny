namespace Tawny.Domain.Entities;

public class ThreatIntelFeed
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public required string Name { get; set; }
    public ThreatIntelFeedKind Kind { get; set; }
    public required string Url { get; set; }
    public string? AuthHeaderName { get; set; }
    public string? AuthHeaderValueEncrypted { get; set; }
    public AlertSeverity DefaultSeverity { get; set; } = AlertSeverity.High;
    public bool IsEnabled { get; set; } = true;
    public int IntervalMinutes { get; set; } = 60;
    public ThreatIntelFeedStatus Status { get; set; } = ThreatIntelFeedStatus.NeverRun;
    public DateTimeOffset? LastRunAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public int LastImportedCount { get; set; }
    public int LastSkippedCount { get; set; }
    public string? LastError { get; set; }
    public string? Etag { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Tenant? Tenant { get; set; }
}
