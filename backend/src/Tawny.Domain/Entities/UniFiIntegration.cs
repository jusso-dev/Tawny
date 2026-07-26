namespace Tawny.Domain.Entities;

public class UniFiIntegration
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public required string BaseUrl { get; set; }
    public required string EventsUrl { get; set; }
    public required string ApiKeyHeader { get; set; } = "X-API-Key";
    public required string ApiKeyEncrypted { get; set; }
    public string RecordsPath { get; set; } = "data";
    public bool VerifyTls { get; set; } = true;
    public bool IsEnabled { get; set; }
    public int IntervalMinutes { get; set; } = 5;
    public string? NetworkVersion { get; set; }
    public DateTimeOffset? LastTestAt { get; set; }
    public DateTimeOffset? LastRunAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public string? LastError { get; set; }
    public int LastRecordsChecked { get; set; }
    public int LastIndicatorsChecked { get; set; }
    public int LastMatchingEvents { get; set; }
    public int LastCasesCreated { get; set; }
    public Guid? UpdatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Tenant? Tenant { get; set; }
    public List<UniFiEventMatch> EventMatches { get; set; } = [];
}
