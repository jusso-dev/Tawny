namespace Tawny.Domain.Entities;

public class Alert
{
    public long Id { get; set; }
    public Guid AlertRuleId { get; set; }
    public Guid AgentId { get; set; }
    public long TelemetryEventId { get; set; }
    public AlertSeverity Severity { get; set; }
    public AlertStatus Status { get; set; } = AlertStatus.Open;
    public required string Title { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public AlertRule? AlertRule { get; set; }
    public Agent? Agent { get; set; }
    public TelemetryEvent? TelemetryEvent { get; set; }
}
