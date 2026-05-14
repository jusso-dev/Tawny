namespace Tawny.Domain.Entities;

public class AlertRule
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public TelemetryEventType? EventType { get; set; }
    public AlertSeverity Severity { get; set; } = AlertSeverity.Medium;
    public AlertRuleOperator Operator { get; set; } = AlertRuleOperator.Contains;
    public string? PayloadPath { get; set; }
    public string? MatchValue { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public List<Alert> Alerts { get; set; } = [];
}
