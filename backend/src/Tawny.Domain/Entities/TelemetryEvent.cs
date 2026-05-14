namespace Tawny.Domain.Entities;

public class TelemetryEvent
{
    public long Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid AgentId { get; set; }
    public TelemetryEventType EventType { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }
    public required string Payload { get; set; }

    public Tenant? Tenant { get; set; }
    public Agent? Agent { get; set; }
}
