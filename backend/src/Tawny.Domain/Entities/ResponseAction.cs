namespace Tawny.Domain.Entities;

public class ResponseAction
{
    public Guid Id { get; set; }
    public Guid AgentId { get; set; }
    public ResponseActionType ActionType { get; set; }
    public ResponseActionStatus Status { get; set; } = ResponseActionStatus.Pending;
    public Guid? RequestedByUserId { get; set; }
    public DateTimeOffset RequestedAt { get; set; }
    public DateTimeOffset? DispatchedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public required string PayloadJson { get; set; }
    public string? ResultJson { get; set; }

    public Agent? Agent { get; set; }
}
