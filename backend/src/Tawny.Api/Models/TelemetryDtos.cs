using System.Text.Json;
using FluentValidation;
using Tawny.Domain;

namespace Tawny.Api.Models;

public record IngestEventsRequest(
    IReadOnlyList<TelemetryEventIngest> Events,
    Guid? BatchId = null,
    /// <summary>Base64 Ed25519 signature over DeviceBatchSignature canonical form.</summary>
    string? Signature = null);

public record TelemetryEventIngest(
    Guid? ClientEventId,
    TelemetryEventType Type,
    long OccurredAt,
    JsonElement Payload,
    long? Sequence = null);

public record TelemetryEventResponse(
    long Id,
    Guid? ClientEventId,
    Guid? BatchId,
    long? SequenceNumber,
    Guid AgentId,
    TelemetryEventType Type,
    DateTimeOffset OccurredAt,
    DateTimeOffset ReceivedAt,
    EvidenceConfidence Confidence,
    JsonElement Payload);

public class IngestEventsRequestValidator : AbstractValidator<IngestEventsRequest>
{
    public IngestEventsRequestValidator()
    {
        RuleFor(x => x.Events)
            .NotNull()
            .NotEmpty()
            .WithMessage("At least one event is required.")
            .Must(events => events is not null && events.Count <= 500)
            .WithMessage("At most 500 events can be ingested in one batch.");

        RuleFor(x => x.BatchId)
            .Must(id => id is null || id != Guid.Empty)
            .WithMessage("batch_id must be a non-empty UUID when supplied.");

        RuleForEach(x => x.Events).ChildRules(ev =>
        {
            ev.RuleFor(x => x.ClientEventId)
                .Must(id => id is null || id != Guid.Empty)
                .WithMessage("client_event_id must be a non-empty UUID when supplied.");
            ev.RuleFor(x => x.Type).IsInEnum();
            ev.RuleFor(x => x.OccurredAt)
                .GreaterThan(0)
                .LessThanOrEqualTo(253402300799)
                .WithMessage("occurred_at must be a Unix timestamp in seconds.");
            ev.RuleFor(x => x.Sequence)
                .Must(s => s is null || s > 0)
                .WithMessage("sequence must be a positive integer when supplied.");
            ev.RuleFor(x => x.Payload)
                .Must(payload => payload.ValueKind == JsonValueKind.Object)
                .WithMessage("payload must be a JSON object.");
        });
    }
}
