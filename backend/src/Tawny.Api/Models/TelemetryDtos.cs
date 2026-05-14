using System.Text.Json;
using FluentValidation;
using Tawny.Domain;

namespace Tawny.Api.Models;

public record IngestEventsRequest(IReadOnlyList<TelemetryEventIngest> Events);

public record TelemetryEventIngest(
    TelemetryEventType Type,
    long OccurredAt,
    JsonElement Payload);

public record TelemetryEventResponse(
    long Id,
    Guid AgentId,
    TelemetryEventType Type,
    DateTimeOffset OccurredAt,
    DateTimeOffset ReceivedAt,
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

        RuleForEach(x => x.Events).ChildRules(ev =>
        {
            ev.RuleFor(x => x.Type).IsInEnum();
            ev.RuleFor(x => x.OccurredAt)
                .GreaterThan(0)
                .LessThanOrEqualTo(253402300799)
                .WithMessage("occurred_at must be a Unix timestamp in seconds.");
            ev.RuleFor(x => x.Payload)
                .Must(payload => payload.ValueKind == JsonValueKind.Object)
                .WithMessage("payload must be a JSON object.");
        });
    }
}
