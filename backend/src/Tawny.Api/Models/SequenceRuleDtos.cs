using Tawny.Domain;

namespace Tawny.Api.Models;

public record CreateSequenceRuleRequest(
    string Name,
    string? Description,
    AlertSeverity Severity,
    int WindowSeconds,
    IReadOnlyList<SequenceStepInput> Steps,
    IReadOnlyList<string>? MitreTechniques,
    bool? IsEnabled);

public record SequenceStepInput(
    string Name,
    TelemetryEventType EventType,
    string? PayloadPath,
    AlertRuleOperator Operator,
    string? MatchValue);

public record SequenceRuleResponse(
    Guid Id,
    string Name,
    string? Description,
    AlertSeverity Severity,
    int WindowSeconds,
    IReadOnlyList<SequenceStepInput> Steps,
    IReadOnlyList<string> MitreTechniques,
    bool IsEnabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
