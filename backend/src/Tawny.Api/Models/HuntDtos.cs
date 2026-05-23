using System.Text.Json;
using Tawny.Domain;

namespace Tawny.Api.Models;

public record RunHuntRequest(
    string Query,
    int? Limit);

public record HuntMatchResponse(
    long EventId,
    Guid AgentId,
    string Hostname,
    TelemetryEventType EventType,
    DateTimeOffset OccurredAt,
    DateTimeOffset ReceivedAt,
    JsonElement Payload);

public record RunHuntResponse(
    int MatchCount,
    IReadOnlyList<HuntMatchResponse> Matches,
    IReadOnlyList<string> Warnings);

public record CreateSavedHuntRequest(
    string Name,
    string? Description,
    string Query,
    bool? IsScheduled,
    string? ScheduleCron,
    bool? AlertOnMatch,
    AlertSeverity? AlertSeverity,
    IReadOnlyList<string>? MitreTechniques);

public record UpdateSavedHuntRequest(
    string Name,
    string? Description,
    string Query,
    bool IsScheduled,
    string? ScheduleCron,
    bool AlertOnMatch,
    AlertSeverity AlertSeverity,
    IReadOnlyList<string>? MitreTechniques);

public record SavedHuntResponse(
    Guid Id,
    string Name,
    string? Description,
    string Query,
    bool IsScheduled,
    string? ScheduleCron,
    bool AlertOnMatch,
    AlertSeverity AlertSeverity,
    IReadOnlyList<string> MitreTechniques,
    DateTimeOffset? LastRunAt,
    int? LastMatchCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public record HuntRunResponse(
    long Id,
    Guid SavedHuntId,
    HuntRunStatus Status,
    DateTimeOffset StartedAt,
    DateTimeOffset? CompletedAt,
    int MatchCount,
    int AlertsCreated,
    string? ErrorMessage);
