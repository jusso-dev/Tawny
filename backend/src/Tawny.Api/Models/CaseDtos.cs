using Tawny.Domain.Entities;

namespace Tawny.Api.Models;

public record CreateCaseRequest(
    string Title,
    string? Summary,
    CasePriority? Priority,
    IReadOnlyList<long>? AlertIds,
    IReadOnlyList<string>? MitreTechniques);

public record UpdateCaseRequest(
    string Title,
    string? Summary,
    CaseStatus Status,
    CasePriority Priority,
    Guid? AssignedToUserId,
    IReadOnlyList<string>? MitreTechniques);

public record CaseAlertResponse(
    long Id,
    long AlertId,
    string AlertTitle,
    string AlertHostname,
    string AlertSeverity,
    DateTimeOffset AlertCreatedAt,
    DateTimeOffset AddedAt);

public record CaseNoteResponse(
    long Id,
    Guid? AuthorUserId,
    string Body,
    DateTimeOffset CreatedAt);

public record CaseResponse(
    long Id,
    string Title,
    string? Summary,
    CaseStatus Status,
    CasePriority Priority,
    Guid? AssignedToUserId,
    Guid? CreatedByUserId,
    int AlertCount,
    int NoteCount,
    IReadOnlyList<string> MitreTechniques,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? ClosedAt);

public record CaseDetailResponse(
    long Id,
    string Title,
    string? Summary,
    CaseStatus Status,
    CasePriority Priority,
    Guid? AssignedToUserId,
    Guid? CreatedByUserId,
    IReadOnlyList<string> MitreTechniques,
    IReadOnlyList<CaseAlertResponse> Alerts,
    IReadOnlyList<CaseNoteResponse> Notes,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? ClosedAt);

public record AddCaseAlertRequest(IReadOnlyList<long> AlertIds);

public record AddCaseNoteRequest(string Body);
