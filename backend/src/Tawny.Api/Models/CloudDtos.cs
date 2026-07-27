using System.Text.Json;
using Tawny.Domain;

namespace Tawny.Api.Models;

public sealed record UpsertCloudConnectionRequest(
    string Name,
    CloudProvider Provider,
    string ExternalAccountId,
    CloudCredentialMode CredentialMode,
    JsonElement Configuration,
    JsonElement? Credential,
    bool IsEnabled);

public sealed record CloudConnectionResponse(
    Guid Id,
    string Name,
    CloudProvider Provider,
    string ExternalAccountId,
    CloudCredentialMode CredentialMode,
    JsonElement Configuration,
    bool HasCredential,
    bool IsEnabled,
    DateTimeOffset? LastTestAt,
    DateTimeOffset? LastSuccessAt,
    string? LastError,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record CloudConnectionTestRequest(CloudSourceKind Source);

public sealed record CloudConnectionTestResponse(
    CloudSourceKind Source,
    int RecordsRead,
    DateTimeOffset TestedAt);

public sealed record UpsertCloudHuntRequest(
    Guid CloudConnectionId,
    string Name,
    string? Description,
    CloudSourceKind Source,
    JsonElement Query,
    bool IsEnabled,
    int IntervalMinutes,
    int LookbackMinutes,
    AlertSeverity Severity,
    IReadOnlyList<string>? MitreTechniques);

public sealed record CloudHuntResponse(
    Guid Id,
    Guid CloudConnectionId,
    string ConnectionName,
    string Name,
    string? Description,
    CloudSourceKind Source,
    JsonElement Query,
    bool IsEnabled,
    int IntervalMinutes,
    int LookbackMinutes,
    AlertSeverity Severity,
    IReadOnlyList<string> MitreTechniques,
    DateTimeOffset? LastRunAt,
    DateTimeOffset? LastSuccessAt,
    int LastMatchCount,
    string? LastError,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record CloudRunResponse(
    long RunId,
    int RecordsRead,
    int FindingsCreated,
    DateTimeOffset WindowFrom,
    DateTimeOffset WindowTo);

public sealed record CloudHuntRunResponse(
    long Id,
    CloudRunStatus Status,
    DateTimeOffset WindowFrom,
    DateTimeOffset WindowTo,
    DateTimeOffset StartedAt,
    DateTimeOffset? CompletedAt,
    int RecordsRead,
    int FindingsCreated,
    string? ErrorMessage);

public sealed record CloudFindingResponse(
    long Id,
    Guid CloudHuntId,
    string HuntName,
    CloudProvider Provider,
    CloudSourceKind Source,
    string ProviderEventId,
    string Title,
    AlertSeverity Severity,
    CloudFindingStatus Status,
    string? Actor,
    string? Resource,
    DateTimeOffset OccurredAt,
    JsonElement Evidence,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record UpdateCloudFindingRequest(CloudFindingStatus Status);
