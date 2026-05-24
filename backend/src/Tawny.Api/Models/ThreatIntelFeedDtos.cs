using Tawny.Domain;

namespace Tawny.Api.Models;

public record CreateThreatIntelFeedRequest(
    string Name,
    ThreatIntelFeedKind Kind,
    string Url,
    string? AuthHeaderName,
    string? AuthHeaderValue,
    AlertSeverity? DefaultSeverity,
    int? IntervalMinutes,
    bool? IsEnabled);

public record UpdateThreatIntelFeedRequest(
    string Name,
    ThreatIntelFeedKind Kind,
    string Url,
    string? AuthHeaderName,
    string? AuthHeaderValue,
    AlertSeverity DefaultSeverity,
    int IntervalMinutes,
    bool IsEnabled);

public record ThreatIntelFeedResponse(
    Guid Id,
    string Name,
    ThreatIntelFeedKind Kind,
    string Url,
    string? AuthHeaderName,
    AlertSeverity DefaultSeverity,
    int IntervalMinutes,
    bool IsEnabled,
    ThreatIntelFeedStatus Status,
    DateTimeOffset? LastRunAt,
    DateTimeOffset? LastSuccessAt,
    int LastImportedCount,
    int LastSkippedCount,
    string? LastError,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
