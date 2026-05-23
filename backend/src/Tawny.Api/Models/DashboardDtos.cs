using Tawny.Domain;

namespace Tawny.Api.Models;

public record DashboardSummaryResponse(
    int TotalAgents,
    int OnlineAgents,
    int OfflineAgents,
    int StaleAgents,
    int UnknownAgents,
    IReadOnlyList<DashboardRecentEvent> RecentEvents,
    IReadOnlyList<DashboardEventVolumeBucket> EventVolume,
    IReadOnlyList<DashboardMitreHeatmapEntry> MitreHeatmap);

public record DashboardMitreHeatmapEntry(
    string TechniqueId,
    int AlertCount);

public record DashboardRecentEvent(
    long Id,
    Guid AgentId,
    string Hostname,
    TelemetryEventType Type,
    DateTimeOffset OccurredAt,
    DateTimeOffset ReceivedAt);

public record DashboardEventVolumeBucket(
    DateTimeOffset BucketStart,
    int Count);
