using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Jobs.Cloud;

public sealed record CloudLogRecord(
    string ProviderEventId,
    DateTimeOffset OccurredAt,
    string Title,
    string? Actor,
    string? Resource,
    string EvidenceJson);

public sealed record CloudQueryResult(
    int RecordsRead,
    IReadOnlyList<CloudLogRecord> Matches);

public interface ICloudLogProvider
{
    bool Supports(CloudSourceKind source);

    Task<CloudQueryResult> QueryAsync(
        CloudConnection connection,
        CloudHunt hunt,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        CancellationToken ct);
}
