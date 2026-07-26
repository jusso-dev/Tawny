namespace Tawny.Api.Models;

public sealed record UpdateUniFiIntegrationRequest(
    string BaseUrl,
    string EventsUrl,
    string ApiKeyHeader,
    string? ApiKey,
    string? RecordsPath,
    bool VerifyTls,
    bool IsEnabled,
    int IntervalMinutes);

public sealed record UniFiIntegrationResponse(
    Guid Id,
    string BaseUrl,
    string EventsUrl,
    string ApiKeyHeader,
    bool HasApiKey,
    string RecordsPath,
    bool VerifyTls,
    bool IsEnabled,
    int IntervalMinutes,
    string? NetworkVersion,
    DateTimeOffset? LastTestAt,
    DateTimeOffset? LastRunAt,
    DateTimeOffset? LastSuccessAt,
    string? LastError,
    int LastRecordsChecked,
    int LastIndicatorsChecked,
    int LastMatchingEvents,
    int LastCasesCreated,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record UniFiConnectionTestResponse(
    string ApplicationVersion,
    DateTimeOffset TestedAt);
