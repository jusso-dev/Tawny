using System.Text.Json;
using Amazon;
using Amazon.CloudTrail;
using Amazon.CloudTrail.Model;
using Amazon.GuardDuty;
using Amazon.GuardDuty.Model;
using Amazon.Runtime;
using Amazon.Runtime.Credentials;
using Amazon.SecurityToken;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure.Security;

namespace Tawny.Jobs.Cloud;

public sealed class AwsCloudLogProvider(IIntegrationSecretProtector secrets) : ICloudLogProvider
{
    private const int PageSize = 50;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public bool Supports(CloudSourceKind source)
        => source is CloudSourceKind.AwsCloudTrail or CloudSourceKind.AwsGuardDuty;

    public async Task<CloudQueryResult> QueryAsync(
        CloudConnection connection,
        CloudHunt hunt,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        CancellationToken ct)
    {
        if (connection.Provider != Tawny.Domain.CloudProvider.Aws)
            throw new InvalidOperationException("AWS source requires an AWS connection.");

        var config = CloudConfiguration.Read<AwsConnectionConfig>(connection);
        if (config.Regions is not { Length: > 0 })
            throw new InvalidOperationException("AWS connection requires at least one region.");

        var credentials = CreateCredentials(connection, config);
        return hunt.Source switch
        {
            CloudSourceKind.AwsCloudTrail => await QueryCloudTrailAsync(credentials, config, hunt, from, to, limit, ct),
            CloudSourceKind.AwsGuardDuty => await QueryGuardDutyAsync(credentials, config, from, to, limit, ct),
            _ => throw new InvalidOperationException($"Unsupported AWS source {hunt.Source}."),
        };
    }

    private AWSCredentials CreateCredentials(CloudConnection connection, AwsConnectionConfig config)
    {
        if (connection.CredentialMode != CloudCredentialMode.AwsAssumeRole)
            throw new InvalidOperationException("AWS connections must use AssumeRole.");
        if (string.IsNullOrWhiteSpace(config.RoleArn))
            throw new InvalidOperationException("AWS connection requires role_arn.");

        var credential = CloudConfiguration.ReadCredential<AwsCredential>(connection, secrets);
        var options = new AssumeRoleAWSCredentialsOptions();
        if (!string.IsNullOrWhiteSpace(credential?.ExternalId)) options.ExternalId = credential.ExternalId;
        return new AssumeRoleAWSCredentials(
            DefaultAWSCredentialsIdentityResolver.GetCredentials(new AmazonSecurityTokenServiceConfig()),
            config.RoleArn,
            $"tawny-{connection.Id:N}"[..Math.Min(32, $"tawny-{connection.Id:N}".Length)],
            options);
    }

    private static async Task<CloudQueryResult> QueryCloudTrailAsync(
        AWSCredentials credentials,
        AwsConnectionConfig config,
        CloudHunt hunt,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        CancellationToken ct)
    {
        var filter = ParseCloudTrailQuery(hunt.QueryJson);
        var matches = new List<CloudLogRecord>();
        var recordsRead = 0;

        foreach (var region in config.Regions)
        {
            using var client = new AmazonCloudTrailClient(credentials, RegionEndpoint.GetBySystemName(region));
            string? token = null;
            do
            {
                var request = new LookupEventsRequest
                {
                    StartTime = from.UtcDateTime,
                    EndTime = to.UtcDateTime,
                    MaxResults = PageSize,
                    NextToken = token,
                };
                var attribute = ToLookupAttribute(filter);
                if (attribute is not null) request.LookupAttributes = [attribute];

                var response = await client.LookupEventsAsync(request, ct);
                token = response.NextToken;
                foreach (var item in response.Events)
                {
                    recordsRead++;
                    var evidence = string.IsNullOrWhiteSpace(item.CloudTrailEvent) ? "{}" : item.CloudTrailEvent;
                    using var document = JsonDocument.Parse(evidence);
                    if (!MatchesCloudTrailFilter(document.RootElement, filter)) continue;
                    var eventId = string.IsNullOrWhiteSpace(item.EventId)
                        ? $"{region}:{item.EventTime:O}:{item.EventName}:{recordsRead}"
                        : $"{region}:{item.EventId}";
                    matches.Add(new CloudLogRecord(
                        eventId,
                        new DateTimeOffset(item.EventTime ?? from.UtcDateTime, TimeSpan.Zero),
                        item.EventName ?? "AWS CloudTrail event",
                        item.Username ?? ReadString(document.RootElement, "userIdentity", "arn"),
                        item.Resources?.FirstOrDefault()?.ResourceName,
                        evidence));
                    if (matches.Count >= limit) return new CloudQueryResult(recordsRead, matches);
                }
            } while (!string.IsNullOrWhiteSpace(token) && matches.Count < limit);
        }

        return new CloudQueryResult(recordsRead, matches);
    }

    private static async Task<CloudQueryResult> QueryGuardDutyAsync(
        AWSCredentials credentials,
        AwsConnectionConfig config,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        CancellationToken ct)
    {
        var matches = new List<CloudLogRecord>();
        var recordsRead = 0;
        foreach (var region in config.Regions)
        {
            using var client = new AmazonGuardDutyClient(credentials, RegionEndpoint.GetBySystemName(region));
            foreach (var detectorId in await ListDetectorIdsAsync(client, ct))
            {
                string? token = null;
                do
                {
                    var list = await client.ListFindingsAsync(new ListFindingsRequest
                    {
                        DetectorId = detectorId,
                        MaxResults = PageSize,
                        NextToken = token,
                        FindingCriteria = new FindingCriteria
                        {
                            Criterion = new Dictionary<string, Condition>
                            {
                                ["updatedAt"] = new()
                                {
                                    GreaterThanOrEqual = from.ToUnixTimeMilliseconds(),
                                    LessThanOrEqual = to.ToUnixTimeMilliseconds(),
                                },
                            },
                        },
                    }, ct);
                    token = list.NextToken;
                    if (list.FindingIds.Count == 0) continue;

                    var detail = await client.GetFindingsAsync(new GetFindingsRequest
                    {
                        DetectorId = detectorId,
                        FindingIds = list.FindingIds,
                    }, ct);
                    recordsRead += detail.Findings.Count;
                    foreach (var finding in detail.Findings)
                    {
                        var evidence = JsonSerializer.Serialize(finding, JsonOptions);
                        matches.Add(new CloudLogRecord(
                            $"{region}:{finding.Id}",
                            DateTimeOffset.TryParse(finding.UpdatedAt, out var updatedAt) ? updatedAt : from,
                            finding.Title ?? finding.Type ?? "AWS GuardDuty finding",
                            finding.Service?.Action?.ActionType,
                            finding.Resource?.ResourceType,
                            evidence));
                        if (matches.Count >= limit) return new CloudQueryResult(recordsRead, matches);
                    }
                } while (!string.IsNullOrWhiteSpace(token) && matches.Count < limit);
            }
        }
        return new CloudQueryResult(recordsRead, matches);
    }

    private static async Task<IReadOnlyList<string>> ListDetectorIdsAsync(
        IAmazonGuardDuty client,
        CancellationToken ct)
    {
        var ids = new List<string>();
        string? token = null;
        do
        {
            var response = await client.ListDetectorsAsync(new ListDetectorsRequest
            {
                MaxResults = PageSize,
                NextToken = token,
            }, ct);
            ids.AddRange(response.DetectorIds);
            token = response.NextToken;
        } while (!string.IsNullOrWhiteSpace(token));
        return ids;
    }

    private static CloudTrailQuery ParseCloudTrailQuery(string json)
        => string.IsNullOrWhiteSpace(json) || json == "{}"
            ? new CloudTrailQuery()
            : JsonSerializer.Deserialize<CloudTrailQuery>(json, JsonOptions) ?? new CloudTrailQuery();

    private static LookupAttribute? ToLookupAttribute(CloudTrailQuery query)
    {
        if (string.IsNullOrWhiteSpace(query.AttributeKey) || string.IsNullOrWhiteSpace(query.AttributeValue)) return null;
        var key = query.AttributeKey.Trim().ToLowerInvariant() switch
        {
            "event_id" => LookupAttributeKey.EventId,
            "event_name" => LookupAttributeKey.EventName,
            "read_only" => LookupAttributeKey.ReadOnly,
            "resource_name" => LookupAttributeKey.ResourceName,
            "resource_type" => LookupAttributeKey.ResourceType,
            "username" => LookupAttributeKey.Username,
            "access_key_id" => LookupAttributeKey.AccessKeyId,
            "event_source" => LookupAttributeKey.EventSource,
            _ => throw new InvalidOperationException("Unsupported CloudTrail attribute_key."),
        };
        return new LookupAttribute { AttributeKey = key, AttributeValue = query.AttributeValue };
    }

    private static bool MatchesCloudTrailFilter(JsonElement root, CloudTrailQuery query)
    {
        if (!string.IsNullOrWhiteSpace(query.SourceIp)
            && !string.Equals(ReadString(root, "sourceIPAddress"), query.SourceIp, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrWhiteSpace(query.ErrorCode)
            && !string.Equals(ReadString(root, "errorCode"), query.ErrorCode, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static string? ReadString(JsonElement root, params string[] path)
    {
        var current = root;
        foreach (var segment in path)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out current)) return null;
        }
        return current.ValueKind == JsonValueKind.String ? current.GetString() : current.GetRawText();
    }

    private sealed record AwsConnectionConfig(string RoleArn, string[] Regions);
    private sealed record AwsCredential(string? ExternalId);
    private sealed record CloudTrailQuery(
        string? AttributeKey = null,
        string? AttributeValue = null,
        string? SourceIp = null,
        string? ErrorCode = null);
}
