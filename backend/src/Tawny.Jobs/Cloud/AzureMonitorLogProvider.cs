using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure.Security;

namespace Tawny.Jobs.Cloud;

public sealed class AzureMonitorLogProvider(IIntegrationSecretProtector secrets) : ICloudLogProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public bool Supports(CloudSourceKind source)
        => source is CloudSourceKind.AzureActivityLog
            or CloudSourceKind.AzureEntraAuditLog
            or CloudSourceKind.AzureEntraSignInLog;

    public async Task<CloudQueryResult> QueryAsync(
        CloudConnection connection,
        CloudHunt hunt,
        DateTimeOffset from,
        DateTimeOffset to,
        int limit,
        CancellationToken ct)
    {
        if (connection.Provider != CloudProvider.Azure)
            throw new InvalidOperationException("Azure Activity Log requires an Azure connection.");

        var config = CloudConfiguration.Read<AzureConnectionConfig>(connection);
        if (string.IsNullOrWhiteSpace(config.WorkspaceId))
            throw new InvalidOperationException("Azure connection requires workspace_id containing AzureActivity.");

        var credential = CreateCredential(connection, config);
        var client = new LogsQueryClient(credential);
        var query = ParseQuery(hunt.QueryJson);
        var tableName = hunt.Source switch
        {
            CloudSourceKind.AzureActivityLog => "AzureActivity",
            CloudSourceKind.AzureEntraAuditLog => "AuditLogs",
            CloudSourceKind.AzureEntraSignInLog => "SigninLogs",
            _ => throw new InvalidOperationException($"Unsupported Azure source {hunt.Source}."),
        };
        var kql = string.IsNullOrWhiteSpace(query.Kql)
            ? $"{tableName} | order by TimeGenerated desc | take {limit}"
            : $"{query.Kql.Trim().TrimEnd(';')} | take {limit}";
        var response = await client.QueryWorkspaceAsync(
            config.WorkspaceId,
            kql,
            new QueryTimeRange(from, to),
            cancellationToken: ct);

        var table = response.Value.Table;
        var matches = new List<CloudLogRecord>(Math.Min(limit, table.Rows.Count));
        foreach (var row in table.Rows.Take(limit))
        {
            var values = new Dictionary<string, object?>();
            for (var index = 0; index < table.Columns.Count; index++)
            {
                values[table.Columns[index].Name] = row[index];
            }
            var evidence = JsonSerializer.Serialize(values, JsonOptions);
            var occurredAt = ReadDate(values, "TimeGenerated") ?? from;
            var eventId = ReadText(values, "CorrelationId")
                ?? ReadText(values, "EventDataId")
                ?? ReadText(values, "Id")
                ?? $"{occurredAt:O}:{matches.Count}";
            matches.Add(new CloudLogRecord(
                eventId,
                occurredAt,
                ReadText(values, "OperationNameValue")
                    ?? ReadText(values, "OperationName")
                    ?? ReadText(values, "AppDisplayName")
                    ?? "Azure security event",
                ReadText(values, "Caller")
                    ?? ReadText(values, "UserPrincipalName")
                    ?? ReadText(values, "Identity")
                    ?? ReadText(values, "InitiatedBy"),
                ReadText(values, "ResourceId")
                    ?? ReadText(values, "_ResourceId")
                    ?? ReadText(values, "ResourceDisplayName")
                    ?? ReadText(values, "AppDisplayName")
                    ?? ReadText(values, "TargetResources"),
                evidence));
        }

        return new CloudQueryResult(table.Rows.Count, matches);
    }

    private TokenCredential CreateCredential(CloudConnection connection, AzureConnectionConfig config)
    {
        return connection.CredentialMode switch
        {
            CloudCredentialMode.AzureManagedIdentity => new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ManagedIdentityClientId = config.ClientId,
            }),
            CloudCredentialMode.AzureClientSecret => CreateClientSecret(connection, config),
            _ => throw new InvalidOperationException("Unsupported Azure credential mode."),
        };
    }

    private ClientSecretCredential CreateClientSecret(CloudConnection connection, AzureConnectionConfig config)
    {
        var credential = CloudConfiguration.ReadCredential<AzureCredential>(connection, secrets)
            ?? throw new InvalidOperationException("Azure client secret is missing.");
        if (string.IsNullOrWhiteSpace(config.TenantId) || string.IsNullOrWhiteSpace(config.ClientId))
            throw new InvalidOperationException("Azure client-secret mode requires tenant_id and client_id.");
        return new ClientSecretCredential(config.TenantId, config.ClientId, credential.ClientSecret);
    }

    private static AzureActivityQuery ParseQuery(string json)
        => string.IsNullOrWhiteSpace(json) || json == "{}"
            ? new AzureActivityQuery()
            : JsonSerializer.Deserialize<AzureActivityQuery>(json, JsonOptions) ?? new AzureActivityQuery();

    private static string? ReadText(IReadOnlyDictionary<string, object?> values, string name)
        => values.TryGetValue(name, out var value) ? value?.ToString() : null;

    private static DateTimeOffset? ReadDate(IReadOnlyDictionary<string, object?> values, string name)
    {
        if (!values.TryGetValue(name, out var value) || value is null) return null;
        if (value is DateTimeOffset offset) return offset;
        if (value is DateTime date) return new DateTimeOffset(date, TimeSpan.Zero);
        return DateTimeOffset.TryParse(value.ToString(), out var parsed) ? parsed : null;
    }

    private sealed record AzureConnectionConfig(string WorkspaceId, string? TenantId, string? ClientId);
    private sealed record AzureCredential(string ClientSecret);
    private sealed record AzureActivityQuery(string? Kql = null);
}
