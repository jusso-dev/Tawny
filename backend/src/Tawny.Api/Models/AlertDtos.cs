using System.Text.Json;
using Tawny.Domain;

namespace Tawny.Api.Models;

public record AlertRuleResponse(
    Guid Id,
    string Name,
    AlertRuleFormat Format,
    string? ExternalId,
    string? Description,
    TelemetryEventType? EventType,
    AlertSeverity Severity,
    AlertRuleOperator Operator,
    string? PayloadPath,
    string? MatchValue,
    string? SourceDefinition,
    bool IsEnabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public record CreateAlertRuleRequest(
    string Name,
    TelemetryEventType? EventType,
    AlertSeverity Severity,
    AlertRuleOperator Operator,
    string? PayloadPath,
    string? MatchValue,
    bool? IsEnabled);

public record UpdateAlertRuleRequest(
    string Name,
    TelemetryEventType? EventType,
    AlertSeverity Severity,
    AlertRuleOperator Operator,
    string? PayloadPath,
    string? MatchValue,
    bool IsEnabled);

public record ImportSigmaRuleRequest(
    string RuleYaml,
    bool? IsEnabled);

public record ImportIocRulesRequest(
    string Definition,
    string? SourceFormat,
    AlertSeverity? Severity,
    bool? IsEnabled);

public record ImportIocRulesResponse(
    IReadOnlyList<AlertRuleResponse> Rules,
    IReadOnlyList<string> SkippedIndicators);

public record AlertResponse(
    long Id,
    Guid AlertRuleId,
    string RuleName,
    TelemetryEventType? RuleEventType,
    AlertRuleOperator RuleOperator,
    string? RulePayloadPath,
    string? RuleMatchValue,
    Guid AgentId,
    string Hostname,
    long TelemetryEventId,
    TelemetryEventType EventType,
    DateTimeOffset OccurredAt,
    DateTimeOffset ReceivedAt,
    JsonElement Payload,
    AlertSeverity Severity,
    AlertStatus Status,
    AlertNotificationStatus SlackNotificationStatus,
    DateTimeOffset? SlackNotifiedAt,
    string? SlackNotificationError,
    AlertNotificationStatus SentinelNotificationStatus,
    DateTimeOffset? SentinelNotifiedAt,
    string? SentinelNotificationError,
    string Title,
    string? Description,
    DateTimeOffset CreatedAt);
