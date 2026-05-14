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

public record AlertResponse(
    long Id,
    Guid AlertRuleId,
    string RuleName,
    Guid AgentId,
    string Hostname,
    long TelemetryEventId,
    AlertSeverity Severity,
    AlertStatus Status,
    string Title,
    string? Description,
    DateTimeOffset CreatedAt);
