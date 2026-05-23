using Tawny.Domain;

namespace Tawny.Api.Models;

public record CreateSuppressionRuleRequest(
    string Name,
    string? Reason,
    SuppressionScope Scope,
    Guid? AlertRuleId,
    Guid? AgentId,
    string? PayloadPath,
    AlertRuleOperator Operator,
    string? MatchValue,
    bool? IsEnabled,
    DateTimeOffset? ExpiresAt);

public record UpdateSuppressionRuleRequest(
    string Name,
    string? Reason,
    SuppressionScope Scope,
    Guid? AlertRuleId,
    Guid? AgentId,
    string? PayloadPath,
    AlertRuleOperator Operator,
    string? MatchValue,
    bool IsEnabled,
    DateTimeOffset? ExpiresAt);

public record SuppressionRuleResponse(
    Guid Id,
    string Name,
    string? Reason,
    SuppressionScope Scope,
    Guid? AlertRuleId,
    string? AlertRuleName,
    Guid? AgentId,
    string? AgentHostname,
    string? PayloadPath,
    AlertRuleOperator Operator,
    string? MatchValue,
    bool IsEnabled,
    DateTimeOffset? ExpiresAt,
    int SuppressedCount,
    DateTimeOffset? LastSuppressedAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
