namespace Tawny.Domain.Entities;

public class SuppressionRule
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public required string Name { get; set; }
    public string? Reason { get; set; }
    public SuppressionScope Scope { get; set; } = SuppressionScope.SpecificRule;
    public Guid? AlertRuleId { get; set; }
    public Guid? AgentId { get; set; }
    public string? PayloadPath { get; set; }
    public AlertRuleOperator Operator { get; set; } = AlertRuleOperator.Contains;
    public string? MatchValue { get; set; }
    public bool IsEnabled { get; set; } = true;
    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public int SuppressedCount { get; set; }
    public DateTimeOffset? LastSuppressedAt { get; set; }

    public Tenant? Tenant { get; set; }
    public AlertRule? AlertRule { get; set; }
    public Agent? Agent { get; set; }
}
