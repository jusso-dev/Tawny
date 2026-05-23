namespace Tawny.Domain.Entities;

public class ApiToken
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public required string Name { get; set; }
    public required string TokenHash { get; set; }
    public required string TokenPrefix { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public UserRole Role { get; set; } = UserRole.Viewer;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }

    public Tenant? Tenant { get; set; }
}
