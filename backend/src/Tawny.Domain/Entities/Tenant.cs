namespace Tawny.Domain.Entities;

public class Tenant
{
    public Guid Id { get; set; }
    public required string Slug { get; set; }
    public required string Name { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public List<Agent> Agents { get; set; } = [];
    public List<EnrollmentToken> EnrollmentTokens { get; set; } = [];
    public List<TelemetryEvent> TelemetryEvents { get; set; } = [];
    public List<User> Users { get; set; } = [];
    public List<AuditLog> AuditLog { get; set; } = [];
}
