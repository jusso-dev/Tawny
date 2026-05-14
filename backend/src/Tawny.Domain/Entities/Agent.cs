namespace Tawny.Domain.Entities;

public class Agent
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public required string Hostname { get; set; }
    public AgentPlatform OperatingSystem { get; set; }
    public required string OsVersion { get; set; }
    public required string AgentVersion { get; set; }
    public AgentArchitecture Architecture { get; set; }
    public string? PublicIp { get; set; }
    public DateTimeOffset EnrolledAt { get; set; }
    public DateTimeOffset? LastHeartbeatAt { get; set; }
    public AgentStatus Status { get; set; } = AgentStatus.Unknown;
    public string TagsJson { get; set; } = "[]";

    public Tenant? Tenant { get; set; }
    public List<TelemetryEvent> Events { get; set; } = [];
}
