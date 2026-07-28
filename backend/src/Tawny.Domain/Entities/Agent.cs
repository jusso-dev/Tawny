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

    /// <summary>
    /// Monotonic credential version. Incremented on revoke/re-issue so old JWTs fail validation.
    /// </summary>
    public int CredentialVersion { get; set; } = 1;

    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>Highest agent-supplied telemetry sequence accepted for this agent.</summary>
    public long LastTelemetrySequence { get; set; }

    public Guid? LastTelemetryBatchId { get; set; }

    /// <summary>Last observed agent clock skew in seconds (agent_occurred - server_received).</summary>
    public int LastClockSkewSeconds { get; set; }

    public int LastIngestEventCount { get; set; }

    /// <summary>
    /// Base64-encoded Ed25519 public key registered at enrollment (device-bound credentials).
    /// Private key stays on the endpoint; used for future batch signing / PoP.
    /// </summary>
    public string? DevicePublicKey { get; set; }

    public Tenant? Tenant { get; set; }
    public List<TelemetryEvent> Events { get; set; } = [];
}
