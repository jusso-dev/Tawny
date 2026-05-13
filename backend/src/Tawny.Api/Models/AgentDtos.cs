using Tawny.Domain;

namespace Tawny.Api.Models;

public record EnrollRequest(
    string EnrollmentToken,
    string Hostname,
    string Os,
    string OsVersion,
    string Arch,
    string AgentVersion);

public record EnrollResponse(
    Guid AgentId,
    string Jwt,
    DateTimeOffset JwtExpiresAt,
    EnrollConfig Config);

public record EnrollConfig(int HeartbeatIntervalSeconds);

public record HeartbeatRequest(
    string AgentVersion,
    long UptimeSeconds,
    int BufferDepth);

public record HeartbeatResponse(
    string? LatestAgentVersion,
    string? DownloadUrl,
    string? Sha256,
    string? RotatedJwt,
    DateTimeOffset? JwtExpiresAt);

public record AgentSummary(
    Guid Id,
    string Hostname,
    AgentPlatform OperatingSystem,
    string OsVersion,
    string AgentVersion,
    AgentArchitecture Architecture,
    AgentStatus Status,
    DateTimeOffset? LastHeartbeatAt,
    DateTimeOffset EnrolledAt);
