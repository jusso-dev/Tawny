using FluentValidation;
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
    DateTimeOffset? JwtExpiresAt,
    IReadOnlyList<ResponseActionCommand> Actions);

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

public class EnrollRequestValidator : AbstractValidator<EnrollRequest>
{
    private static readonly string[] SupportedOperatingSystems = ["windows", "macos", "linux"];
    private static readonly string[] SupportedArchitectures = ["x64", "amd64", "x86_64", "arm64", "aarch64"];

    public EnrollRequestValidator()
    {
        RuleFor(x => x.EnrollmentToken)
            .NotEmpty()
            .MaximumLength(512);
        RuleFor(x => x.Hostname)
            .Cascade(CascadeMode.Stop)
            .NotEmpty()
            .MaximumLength(255)
            .Must(value => value.All(c => !char.IsControl(c)))
            .WithMessage("hostname must not contain control characters.");
        RuleFor(x => x.Os)
            .Must(value => SupportedOperatingSystems.Contains(value, StringComparer.OrdinalIgnoreCase))
            .WithMessage("os must be windows, macos, or linux.");
        RuleFor(x => x.OsVersion)
            .NotEmpty()
            .MaximumLength(64);
        RuleFor(x => x.Arch)
            .Must(value => SupportedArchitectures.Contains(value, StringComparer.OrdinalIgnoreCase))
            .WithMessage("arch must be x64/amd64/x86_64 or arm64/aarch64.");
        RuleFor(x => x.AgentVersion)
            .NotEmpty()
            .MaximumLength(32);
    }
}

public class HeartbeatRequestValidator : AbstractValidator<HeartbeatRequest>
{
    public HeartbeatRequestValidator()
    {
        RuleFor(x => x.AgentVersion)
            .NotEmpty()
            .MaximumLength(32);
        RuleFor(x => x.UptimeSeconds)
            .GreaterThanOrEqualTo(0);
        RuleFor(x => x.BufferDepth)
            .InclusiveBetween(0, 10_000_000);
    }
}
