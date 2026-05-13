namespace Tawny.Api.Models;

public record CreateEnrollmentTokenRequest(int? LifetimeHours);

public record CreateEnrollmentTokenResponse(
    Guid Id,
    string Token,
    DateTimeOffset ExpiresAt);

public record EnrollmentTokenSummary(
    Guid Id,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset? UsedAt,
    Guid? UsedByAgentId);
