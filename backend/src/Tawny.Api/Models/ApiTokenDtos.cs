using Tawny.Domain;

namespace Tawny.Api.Models;

public record CreateApiTokenRequest(
    string Name,
    UserRole? Role,
    DateTimeOffset? ExpiresAt);

public record CreatedApiTokenResponse(
    Guid Id,
    string Name,
    string Token,
    string TokenPrefix,
    UserRole Role,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt);

public record ApiTokenResponse(
    Guid Id,
    string Name,
    string TokenPrefix,
    UserRole Role,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? RevokedAt);
