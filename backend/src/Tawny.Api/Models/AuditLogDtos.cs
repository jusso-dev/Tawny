using System.Text.Json;

namespace Tawny.Api.Models;

public record AuditLogResponse(
    long Id,
    Guid? UserId,
    string Action,
    string? Target,
    JsonElement? Metadata,
    DateTimeOffset OccurredAt);
