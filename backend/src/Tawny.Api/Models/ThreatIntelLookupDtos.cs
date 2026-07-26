using Tawny.Domain;

namespace Tawny.Api.Models;

public record ThreatIntelLookupRequest(IReadOnlyList<string> Values);

public record ThreatIntelMatchResponse(
    string Value,
    string Kind,
    Guid RuleId,
    string RuleName,
    string? Description,
    AlertSeverity Severity,
    Guid FeedId,
    string FeedName);

public record ThreatIntelLookupResponse(
    IReadOnlyList<ThreatIntelMatchResponse> Matches);
