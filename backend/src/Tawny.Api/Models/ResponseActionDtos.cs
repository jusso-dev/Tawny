using System.Text.Json;
using Tawny.Domain;

namespace Tawny.Api.Models;

public record CreateResponseActionRequest(
    ResponseActionType ActionType,
    JsonElement Payload);

public record ResponseActionCommand(
    Guid Id,
    ResponseActionType ActionType,
    JsonElement Payload);

public record ResponseActionResultRequest(
    ResponseActionStatus Status,
    string? Message,
    JsonElement? Result);

public record ResponseActionResponse(
    Guid Id,
    Guid AgentId,
    ResponseActionType ActionType,
    ResponseActionStatus Status,
    Guid? RequestedByUserId,
    DateTimeOffset RequestedAt,
    DateTimeOffset? DispatchedAt,
    DateTimeOffset? CompletedAt,
    JsonElement Payload,
    JsonElement? Result);
