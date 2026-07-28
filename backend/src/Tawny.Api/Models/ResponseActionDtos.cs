using System.Text.Json;
using Tawny.Domain;

namespace Tawny.Api.Models;

public record CreateResponseActionRequest(
    ResponseActionType ActionType,
    JsonElement Payload,
    string? IdempotencyKey = null);

public record ResponseActionCommand(
    Guid Id,
    ResponseActionType ActionType,
    JsonElement Payload,
    string ExecutionToken,
    DateTimeOffset ExpiresAt,
    string PayloadHash);

public record ResponseActionResultRequest(
    ResponseActionStatus Status,
    string ExecutionToken,
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
    DateTimeOffset? ExpiresAt,
    JsonElement Payload,
    JsonElement? Result);
