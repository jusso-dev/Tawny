using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api")]
public class ResponseActionsController(TawnyDbContext db, AuditLogger audit) : ControllerBase
{
    public const int MaxPendingPerAgent = 20;
    public static readonly TimeSpan DefaultActionTtl = TimeSpan.FromMinutes(15);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private static readonly HashSet<ResponseActionStatus> TerminalStatuses =
    [
        ResponseActionStatus.Succeeded,
        ResponseActionStatus.Failed,
        ResponseActionStatus.Expired,
        ResponseActionStatus.Cancelled,
    ];

    [HttpPost("agents/{agentId:guid}/actions")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    [EnableRateLimiting("response-actions")]
    public async Task<ActionResult<ResponseActionResponse>> Create(
        Guid agentId,
        CreateResponseActionRequest req,
        CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        if (!await db.Agents.AnyAsync(a => a.Id == agentId && a.TenantId == tenantId, ct))
        {
            return NotFound();
        }

        var validation = ValidatePayload(req.ActionType, req.Payload);
        if (validation is not null)
        {
            return validation;
        }

        if (!string.IsNullOrWhiteSpace(req.IdempotencyKey))
        {
            var existing = await db.ResponseActions.AsNoTracking()
                .FirstOrDefaultAsync(
                    a => a.AgentId == agentId
                        && a.TenantId == tenantId
                        && a.IdempotencyKey == req.IdempotencyKey,
                    ct);
            if (existing is not null)
            {
                return Ok(ToResponse(existing));
            }
        }

        var pendingCount = await db.ResponseActions.CountAsync(
            a => a.AgentId == agentId
                && a.Status == ResponseActionStatus.Pending,
            ct);
        if (pendingCount >= MaxPendingPerAgent)
        {
            return Problem(
                statusCode: StatusCodes.Status429TooManyRequests,
                title: $"Agent already has {MaxPendingPerAgent} pending response actions.");
        }

        var payloadJson = req.Payload.GetRawText();
        var userIdRaw = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        Guid? userId = Guid.TryParse(userIdRaw, out var parsed) ? parsed : null;
        var now = DateTimeOffset.UtcNow;
        var action = new ResponseAction
        {
            Id = Guid.NewGuid(),
            AgentId = agentId,
            TenantId = tenantId,
            ActionType = req.ActionType,
            RequestedByUserId = userId,
            RequestedAt = now,
            ExpiresAt = now.Add(DefaultActionTtl),
            PayloadJson = payloadJson,
            PayloadHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payloadJson))),
            IdempotencyKey = string.IsNullOrWhiteSpace(req.IdempotencyKey) ? null : req.IdempotencyKey.Trim(),
        };
        db.ResponseActions.Add(action);
        audit.Add(User, "response_action.create", action.Id.ToString(), new
        {
            action.AgentId,
            action.ActionType,
            action.PayloadHash,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(ListForAgent), new { agentId }, ToResponse(action));
    }

    [HttpGet("agents/{agentId:guid}/actions")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
    public async Task<ActionResult<IReadOnlyList<ResponseActionResponse>>> ListForAgent(
        Guid agentId,
        CancellationToken ct)
    {
        if (User.HasClaim(claim => claim.Type == "api_token_id") && !User.IsInRole("Admin"))
        {
            return Forbid();
        }

        var tenantId = User.GetTenantId();
        if (!await db.Agents.AnyAsync(a => a.Id == agentId && a.TenantId == tenantId, ct))
        {
            return NotFound();
        }

        var rows = await db.ResponseActions
            .AsNoTracking()
            .Where(a => a.AgentId == agentId && a.TenantId == tenantId)
            .OrderByDescending(a => a.RequestedAt)
            .Take(100)
            .ToListAsync(ct);

        return Ok(rows.Select(ToResponse).ToList());
    }

    [HttpPost("agents/{agentId:guid}/actions/{id:guid}/cancel")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<ResponseActionResponse>> Cancel(Guid agentId, Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var action = await db.ResponseActions
            .FirstOrDefaultAsync(a => a.Id == id && a.AgentId == agentId && a.TenantId == tenantId, ct);
        if (action is null)
        {
            return NotFound();
        }

        if (TerminalStatuses.Contains(action.Status))
        {
            return Problem(statusCode: 409, title: $"Action already terminal ({action.Status}).");
        }

        action.Status = ResponseActionStatus.Cancelled;
        action.CompletedAt = DateTimeOffset.UtcNow;
        action.ExecutionTokenHash = null;
        audit.Add(User, "response_action.cancel", action.Id.ToString(), new { action.AgentId });
        await db.SaveChangesAsync(ct);
        return Ok(ToResponse(action));
    }

    [HttpPost("agents/actions/{id:guid}/result")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.AgentJwt)]
    public async Task<IActionResult> Complete(Guid id, ResponseActionResultRequest req, CancellationToken ct)
    {
        if (!TryGetAgentId(out var agentId) || !User.TryGetTenantId(out var tenantId))
        {
            return Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(req.ExecutionToken))
        {
            return Problem(statusCode: 400, title: "execution_token is required.");
        }

        if (req.Status is not (ResponseActionStatus.Succeeded or ResponseActionStatus.Failed))
        {
            return Problem(statusCode: 400, title: "Response action results must be succeeded or failed.");
        }

        var action = await db.ResponseActions
            .FirstOrDefaultAsync(a => a.Id == id && a.AgentId == agentId && a.TenantId == tenantId, ct);
        if (action is null)
        {
            return NotFound();
        }

        if (TerminalStatuses.Contains(action.Status))
        {
            audit.Add((Guid?)null, tenantId, "response_action.complete_rejected", action.Id.ToString(), new
            {
                reason = "already_terminal",
                action.Status,
            });
            await db.SaveChangesAsync(ct);
            return Problem(statusCode: 409, title: "Action already completed.");
        }

        if (action.Status is not (ResponseActionStatus.Dispatched or ResponseActionStatus.Running))
        {
            audit.Add((Guid?)null, tenantId, "response_action.complete_rejected", action.Id.ToString(), new
            {
                reason = "not_dispatched",
                action.Status,
            });
            await db.SaveChangesAsync(ct);
            return Problem(statusCode: 409, title: "Action was never dispatched.");
        }

        if (action.ExpiresAt is not null && action.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            action.Status = ResponseActionStatus.Expired;
            action.CompletedAt = DateTimeOffset.UtcNow;
            action.ExecutionTokenHash = null;
            audit.Add((Guid?)null, tenantId, "response_action.expired", action.Id.ToString(), new { action.AgentId });
            await db.SaveChangesAsync(ct);
            return Problem(statusCode: 410, title: "Action expired.");
        }

        if (string.IsNullOrEmpty(action.ExecutionTokenHash)
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(action.ExecutionTokenHash),
                Encoding.UTF8.GetBytes(TokenHashing.Hash(req.ExecutionToken))))
        {
            audit.Add((Guid?)null, tenantId, "response_action.complete_rejected", action.Id.ToString(), new
            {
                reason = "bad_execution_token",
            });
            await db.SaveChangesAsync(ct);
            return Problem(statusCode: 401, title: "Invalid execution token.");
        }

        // Single-use: clear hash before success path so replays fail.
        action.ExecutionTokenHash = null;
        action.Status = req.Status;
        action.CompletedAt = DateTimeOffset.UtcNow;
        action.ReceivedAt = DateTimeOffset.UtcNow;
        action.ResultJson = JsonSerializer.Serialize(new
        {
            req.Message,
            result = req.Result,
        }, JsonOptions);
        audit.Add((Guid?)null, tenantId, "response_action.complete", action.Id.ToString(), new
        {
            action.AgentId,
            action.ActionType,
            action.Status,
        });
        await db.SaveChangesAsync(ct);

        return NoContent();
    }

    private static ActionResult<ResponseActionResponse>? ValidatePayload(
        ResponseActionType actionType,
        JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            return ProblemResult("payload must be a JSON object.");
        }

        if (actionType == ResponseActionType.KillProcess)
        {
            if (!payload.TryGetProperty("pid", out var pid)
                || pid.ValueKind != JsonValueKind.Number
                || !pid.TryGetInt32(out var pidValue)
                || pidValue <= 0)
            {
                return ProblemResult("kill_process requires a positive integer payload.pid.");
            }
        }

        return null;
    }

    private static ActionResult<ResponseActionResponse> ProblemResult(string title) =>
        new BadRequestObjectResult(new ProblemDetails
        {
            Status = StatusCodes.Status400BadRequest,
            Title = title,
        });

    private static ResponseActionResponse ToResponse(ResponseAction action) => new(
        action.Id,
        action.AgentId,
        action.ActionType,
        action.Status,
        action.RequestedByUserId,
        action.RequestedAt,
        action.DispatchedAt,
        action.CompletedAt,
        action.ExpiresAt,
        JsonSerializer.Deserialize<JsonElement>(action.PayloadJson),
        string.IsNullOrWhiteSpace(action.ResultJson)
            ? null
            : JsonSerializer.Deserialize<JsonElement>(action.ResultJson));

    private bool TryGetAgentId(out Guid id)
    {
        var claim = User.FindFirst("agent_id")?.Value;
        return Guid.TryParse(claim, out id);
    }
}
