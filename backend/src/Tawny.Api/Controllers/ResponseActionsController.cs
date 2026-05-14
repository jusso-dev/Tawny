using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    [HttpPost("agents/{agentId:guid}/actions")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
    public async Task<ActionResult<ResponseActionResponse>> Create(
        Guid agentId,
        CreateResponseActionRequest req,
        CancellationToken ct)
    {
        if (!await db.Agents.AnyAsync(a => a.Id == agentId, ct))
        {
            return NotFound();
        }

        var validation = ValidatePayload(req.ActionType, req.Payload);
        if (validation is not null)
        {
            return validation;
        }

        var userIdRaw = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        Guid? userId = Guid.TryParse(userIdRaw, out var parsed) ? parsed : null;
        var action = new ResponseAction
        {
            Id = Guid.NewGuid(),
            AgentId = agentId,
            ActionType = req.ActionType,
            RequestedByUserId = userId,
            RequestedAt = DateTimeOffset.UtcNow,
            PayloadJson = req.Payload.GetRawText(),
        };
        db.ResponseActions.Add(action);
        audit.Add(User, "response_action.create", action.Id.ToString(), new
        {
            action.AgentId,
            action.ActionType,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(ListForAgent), new { agentId }, ToResponse(action));
    }

    [HttpGet("agents/{agentId:guid}/actions")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
    public async Task<ActionResult<IReadOnlyList<ResponseActionResponse>>> ListForAgent(
        Guid agentId,
        CancellationToken ct)
    {
        if (!await db.Agents.AnyAsync(a => a.Id == agentId, ct))
        {
            return NotFound();
        }

        var rows = await db.ResponseActions
            .AsNoTracking()
            .Where(a => a.AgentId == agentId)
            .OrderByDescending(a => a.RequestedAt)
            .Take(100)
            .ToListAsync(ct);

        return Ok(rows.Select(ToResponse).ToList());
    }

    [HttpPost("agents/actions/{id:guid}/result")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.AgentJwt)]
    public async Task<IActionResult> Complete(Guid id, ResponseActionResultRequest req, CancellationToken ct)
    {
        if (!TryGetAgentId(out var agentId))
        {
            return Unauthorized();
        }

        var action = await db.ResponseActions.FirstOrDefaultAsync(a => a.Id == id && a.AgentId == agentId, ct);
        if (action is null)
        {
            return NotFound();
        }

        if (req.Status is not (ResponseActionStatus.Succeeded or ResponseActionStatus.Failed))
        {
            return Problem(statusCode: 400, title: "Response action results must be succeeded or failed.");
        }

        action.Status = req.Status;
        action.CompletedAt = DateTimeOffset.UtcNow;
        action.ResultJson = JsonSerializer.Serialize(new
        {
            req.Message,
            result = req.Result,
        }, JsonOptions);
        audit.Add((Guid?)null, "response_action.complete", action.Id.ToString(), new
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

        if (actionType == ResponseActionType.KillProcess
            && (!payload.TryGetProperty("pid", out var pid)
                || pid.ValueKind != JsonValueKind.Number
                || !pid.TryGetInt32(out var pidValue)
                || pidValue <= 0))
        {
            return ProblemResult("kill_process requires a positive integer payload.pid.");
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
