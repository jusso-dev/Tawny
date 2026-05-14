using System.Text.Json;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/agents")]
public class TelemetryController(
    TawnyDbContext db,
    IValidator<IngestEventsRequest> validator) : ControllerBase
{
    private const int MaxRequestBytes = 1024 * 1024;
    private const int DefaultLimit = 50;
    private const int MaxLimit = 200;

    [HttpPost("events")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.AgentJwt)]
    [RequestSizeLimit(MaxRequestBytes)]
    public async Task<IActionResult> Ingest(
        [FromBody] IngestEventsRequest req,
        CancellationToken ct)
    {
        if (Request.ContentLength > MaxRequestBytes)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        if (!TryGetAgentId(out var agentId))
        {
            return Unauthorized();
        }

        if (!await db.Agents.AnyAsync(a => a.Id == agentId, ct))
        {
            return NotFound();
        }

        var validation = await validator.ValidateAsync(req, ct);
        if (!validation.IsValid)
        {
            return ValidationProblem(new ValidationProblemDetails(validation.ToDictionary()));
        }

        var receivedAt = DateTimeOffset.UtcNow;
        var events = req.Events.Select(ev => new TelemetryEvent
        {
            AgentId = agentId,
            EventType = ev.Type,
            OccurredAt = DateTimeOffset.FromUnixTimeSeconds(ev.OccurredAt),
            ReceivedAt = receivedAt,
            Payload = ev.Payload.GetRawText(),
        });

        db.TelemetryEvents.AddRange(events);
        await db.SaveChangesAsync(ct);

        return Accepted();
    }

    [HttpGet("{id:guid}/events")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
    public async Task<ActionResult<IReadOnlyList<TelemetryEventResponse>>> List(
        Guid id,
        [FromQuery] string? type,
        [FromQuery] DateTimeOffset? before,
        [FromQuery] int limit = DefaultLimit,
        CancellationToken ct = default)
    {
        if (!await db.Agents.AnyAsync(a => a.Id == id, ct))
        {
            return NotFound();
        }

        TelemetryEventType? eventType = null;
        if (!string.IsNullOrWhiteSpace(type))
        {
            if (!TryParseEventType(type, out var parsed))
            {
                return Problem(statusCode: 400, title: $"Unknown telemetry event type: {type}");
            }
            eventType = parsed;
        }

        var take = Math.Clamp(limit, 1, MaxLimit);
        var query = db.TelemetryEvents
            .AsNoTracking()
            .Where(e => e.AgentId == id);

        if (eventType is not null)
        {
            query = query.Where(e => e.EventType == eventType.Value);
        }

        if (before is not null)
        {
            query = query.Where(e => e.ReceivedAt < before.Value);
        }

        var rows = await query
            .OrderByDescending(e => e.ReceivedAt)
            .ThenByDescending(e => e.Id)
            .Take(take)
            .ToListAsync(ct);

        return Ok(rows.Select(e => new TelemetryEventResponse(
            e.Id,
            e.AgentId,
            e.EventType,
            e.OccurredAt,
            e.ReceivedAt,
            JsonSerializer.Deserialize<JsonElement>(e.Payload))).ToList());
    }

    private bool TryGetAgentId(out Guid id)
    {
        var claim = User.FindFirst("agent_id")?.Value;
        return Guid.TryParse(claim, out id);
    }

    private static bool TryParseEventType(string value, out TelemetryEventType eventType)
    {
        foreach (var candidate in Enum.GetValues<TelemetryEventType>())
        {
            if (string.Equals(ToWireName(candidate), value, StringComparison.OrdinalIgnoreCase)
                || string.Equals(candidate.ToString(), value, StringComparison.OrdinalIgnoreCase))
            {
                eventType = candidate;
                return true;
            }
        }

        eventType = default;
        return false;
    }

    private static string ToWireName(TelemetryEventType type) => type switch
    {
        TelemetryEventType.ProcessSnapshot => "process_snapshot",
        TelemetryEventType.NetworkSnapshot => "network_snapshot",
        TelemetryEventType.UserSession => "user_session",
        TelemetryEventType.SystemInfo => "system_info",
        TelemetryEventType.FileIntegrity => "file_integrity",
        TelemetryEventType.Heartbeat => "heartbeat",
        _ => type.ToString(),
    };
}
