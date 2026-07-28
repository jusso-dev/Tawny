using System.Text.Json;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/agents")]
public class TelemetryController(
    TawnyDbContext db,
    AuditLogger audit,
    IValidator<IngestEventsRequest> validator,
    AlertRuleEvaluator alertRules,
    ITelemetrySink telemetrySink,
    IAlertSink alertSink,
    AgentEventBroker eventBroker,
    IOptions<TelemetryIntegrityOptions> integrityOptions) : ControllerBase
{
    private const int MaxRequestBytes = 1024 * 1024;
    private const int DefaultLimit = 50;
    private const int MaxLimit = 200;

    [HttpPost("events")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.AgentJwt)]
    [EnableRateLimiting("agent-events")]
    [RequestSizeLimit(MaxRequestBytes)]
    public async Task<IActionResult> Ingest(
        [FromBody] IngestEventsRequest req,
        CancellationToken ct)
    {
        if (Request.ContentLength > MaxRequestBytes)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        if (!TryGetAgentId(out var agentId) || !User.TryGetTenantId(out var tenantId))
        {
            return Unauthorized();
        }

        var agent = await db.Agents.FirstOrDefaultAsync(a => a.Id == agentId && a.TenantId == tenantId, ct);
        if (agent is null)
        {
            return NotFound();
        }

        if (agent.RevokedAt is not null || agent.Status == AgentStatus.Revoked)
        {
            return Unauthorized();
        }

        var validation = await validator.ValidateAsync(req, ct);
        if (!validation.IsValid)
        {
            return ValidationProblem(new ValidationProblemDetails(validation.ToDictionary()));
        }

        var options = integrityOptions.Value;
        var receivedAt = DateTimeOffset.UtcNow;
        var batchId = req.BatchId is null || req.BatchId == Guid.Empty
            ? Guid.NewGuid()
            : req.BatchId.Value;

        var sequenceAssessment = TelemetryIntegrity.AssessSequence(
            agent,
            req.Events.Select(e => e.Sequence).ToList());
        if (sequenceAssessment.Rollback)
        {
            audit.Add((Guid?)null, tenantId, "telemetry.sequence_rollback", agentId.ToString(), new
            {
                previous_max = sequenceAssessment.PreviousMax,
                batch_min = sequenceAssessment.MinSequence,
                batch_id = batchId,
            });
        }
        else if (sequenceAssessment.Gap)
        {
            audit.Add((Guid?)null, tenantId, "telemetry.sequence_gap", agentId.ToString(), new
            {
                previous_max = sequenceAssessment.PreviousMax,
                batch_min = sequenceAssessment.MinSequence,
                batch_id = batchId,
            });
        }

        if (TelemetryIntegrity.IsVolumeSpike(agent, req.Events.Count, options))
        {
            audit.Add((Guid?)null, tenantId, "telemetry.volume_spike", agentId.ToString(), new
            {
                previous_count = agent.LastIngestEventCount,
                batch_count = req.Events.Count,
                batch_id = batchId,
            });
        }

        // Hostname / source network change tracking.
        var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrEmpty(remoteIp)
            && !string.IsNullOrEmpty(agent.PublicIp)
            && !string.Equals(remoteIp, agent.PublicIp, StringComparison.Ordinal))
        {
            audit.Add((Guid?)null, tenantId, "telemetry.source_network_change", agentId.ToString(), new
            {
                previous_ip = agent.PublicIp,
                current_ip = remoteIp,
            });
            agent.PublicIp = remoteIp;
        }
        else if (string.IsNullOrEmpty(agent.PublicIp) && !string.IsNullOrEmpty(remoteIp))
        {
            agent.PublicIp = remoteIp;
        }

        var clientEventIds = req.Events
            .Where(ev => ev.ClientEventId is not null)
            .Select(ev => ev.ClientEventId!.Value)
            .ToHashSet();
        var seenClientEventIds = clientEventIds.Count == 0
            ? []
            : await db.TelemetryEvents
                .AsNoTracking()
                .Where(e => e.TenantId == tenantId
                    && e.AgentId == agentId
                    && e.ClientEventId != null
                    && clientEventIds.Contains(e.ClientEventId.Value))
                .Select(e => e.ClientEventId!.Value)
                .ToHashSetAsync(ct);

        var events = new List<TelemetryEvent>();
        long? maxSkewAbs = null;
        foreach (var ev in req.Events)
        {
            if (ev.ClientEventId is not null && !seenClientEventIds.Add(ev.ClientEventId.Value))
            {
                continue; // replay of known client_event_id
            }

            if (!TelemetryIntegrity.TryMapOccurredAt(
                    ev.OccurredAt, receivedAt, options, out var occurredAt, out var rejectReason))
            {
                audit.Add((Guid?)null, tenantId, "telemetry.timestamp_rejected", agentId.ToString(), new
                {
                    reason = rejectReason,
                    occurred_at = ev.OccurredAt,
                    batch_id = batchId,
                });
                return Problem(statusCode: 400, title: rejectReason);
            }

            var skew = (int)Math.Round((occurredAt - receivedAt).TotalSeconds);
            maxSkewAbs = maxSkewAbs is null ? Math.Abs(skew) : Math.Max(maxSkewAbs.Value, Math.Abs(skew));

            // Sequence rollback: still store but do not advance watermark; confidence stays agent_reported.
            if (ev.Sequence is not null
                && agent.LastTelemetrySequence > 0
                && ev.Sequence.Value < agent.LastTelemetrySequence)
            {
                // already audited at batch level
            }

            var payload = ev.Payload.GetRawText();
            events.Add(new TelemetryEvent
            {
                ClientEventId = ev.ClientEventId,
                BatchId = batchId,
                SequenceNumber = ev.Sequence,
                TenantId = tenantId,
                AgentId = agentId,
                EventType = ev.Type,
                OccurredAt = occurredAt,
                ReceivedAt = receivedAt,
                Confidence = EvidenceConfidence.AgentReported,
                PayloadDigest = TelemetryIntegrity.PayloadDigest(payload),
                Payload = payload,
            });
        }

        if (events.Count == 0)
        {
            return Accepted();
        }

        if (maxSkewAbs is not null)
        {
            agent.LastClockSkewSeconds = (int)(events
                .Select(e => (e.OccurredAt - receivedAt).TotalSeconds)
                .OrderByDescending(Math.Abs)
                .First());
        }

        if (!sequenceAssessment.Rollback && sequenceAssessment.NewMax is not null)
        {
            agent.LastTelemetrySequence = sequenceAssessment.NewMax.Value;
        }

        agent.LastTelemetryBatchId = batchId;
        agent.LastIngestEventCount = events.Count;

        db.TelemetryEvents.AddRange(events);
        audit.Add((Guid?)null, tenantId, "telemetry.ingest", agentId.ToString(), new
        {
            event_count = req.Events.Count,
            accepted_count = events.Count,
            received_at = receivedAt,
            batch_id = batchId,
            confidence = EvidenceConfidence.AgentReported.ToString(),
        });
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException) when (events.All(e => e.ClientEventId is not null))
        {
            var attemptedIds = events.Select(e => e.ClientEventId!.Value).ToHashSet();
            db.ChangeTracker.Clear();
            var persistedIds = await db.TelemetryEvents
                .AsNoTracking()
                .Where(e => e.TenantId == tenantId
                    && e.AgentId == agentId
                    && e.ClientEventId != null
                    && attemptedIds.Contains(e.ClientEventId.Value))
                .Select(e => e.ClientEventId!.Value)
                .ToHashSetAsync(ct);
            if (persistedIds.SetEquals(attemptedIds))
            {
                return Accepted();
            }

            throw;
        }

        eventBroker.Publish(agent, events);
        await telemetrySink.PublishAsync(agent, events, ct);

        var alerts = await alertRules.EvaluateAsync(agent, events, receivedAt, ct);
        if (alerts.Count > 0)
        {
            audit.Add((Guid?)null, tenantId, "alert.evaluate", agentId.ToString(), new
            {
                alert_count = alerts.Count,
                event_count = events.Count,
                received_at = receivedAt,
            });
        }

        await db.SaveChangesAsync(ct);
        if (alerts.Count > 0)
        {
            await alertSink.PublishAsync(
                agent,
                alerts,
                events.ToDictionary(e => e.Id),
                ct);
            await db.SaveChangesAsync(ct);
        }

        return Accepted();
    }

    [HttpGet("{id:guid}/events")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
    [EnableRateLimiting("web-read")]
    public async Task<ActionResult<IReadOnlyList<TelemetryEventResponse>>> List(
        Guid id,
        [FromQuery] string? type,
        [FromQuery] DateTimeOffset? before,
        [FromQuery] int limit = DefaultLimit,
        CancellationToken ct = default)
    {
        var tenantId = User.GetTenantId();
        if (!await db.Agents.AnyAsync(a => a.Id == id && a.TenantId == tenantId, ct))
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
            .Where(e => e.AgentId == id && e.TenantId == tenantId);

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
            e.ClientEventId,
            e.BatchId,
            e.SequenceNumber,
            e.AgentId,
            e.EventType,
            e.OccurredAt,
            e.ReceivedAt,
            e.Confidence,
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
        TelemetryEventType.DnsQuery => "dns_query",
        TelemetryEventType.ProcessLaunch => "process_launch",
        TelemetryEventType.FileEvent => "file_event",
        TelemetryEventType.PackageInventory => "package_inventory",
        TelemetryEventType.EditorExtension => "editor_extension",
        TelemetryEventType.BrowserExtension => "browser_extension",
        TelemetryEventType.McpConfig => "mcp_config",
        _ => type.ToString(),
    };
}
