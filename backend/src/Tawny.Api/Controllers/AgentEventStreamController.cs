using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Services;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/agents")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
public class AgentEventStreamController(
    TawnyDbContext db,
    AgentEventBroker broker) : ControllerBase
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    /// <summary>
    /// Server-Sent Events stream of new telemetry for a single agent.
    /// The client receives one JSON-encoded event per `data:` frame and a
    /// `: keep-alive` comment every 15s to keep proxies happy.
    /// </summary>
    [HttpGet("{id:guid}/events/stream")]
    public async Task Stream(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        if (!await db.Agents.AnyAsync(a => a.Id == id && a.TenantId == tenantId, ct))
        {
            Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        Response.Headers["Content-Type"] = "text/event-stream";
        Response.Headers["Cache-Control"] = "no-cache, no-transform";
        Response.Headers["X-Accel-Buffering"] = "no";

        await Response.WriteAsync("retry: 5000\n\n", ct);
        await Response.Body.FlushAsync(ct);

        using var sub = broker.Subscribe(tenantId, id, out var channel);
        var reader = channel.Reader;
        var keepAlive = TimeSpan.FromSeconds(15);
        var lastWrite = DateTimeOffset.UtcNow;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var heartbeatCts = new CancellationTokenSource(keepAlive);
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, heartbeatCts.Token);

                StreamedEvent next;
                try
                {
                    next = await reader.ReadAsync(linked.Token);
                }
                catch (OperationCanceledException) when (heartbeatCts.IsCancellationRequested && !ct.IsCancellationRequested)
                {
                    await Response.WriteAsync(": keep-alive\n\n", ct);
                    await Response.Body.FlushAsync(ct);
                    lastWrite = DateTimeOffset.UtcNow;
                    continue;
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                var payload = JsonSerializer.Serialize(new
                {
                    id = next.Id,
                    agent_id = next.AgentId,
                    type = WireName(next.EventType),
                    occurred_at = next.OccurredAt,
                    received_at = next.ReceivedAt,
                    payload = next.Payload,
                }, JsonOpts);
                await Response.WriteAsync($"data: {payload}\n\n", ct);
                await Response.Body.FlushAsync(ct);
                lastWrite = DateTimeOffset.UtcNow;
            }
        }
        catch (OperationCanceledException) { }
    }

    private static string WireName(Domain.TelemetryEventType t) => t switch
    {
        Domain.TelemetryEventType.ProcessSnapshot => "process_snapshot",
        Domain.TelemetryEventType.NetworkSnapshot => "network_snapshot",
        Domain.TelemetryEventType.UserSession => "user_session",
        Domain.TelemetryEventType.SystemInfo => "system_info",
        Domain.TelemetryEventType.FileIntegrity => "file_integrity",
        Domain.TelemetryEventType.Heartbeat => "heartbeat",
        _ => t.ToString().ToLowerInvariant(),
    };
}
