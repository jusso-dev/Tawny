using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/alerts")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
[EnableRateLimiting("web-read")]
public class AlertsController(TawnyDbContext db) : ControllerBase
{
    /// <summary>
    /// Lists alerts. Without <paramref name="afterId"/>/<paramref name="since"/> the newest
    /// alerts come first (dashboard). With either, alerts are returned oldest-first by id so
    /// integrations (e.g. BlakSoc) can page forward: pass the last returned id as after_id.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<AlertResponse>>> List(
        [FromQuery] AlertStatus? status,
        [FromQuery(Name = "after_id")] long? afterId,
        [FromQuery] DateTimeOffset? since,
        [FromQuery] int limit = 50,
        CancellationToken ct = default)
    {
        var tenantId = User.GetTenantId();
        var take = Math.Clamp(limit, 1, 500);
        var query = db.Alerts.AsNoTracking().Where(a => a.TenantId == tenantId);
        if (status is not null)
        {
            query = query.Where(a => a.Status == status.Value);
        }
        if (afterId is not null)
        {
            query = query.Where(a => a.Id > afterId.Value);
        }
        if (since is not null)
        {
            query = query.Where(a => a.CreatedAt >= since.Value);
        }

        var forward = afterId is not null || since is not null;
        var ordered = forward
            ? query.OrderBy(a => a.Id)
            : query.OrderByDescending(a => a.CreatedAt).ThenByDescending(a => a.Id);

        return Ok(await LoadAsync(ordered.Take(take), ct));
    }

    [HttpGet("{id:long}")]
    public async Task<ActionResult<AlertResponse>> Get(long id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var rows = await LoadAsync(db.Alerts.AsNoTracking().Where(a => a.TenantId == tenantId && a.Id == id), ct);
        return rows.Count == 0 ? NotFound() : Ok(rows[0]);
    }

    private static async Task<List<AlertResponse>> LoadAsync(IQueryable<Tawny.Domain.Entities.Alert> source, CancellationToken ct)
    {
        var rows = await source
            .Select(a => new
            {
                a.Id,
                a.AlertRuleId,
                RuleName = a.AlertRule!.Name,
                RuleEventType = a.AlertRule.EventType,
                RuleOperator = a.AlertRule.Operator,
                RulePayloadPath = a.AlertRule.PayloadPath,
                RuleMatchValue = a.AlertRule.MatchValue,
                RuleMitre = a.AlertRule.MitreTechniquesJson,
                a.AgentId,
                Hostname = a.Agent!.Hostname,
                AgentOs = a.Agent.OperatingSystem,
                AgentOsVersion = a.Agent.OsVersion,
                a.TelemetryEventId,
                EventType = a.TelemetryEvent!.EventType,
                a.TelemetryEvent.OccurredAt,
                a.TelemetryEvent.ReceivedAt,
                a.TelemetryEvent.Payload,
                a.Severity,
                a.Status,
                a.SlackNotificationStatus,
                a.SlackNotifiedAt,
                a.SlackNotificationError,
                a.SentinelNotificationStatus,
                a.SentinelNotifiedAt,
                a.SentinelNotificationError,
                a.Title,
                a.Description,
                a.EnrichmentJson,
                a.CreatedAt,
            })
            .ToListAsync(ct);

        return rows.Select(a => new AlertResponse(
            a.Id,
            a.AlertRuleId,
            a.RuleName,
            a.RuleEventType,
            a.RuleOperator,
            a.RulePayloadPath,
            a.RuleMatchValue,
            a.AgentId,
            a.Hostname,
            a.TelemetryEventId,
            a.EventType,
            a.OccurredAt,
            a.ReceivedAt,
            JsonSerializer.Deserialize<JsonElement>(a.Payload),
            a.Severity,
            a.Status,
            a.SlackNotificationStatus,
            a.SlackNotifiedAt,
            a.SlackNotificationError,
            a.SentinelNotificationStatus,
            a.SentinelNotifiedAt,
            a.SentinelNotificationError,
            a.Title,
            a.Description,
            string.IsNullOrEmpty(a.EnrichmentJson) ? null : JsonSerializer.Deserialize<JsonElement>(a.EnrichmentJson),
            a.CreatedAt,
            ParseTechniques(a.RuleMitre),
            a.AgentOs,
            a.AgentOsVersion)).ToList();
    }

    private static IReadOnlyList<string> ParseTechniques(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return JsonSerializer.Deserialize<string[]>(json) ?? []; }
        catch (JsonException) { return []; }
    }
}
