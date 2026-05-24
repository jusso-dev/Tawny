using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.Hunting;

namespace Tawny.Api.Controllers;

public record RuleTestEventBody(
    TelemetryEventType EventType,
    DateTimeOffset OccurredAt,
    JsonElement Payload);

public record RuleTestRequest(IReadOnlyList<RuleTestEventBody> Events);

public record RuleTestResponse(
    bool Matched,
    string? FailReason,
    IReadOnlyList<RuleTestStepTrace> Trace);

[ApiController]
[Route("api/alert-rules")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class RuleTestController(TawnyDbContext db, RuleTestHarness harness) : ControllerBase
{
    /// <summary>
    /// Run a saved rule against a supplied list of events without touching the DB.
    /// Returns whether it would fire and a per-step trace of why or why not.
    /// </summary>
    [HttpPost("{id:guid}/test")]
    public async Task<ActionResult<RuleTestResponse>> Test(
        Guid id,
        [FromBody] RuleTestRequest req,
        CancellationToken ct)
    {
        if (req.Events is null || req.Events.Count == 0)
        {
            return Problem(statusCode: 400, title: "events array is required and must contain at least one event.");
        }
        var rule = await db.AlertRules.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule is null) return NotFound();

        var inputs = req.Events
            .Select(e => new RuleTestEventInput(e.EventType, e.OccurredAt, e.Payload))
            .ToList();
        var result = harness.Test(rule, inputs);
        return Ok(new RuleTestResponse(result.Matched, result.FailReason, result.Trace));
    }
}
