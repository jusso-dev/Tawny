using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.ThreatIntel;
using Tawny.Jobs;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/threat-intel-feeds")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class ThreatIntelFeedsController(
    TawnyDbContext db,
    AuditLogger audit,
    ThreatIntelFeedsJob job) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ThreatIntelFeedResponse>>> List(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var rows = await db.ThreatIntelFeeds
            .AsNoTracking()
            .Where(f => f.TenantId == tenantId)
            .OrderBy(f => f.Name)
            .Select(f => new ThreatIntelFeedResponse(
                f.Id, f.Name, f.Kind, f.Url, f.AuthHeaderName,
                f.DefaultSeverity, f.IntervalMinutes, f.IsEnabled,
                f.Status, f.LastRunAt, f.LastSuccessAt,
                f.LastImportedCount, f.LastSkippedCount, f.LastError,
                f.CreatedAt, f.UpdatedAt))
            .ToListAsync(ct);
        return Ok(rows);
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<ThreatIntelFeedResponse>> Create(
        [FromBody] CreateThreatIntelFeedRequest req,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Name) || req.Name.Length > 160)
        {
            return Problem(statusCode: 400, title: "name is required and must be 160 characters or fewer.");
        }
        if (!Uri.TryCreate(req.Url, UriKind.Absolute, out _))
        {
            return Problem(statusCode: 400, title: "url must be an absolute URL.");
        }
        var interval = req.IntervalMinutes ?? 60;
        if (interval < 5 || interval > 10_080)
        {
            return Problem(statusCode: 400, title: "interval_minutes must be between 5 and 10080.");
        }

        var now = DateTimeOffset.UtcNow;
        var feed = new ThreatIntelFeed
        {
            Id = Guid.NewGuid(),
            TenantId = User.GetTenantId(),
            Name = req.Name.Trim(),
            Kind = req.Kind,
            Url = req.Url.Trim(),
            AuthHeaderName = NullIfEmpty(req.AuthHeaderName),
            AuthHeaderValueEncrypted = NullIfEmpty(req.AuthHeaderValue),
            DefaultSeverity = req.DefaultSeverity ?? AlertSeverity.High,
            IntervalMinutes = interval,
            IsEnabled = req.IsEnabled ?? true,
            CreatedByUserId = TryGetUserId(),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.ThreatIntelFeeds.Add(feed);
        audit.Add(User, "threat_intel_feed.create", feed.Id.ToString(), new
        {
            feed.Name, feed.Kind, feed.Url, feed.IntervalMinutes,
        });
        await db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(List), new { id = feed.Id }, ToResponse(feed));
    }

    [HttpPut("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<ThreatIntelFeedResponse>> Update(
        Guid id,
        [FromBody] UpdateThreatIntelFeedRequest req,
        CancellationToken ct)
    {
        if (!Uri.TryCreate(req.Url, UriKind.Absolute, out _))
        {
            return Problem(statusCode: 400, title: "url must be an absolute URL.");
        }
        if (req.IntervalMinutes < 5 || req.IntervalMinutes > 10_080)
        {
            return Problem(statusCode: 400, title: "interval_minutes must be between 5 and 10080.");
        }

        var feed = await db.ThreatIntelFeeds.FirstOrDefaultAsync(f => f.Id == id && f.TenantId == User.GetTenantId(), ct);
        if (feed is null) return NotFound();

        feed.Name = req.Name.Trim();
        feed.Kind = req.Kind;
        feed.Url = req.Url.Trim();
        feed.AuthHeaderName = NullIfEmpty(req.AuthHeaderName);
        if (!string.IsNullOrWhiteSpace(req.AuthHeaderValue))
        {
            feed.AuthHeaderValueEncrypted = req.AuthHeaderValue;
        }
        feed.DefaultSeverity = req.DefaultSeverity;
        feed.IntervalMinutes = req.IntervalMinutes;
        feed.IsEnabled = req.IsEnabled;
        feed.UpdatedAt = DateTimeOffset.UtcNow;
        audit.Add(User, "threat_intel_feed.update", feed.Id.ToString(), new
        {
            feed.Name, feed.Kind, feed.IntervalMinutes, feed.IsEnabled,
        });
        await db.SaveChangesAsync(ct);
        return Ok(ToResponse(feed));
    }

    [HttpDelete("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var deleted = await db.ThreatIntelFeeds
            .Where(f => f.Id == id && f.TenantId == User.GetTenantId())
            .ExecuteDeleteAsync(ct);
        if (deleted == 0) return NotFound();
        audit.Add(User, "threat_intel_feed.delete", id.ToString());
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    [HttpPost("{id:guid}/run")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<ThreatIntelFeedResponse>> Run(Guid id, CancellationToken ct)
    {
        var feed = await db.ThreatIntelFeeds.FirstOrDefaultAsync(f => f.Id == id && f.TenantId == User.GetTenantId(), ct);
        if (feed is null) return NotFound();
        // Reset throttle so the job picks it up immediately.
        feed.LastRunAt = null;
        await db.SaveChangesAsync(ct);
        await job.ExecuteAsync(ct);
        await db.Entry(feed).ReloadAsync(ct);
        audit.Add(User, "threat_intel_feed.run", feed.Id.ToString());
        await db.SaveChangesAsync(ct);
        return Ok(ToResponse(feed));
    }

    private static ThreatIntelFeedResponse ToResponse(ThreatIntelFeed f) => new(
        f.Id, f.Name, f.Kind, f.Url, f.AuthHeaderName,
        f.DefaultSeverity, f.IntervalMinutes, f.IsEnabled,
        f.Status, f.LastRunAt, f.LastSuccessAt,
        f.LastImportedCount, f.LastSkippedCount, f.LastError,
        f.CreatedAt, f.UpdatedAt);

    private static string? NullIfEmpty(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }

    private Guid? TryGetUserId()
    {
        var raw = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
