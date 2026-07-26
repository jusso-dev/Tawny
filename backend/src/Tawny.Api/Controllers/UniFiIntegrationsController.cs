using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.Security;
using Tawny.Jobs;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/integrations/unifi")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
public sealed partial class UniFiIntegrationsController(
    TawnyDbContext db,
    IIntegrationSecretProtector secrets,
    UniFiConnector connector,
    AuditLogger audit,
    TimeProvider timeProvider) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<UniFiIntegrationResponse>> Get(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var integration = await db.UniFiIntegrations
            .AsNoTracking()
            .SingleOrDefaultAsync(item => item.TenantId == tenantId, ct);
        return integration is null ? NotFound() : Ok(ToResponse(integration));
    }

    [HttpPut]
    public async Task<ActionResult<UniFiIntegrationResponse>> Upsert(
        [FromBody] UpdateUniFiIntegrationRequest request,
        CancellationToken ct)
    {
        var validationError = Validate(request);
        if (validationError is not null)
        {
            return Problem(statusCode: 400, title: validationError);
        }

        var tenantId = User.GetTenantId();
        var integration = await db.UniFiIntegrations
            .SingleOrDefaultAsync(item => item.TenantId == tenantId, ct);
        if (integration is null && string.IsNullOrWhiteSpace(request.ApiKey))
        {
            return Problem(statusCode: 400, title: "API key is required when creating the integration.");
        }

        var now = timeProvider.GetUtcNow();
        if (integration is null)
        {
            integration = new UniFiIntegration
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId,
                BaseUrl = request.BaseUrl.TrimEnd('/'),
                EventsUrl = request.EventsUrl.Trim(),
                ApiKeyHeader = request.ApiKeyHeader.Trim(),
                ApiKeyEncrypted = secrets.Protect(request.ApiKey!.Trim()),
                RecordsPath = request.RecordsPath?.Trim() ?? "",
                VerifyTls = request.VerifyTls,
                IsEnabled = request.IsEnabled,
                IntervalMinutes = request.IntervalMinutes,
                UpdatedByUserId = TryGetUserId(),
                CreatedAt = now,
                UpdatedAt = now,
            };
            db.UniFiIntegrations.Add(integration);
        }
        else
        {
            integration.BaseUrl = request.BaseUrl.TrimEnd('/');
            integration.EventsUrl = request.EventsUrl.Trim();
            integration.ApiKeyHeader = request.ApiKeyHeader.Trim();
            integration.RecordsPath = request.RecordsPath?.Trim() ?? "";
            integration.VerifyTls = request.VerifyTls;
            integration.IsEnabled = request.IsEnabled;
            integration.IntervalMinutes = request.IntervalMinutes;
            integration.UpdatedByUserId = TryGetUserId();
            integration.UpdatedAt = now;
            if (!string.IsNullOrWhiteSpace(request.ApiKey))
            {
                integration.ApiKeyEncrypted = secrets.Protect(request.ApiKey.Trim());
            }
        }

        audit.Add(User, "integration.unifi.update", integration.Id.ToString(), new
        {
            integration.BaseUrl,
            integration.EventsUrl,
            integration.ApiKeyHeader,
            integration.RecordsPath,
            integration.VerifyTls,
            integration.IsEnabled,
            integration.IntervalMinutes,
            ApiKeyChanged = !string.IsNullOrWhiteSpace(request.ApiKey),
        });
        await db.SaveChangesAsync(ct);
        return Ok(ToResponse(integration));
    }

    [HttpPost("test")]
    public async Task<ActionResult<UniFiConnectionTestResponse>> Test(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var integration = await db.UniFiIntegrations
            .SingleOrDefaultAsync(item => item.TenantId == tenantId, ct);
        if (integration is null)
        {
            return NotFound();
        }

        var testedAt = timeProvider.GetUtcNow();
        integration.LastTestAt = testedAt;
        try
        {
            var info = await connector.FetchInfoAsync(integration, ct);
            integration.NetworkVersion = info.ApplicationVersion;
            integration.LastError = null;
            integration.UpdatedAt = testedAt;
            audit.Add(User, "integration.unifi.test", integration.Id.ToString(), new
            {
                Success = true,
                info.ApplicationVersion,
            });
            await db.SaveChangesAsync(ct);
            return Ok(new UniFiConnectionTestResponse(info.ApplicationVersion, testedAt));
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            integration.LastError = Truncate(ex.Message, 2048);
            integration.UpdatedAt = testedAt;
            audit.Add(User, "integration.unifi.test", integration.Id.ToString(), new
            {
                Success = false,
                Error = integration.LastError,
            });
            await db.SaveChangesAsync(ct);
            return Problem(
                statusCode: 502,
                title: "UniFi connection test failed.",
                detail: integration.LastError);
        }
    }

    private static string? Validate(UpdateUniFiIntegrationRequest request)
    {
        try
        {
            UniFiConnector.RequirePrivateHttpUri(request.BaseUrl, "Controller URL");
            UniFiConnector.RequirePrivateHttpUri(request.EventsUrl, "Events URL");
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }

        if (!HeaderNameRegex().IsMatch(request.ApiKeyHeader.Trim()))
        {
            return "API key header must contain only letters, numbers, and hyphens.";
        }
        if (request.ApiKey is { Length: > 4096 })
        {
            return "API key must be 4096 characters or fewer.";
        }
        if (request.IntervalMinutes is < 1 or > 1440)
        {
            return "Schedule interval must be between 1 and 1440 minutes.";
        }
        if (!RecordsPathRegex().IsMatch(request.RecordsPath?.Trim() ?? ""))
        {
            return "Records path must be a dot-separated JSON property path.";
        }

        return null;
    }

    private Guid? TryGetUserId()
    {
        var raw = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(raw, out var id) ? id : null;
    }

    private static UniFiIntegrationResponse ToResponse(UniFiIntegration integration)
        => new(
            integration.Id,
            integration.BaseUrl,
            integration.EventsUrl,
            integration.ApiKeyHeader,
            !string.IsNullOrWhiteSpace(integration.ApiKeyEncrypted),
            integration.RecordsPath,
            integration.VerifyTls,
            integration.IsEnabled,
            integration.IntervalMinutes,
            integration.NetworkVersion,
            integration.LastTestAt,
            integration.LastRunAt,
            integration.LastSuccessAt,
            integration.LastError,
            integration.LastRecordsChecked,
            integration.LastIndicatorsChecked,
            integration.LastMatchingEvents,
            integration.LastCasesCreated,
            integration.CreatedAt,
            integration.UpdatedAt);

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    [GeneratedRegex(@"^[A-Za-z0-9-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex HeaderNameRegex();

    [GeneratedRegex(
        @"^(?:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex RecordsPathRegex();
}
