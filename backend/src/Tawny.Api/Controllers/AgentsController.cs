using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentValidation;
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
[Route("api/agents")]
public class AgentsController(
    TawnyDbContext db,
    AgentJwtService jwt,
    AuditLogger audit,
    IValidator<EnrollRequest> enrollValidator,
    IValidator<HeartbeatRequest> heartbeatValidator,
    ILogger<AgentsController> log) : ControllerBase
{
    private const int MaxAgentRequestBytes = 16 * 1024;

    [HttpPost("enroll")]
    [AllowAnonymous]
    [EnableRateLimiting("agent-enrollment")]
    [RequestSizeLimit(MaxAgentRequestBytes)]
    public async Task<ActionResult<EnrollResponse>> Enroll(
        [FromBody] EnrollRequest req,
        CancellationToken ct)
    {
        var validation = await enrollValidator.ValidateAsync(req, ct);
        if (!validation.IsValid)
        {
            return ValidationProblem(new ValidationProblemDetails(validation.ToDictionary()));
        }

        var hash = TokenHashing.Hash(req.EnrollmentToken);
        var token = await db.EnrollmentTokens
            .FirstOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (token is null)
        {
            return Problem(statusCode: 401, title: "Unknown enrollment token.");
        }

        if (token.UsedAt is not null)
        {
            return Problem(statusCode: 409, title: "Enrollment token already used.",
                detail: $"Token consumed at {token.UsedAt:o}.");
        }

        if (token.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return Problem(statusCode: 410, title: "Enrollment token expired.");
        }

        var agent = new Agent
        {
            Id = Guid.NewGuid(),
            TenantId = token.TenantId,
            Hostname = req.Hostname,
            OperatingSystem = ParseOs(req.Os),
            OsVersion = req.OsVersion,
            Architecture = ParseArch(req.Arch),
            AgentVersion = req.AgentVersion,
            EnrolledAt = DateTimeOffset.UtcNow,
            LastHeartbeatAt = DateTimeOffset.UtcNow,
            Status = AgentStatus.Online,
            CredentialVersion = 1,
            DevicePublicKey = string.IsNullOrWhiteSpace(req.DevicePublicKey)
                ? null
                : req.DevicePublicKey.Trim(),
            PublicIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
        };

        token.UsedAt = DateTimeOffset.UtcNow;
        token.UsedByAgentId = agent.Id;

        db.Agents.Add(agent);
        audit.Add((Guid?)null, agent.TenantId, "agent.enroll", agent.Id.ToString(), new
        {
            agent.Hostname,
            token_id = token.Id,
            remote_ip = agent.PublicIp,
            credential_version = agent.CredentialVersion,
            has_device_public_key = agent.DevicePublicKey is not null,
        });
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            return Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "Enrollment token already used.");
        }

        var (jwtToken, exp, jti) = jwt.Issue(agent.Id, agent.TenantId, agent.CredentialVersion);
        audit.Add((Guid?)null, agent.TenantId, "agent.credential_issue", agent.Id.ToString(), new
        {
            jti,
            expires_at = exp,
            credential_version = agent.CredentialVersion,
        });
        await db.SaveChangesAsync(ct);
        log.LogInformation("Agent {AgentId} enrolled (hostname={Hostname})", agent.Id, agent.Hostname);

        return Ok(new EnrollResponse(agent.Id, jwtToken, exp, new EnrollConfig(60)));
    }

    [HttpPost("heartbeat")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.AgentJwt)]
    [EnableRateLimiting("agent-heartbeat")]
    [RequestSizeLimit(MaxAgentRequestBytes)]
    public async Task<ActionResult<HeartbeatResponse>> Heartbeat(
        [FromBody] HeartbeatRequest req,
        CancellationToken ct)
    {
        var validation = await heartbeatValidator.ValidateAsync(req, ct);
        if (!validation.IsValid)
        {
            return ValidationProblem(new ValidationProblemDetails(validation.ToDictionary()));
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
            audit.Add((Guid?)null, tenantId, "agent.auth_failed", agent.Id.ToString(), new
            {
                reason = "revoked",
            });
            await db.SaveChangesAsync(ct);
            return Unauthorized();
        }

        if (!TryGetCredentialVersion(out var tokenCv) || tokenCv != agent.CredentialVersion)
        {
            audit.Add((Guid?)null, tenantId, "agent.auth_failed", agent.Id.ToString(), new
            {
                reason = "credential_version_mismatch",
                token_cv = tokenCv,
                agent_cv = agent.CredentialVersion,
            });
            await db.SaveChangesAsync(ct);
            return Unauthorized();
        }

        var previousStatus = agent.Status;
        agent.LastHeartbeatAt = DateTimeOffset.UtcNow;
        agent.Status = AgentStatus.Online;
        agent.AgentVersion = req.AgentVersion;
        audit.Add((Guid?)null, tenantId, "agent.heartbeat", agent.Id.ToString(), new
        {
            req.AgentVersion,
            req.BufferDepth,
            previous_status = previousStatus,
        });
        await db.SaveChangesAsync(ct);

        var latest = await db.AgentReleases
            .Where(r => r.IsLatest && r.Platform == PlatformKey(agent))
            .FirstOrDefaultAsync(ct);

        var now = DateTimeOffset.UtcNow;
        // Expire stale pending/dispatched actions.
        var stale = await db.ResponseActions
            .Where(a => a.AgentId == agent.Id
                && a.ExpiresAt != null
                && a.ExpiresAt <= now
                && (a.Status == ResponseActionStatus.Pending
                    || a.Status == ResponseActionStatus.Dispatched
                    || a.Status == ResponseActionStatus.Running))
            .ToListAsync(ct);
        foreach (var expired in stale)
        {
            expired.Status = ResponseActionStatus.Expired;
            expired.CompletedAt = now;
            expired.ExecutionTokenHash = null;
            audit.Add((Guid?)null, tenantId, "response_action.expired", expired.Id.ToString(), new
            {
                expired.AgentId,
            });
        }

        if (stale.Count > 0)
        {
            await db.SaveChangesAsync(ct);
        }

        var pendingActions = await db.ResponseActions
            .Where(a => a.AgentId == agent.Id && a.Status == ResponseActionStatus.Pending)
            .OrderBy(a => a.RequestedAt)
            .Take(10)
            .ToListAsync(ct);

        var commands = new List<ResponseActionCommand>(pendingActions.Count);
        foreach (var action in pendingActions)
        {
            var executionToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            action.Status = ResponseActionStatus.Dispatched;
            action.DispatchedAt = now;
            action.ExecutionTokenHash = TokenHashing.Hash(executionToken);
            action.ExpiresAt ??= now.Add(ResponseActionsController.DefaultActionTtl);
            action.PayloadHash ??= Convert.ToHexStringLower(
                SHA256.HashData(Encoding.UTF8.GetBytes(action.PayloadJson)));
            action.TenantId = agent.TenantId;

            commands.Add(new ResponseActionCommand(
                action.Id,
                action.ActionType,
                JsonSerializer.Deserialize<JsonElement>(action.PayloadJson),
                executionToken,
                action.ExpiresAt!.Value,
                action.PayloadHash!));
        }

        if (pendingActions.Count > 0)
        {
            audit.Add((Guid?)null, tenantId, "response_action.dispatch", agent.Id.ToString(), new
            {
                action_count = pendingActions.Count,
            });
            await db.SaveChangesAsync(ct);
        }

        string? rotatedJwt = null;
        DateTimeOffset? jwtExpiresAt = null;
        var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value
            ?? User.FindFirst("exp")?.Value;
        DateTimeOffset? currentExp = null;
        if (long.TryParse(expClaim, out var expUnix))
        {
            currentExp = DateTimeOffset.FromUnixTimeSeconds(expUnix);
        }

        if (jwt.ShouldRotate(currentExp))
        {
            var (token, exp, jti) = jwt.Issue(agent.Id, agent.TenantId, agent.CredentialVersion);
            rotatedJwt = token;
            jwtExpiresAt = exp;
            audit.Add((Guid?)null, tenantId, "agent.credential_rotate", agent.Id.ToString(), new
            {
                jti,
                expires_at = exp,
                credential_version = agent.CredentialVersion,
            });
            await db.SaveChangesAsync(ct);
        }

        return Ok(new HeartbeatResponse(
            LatestAgentVersion: latest?.Version,
            DownloadUrl: latest?.DownloadUrl,
            Sha256: latest?.Sha256,
            RotatedJwt: rotatedJwt,
            JwtExpiresAt: jwtExpiresAt,
            Actions: commands));
    }

    [HttpPost("{id:guid}/revoke")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken, Roles = "Admin")]
    public async Task<ActionResult<AgentSummary>> Revoke(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var agent = await db.Agents.FirstOrDefaultAsync(a => a.Id == id && a.TenantId == tenantId, ct);
        if (agent is null)
        {
            return NotFound();
        }

        agent.Status = AgentStatus.Revoked;
        agent.RevokedAt = DateTimeOffset.UtcNow;
        agent.CredentialVersion += 1;
        audit.Add(User, "agent.revoke", agent.Id.ToString(), new
        {
            credential_version = agent.CredentialVersion,
        });
        await db.SaveChangesAsync(ct);

        return Ok(new AgentSummary(
            agent.Id, agent.Hostname, agent.OperatingSystem, agent.OsVersion,
            agent.AgentVersion, agent.Architecture, agent.Status,
            agent.LastHeartbeatAt, agent.EnrolledAt));
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
    public async Task<ActionResult<IReadOnlyList<AgentSummary>>> List(CancellationToken ct)
    {
        var agents = await db.Agents
            .Where(a => a.TenantId == User.GetTenantId())
            .OrderByDescending(a => a.LastHeartbeatAt)
            .Select(a => new AgentSummary(
                a.Id, a.Hostname, a.OperatingSystem, a.OsVersion,
                a.AgentVersion, a.Architecture, a.Status,
                a.LastHeartbeatAt, a.EnrolledAt))
            .ToListAsync(ct);
        return Ok(agents);
    }

    [HttpGet("{id:guid}")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
    public async Task<ActionResult<AgentSummary>> Get(Guid id, CancellationToken ct)
    {
        var a = await db.Agents.FirstOrDefaultAsync(x => x.Id == id && x.TenantId == User.GetTenantId(), ct);
        if (a is null) return NotFound();
        return Ok(new AgentSummary(
            a.Id, a.Hostname, a.OperatingSystem, a.OsVersion,
            a.AgentVersion, a.Architecture, a.Status,
            a.LastHeartbeatAt, a.EnrolledAt));
    }

    private bool TryGetAgentId(out Guid id)
    {
        var claim = User.FindFirst("agent_id")?.Value;
        return Guid.TryParse(claim, out id);
    }

    private bool TryGetCredentialVersion(out int version)
    {
        var claim = User.FindFirst(AgentJwtService.CredentialVersionClaim)?.Value;
        return int.TryParse(claim, out version);
    }

    private static AgentPlatform ParseOs(string os) => os.ToLowerInvariant() switch
    {
        "windows" => AgentPlatform.Windows,
        "macos" => AgentPlatform.Macos,
        "linux" => AgentPlatform.Linux,
        _ => throw new ArgumentException($"Unsupported os: {os}"),
    };

    private static AgentArchitecture ParseArch(string arch) => arch.ToLowerInvariant() switch
    {
        "x64" or "amd64" or "x86_64" => AgentArchitecture.X64,
        "arm64" or "aarch64" => AgentArchitecture.Arm64,
        _ => throw new ArgumentException($"Unsupported arch: {arch}"),
    };

    private static string PlatformKey(Agent a) =>
        $"{a.OperatingSystem.ToString().ToLowerInvariant()}-{(a.Architecture == AgentArchitecture.X64 ? "x64" : "arm64")}";
}
