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
[Route("api/agents")]
public class AgentsController(
    TawnyDbContext db,
    AgentJwtService jwt,
    AuditLogger audit,
    ILogger<AgentsController> log) : ControllerBase
{
    [HttpPost("enroll")]
    [AllowAnonymous]
    public async Task<ActionResult<EnrollResponse>> Enroll(
        [FromBody] EnrollRequest req,
        CancellationToken ct)
    {
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
        });
        await db.SaveChangesAsync(ct);

        var (jwtToken, exp) = jwt.Issue(agent.Id, agent.TenantId);
        log.LogInformation("Agent {AgentId} enrolled (hostname={Hostname})", agent.Id, agent.Hostname);

        return Ok(new EnrollResponse(agent.Id, jwtToken, exp, new EnrollConfig(60)));
    }

    [HttpPost("heartbeat")]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.AgentJwt)]
    public async Task<ActionResult<HeartbeatResponse>> Heartbeat(
        [FromBody] HeartbeatRequest req,
        CancellationToken ct)
    {
        if (!TryGetAgentId(out var agentId) || !User.TryGetTenantId(out var tenantId))
        {
            return Unauthorized();
        }

        var agent = await db.Agents.FirstOrDefaultAsync(a => a.Id == agentId && a.TenantId == tenantId, ct);
        if (agent is null)
        {
            return NotFound();
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

        return Ok(new HeartbeatResponse(
            LatestAgentVersion: latest?.Version,
            DownloadUrl: latest?.DownloadUrl,
            Sha256: latest?.Sha256,
            RotatedJwt: null,
            JwtExpiresAt: null));
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
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
    [Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser)]
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

    private static AgentPlatform ParseOs(string os) => os.ToLowerInvariant() switch
    {
        "windows" => AgentPlatform.Windows,
        "macos" => AgentPlatform.Macos,
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
