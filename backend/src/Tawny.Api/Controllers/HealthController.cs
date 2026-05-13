using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/health")]
[AllowAnonymous]
public class HealthController(TawnyDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        var canConnect = await db.Database.CanConnectAsync(ct);
        return canConnect
            ? Ok(new { status = "ok", time = DateTimeOffset.UtcNow })
            : StatusCode(503, new { status = "db unreachable" });
    }
}
