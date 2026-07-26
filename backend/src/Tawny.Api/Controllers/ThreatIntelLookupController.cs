using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/threat-intel")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public sealed class ThreatIntelLookupController(ThreatIntelLookupService lookup) : ControllerBase
{
    [HttpPost("lookup")]
    public async Task<ActionResult<ThreatIntelLookupResponse>> Lookup(
        [FromBody] ThreatIntelLookupRequest request,
        CancellationToken ct)
    {
        if (request.Values is null || request.Values.Count == 0)
        {
            return Problem(statusCode: 400, title: "values must contain at least one indicator.");
        }
        if (request.Values.Count > 500)
        {
            return Problem(statusCode: 400, title: "values may contain at most 500 indicators.");
        }
        if (request.Values.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 512))
        {
            return Problem(statusCode: 400, title: "each indicator must contain 1 to 512 characters.");
        }

        var matches = await lookup.LookupAsync(User.GetTenantId(), request.Values, ct);
        return Ok(new ThreatIntelLookupResponse(matches));
    }
}
