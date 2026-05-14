using Hangfire.Dashboard;
using Microsoft.AspNetCore.Authentication;

namespace Tawny.Api.Auth;

public class HangfireWebUserAuthorizationFilter : IDashboardAuthorizationFilter
{
    public bool Authorize(DashboardContext context)
    {
        var http = context.GetHttpContext();
        var result = http.AuthenticateAsync(TawnyAuthSchemes.WebUser)
            .GetAwaiter()
            .GetResult();

        return result.Succeeded
            && result.Principal?.IsInRole("Admin") == true;
    }
}
