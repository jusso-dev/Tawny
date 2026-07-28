using System.Reflection;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Xunit;

namespace Tawny.Api.Tests;

/// <summary>
/// Fails when a controller action is missing explicit auth metadata.
/// AllowAnonymous endpoints must be listed below with a documented reason.
/// </summary>
public class EndpointAuthorizationInventoryTests
{
    /// <summary>
    /// Known intentionally anonymous endpoints: method declaring type full name + method name.
    /// </summary>
    private static readonly HashSet<string> AllowedAnonymous = new(StringComparer.Ordinal)
    {
        // Public agent enrollment (rate-limited, single-use token).
        "Tawny.Api.Controllers.AgentsController.Enroll",
        // Liveness / readiness for orchestrators.
        "Tawny.Api.Controllers.HealthController.Get",
    };

    [Fact]
    public void EveryControllerAction_DeclaresAuthorizeOrAllowAnonymous()
    {
        var apiAssembly = typeof(Tawny.Api.Controllers.AgentsController).Assembly;
        var controllers = apiAssembly.GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && typeof(ControllerBase).IsAssignableFrom(t));

        var failures = new List<string>();
        var anonymous = new List<string>();

        foreach (var controller in controllers)
        {
            var controllerAuth = controller.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any();
            var controllerAnonymous = controller.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any();

            foreach (var method in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                if (method.GetCustomAttributes<NonActionAttribute>().Any()) continue;
                var isAction = method.GetCustomAttributes().Any(a => a is HttpMethodAttribute or RouteAttribute);
                if (!isAction) continue;

                var key = $"{controller.FullName}.{method.Name}";
                var methodAuth = method.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any();
                var methodAnonymous = method.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any()
                    || controllerAnonymous;

                if (methodAnonymous)
                {
                    anonymous.Add(key);
                    if (!AllowedAnonymous.Contains(key))
                    {
                        failures.Add($"{key}: AllowAnonymous is not on the approved inventory list.");
                    }

                    continue;
                }

                if (!controllerAuth && !methodAuth)
                {
                    failures.Add($"{key}: missing [Authorize] or [AllowAnonymous].");
                }
            }
        }

        // Ensure inventory stays honest — no stale allow entries.
        foreach (var allowed in AllowedAnonymous)
        {
            if (!anonymous.Contains(allowed))
            {
                failures.Add($"{allowed}: listed as AllowAnonymous but not found on any controller action.");
            }
        }

        failures.Should().BeEmpty(
            "every API action needs explicit auth metadata. Failures:\n" + string.Join("\n", failures));
    }
}
