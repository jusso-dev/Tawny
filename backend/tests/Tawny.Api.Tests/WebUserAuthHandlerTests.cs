using System.Net;
using System.Text;
using FluentAssertions;
using Tawny.Api.Auth;
using Xunit;

namespace Tawny.Api.Tests;

public class WebUserAuthHandlerTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    [Fact]
    public async Task SignedRequest_IsAccepted()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        req.AddWebUserSignature("/api/agents");

        var res = await client.SendAsync(req);

        res.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task BadSignature_IsRejected()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        req.AddWebUserSignature("/api/agents", secret: "wrong-secret-that-is-long-enough-32b!");

        var res = await client.SendAsync(req);

        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ReplayWindow_IsRejected()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        req.AddWebUserSignature("/api/agents", unix: DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds());

        var res = await client.SendAsync(req);

        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BodyTampering_InvalidatesSignature()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        var body = """{"lifetime_hours":24}""";
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/enrollment-tokens")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        req.AddWebUserSignature("/api/enrollment-tokens");
        // Tamper after signing.
        req.Content = new StringContent("""{"lifetime_hours":1}""", Encoding.UTF8, "application/json");

        var res = await client.SendAsync(req);

        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task QueryTampering_InvalidatesSignature()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/agents?limit=1");
        req.AddWebUserSignature("/api/agents?limit=1");
        req.RequestUri = new Uri("/api/agents?limit=999", UriKind.Relative);

        var res = await client.SendAsync(req);

        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task NonceReplay_IsRejected()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        const string nonce = "0123456789abcdef0123456789abcdef";

        using var first = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        first.AddWebUserSignature("/api/agents", nonce: nonce);
        (await client.SendAsync(first)).StatusCode.Should().Be(HttpStatusCode.OK);

        using var second = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        second.AddWebUserSignature("/api/agents", nonce: nonce);
        (await client.SendAsync(second)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RoleChange_InvalidatesSignature()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        req.AddWebUserSignature("/api/agents", role: "Admin");
        req.Headers.Remove("X-User-Role");
        req.Headers.Add("X-User-Role", "Viewer");

        var res = await client.SendAsync(req);

        res.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public void WeakSecret_FailsStartupInProductionMode()
    {
        var act = () => SecurityOptionsValidator.Validate(
            "Production",
            "short",
            new AgentJwtOptions { RequireConfiguredSigningKey = true, SigningKeyPem = "dummy" },
            "Server=.;Database=tawny;Trusted_Connection=True",
            new SecurityOptions
            {
                PublicApiUrl = "https://api.example",
                PublicWebUrl = "https://web.example",
            });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*WebUserHmacSecret*");
    }

    [Fact]
    public void EmptySecret_FailsStartup()
    {
        var act = () => SecurityOptionsValidator.Validate(
            "Development",
            "",
            new AgentJwtOptions(),
            null,
            new SecurityOptions());

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*WebUserHmacSecret*");
    }
}
