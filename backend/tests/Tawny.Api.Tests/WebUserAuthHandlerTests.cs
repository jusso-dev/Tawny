using System.Net;
using FluentAssertions;
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
        req.AddWebUserSignature("/api/agents", secret: "wrong-secret");

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
}
