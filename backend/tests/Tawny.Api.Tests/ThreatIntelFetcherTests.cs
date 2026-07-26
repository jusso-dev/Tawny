using System.Net;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure.ThreatIntel;
using Xunit;

namespace Tawny.Api.Tests;

public class ThreatIntelFetcherTests
{
    [Fact]
    public async Task GenericCsv_NormalizesPublicFeedShapes()
    {
        const string body = """
            # public threat feed
            https://Login.Example.test/phish?id=42
            observed,203.0.113.7,scanner
            0123456789ABCDEF0123456789ABCDEF01234567
            not-an-indicator
            """;
        var http = new HttpClient(new StaticResponseHandler(body));
        var fetcher = new ThreatIntelFetcher(http, NullLogger<ThreatIntelFetcher>.Instance);
        var feed = new ThreatIntelFeed
        {
            Name = "Public indicators",
            Kind = ThreatIntelFeedKind.GenericCsv,
            Url = "https://feed.example/indicators.txt",
        };

        var result = await fetcher.FetchAsync(feed, CancellationToken.None);

        result.Indicators.Should().BeEquivalentTo(
        [
            new FetchedIndicator("domain", "login.example.test", "Generic CSV URL: https://Login.Example.test/phish?id=42"),
            new FetchedIndicator("ipv4", "203.0.113.7", "Generic CSV"),
            new FetchedIndicator("sha1", "0123456789abcdef0123456789abcdef01234567", "Generic CSV"),
        ]);
    }

    private sealed class StaticResponseHandler(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            });
    }
}
