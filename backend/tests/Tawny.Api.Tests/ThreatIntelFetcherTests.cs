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
        var fetcher = new ThreatIntelFetcher(http, TestSecrets.Protector, NullLogger<ThreatIntelFetcher>.Instance);
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task FetchAsync_SendsDecryptedAuthHeader(bool storedEncrypted)
    {
        var handler = new StaticResponseHandler("203.0.113.7\n");
        var fetcher = new ThreatIntelFetcher(
            new HttpClient(handler), TestSecrets.Protector, NullLogger<ThreatIntelFetcher>.Instance);
        var feed = new ThreatIntelFeed
        {
            Name = "Private feed",
            Kind = ThreatIntelFeedKind.GenericCsv,
            Url = "https://feed.example/private.txt",
            AuthHeaderName = "X-Api-Key",
            AuthHeaderValueEncrypted = storedEncrypted ? TestSecrets.Protector.Protect("s3cret") : "s3cret",
        };

        await fetcher.FetchAsync(feed, CancellationToken.None);

        handler.LastRequest!.Headers.GetValues("X-Api-Key").Should().ContainSingle().Which.Should().Be("s3cret");
    }

    private sealed class StaticResponseHandler(string body) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            });
        }
    }
}
