using System.Net;
using System.Text;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Infrastructure;
using Tawny.Infrastructure.ThreatIntel;
using Xunit;

namespace Tawny.Api.Tests;

/// <summary>
/// Brolga is the operator's own intelligence store, so its verdict carries further than a third
/// party's. These cover the mapping from its disposition onto Tawny's verdict, which is where a
/// wrong answer would quietly change whether an alert fires.
/// </summary>
public class BrolgaReputationTests
{
    private static ReputationEnricher Enricher(RecordingHandler handler, string? baseUrl = "http://brolga.test:8787")
    {
        var options = new DbContextOptionsBuilder<TawnyDbContext>()
            .UseInMemoryDatabase($"brolga-{Guid.NewGuid()}")
            .Options;

        return new ReputationEnricher(
            new TawnyDbContext(options),
            new HttpClient(handler),
            Options.Create(new ReputationOptions
            {
                BrolgaBaseUrl = baseUrl,
                BrolgaApiToken = "0123456789abcdef0123456789abcdef",
            }),
            TimeProvider.System,
            NullLogger<ReputationEnricher>.Instance);
    }

    private static string Pack(string disposition) => $$"""
        {
          "schema_version": "brolga.context_pack/1.0",
          "subject": { "kind": "ipv4_address", "value": "203.0.113.42" },
          "observable_id": "observable:7168327b",
          "disposition": "{{disposition}}",
          "entities": [{ "id": "entity:9c8e", "kind": "report", "name": "C2 infrastructure" }],
          "claims": [],
          "relationships": [],
          "evidence": [{ "source_object_id": "source:12fc" }],
          "gaps": [],
          "exclusions": []
        }
        """;

    [Theory]
    [InlineData("malicious", ReputationVerdict.Malicious)]
    [InlineData("suspicious", ReputationVerdict.Suspicious)]
    [InlineData("benign", ReputationVerdict.Clean)]
    [InlineData("allow_listed", ReputationVerdict.AllowListed)]
    public async Task Disposition_MapsOntoTheMatchingVerdict(string disposition, ReputationVerdict expected)
    {
        var handler = new RecordingHandler(Pack(disposition));
        var results = await Enricher(handler).LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        results.Should().ContainSingle(r => r.Provider == ReputationProvider.Brolga)
            .Which.Verdict.Should().Be(expected);
    }

    /// <summary>
    /// The mapping that matters most. Brolga's "unknown" means it has not heard of the indicator.
    /// Reading that as Clean would suppress an alert that nothing has actually cleared.
    /// </summary>
    [Fact]
    public async Task Unknown_IsNeverReadAsClean()
    {
        var handler = new RecordingHandler(Pack("unknown"));
        var results = await Enricher(handler).LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        var brolga = results.Single(r => r.Provider == ReputationProvider.Brolga);
        brolga.Verdict.Should().Be(ReputationVerdict.Unknown);
        brolga.Verdict.Should().NotBe(ReputationVerdict.Clean);
    }

    /// <summary>
    /// A disposition from a later Brolga must not be guessed at. Defaulting to Clean would mean a
    /// Brolga upgrade could silently start suppressing alerts.
    /// </summary>
    [Fact]
    public async Task AnUnrecognisedDisposition_FallsBackToUnknownRatherThanClean()
    {
        var handler = new RecordingHandler(Pack("something_brolga_added_later"));
        var results = await Enricher(handler).LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        results.Single(r => r.Provider == ReputationProvider.Brolga)
            .Verdict.Should().Be(ReputationVerdict.Unknown);
    }

    [Fact]
    public async Task TheRequestGoesToTheVersionedRouteWithABearerToken()
    {
        var handler = new RecordingHandler(Pack("malicious"));
        await Enricher(handler).LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        var request = handler.Brolga.Should().NotBeNull().And.Subject.As<Recorded>();
        request.Uri.Should().Be("http://brolga.test:8787/api/v1/context");
        request.Method.Should().Be(HttpMethod.Post);
        request.Authorization.Should().Be("Bearer 0123456789abcdef0123456789abcdef");
        request.Body.Should().Contain("\"kind\":\"ipv4\"").And.Contain("203.0.113.42");
    }

    /// <summary>
    /// A base URL that already carries a path would otherwise produce `/api/v1/api/v1/context`.
    /// </summary>
    [Fact]
    public async Task ATrailingSlashOnTheBaseUrlDoesNotDoubleTheSeparator()
    {
        var handler = new RecordingHandler(Pack("malicious"));
        await Enricher(handler, "http://brolga.test:8787/")
            .LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        handler.Brolga.Should().NotBeNull();
        handler.Brolga!.Uri.Should().Be("http://brolga.test:8787/api/v1/context");
    }

    /// <summary>
    /// The evidence has to survive into the cached detail, or an analyst reading the verdict has
    /// nothing to cite for it.
    /// </summary>
    [Fact]
    public async Task TheEvidenceAndEntitiesSurviveIntoTheDetail()
    {
        var handler = new RecordingHandler(Pack("malicious"));
        var results = await Enricher(handler).LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        var detail = System.Text.Json.JsonSerializer.Serialize(
            results.Single(r => r.Provider == ReputationProvider.Brolga).Detail);

        detail.Should().Contain("source:12fc");
        detail.Should().Contain("C2 infrastructure");
    }

    /// <summary>
    /// Brolga refuses to serve a reachable address without a token, so a configured base URL with
    /// no token is a misconfiguration. It must not be asked at all rather than asked and refused.
    /// </summary>
    [Fact]
    public async Task WithoutATokenBrolgaIsNotAsked()
    {
        var handler = new RecordingHandler(Pack("malicious"));
        var options = new DbContextOptionsBuilder<TawnyDbContext>()
            .UseInMemoryDatabase($"brolga-{Guid.NewGuid()}")
            .Options;

        var enricher = new ReputationEnricher(
            new TawnyDbContext(options),
            new HttpClient(handler),
            Options.Create(new ReputationOptions
            {
                BrolgaBaseUrl = "http://brolga.test:8787",
                BrolgaApiToken = null,
            }),
            TimeProvider.System,
            NullLogger<ReputationEnricher>.Instance);

        var results = await enricher.LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        results.Should().NotContain(r => r.Provider == ReputationProvider.Brolga);
        // Other providers still run for an IPv4 indicator, so the assertion is that *Brolga* was
        // not reached — not that nothing was.
        handler.Brolga.Should().BeNull();
    }

    /// <summary>
    /// A failed lookup is Error, not Unknown. "Brolga did not answer" and "Brolga has not heard of
    /// this" are different facts, and only one of them says anything about the indicator.
    /// </summary>
    [Fact]
    public async Task AFailedLookupIsAnErrorRatherThanAnAbsenceOfKnowledge()
    {
        var handler = new RecordingHandler("upstream is unwell", HttpStatusCode.ServiceUnavailable);
        var results = await Enricher(handler).LookupAsync(Guid.NewGuid(), "ipv4", "203.0.113.42", CancellationToken.None);

        results.Single(r => r.Provider == ReputationProvider.Brolga)
            .Verdict.Should().Be(ReputationVerdict.Error);
    }

    private sealed record Recorded(string Uri, HttpMethod Method, string? Authorization, string? Body);

    /// <summary>
    /// Records every request, not just the last one. GreyNoise needs no API key and so is always
    /// asked about an IPv4 indicator; a handler that kept only the most recent request would make
    /// these assertions depend on the order providers happen to run in.
    /// </summary>
    private sealed class RecordingHandler(string body, HttpStatusCode status = HttpStatusCode.OK)
        : HttpMessageHandler
    {
        private readonly List<Recorded> _requests = [];

        public IReadOnlyList<Recorded> Requests => _requests;

        public Recorded? Brolga =>
            _requests.SingleOrDefault(request => request.Uri.Contains("/api/v1/context"));

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            _requests.Add(new Recorded(
                request.RequestUri?.ToString() ?? string.Empty,
                request.Method,
                request.Headers.Authorization?.ToString(),
                request.Content is null
                    ? null
                    : await request.Content.ReadAsStringAsync(cancellationToken)));

            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
        }
    }
}
