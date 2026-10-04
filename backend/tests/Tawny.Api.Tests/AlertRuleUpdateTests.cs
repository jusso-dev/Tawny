using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Domain;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public class AlertRuleUpdateTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    private const string RuleYaml = """
title: Suspicious Process From Sigma
id: 8c6f0f07-5a44-4c41-83cc-2e0e0f6ef9f1
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.name|contains: suspicious.exe
  condition: selection
level: high
""";

    [Fact]
    public async Task UpdatingImportedSigmaRuleMetadata_KeepsItsSourceAndFormat()
    {
        var client = factory.CreateClient();
        var rule = await ImportAsync(client);

        var res = await PutAsync(client, rule.Id, new
        {
            name = "Renamed",
            event_type = rule.EventType,
            severity = "Critical",
            @operator = rule.Operator,
            payload_path = rule.PayloadPath,
            match_value = rule.MatchValue,
            is_enabled = false,
            mitre_techniques = new[] { "T1059" },
        });
        res.StatusCode.Should().Be(HttpStatusCode.OK);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var stored = await db.AlertRules.AsNoTracking().SingleAsync(r => r.Id == rule.Id);
        stored.Format.Should().Be(AlertRuleFormat.Sigma);
        stored.SourceDefinition.Should().Be(rule.SourceDefinition);
        stored.ExternalId.Should().Be(rule.ExternalId);
        stored.Name.Should().Be("Renamed");
        stored.Severity.Should().Be(AlertSeverity.Critical);
        stored.IsEnabled.Should().BeFalse();
    }

    [Fact]
    public async Task MultiSelectionSigmaRule_CanBeDisabled()
    {
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        const string yaml = """
title: Multi selection
id: 9c6f0f07-5a44-4c41-83cc-2e0e0f6ef9f2
logsource:
  product: windows
  category: process_creation
detection:
  a:
    processes.name|contains: powershell
  b:
    processes.command_line|contains: -enc
  condition: a and b
level: high
""";
        using var importReq = new HttpRequestMessage(HttpMethod.Post, "/api/alert-rules/sigma")
        {
            Content = JsonContent.Create(new { rule_yaml = yaml }),
        };
        importReq.AddWebUserSignature("/api/alert-rules/sigma");
        (await client.SendAsync(importReq)).EnsureSuccessStatusCode();

        Tawny.Domain.Entities.AlertRule rule;
        using (var scope = factory.Services.CreateScope())
        {
            rule = await scope.ServiceProvider.GetRequiredService<TawnyDbContext>()
                .AlertRules.AsNoTracking().SingleAsync();
        }
        rule.MatchValue.Should().BeNull("multi-selection rules are stored as a compiled expression");

        var res = await PutAsync(client, rule.Id, new
        {
            name = rule.Name,
            event_type = rule.EventType,
            severity = "High",
            @operator = rule.Operator,
            payload_path = rule.PayloadPath,
            match_value = rule.MatchValue,
            is_enabled = false,
        });
        res.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ChangingImportedRuleMatchLogic_IsRejected()
    {
        var client = factory.CreateClient();
        var rule = await ImportAsync(client);

        var res = await PutAsync(client, rule.Id, new
        {
            name = rule.Name,
            event_type = rule.EventType,
            severity = "High",
            @operator = rule.Operator,
            payload_path = rule.PayloadPath,
            match_value = "something-else.exe",
            is_enabled = true,
        });

        res.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    private async Task<Tawny.Domain.Entities.AlertRule> ImportAsync(HttpClient client)
    {
        await factory.ResetDatabaseAsync();
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/alert-rules/sigma")
        {
            Content = JsonContent.Create(new { rule_yaml = RuleYaml }),
        };
        req.AddWebUserSignature("/api/alert-rules/sigma");
        (await client.SendAsync(req)).EnsureSuccessStatusCode();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        return await db.AlertRules.AsNoTracking().SingleAsync();
    }

    private static async Task<HttpResponseMessage> PutAsync(HttpClient client, Guid id, object body)
    {
        var path = $"/api/alert-rules/{id}";
        using var req = new HttpRequestMessage(HttpMethod.Put, path) { Content = JsonContent.Create(body) };
        req.AddWebUserSignature(path);
        return await client.SendAsync(req);
    }
}
