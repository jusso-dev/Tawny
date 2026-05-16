using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public class AgentFlowIntegrationTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    [Fact]
    public async Task EnrollHeartbeatAndEventsFlow_PersistsFirstEvent()
    {
        await factory.ResetDatabaseAsync();
        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                TokenHash = TokenHashing.Hash(enrollmentToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                CreatedByUserId = Guid.Empty,
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname = "edr-host-01",
            os = "windows",
            os_version = "11",
            arch = "x64",
            agent_version = "0.1.0",
        });
        enroll.EnsureSuccessStatusCode();
        var enrollBody = await enroll.Content.ReadFromJsonAsync<EnrollBody>();
        enrollBody.Should().NotBeNull();
        enrollBody!.Jwt.Should().NotBeNullOrWhiteSpace();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", enrollBody.Jwt);
        var heartbeat = await client.PostAsJsonAsync("/api/agents/heartbeat", new
        {
            agent_version = "0.1.1",
            uptime_seconds = 42,
            buffer_depth = 0,
        });
        heartbeat.EnsureSuccessStatusCode();

        var events = await client.PostAsJsonAsync("/api/agents/events", new
        {
            events = new[]
            {
                new
                {
                    type = "process_snapshot",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    payload = new { processes = Array.Empty<object>() },
                },
            },
        });
        events.StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var readReq = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/agents/{enrollBody.AgentId}/events?type=process_snapshot");
        readReq.AddWebUserSignature($"/api/agents/{enrollBody.AgentId}/events");
        var read = await client.SendAsync(readReq);
        read.EnsureSuccessStatusCode();
        var stored = await read.Content.ReadFromJsonAsync<TelemetryEventBody[]>();

        stored.Should().ContainSingle();
        stored![0].AgentId.Should().Be(enrollBody.AgentId);
        stored[0].Type.Should().Be("process_snapshot");
    }

    [Fact]
    public async Task WebReads_AreScopedToSignedTenant()
    {
        await factory.ResetDatabaseAsync();
        var otherTenantId = Guid.NewGuid();
        var defaultAgentId = Guid.NewGuid();
        var otherAgentId = Guid.NewGuid();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.Tenants.Add(new Tenant
            {
                Id = otherTenantId,
                Slug = "other",
                Name = "Other",
                CreatedAt = DateTimeOffset.UtcNow,
            });
            db.Agents.AddRange(
                NewAgent(defaultAgentId, TenantDefaults.DefaultTenantId, "default-host"),
                NewAgent(otherAgentId, otherTenantId, "other-host"));
            db.TelemetryEvents.AddRange(
                NewEvent(defaultAgentId, TenantDefaults.DefaultTenantId),
                NewEvent(otherAgentId, otherTenantId));
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        using var defaultReq = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        defaultReq.AddWebUserSignature("/api/agents");
        var defaultRead = await client.SendAsync(defaultReq);
        defaultRead.EnsureSuccessStatusCode();
        var defaultAgents = await defaultRead.Content.ReadFromJsonAsync<AgentSummaryBody[]>();
        defaultAgents.Should().ContainSingle(a => a.Id == defaultAgentId);
        defaultAgents.Should().NotContain(a => a.Id == otherAgentId);

        using var otherReq = new HttpRequestMessage(HttpMethod.Get, "/api/agents");
        otherReq.AddWebUserSignature("/api/agents", tenantId: otherTenantId);
        var otherRead = await client.SendAsync(otherReq);
        otherRead.EnsureSuccessStatusCode();
        var otherAgents = await otherRead.Content.ReadFromJsonAsync<AgentSummaryBody[]>();
        otherAgents.Should().ContainSingle(a => a.Id == otherAgentId);
        otherAgents.Should().NotContain(a => a.Id == defaultAgentId);
    }

    [Fact]
    public async Task Enroll_AcceptsLinuxAgents()
    {
        await factory.ResetDatabaseAsync();
        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                TokenHash = TokenHashing.Hash(enrollmentToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                CreatedByUserId = Guid.Empty,
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname = "linux-edr-01",
            os = "linux",
            os_version = "6.12",
            arch = "arm64",
            agent_version = "0.1.0",
        });

        enroll.EnsureSuccessStatusCode();

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var agent = await verifyDb.Agents.SingleAsync(a => a.Hostname == "linux-edr-01");
        agent.OperatingSystem.Should().Be(AgentPlatform.Linux);
        agent.Architecture.Should().Be(AgentArchitecture.Arm64);
    }

    [Fact]
    public async Task IngestEvents_CreatesAlertsForMatchingRules()
    {
        await factory.ResetDatabaseAsync();
        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                TokenHash = TokenHashing.Hash(enrollmentToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                CreatedByUserId = Guid.Empty,
            });
            db.AlertRules.Add(new AlertRule
            {
                Id = Guid.NewGuid(),
                Name = "Suspicious process",
                EventType = TelemetryEventType.ProcessSnapshot,
                Severity = AlertSeverity.High,
                Operator = AlertRuleOperator.Contains,
                PayloadPath = "processes",
                MatchValue = "suspicious.exe",
                IsEnabled = true,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname = "alert-host-01",
            os = "windows",
            os_version = "11",
            arch = "x64",
            agent_version = "0.1.0",
        });
        enroll.EnsureSuccessStatusCode();
        var enrollBody = await enroll.Content.ReadFromJsonAsync<EnrollBody>();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", enrollBody!.Jwt);
        var events = await client.PostAsJsonAsync("/api/agents/events", new
        {
            events = new[]
            {
                new
                {
                    type = "process_snapshot",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    payload = new
                    {
                        processes = new[]
                        {
                            new { name = "suspicious.exe", pid = 4242 },
                        },
                    },
                },
            },
        });

        events.StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var alerts = await verifyDb.Alerts.ToListAsync();

        alerts.Should().ContainSingle();
        alerts[0].Severity.Should().Be(AlertSeverity.High);
        alerts[0].Status.Should().Be(AlertStatus.Open);
        alerts[0].Title.Should().Contain("Suspicious process");
        alerts[0].TelemetryEventId.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task ImportedSigmaRule_CreatesAlertForMatchingTelemetry()
    {
        await factory.ResetDatabaseAsync();
        const string ruleYaml = """
title: Suspicious Process From Sigma
id: 8c6f0f07-5a44-4c41-83cc-2e0e0f6ef9f1
status: experimental
description: Detects a suspicious process name from Tawny process telemetry.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    processes.name|contains: suspicious.exe
  condition: selection
level: high
""";

        var client = factory.CreateClient();
        using var importReq = new HttpRequestMessage(HttpMethod.Post, "/api/alert-rules/sigma")
        {
            Content = JsonContent.Create(new
            {
                rule_yaml = ruleYaml,
            }),
        };
        importReq.AddWebUserSignature("/api/alert-rules/sigma");
        var importRes = await client.SendAsync(importReq);
        importRes.EnsureSuccessStatusCode();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            var rule = await db.AlertRules.SingleAsync();
            rule.Format.Should().Be(AlertRuleFormat.Sigma);
            rule.ExternalId.Should().Be("8c6f0f07-5a44-4c41-83cc-2e0e0f6ef9f1");
            rule.EventType.Should().Be(TelemetryEventType.ProcessSnapshot);
            rule.PayloadPath.Should().Be("processes.name");
        }

        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                TokenHash = TokenHashing.Hash(enrollmentToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                CreatedByUserId = Guid.Empty,
            });
            await db.SaveChangesAsync();
        }

        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname = "sigma-host-01",
            os = "windows",
            os_version = "11",
            arch = "x64",
            agent_version = "0.1.0",
        });
        enroll.EnsureSuccessStatusCode();
        var enrollBody = await enroll.Content.ReadFromJsonAsync<EnrollBody>();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", enrollBody!.Jwt);
        var events = await client.PostAsJsonAsync("/api/agents/events", new
        {
            events = new[]
            {
                new
                {
                    type = "process_snapshot",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    payload = new
                    {
                        processes = new[]
                        {
                            new { name = "very-suspicious.exe", pid = 4242 },
                        },
                    },
                },
            },
        });
        events.StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var alert = await verifyDb.Alerts.SingleAsync();
        alert.Title.Should().Contain("Suspicious Process From Sigma");
        alert.Severity.Should().Be(AlertSeverity.High);
    }

    [Fact]
    public async Task ImportSigmaRule_RejectsUnsupportedModifier()
    {
        await factory.ResetDatabaseAsync();
        const string ruleYaml = """
title: Unsupported Sigma Modifier
detection:
  selection:
    processes.name|startswith: suspicious.exe
  condition: selection
level: high
""";

        var client = factory.CreateClient();
        using var importReq = new HttpRequestMessage(HttpMethod.Post, "/api/alert-rules/sigma")
        {
            Content = JsonContent.Create(new
            {
                rule_yaml = ruleYaml,
            }),
        };
        importReq.AddWebUserSignature("/api/alert-rules/sigma");

        var importRes = await client.SendAsync(importReq);

        importRes.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await importRes.Content.ReadAsStringAsync();
        body.Should().Contain("Unsupported Sigma field modifier");
    }

    [Fact]
    public async Task ImportedStixIocs_CreateRulesAndAlertForMatchingNetworkTelemetry()
    {
        await factory.ResetDatabaseAsync();
        const string stix = """
{
  "type": "bundle",
  "id": "bundle--9b1ad7d3-c5f3-4b2c-91c8-cb5a8912e7e1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--9fe9d1b7-27e6-4a78-836f-3358e08b1f0d",
      "name": "Advisory IoCs",
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = '203.0.113.44'] OR [domain-name:value = 'payload.example.com'] OR [file:hashes.'SHA-256' = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']"
    }
  ]
}
""";

        var client = factory.CreateClient();
        using var importReq = new HttpRequestMessage(HttpMethod.Post, "/api/alert-rules/iocs")
        {
            Content = JsonContent.Create(new
            {
                definition = stix,
                source_format = "stix",
            }),
        };
        importReq.AddWebUserSignature("/api/alert-rules/iocs");
        var importRes = await client.SendAsync(importReq);
        importRes.EnsureSuccessStatusCode();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            var rules = await db.AlertRules.OrderBy(r => r.PayloadPath).ToListAsync();
            rules.Should().HaveCount(3);
            rules.Should().OnlyContain(r => r.Format == AlertRuleFormat.Ioc);
            rules.Should().Contain(r =>
                r.EventType == TelemetryEventType.NetworkSnapshot &&
                r.PayloadPath == "connections.remote_address" &&
                r.MatchValue == "203.0.113.44");
            rules.Should().Contain(r =>
                r.EventType == TelemetryEventType.FileIntegrity &&
                r.PayloadPath == "new_sha256");
            rules.Should().Contain(r =>
                r.EventType == TelemetryEventType.ProcessSnapshot &&
                r.PayloadPath == "processes.command_line" &&
                r.MatchValue == "payload.example.com");
        }

        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                TokenHash = TokenHashing.Hash(enrollmentToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                CreatedByUserId = Guid.Empty,
            });
            await db.SaveChangesAsync();
        }

        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname = "ioc-host-01",
            os = "macos",
            os_version = "14",
            arch = "arm64",
            agent_version = "0.1.0",
        });
        enroll.EnsureSuccessStatusCode();
        var enrollBody = await enroll.Content.ReadFromJsonAsync<EnrollBody>();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", enrollBody!.Jwt);
        var events = await client.PostAsJsonAsync("/api/agents/events", new
        {
            events = new[]
            {
                new
                {
                    type = "network_snapshot",
                    occurred_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    payload = new
                    {
                        connections = new[]
                        {
                            new { remote_address = "203.0.113.44", remote_port = 443 },
                        },
                    },
                },
            },
        });
        events.StatusCode.Should().Be(HttpStatusCode.Accepted);

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var alert = await verifyDb.Alerts.SingleAsync();
        alert.Title.Should().Contain("IoC IP");
        alert.Severity.Should().Be(AlertSeverity.High);
    }

    [Fact]
    public async Task ImportRawIocs_ReportsSkippedMd5ButImportsSha1()
    {
        await factory.ResetDatabaseAsync();
        const string raw = """
Hash list from advisory:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
""";

        var client = factory.CreateClient();
        using var importReq = new HttpRequestMessage(HttpMethod.Post, "/api/alert-rules/iocs")
        {
            Content = JsonContent.Create(new
            {
                definition = raw,
                source_format = "raw",
                severity = "critical",
            }),
        };
        importReq.AddWebUserSignature("/api/alert-rules/iocs");

        var importRes = await client.SendAsync(importReq);

        importRes.EnsureSuccessStatusCode();
        var body = await importRes.Content.ReadFromJsonAsync<IocImportBody>();
        body!.Rules.Should().ContainSingle();
        body.SkippedIndicators.Should().ContainSingle(s => s.Contains("MD5"));

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var rule = await verifyDb.AlertRules.SingleAsync();
        rule.PayloadPath.Should().Be("new_sha1");
        rule.Severity.Should().Be(AlertSeverity.Critical);
    }

    [Fact]
    public async Task ResponseActions_DispatchOnHeartbeatAndAcceptResult()
    {
        await factory.ResetDatabaseAsync();
        var enrollmentToken = TokenHashing.NewToken();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.EnrollmentTokens.Add(new EnrollmentToken
            {
                Id = Guid.NewGuid(),
                TenantId = TenantDefaults.DefaultTenantId,
                TokenHash = TokenHashing.Hash(enrollmentToken),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                CreatedByUserId = Guid.Empty,
            });
            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        var enroll = await client.PostAsJsonAsync("/api/agents/enroll", new
        {
            enrollment_token = enrollmentToken,
            hostname = "response-host-01",
            os = "windows",
            os_version = "11",
            arch = "x64",
            agent_version = "0.1.0",
        });
        enroll.EnsureSuccessStatusCode();
        var enrollBody = await enroll.Content.ReadFromJsonAsync<EnrollBody>();
        enrollBody.Should().NotBeNull();

        using var createReq = new HttpRequestMessage(
            HttpMethod.Post,
            $"/api/agents/{enrollBody!.AgentId}/actions")
        {
            Content = JsonContent.Create(new
            {
                action_type = "kill_process",
                payload = new { pid = 4242 },
            }),
        };
        createReq.AddWebUserSignature($"/api/agents/{enrollBody.AgentId}/actions");
        var createRes = await client.SendAsync(createReq);
        createRes.EnsureSuccessStatusCode();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", enrollBody.Jwt);
        var heartbeat = await client.PostAsJsonAsync("/api/agents/heartbeat", new
        {
            agent_version = "0.1.1",
            uptime_seconds = 42,
            buffer_depth = 0,
        });
        heartbeat.EnsureSuccessStatusCode();
        var heartbeatBody = await heartbeat.Content.ReadFromJsonAsync<HeartbeatBody>();
        heartbeatBody!.Actions.Should().ContainSingle();
        heartbeatBody.Actions[0].ActionType.Should().Be("kill_process");
        heartbeatBody.Actions[0].Payload.GetProperty("pid").GetInt32().Should().Be(4242);

        var result = await client.PostAsJsonAsync($"/api/agents/actions/{heartbeatBody.Actions[0].Id}/result", new
        {
            status = "succeeded",
            message = "process terminated",
            result = new { exit_code = 0 },
        });
        result.StatusCode.Should().Be(HttpStatusCode.NoContent);

        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var action = await verifyDb.ResponseActions.SingleAsync();
        action.Status.Should().Be(ResponseActionStatus.Succeeded);
        action.DispatchedAt.Should().NotBeNull();
        action.CompletedAt.Should().NotBeNull();
        action.ResultJson.Should().Contain("process terminated");
    }

    private static Agent NewAgent(Guid id, Guid tenantId, string hostname) => new()
    {
        Id = id,
        TenantId = tenantId,
        Hostname = hostname,
        OperatingSystem = AgentPlatform.Windows,
        OsVersion = "11",
        Architecture = AgentArchitecture.X64,
        AgentVersion = "0.1.0",
        EnrolledAt = DateTimeOffset.UtcNow,
        LastHeartbeatAt = DateTimeOffset.UtcNow,
        Status = AgentStatus.Online,
    };

    private static TelemetryEvent NewEvent(Guid agentId, Guid tenantId) => new()
    {
        AgentId = agentId,
        TenantId = tenantId,
        EventType = TelemetryEventType.ProcessSnapshot,
        OccurredAt = DateTimeOffset.UtcNow,
        ReceivedAt = DateTimeOffset.UtcNow,
        Payload = "{}",
    };

    private sealed record EnrollBody(
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("jwt")] string Jwt);

    private sealed record AgentSummaryBody(
        [property: JsonPropertyName("id")] Guid Id);

    private sealed record HeartbeatBody(
        [property: JsonPropertyName("actions")] ResponseActionCommandBody[] Actions);

    private sealed record IocImportBody(
        [property: JsonPropertyName("rules")] AlertRuleBody[] Rules,
        [property: JsonPropertyName("skipped_indicators")] string[] SkippedIndicators);

    private sealed record AlertRuleBody(
        [property: JsonPropertyName("id")] Guid Id,
        [property: JsonPropertyName("name")] string Name);

    private sealed record ResponseActionCommandBody(
        [property: JsonPropertyName("id")] Guid Id,
        [property: JsonPropertyName("action_type")] string ActionType,
        [property: JsonPropertyName("payload")] System.Text.Json.JsonElement Payload);

    private sealed record TelemetryEventBody(
        [property: JsonPropertyName("id")] long Id,
        [property: JsonPropertyName("agent_id")] Guid AgentId,
        [property: JsonPropertyName("type")] string Type);
}
