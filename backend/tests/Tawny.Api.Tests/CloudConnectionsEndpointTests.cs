using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Xunit;

namespace Tawny.Api.Tests;

public sealed class CloudConnectionsEndpointTests(TawnyWebApplicationFactory factory)
    : IClassFixture<TawnyWebApplicationFactory>
{
    [Fact]
    public async Task Create_encrypts_credential_and_never_returns_it()
    {
        await factory.ResetDatabaseAsync();
        using var client = factory.CreateClient();
        const string path = "/api/cloud-connections";
        const string secret = "external-secret-value";
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(
                """
                {
                  "name": "AWS production",
                  "provider": "aws",
                  "external_account_id": "123456789012",
                  "credential_mode": "aws_assume_role",
                  "configuration": {
                    "role_arn": "arn:aws:iam::123456789012:role/TawnyReadOnly",
                    "regions": ["ap-southeast-2"]
                  },
                  "credential": { "external_id": "external-secret-value" },
                  "is_enabled": true
                }
                """,
                Encoding.UTF8,
                "application/json"),
        };
        request.AddWebUserSignature(path);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        response.StatusCode.Should().Be(HttpStatusCode.Created, body);
        body.Should().NotContain(secret);
        body.Should().NotContain("credential_encrypted");
        using var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("has_credential").GetBoolean().Should().BeTrue();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
        var stored = await db.CloudConnections.SingleAsync();
        stored.CredentialEncrypted.Should().NotBeNullOrWhiteSpace();
        stored.CredentialEncrypted.Should().NotContain(secret);
    }

    [Fact]
    public async Task List_is_tenant_scoped()
    {
        await factory.ResetDatabaseAsync();
        var otherTenantId = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
            db.Tenants.Add(new Tenant
            {
                Id = otherTenantId,
                Slug = $"tenant-{otherTenantId:N}",
                Name = "Other tenant",
                CreatedAt = DateTimeOffset.UtcNow,
            });
            db.CloudConnections.AddRange(
                Connection(TenantDefaults.DefaultTenantId, "Default AWS"),
                Connection(otherTenantId, "Other AWS"));
            await db.SaveChangesAsync();
        }

        using var client = factory.CreateClient();
        const string path = "/api/cloud-connections";
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.AddWebUserSignature(path, tenantId: otherTenantId);
        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        response.StatusCode.Should().Be(HttpStatusCode.OK, body);
        body.Should().Contain("Other AWS");
        body.Should().NotContain("Default AWS");
    }

    [Fact]
    public async Task Viewer_cannot_create_connection()
    {
        await factory.ResetDatabaseAsync();
        using var client = factory.CreateClient();
        const string path = "/api/cloud-connections";
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.AddWebUserSignature(path, role: "Viewer");

        using var response = await client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    private static CloudConnection Connection(Guid tenantId, string name)
        => new()
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            Name = name,
            Provider = CloudProvider.Aws,
            ExternalAccountId = "123456789012",
            CredentialMode = CloudCredentialMode.AwsAssumeRole,
            ConfigurationJson = """{"role_arn":"arn:aws:iam::123456789012:role/TawnyReadOnly","regions":["ap-southeast-2"]}""",
            IsEnabled = true,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        };
}
