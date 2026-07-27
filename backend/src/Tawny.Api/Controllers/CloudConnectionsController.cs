using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Api.Models;
using Tawny.Api.Services;
using Tawny.Domain;
using Tawny.Domain.Entities;
using Tawny.Infrastructure;
using Tawny.Infrastructure.Security;
using Tawny.Jobs.Cloud;

namespace Tawny.Api.Controllers;

[ApiController]
[Route("api/cloud-connections")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser, Roles = "Admin")]
public sealed class CloudConnectionsController(
    TawnyDbContext db,
    IIntegrationSecretProtector secrets,
    IEnumerable<ICloudLogProvider> providers,
    AuditLogger audit,
    TimeProvider timeProvider) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<CloudConnectionResponse>>> List(CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var rows = await db.CloudConnections.AsNoTracking()
            .Where(c => c.TenantId == tenantId)
            .OrderBy(c => c.Provider).ThenBy(c => c.Name)
            .ToListAsync(ct);
        return Ok(rows.Select(ToResponse).ToArray());
    }

    [HttpPost]
    public async Task<ActionResult<CloudConnectionResponse>> Create(
        [FromBody] UpsertCloudConnectionRequest request,
        CancellationToken ct)
    {
        var error = Validate(request, creating: true);
        if (error is not null) return Problem(statusCode: 400, title: error);
        var now = timeProvider.GetUtcNow();
        var connection = new CloudConnection
        {
            Id = Guid.NewGuid(),
            TenantId = User.GetTenantId(),
            Name = request.Name.Trim(),
            Provider = request.Provider,
            ExternalAccountId = request.ExternalAccountId.Trim(),
            CredentialMode = request.CredentialMode,
            ConfigurationJson = request.Configuration.GetRawText(),
            CredentialEncrypted = Protect(request.Credential),
            IsEnabled = request.IsEnabled,
            UpdatedByUserId = TryGetUserId(),
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.CloudConnections.Add(connection);
        audit.Add(User, "cloud.connection.create", connection.Id.ToString(), new
        {
            connection.Name,
            connection.Provider,
            connection.ExternalAccountId,
            connection.CredentialMode,
            connection.IsEnabled,
            HasCredential = connection.CredentialEncrypted is not null,
        });
        await db.SaveChangesAsync(ct);
        return CreatedAtAction(nameof(List), new { id = connection.Id }, ToResponse(connection));
    }

    [HttpPut("{id:guid}")]
    public async Task<ActionResult<CloudConnectionResponse>> Update(
        Guid id,
        [FromBody] UpsertCloudConnectionRequest request,
        CancellationToken ct)
    {
        var error = Validate(request, creating: false);
        if (error is not null) return Problem(statusCode: 400, title: error);
        var tenantId = User.GetTenantId();
        var connection = await db.CloudConnections
            .SingleOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId, ct);
        if (connection is null) return NotFound();

        connection.Name = request.Name.Trim();
        connection.Provider = request.Provider;
        connection.ExternalAccountId = request.ExternalAccountId.Trim();
        connection.CredentialMode = request.CredentialMode;
        connection.ConfigurationJson = request.Configuration.GetRawText();
        connection.IsEnabled = request.IsEnabled;
        connection.UpdatedByUserId = TryGetUserId();
        connection.UpdatedAt = timeProvider.GetUtcNow();
        if (request.Credential is { ValueKind: not JsonValueKind.Null })
        {
            connection.CredentialEncrypted = Protect(request.Credential);
        }
        audit.Add(User, "cloud.connection.update", connection.Id.ToString(), new
        {
            connection.Name,
            connection.Provider,
            connection.ExternalAccountId,
            connection.CredentialMode,
            connection.IsEnabled,
            CredentialChanged = request.Credential is { ValueKind: not JsonValueKind.Null },
        });
        await db.SaveChangesAsync(ct);
        return Ok(ToResponse(connection));
    }

    [HttpPost("{id:guid}/test")]
    public async Task<ActionResult<CloudConnectionTestResponse>> Test(
        Guid id,
        [FromBody] CloudConnectionTestRequest request,
        CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var connection = await db.CloudConnections
            .SingleOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId, ct);
        if (connection is null) return NotFound();
        var provider = providers.SingleOrDefault(p => p.Supports(request.Source));
        if (provider is null) return Problem(statusCode: 400, title: "Unsupported cloud source.");
        var testedAt = timeProvider.GetUtcNow();
        connection.LastTestAt = testedAt;
        try
        {
            var probe = new CloudHunt
            {
                Id = Guid.NewGuid(),
                TenantId = tenantId,
                CloudConnectionId = connection.Id,
                Name = "connection-test",
                Source = request.Source,
                QueryJson = "{}",
                LookbackMinutes = 5,
                CreatedAt = testedAt,
                UpdatedAt = testedAt,
            };
            var result = await provider.QueryAsync(connection, probe, testedAt.AddMinutes(-5), testedAt, 1, ct);
            connection.LastSuccessAt = testedAt;
            connection.LastError = null;
            audit.Add(User, "cloud.connection.test", connection.Id.ToString(), new
            {
                Success = true,
                request.Source,
                result.RecordsRead,
            });
            await db.SaveChangesAsync(ct);
            return Ok(new CloudConnectionTestResponse(request.Source, result.RecordsRead, testedAt));
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            connection.LastError = Truncate(ex.Message, 2048);
            audit.Add(User, "cloud.connection.test", connection.Id.ToString(), new
            {
                Success = false,
                request.Source,
                Error = connection.LastError,
            });
            await db.SaveChangesAsync(ct);
            return Problem(statusCode: 502, title: "Cloud connection test failed.", detail: connection.LastError);
        }
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var tenantId = User.GetTenantId();
        var connection = await db.CloudConnections
            .SingleOrDefaultAsync(c => c.Id == id && c.TenantId == tenantId, ct);
        if (connection is null) return NotFound();
        db.CloudConnections.Remove(connection);
        audit.Add(User, "cloud.connection.delete", connection.Id.ToString(), new
        {
            connection.Name,
            connection.Provider,
        });
        await db.SaveChangesAsync(ct);
        return NoContent();
    }

    private string? Protect(JsonElement? credential)
    {
        if (credential is null || credential.Value.ValueKind == JsonValueKind.Null) return null;
        return secrets.Protect(credential.Value.GetRawText());
    }

    private static string? Validate(UpsertCloudConnectionRequest request, bool creating)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length > 160)
            return "Name is required and must be 160 characters or fewer.";
        if (string.IsNullOrWhiteSpace(request.ExternalAccountId) || request.ExternalAccountId.Trim().Length > 128)
            return "AWS account ID or Azure subscription ID is required.";
        if (request.Configuration.ValueKind != JsonValueKind.Object || request.Configuration.GetRawText().Length > 32_768)
            return "Configuration must be a JSON object no larger than 32 KiB.";
        if (request.Credential?.GetRawText().Length > 16_384)
            return "Credential must be no larger than 16 KiB.";
        if (creating && request.CredentialMode is CloudCredentialMode.AwsAssumeRole or CloudCredentialMode.AzureClientSecret
            && request.Credential is null)
            return "Credential is required for this authentication mode.";
        if (request.Provider == CloudProvider.Aws && request.CredentialMode != CloudCredentialMode.AwsAssumeRole)
            return "AWS connections must use aws_assume_role.";
        if (request.Provider == CloudProvider.Azure && request.CredentialMode == CloudCredentialMode.AwsAssumeRole)
            return "Azure connections must use an Azure credential mode.";
        if (request.Configuration.TryGetProperty("external_id", out _)
            || request.Configuration.TryGetProperty("client_secret", out _)
            || request.Configuration.TryGetProperty("secret_access_key", out _)
            || request.Configuration.TryGetProperty("access_key_id", out _))
            return "Secrets must be supplied in the credential object, not configuration.";
        return ValidateProviderConfiguration(request, creating);
    }

    private static string? ValidateProviderConfiguration(UpsertCloudConnectionRequest request, bool creating)
    {
        if (request.Provider == CloudProvider.Aws)
        {
            if (request.ExternalAccountId.Length != 12 || !request.ExternalAccountId.All(char.IsDigit))
                return "AWS account ID must contain 12 digits.";
            if (!TryReadString(request.Configuration, "role_arn", out var roleArn)
                || !roleArn.StartsWith("arn:", StringComparison.Ordinal)
                || !roleArn.Contains(":iam::", StringComparison.Ordinal)
                || !roleArn.Contains(":role/", StringComparison.Ordinal))
                return "AWS configuration requires a valid role_arn.";
            if (!request.Configuration.TryGetProperty("regions", out var regions)
                || regions.ValueKind != JsonValueKind.Array
                || regions.GetArrayLength() is < 1 or > 50
                || regions.EnumerateArray().Any(region => region.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(region.GetString())))
                return "AWS configuration requires 1 to 50 regions.";
            if (creating && (request.Credential is not { ValueKind: JsonValueKind.Object } credential
                || !TryReadString(credential, "external_id", out _)))
                return "AWS credential requires external_id.";
            return null;
        }

        if (!Guid.TryParse(request.ExternalAccountId, out _))
            return "Azure subscription ID must be a GUID.";
        if (!TryReadString(request.Configuration, "workspace_id", out _))
            return "Azure configuration requires workspace_id.";
        if (request.CredentialMode == CloudCredentialMode.AzureClientSecret)
        {
            if (!TryReadString(request.Configuration, "tenant_id", out _)
                || !TryReadString(request.Configuration, "client_id", out _))
                return "Azure client-secret mode requires tenant_id and client_id.";
            if (creating && (request.Credential is not { ValueKind: JsonValueKind.Object } credential
                || !TryReadString(credential, "client_secret", out _)))
                return "Azure credential requires client_secret.";
        }
        return null;
    }

    private static bool TryReadString(JsonElement value, string name, out string text)
    {
        text = "";
        if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return false;
        text = property.GetString()?.Trim() ?? "";
        return text.Length > 0;
    }

    private static CloudConnectionResponse ToResponse(CloudConnection connection)
        => new(
            connection.Id,
            connection.Name,
            connection.Provider,
            connection.ExternalAccountId,
            connection.CredentialMode,
            JsonSerializer.Deserialize<JsonElement>(connection.ConfigurationJson),
            connection.CredentialEncrypted is not null,
            connection.IsEnabled,
            connection.LastTestAt,
            connection.LastSuccessAt,
            connection.LastError,
            connection.CreatedAt,
            connection.UpdatedAt);

    private Guid? TryGetUserId()
        => Guid.TryParse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id) ? id : null;

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}
