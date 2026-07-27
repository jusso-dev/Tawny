using System.Text.Json;
using Tawny.Domain.Entities;
using Tawny.Infrastructure.Security;

namespace Tawny.Jobs.Cloud;

internal static class CloudConfiguration
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static T Read<T>(CloudConnection connection)
        => JsonSerializer.Deserialize<T>(connection.ConfigurationJson, JsonOptions)
            ?? throw new InvalidOperationException("Cloud connection configuration is invalid.");

    public static T? ReadCredential<T>(CloudConnection connection, IIntegrationSecretProtector secrets)
        where T : class
    {
        if (string.IsNullOrWhiteSpace(connection.CredentialEncrypted)) return null;
        return JsonSerializer.Deserialize<T>(secrets.Unprotect(connection.CredentialEncrypted), JsonOptions)
            ?? throw new InvalidOperationException("Cloud connection credential is invalid.");
    }
}
