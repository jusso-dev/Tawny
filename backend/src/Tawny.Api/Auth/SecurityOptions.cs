namespace Tawny.Api.Auth;

public sealed class SecurityOptions
{
    /// <summary>
    /// When true, enforce production secret strength and HTTPS public URLs even outside Production environment.
    /// </summary>
    public bool EnforceSecureDefaults { get; set; }

    /// <summary>
    /// Explicit escape hatch for plain-HTTP public URLs in constrained deployments.
    /// </summary>
    public bool AllowInsecurePublicHttp { get; set; }

    public string? PublicApiUrl { get; set; }
    public string? PublicWebUrl { get; set; }
}

public sealed class SecurityOptionsValidator
{
    public static void Validate(
        string environmentName,
        string? webUserHmacSecret,
        AgentJwtOptions agentJwt,
        string? connectionString,
        SecurityOptions security)
    {
        var enforce = security.EnforceSecureDefaults
            || string.Equals(environmentName, "Production", StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(webUserHmacSecret))
        {
            throw new InvalidOperationException(
                "Tawny:WebUserHmacSecret is required. Generate at least 32 random bytes (e.g. openssl rand -hex 32).");
        }

        if (enforce && !WebUserCanonical.IsSecretStrongEnough(webUserHmacSecret))
        {
            throw new InvalidOperationException(
                $"Tawny:WebUserHmacSecret must be at least {WebUserCanonical.MinimumSecretBytes} bytes when secure defaults are enforced.");
        }

        if (enforce && agentJwt.RequireConfiguredSigningKey && string.IsNullOrWhiteSpace(agentJwt.SigningKeyPem))
        {
            throw new InvalidOperationException(
                "Tawny:AgentJwt:SigningKeyPem must be configured with a stable RSA private key in production.");
        }

        if (enforce && string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Default is required in production.");
        }

        if (enforce && !security.AllowInsecurePublicHttp)
        {
            RequireHttpsUrl(security.PublicApiUrl, "Tawny:Security:PublicApiUrl");
            RequireHttpsUrl(security.PublicWebUrl, "Tawny:Security:PublicWebUrl");
        }
    }

    private static void RequireHttpsUrl(string? url, string name)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            throw new InvalidOperationException(
                $"{name} is required in production (HTTPS). Set Tawny:Security:AllowInsecurePublicHttp=true only if you accept the risk.");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"{name} must be an absolute https:// URL (got '{url}'). Set Tawny:Security:AllowInsecurePublicHttp=true only if you accept the risk.");
        }
    }
}
