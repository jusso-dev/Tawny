namespace Tawny.Api.Auth;

public class AgentJwtOptions
{
    public string Issuer { get; set; } = "tawny";
    public string Audience { get; set; } = "tawny-agents";

    /// <summary>Access token lifetime in minutes (default 60).</summary>
    public int LifetimeMinutes { get; set; } = 60;

    /// <summary>Rotate when remaining lifetime is below this many minutes.</summary>
    public int RotateWithinMinutes { get; set; } = 15;

    /// <summary>Obsolete long-lived setting retained for config compatibility; ignored when LifetimeMinutes is set.</summary>
    public int LifetimeDays { get; set; } = 0;

    public int RotateWithinDays { get; set; } = 0;

    /// <summary>Path to a PEM-encoded RSA private key, or inline PEM.</summary>
    public string? SigningKeyPem { get; set; }
    public bool RequireConfiguredSigningKey { get; set; }
}
