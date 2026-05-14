namespace Tawny.Api.Auth;

public class AgentJwtOptions
{
    public string Issuer { get; set; } = "tawny";
    public string Audience { get; set; } = "tawny-agents";
    public int LifetimeDays { get; set; } = 90;
    public int RotateWithinDays { get; set; } = 7;

    /// <summary>Path to a PEM-encoded RSA private key, or inline PEM.</summary>
    public string? SigningKeyPem { get; set; }
    public bool RequireConfiguredSigningKey { get; set; }
}
