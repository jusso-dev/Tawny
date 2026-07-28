using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;

namespace Tawny.Api.Logging;

/// <summary>
/// Redacts secret-like property names and values from Serilog events.
/// </summary>
public sealed partial class SecretRedactingEnricher : ILogEventEnricher
{
    private static readonly HashSet<string> SensitiveNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "passwd", "secret", "token", "apikey", "api_key", "authorization",
        "client_secret", "access_key", "private_key", "hmac", "jwt", "enrollment_token",
        "webuserhmacsecret", "signingkeypem", "x-signature", "x-nonce", "devicekey",
    };

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        var replacements = new List<LogEventProperty>();
        foreach (var prop in logEvent.Properties)
        {
            if (IsSensitiveName(prop.Key))
            {
                replacements.Add(propertyFactory.CreateProperty(prop.Key, "[REDACTED]"));
                continue;
            }

            if (prop.Value is ScalarValue { Value: string s } && LooksLikeSecret(s))
            {
                replacements.Add(propertyFactory.CreateProperty(prop.Key, "[REDACTED]"));
            }
        }

        foreach (var prop in replacements)
        {
            logEvent.AddOrUpdateProperty(prop);
        }
    }

    public static bool IsSensitiveName(string name)
    {
        var compact = name.Replace("-", "").Replace("_", "");
        if (SensitiveNames.Contains(name) || SensitiveNames.Contains(compact))
        {
            return true;
        }

        foreach (var marker in SensitiveNames)
        {
            if (compact.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static bool LooksLikeSecret(string value)
    {
        if (value.Length < 16) return false;
        if (value.StartsWith("wte_", StringComparison.Ordinal) ||
            value.StartsWith("twny_", StringComparison.Ordinal) ||
            value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("eyJ", StringComparison.Ordinal)) // JWT header
        {
            return true;
        }

        // Long hex blobs often secrets / digests — only redact very long ones when named generically.
        return HexBlob().IsMatch(value) && value.Length >= 64;
    }

    public static string RedactText(string? input)
    {
        if (string.IsNullOrEmpty(input)) return input ?? "";
        var text = BearerToken().Replace(input, "Bearer [REDACTED]");
        text = JwtLike().Replace(text, "[REDACTED_JWT]");
        text = EnrollmentToken().Replace(text, "wte_[REDACTED]");
        return text;
    }

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_\-]+=*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")]
    private static partial Regex JwtLike();

    [GeneratedRegex(@"\bBearer\s+\S+", RegexOptions.IgnoreCase)]
    private static partial Regex BearerToken();

    [GeneratedRegex(@"\bwte_[A-Za-z0-9]+\b")]
    private static partial Regex EnrollmentToken();

    [GeneratedRegex(@"\b[0-9a-fA-F]{64,}\b")]
    private static partial Regex HexBlob();
}
