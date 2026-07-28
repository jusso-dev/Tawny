using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Primitives;

namespace Tawny.Api.Auth;

/// <summary>
/// Versioned HMAC canonical request for web→API authentication.
/// </summary>
public static class WebUserCanonical
{
    public const string Version = "v2";
    public const int MinimumSecretBytes = 32;

    public static string HashBody(ReadOnlySpan<byte> body) =>
        Convert.ToHexStringLower(SHA256.HashData(body));

    public static string HashBody(string? body) =>
        HashBody(Encoding.UTF8.GetBytes(body ?? ""));

    /// <summary>
    /// Build a stable query string: sorted key=value pairs joined by &amp;.
    /// </summary>
    public static string CanonicalQuery(IEnumerable<KeyValuePair<string, StringValues>> query)
    {
        var pairs = new List<(string Key, string Value)>();
        foreach (var (key, values) in query)
        {
            if (values.Count == 0)
            {
                pairs.Add((key, ""));
                continue;
            }

            foreach (var value in values)
            {
                pairs.Add((key, value ?? ""));
            }
        }

        pairs.Sort(static (a, b) =>
        {
            var keyCmp = string.CompareOrdinal(a.Key, b.Key);
            return keyCmp != 0 ? keyCmp : string.CompareOrdinal(a.Value, b.Value);
        });

        if (pairs.Count == 0)
        {
            return "";
        }

        var sb = new StringBuilder();
        for (var i = 0; i < pairs.Count; i++)
        {
            if (i > 0) sb.Append('&');
            sb.Append(Uri.EscapeDataString(pairs[i].Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(pairs[i].Value));
        }

        return sb.ToString();
    }

    public static string CanonicalQueryFromRaw(string? pathAndQuery)
    {
        if (string.IsNullOrEmpty(pathAndQuery))
        {
            return "";
        }

        var q = pathAndQuery.IndexOf('?', StringComparison.Ordinal);
        if (q < 0 || q == pathAndQuery.Length - 1)
        {
            return "";
        }

        var raw = pathAndQuery[(q + 1)..];
        var pairs = new List<KeyValuePair<string, StringValues>>();
        foreach (var part in raw.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            string key;
            string value;
            if (eq < 0)
            {
                key = Uri.UnescapeDataString(part.Replace('+', ' '));
                value = "";
            }
            else
            {
                key = Uri.UnescapeDataString(part[..eq].Replace('+', ' '));
                value = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
            }

            pairs.Add(new KeyValuePair<string, StringValues>(key, value));
        }

        return CanonicalQuery(pairs);
    }

    public static string PathOnly(string pathAndQuery)
    {
        var q = pathAndQuery.IndexOf('?', StringComparison.Ordinal);
        return q < 0 ? pathAndQuery : pathAndQuery[..q];
    }

    public static string Build(
        string method,
        string path,
        string canonicalQuery,
        string bodySha256Hex,
        string contentType,
        string userId,
        string role,
        string tenantId,
        string timestamp,
        string nonce) =>
        string.Join('\n',
            Version,
            method.ToUpperInvariant(),
            path,
            canonicalQuery,
            bodySha256Hex.ToLowerInvariant(),
            contentType,
            userId,
            role,
            tenantId,
            timestamp,
            nonce);

    public static string Sign(string secret, string canonical) =>
        Convert.ToHexStringLower(
            HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(secret),
                Encoding.UTF8.GetBytes(canonical)));

    public static bool IsSecretStrongEnough(string? secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return false;
        }

        return Encoding.UTF8.GetByteCount(secret) >= MinimumSecretBytes;
    }
}
