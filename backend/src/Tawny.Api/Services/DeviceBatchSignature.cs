using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using Tawny.Api.Models;
using Tawny.Domain;

namespace Tawny.Api.Services;

/// <summary>
/// Ed25519 batch signatures for agent telemetry ingest.
/// Canonical form (UTF-8 lines):
/// <code>
/// tawny-batch-v1
/// {agent_id:D}
/// {batch_id:D}
/// {client_event_id or -}|{sequence or 0}|{type}|{occurred_at}|{sha256(payload)}
/// ...one line per event in request order...
/// </code>
/// </summary>
public static class DeviceBatchSignature
{
    public const string Prefix = "tawny-batch-v1";

    public static string BuildCanonical(Guid agentId, Guid batchId, IReadOnlyList<TelemetryEventIngest> events)
    {
        var sb = new StringBuilder();
        sb.Append(Prefix).Append('\n');
        sb.Append(agentId.ToString("D")).Append('\n');
        sb.Append(batchId.ToString("D")).Append('\n');
        foreach (var ev in events)
        {
            var clientId = ev.ClientEventId?.ToString("D") ?? "-";
            var seq = ev.Sequence ?? 0;
            var typeName = ToWireName(ev.Type);
            var payload = ev.Payload.GetRawText();
            var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
            sb.Append(clientId).Append('|')
                .Append(seq).Append('|')
                .Append(typeName).Append('|')
                .Append(ev.OccurredAt).Append('|')
                .Append(digest)
                .Append('\n');
        }

        return sb.ToString();
    }

    public static bool TryVerify(string? devicePublicKeyBase64, string? signatureBase64, string canonical)
    {
        if (string.IsNullOrWhiteSpace(devicePublicKeyBase64) || string.IsNullOrWhiteSpace(signatureBase64))
        {
            return false;
        }

        try
        {
            var publicKeyBytes = Convert.FromBase64String(devicePublicKeyBase64.Trim());
            var signature = Convert.FromBase64String(signatureBase64.Trim());
            if (publicKeyBytes.Length != 32 || signature.Length != 64)
            {
                return false;
            }

            var algorithm = SignatureAlgorithm.Ed25519;
            var publicKey = PublicKey.Import(algorithm, publicKeyBytes, KeyBlobFormat.RawPublicKey);
            return algorithm.Verify(publicKey, Encoding.UTF8.GetBytes(canonical), signature);
        }
        catch
        {
            return false;
        }
    }

    public static string Sign(byte[] privateSeed32, string canonical)
    {
        if (privateSeed32.Length != 32)
        {
            throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(privateSeed32));
        }

        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Import(algorithm, privateSeed32, KeyBlobFormat.RawPrivateKey);
        var sig = algorithm.Sign(key, Encoding.UTF8.GetBytes(canonical));
        return Convert.ToBase64String(sig);
    }

    public static string PublicKeyFromSeed(byte[] privateSeed32)
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Import(algorithm, privateSeed32, KeyBlobFormat.RawPrivateKey);
        return Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    private static string ToWireName(TelemetryEventType type) => type switch
    {
        TelemetryEventType.ProcessSnapshot => "process_snapshot",
        TelemetryEventType.NetworkSnapshot => "network_snapshot",
        TelemetryEventType.UserSession => "user_session",
        TelemetryEventType.SystemInfo => "system_info",
        TelemetryEventType.FileIntegrity => "file_integrity",
        TelemetryEventType.Heartbeat => "heartbeat",
        TelemetryEventType.DnsQuery => "dns_query",
        TelemetryEventType.ProcessLaunch => "process_launch",
        TelemetryEventType.FileEvent => "file_event",
        TelemetryEventType.PackageInventory => "package_inventory",
        TelemetryEventType.EditorExtension => "editor_extension",
        TelemetryEventType.BrowserExtension => "browser_extension",
        TelemetryEventType.McpConfig => "mcp_config",
        _ => type.ToString(),
    };
}
