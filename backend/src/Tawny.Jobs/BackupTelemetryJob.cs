using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Jobs;

public class TelemetryBackupOptions
{
    public string? LocalPath { get; set; } = "backups/telemetry";
    public string? S3Bucket { get; set; }
    public string? S3Prefix { get; set; } = "telemetry";
}

public class BackupTelemetryJob(
    TawnyDbContext db,
    IOptions<TelemetryBackupOptions> options,
    ILogger<BackupTelemetryJob> log)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public async Task ExecuteAsync(CancellationToken ct = default)
    {
        var opts = options.Value;
        if (string.IsNullOrWhiteSpace(opts.LocalPath) && string.IsNullOrWhiteSpace(opts.S3Bucket))
        {
            log.LogInformation("Telemetry backup skipped: no local path or S3 bucket configured.");
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var since = now.AddHours(-24);
        var fileName = $"telemetry-{now:yyyyMMddHHmmss}Z.jsonl.gz";

        var events = await db.TelemetryEvents
            .AsNoTracking()
            .Where(e => e.ReceivedAt >= since && e.ReceivedAt <= now)
            .OrderBy(e => e.ReceivedAt)
            .Select(e => new BackupRow(
                e.Id,
                e.AgentId,
                e.EventType,
                e.OccurredAt,
                e.ReceivedAt,
                e.Payload))
            .ToListAsync(ct);

        await using var compressed = new MemoryStream();
        await WriteGzipJsonLinesAsync(compressed, events, ct);
        compressed.Position = 0;

        if (!string.IsNullOrWhiteSpace(opts.LocalPath))
        {
            Directory.CreateDirectory(opts.LocalPath);
            var path = Path.Combine(opts.LocalPath, fileName);
            await File.WriteAllBytesAsync(path, compressed.ToArray(), ct);
            log.LogInformation("Backed up {Count} telemetry events to {Path}.", events.Count, path);
        }

        if (!string.IsNullOrWhiteSpace(opts.S3Bucket))
        {
            compressed.Position = 0;
            var prefix = string.IsNullOrWhiteSpace(opts.S3Prefix)
                ? ""
                : opts.S3Prefix.Trim('/').Trim() + "/";
            var key = prefix + fileName;

            using var s3 = new AmazonS3Client();
            await s3.PutObjectAsync(new PutObjectRequest
            {
                BucketName = opts.S3Bucket,
                Key = key,
                InputStream = compressed,
                ContentType = "application/gzip",
            }, ct);
            log.LogInformation("Backed up {Count} telemetry events to s3://{Bucket}/{Key}.",
                events.Count, opts.S3Bucket, key);
        }
    }

    private static async Task WriteGzipJsonLinesAsync(
        Stream output,
        IReadOnlyList<BackupRow> events,
        CancellationToken ct)
    {
        await using var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true);
        await using var writer = new StreamWriter(gzip, new UTF8Encoding(false));

        foreach (var row in events)
        {
            ct.ThrowIfCancellationRequested();
            using var payloadDoc = JsonDocument.Parse(row.Payload);
            var line = JsonSerializer.Serialize(new BackupTelemetryEvent(
                row.Id,
                row.AgentId,
                row.Type,
                row.OccurredAt,
                row.ReceivedAt,
                payloadDoc.RootElement), JsonOptions);
            await writer.WriteLineAsync(line);
        }
    }

    private sealed record BackupRow(
        long Id,
        Guid AgentId,
        TelemetryEventType Type,
        DateTimeOffset OccurredAt,
        DateTimeOffset ReceivedAt,
        string Payload);

    private sealed record BackupTelemetryEvent(
        long Id,
        Guid AgentId,
        TelemetryEventType Type,
        DateTimeOffset OccurredAt,
        DateTimeOffset ReceivedAt,
        JsonElement Payload);
}
