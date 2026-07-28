using System.Security.Cryptography;
using System.Text;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public sealed class TelemetryIntegrityOptions
{
    /// <summary>Reject agent timestamps more than this many seconds in the future.</summary>
    public int MaxFutureSkewSeconds { get; set; } = 300;

    /// <summary>Reject agent timestamps older than this many days relative to receive time.</summary>
    public int MaxPastDays { get; set; } = 7;

    /// <summary>Flag (audit) when a batch is larger than this multiple of the prior batch.</summary>
    public double VolumeSpikeMultiplier { get; set; } = 10;

    public int VolumeSpikeMinEvents { get; set; } = 50;
}

public static class TelemetryIntegrity
{
    public static string PayloadDigest(string payload) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));

    public static bool TryMapOccurredAt(
        long unixSeconds,
        DateTimeOffset receivedAt,
        TelemetryIntegrityOptions options,
        out DateTimeOffset occurredAt,
        out string? rejectReason)
    {
        occurredAt = default;
        rejectReason = null;
        if (unixSeconds <= 0 || unixSeconds > 253402300799)
        {
            rejectReason = "occurred_at out of range";
            return false;
        }

        occurredAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        var skew = (occurredAt - receivedAt).TotalSeconds;
        if (skew > options.MaxFutureSkewSeconds)
        {
            rejectReason = "occurred_at too far in the future";
            return false;
        }

        if (occurredAt < receivedAt.AddDays(-options.MaxPastDays))
        {
            rejectReason = "occurred_at too far in the past";
            return false;
        }

        return true;
    }

    public static SequenceAssessment AssessSequence(
        Agent agent,
        IReadOnlyList<long?> sequences)
    {
        long? maxInBatch = null;
        long? minInBatch = null;
        var hasAny = false;
        foreach (var seq in sequences)
        {
            if (seq is null) continue;
            hasAny = true;
            maxInBatch = maxInBatch is null ? seq : Math.Max(maxInBatch.Value, seq.Value);
            minInBatch = minInBatch is null ? seq : Math.Min(minInBatch.Value, seq.Value);
        }

        if (!hasAny)
        {
            return new SequenceAssessment(false, false, null, agent.LastTelemetrySequence, null);
        }

        var rollback = minInBatch!.Value <= agent.LastTelemetrySequence && agent.LastTelemetrySequence > 0
            && minInBatch.Value < agent.LastTelemetrySequence;
        // Gap: first sequence jumps more than 1 past last accepted.
        var gap = agent.LastTelemetrySequence > 0
            && minInBatch.Value > agent.LastTelemetrySequence + 1;

        return new SequenceAssessment(
            Rollback: rollback,
            Gap: gap,
            MinSequence: minInBatch,
            PreviousMax: agent.LastTelemetrySequence,
            NewMax: maxInBatch);
    }

    public static bool IsVolumeSpike(Agent agent, int batchCount, TelemetryIntegrityOptions options)
    {
        if (batchCount < options.VolumeSpikeMinEvents) return false;
        if (agent.LastIngestEventCount <= 0) return false;
        return batchCount >= agent.LastIngestEventCount * options.VolumeSpikeMultiplier;
    }
}

public readonly record struct SequenceAssessment(
    bool Rollback,
    bool Gap,
    long? MinSequence,
    long PreviousMax,
    long? NewMax);
