using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public interface IAlertSink
{
    Task PublishAsync(
        Agent agent,
        IReadOnlyList<Alert> alerts,
        IReadOnlyDictionary<long, TelemetryEvent> telemetryEvents,
        CancellationToken ct);
}

public sealed class NoopAlertSink : IAlertSink
{
    public Task PublishAsync(
        Agent agent,
        IReadOnlyList<Alert> alerts,
        IReadOnlyDictionary<long, TelemetryEvent> telemetryEvents,
        CancellationToken ct) => Task.CompletedTask;
}
