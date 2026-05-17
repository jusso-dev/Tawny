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

public sealed class CompositeAlertSink(
    WazuhAlertSink wazuh,
    SlackAlertSink slack,
    SentinelAlertSink sentinel) : IAlertSink
{
    public async Task PublishAsync(
        Agent agent,
        IReadOnlyList<Alert> alerts,
        IReadOnlyDictionary<long, TelemetryEvent> telemetryEvents,
        CancellationToken ct)
    {
        await wazuh.PublishAsync(agent, alerts, telemetryEvents, ct);
        await slack.PublishAsync(agent, alerts, telemetryEvents, ct);
        await sentinel.PublishAsync(agent, alerts, telemetryEvents, ct);
    }
}
