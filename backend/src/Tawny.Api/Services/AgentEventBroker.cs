using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Api.Services;

public record StreamedEvent(
    long Id,
    Guid TenantId,
    Guid AgentId,
    TelemetryEventType EventType,
    DateTimeOffset OccurredAt,
    DateTimeOffset ReceivedAt,
    JsonElement Payload);

/// <summary>
/// In-process pub/sub for live telemetry events. Each subscriber gets a bounded
/// channel; slow consumers are dropped rather than backpressuring the publisher.
/// This is intentionally not durable — clients reconnect and resume via the
/// existing polling endpoint if they miss events.
/// </summary>
public class AgentEventBroker
{
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, Channel<StreamedEvent>>> _subscribers = new();

    public IDisposable Subscribe(Guid tenantId, Guid agentId, out Channel<StreamedEvent> channel)
    {
        // Build the channel into a local first; C# forbids capturing an `out`
        // parameter inside a lambda (its lifetime isn't guaranteed past the
        // caller's stack frame), so the dispose lambda must close over the
        // local copy instead of `channel` itself.
        var created = Channel.CreateBounded<StreamedEvent>(new BoundedChannelOptions(256)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });
        channel = created;

        var perTenant = _subscribers.GetOrAdd(tenantId, _ => new ConcurrentDictionary<Guid, Channel<StreamedEvent>>());
        var subscriberId = Guid.NewGuid();
        perTenant.TryAdd(subscriberId, created);
        _filters[subscriberId] = agentId;

        return new Subscription(() =>
        {
            perTenant.TryRemove(subscriberId, out _);
            _filters.TryRemove(subscriberId, out _);
            created.Writer.TryComplete();
        });
    }

    private readonly ConcurrentDictionary<Guid, Guid> _filters = new();

    public void Publish(Agent agent, IReadOnlyList<TelemetryEvent> events)
    {
        if (!_subscribers.TryGetValue(agent.TenantId, out var perTenant) || perTenant.IsEmpty) return;

        foreach (var (subscriberId, channel) in perTenant)
        {
            if (!_filters.TryGetValue(subscriberId, out var filterAgent) || filterAgent != agent.Id)
            {
                continue;
            }

            foreach (var ev in events)
            {
                JsonElement payload;
                try { payload = JsonSerializer.Deserialize<JsonElement>(ev.Payload); }
                catch { continue; }
                channel.Writer.TryWrite(new StreamedEvent(
                    ev.Id, ev.TenantId, ev.AgentId, ev.EventType, ev.OccurredAt, ev.ReceivedAt, payload));
            }
        }
    }

    private sealed class Subscription(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }
}
