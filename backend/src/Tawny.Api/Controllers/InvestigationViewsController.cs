using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tawny.Api.Auth;
using Tawny.Domain;
using Tawny.Infrastructure;

namespace Tawny.Api.Controllers;

public record ProcessTreeAcrossHostsRow(
    string ProcessName,
    int HostCount,
    int TotalSeen,
    IReadOnlyList<ProcessTreeHostHit> Hosts);

public record ProcessTreeHostHit(
    Guid AgentId,
    string Hostname,
    int SeenCount,
    DateTimeOffset LastSeen);

public record ProcessTreeAcrossHostsResponse(
    IReadOnlyList<ProcessTreeAcrossHostsRow> Rows,
    DateTimeOffset From,
    DateTimeOffset To);

public record NetworkGraphNode(
    string Id,
    string Label,
    string Kind,
    int Weight);

public record NetworkGraphEdge(
    string SourceId,
    string TargetId,
    int Weight);

public record NetworkGraphResponse(
    IReadOnlyList<NetworkGraphNode> Nodes,
    IReadOnlyList<NetworkGraphEdge> Edges,
    DateTimeOffset From,
    DateTimeOffset To);

[ApiController]
[Route("api/investigation")]
[Authorize(AuthenticationSchemes = TawnyAuthSchemes.WebUser + "," + TawnyAuthSchemes.ApiToken)]
public class InvestigationViewsController(TawnyDbContext db) : ControllerBase
{
    /// <summary>
    /// Aggregates process snapshots in the requested window across every agent,
    /// returning each process name with the hosts that have run it. Useful for
    /// answering "where else has this binary been seen?" without a per-host hunt.
    /// </summary>
    [HttpGet("process-tree")]
    public async Task<ActionResult<ProcessTreeAcrossHostsResponse>> ProcessTree(
        [FromQuery] int hours = 24,
        [FromQuery] string? nameFilter = null,
        [FromQuery] int limit = 50,
        CancellationToken ct = default)
    {
        var tenantId = User.GetTenantId();
        var windowHours = Math.Clamp(hours, 1, 168);
        var since = DateTimeOffset.UtcNow.AddHours(-windowHours);
        var top = Math.Clamp(limit, 1, 200);

        var events = await db.TelemetryEvents
            .AsNoTracking()
            .Where(e => e.TenantId == tenantId
                && e.EventType == TelemetryEventType.ProcessSnapshot
                && e.OccurredAt >= since)
            .Select(e => new { e.AgentId, Hostname = e.Agent!.Hostname, e.OccurredAt, e.Payload })
            .ToListAsync(ct);

        // Aggregate in-memory: SQL Server can't easily walk JSON arrays this way.
        var byName = new Dictionary<string, Dictionary<Guid, ProcessHostAccumulator>>(StringComparer.OrdinalIgnoreCase);
        foreach (var ev in events)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(ev.Payload); }
            catch { continue; }
            using (doc)
            {
                if (!doc.RootElement.TryGetProperty("processes", out var processes)
                    || processes.ValueKind != JsonValueKind.Array) continue;
                foreach (var p in processes.EnumerateArray())
                {
                    if (!p.TryGetProperty("name", out var n) || n.ValueKind != JsonValueKind.String) continue;
                    var name = n.GetString();
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    if (!string.IsNullOrWhiteSpace(nameFilter)
                        && !name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    if (!byName.TryGetValue(name, out var hosts))
                    {
                        hosts = new Dictionary<Guid, ProcessHostAccumulator>();
                        byName[name] = hosts;
                    }
                    if (!hosts.TryGetValue(ev.AgentId, out var acc))
                    {
                        acc = new ProcessHostAccumulator(ev.AgentId, ev.Hostname);
                        hosts[ev.AgentId] = acc;
                    }
                    acc.Bump(ev.OccurredAt);
                }
            }
        }

        var rows = byName
            .Select(kvp => new ProcessTreeAcrossHostsRow(
                kvp.Key,
                kvp.Value.Count,
                kvp.Value.Values.Sum(h => h.SeenCount),
                kvp.Value.Values
                    .OrderByDescending(h => h.LastSeen)
                    .Select(h => new ProcessTreeHostHit(h.AgentId, h.Hostname, h.SeenCount, h.LastSeen))
                    .ToList()))
            .OrderByDescending(r => r.HostCount)
            .ThenByDescending(r => r.TotalSeen)
            .Take(top)
            .ToList();

        return Ok(new ProcessTreeAcrossHostsResponse(rows, since, DateTimeOffset.UtcNow));
    }

    /// <summary>
    /// Builds a directed graph of host -> remote endpoint flows from network
    /// snapshots. Nodes are agents (kind=host) plus distinct remote IPs
    /// (kind=endpoint). Edge weight is the number of observed connections.
    /// </summary>
    [HttpGet("network-graph")]
    public async Task<ActionResult<NetworkGraphResponse>> NetworkGraph(
        [FromQuery] int hours = 24,
        [FromQuery] int maxEndpoints = 100,
        CancellationToken ct = default)
    {
        var tenantId = User.GetTenantId();
        var windowHours = Math.Clamp(hours, 1, 168);
        var since = DateTimeOffset.UtcNow.AddHours(-windowHours);
        var cap = Math.Clamp(maxEndpoints, 10, 500);

        var events = await db.TelemetryEvents
            .AsNoTracking()
            .Where(e => e.TenantId == tenantId
                && e.EventType == TelemetryEventType.NetworkSnapshot
                && e.OccurredAt >= since)
            .Select(e => new { e.AgentId, Hostname = e.Agent!.Hostname, e.Payload })
            .ToListAsync(ct);

        var hostNodes = new Dictionary<Guid, NetworkGraphNode>();
        var endpointNodes = new Dictionary<string, EndpointAccumulator>(StringComparer.OrdinalIgnoreCase);
        var edges = new Dictionary<(Guid HostId, string Endpoint), int>();

        foreach (var ev in events)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(ev.Payload); }
            catch { continue; }
            using (doc)
            {
                if (!doc.RootElement.TryGetProperty("connections", out var conns)
                    || conns.ValueKind != JsonValueKind.Array) continue;
                if (!hostNodes.TryGetValue(ev.AgentId, out _))
                {
                    hostNodes[ev.AgentId] = new NetworkGraphNode(
                        $"host:{ev.AgentId}", ev.Hostname, "host", 0);
                }

                foreach (var conn in conns.EnumerateArray())
                {
                    if (!conn.TryGetProperty("remote_address", out var ra)
                        || ra.ValueKind != JsonValueKind.String) continue;
                    var remote = ra.GetString();
                    if (string.IsNullOrWhiteSpace(remote)
                        || IsLoopbackOrUnspecified(remote)) continue;

                    if (!endpointNodes.TryGetValue(remote, out var acc))
                    {
                        acc = new EndpointAccumulator(remote);
                        endpointNodes[remote] = acc;
                    }
                    acc.Hits += 1;
                    var key = (ev.AgentId, remote);
                    edges[key] = edges.GetValueOrDefault(key) + 1;
                }
            }
        }

        // Cap to the top N busiest endpoints to keep the graph readable.
        var topEndpoints = endpointNodes.Values
            .OrderByDescending(e => e.Hits)
            .Take(cap)
            .ToList();
        var topEndpointKeys = topEndpoints.Select(e => e.Address).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var allNodes = new List<NetworkGraphNode>(hostNodes.Values.Select(h => h with { Weight = 1 }));
        allNodes.AddRange(topEndpoints.Select(e =>
            new NetworkGraphNode($"endpoint:{e.Address}", e.Address, "endpoint", e.Hits)));

        var filteredEdges = edges
            .Where(kvp => topEndpointKeys.Contains(kvp.Key.Endpoint))
            .Select(kvp => new NetworkGraphEdge(
                $"host:{kvp.Key.HostId}",
                $"endpoint:{kvp.Key.Endpoint}",
                kvp.Value))
            .OrderByDescending(e => e.Weight)
            .ToList();

        return Ok(new NetworkGraphResponse(allNodes, filteredEdges, since, DateTimeOffset.UtcNow));
    }

    private static bool IsLoopbackOrUnspecified(string address)
    {
        return address.StartsWith("127.", StringComparison.Ordinal)
            || address == "::1"
            || address == "0.0.0.0"
            || address.StartsWith("169.254.", StringComparison.Ordinal);
    }

    private sealed class ProcessHostAccumulator(Guid agentId, string hostname)
    {
        public Guid AgentId { get; } = agentId;
        public string Hostname { get; } = hostname;
        public int SeenCount { get; private set; }
        public DateTimeOffset LastSeen { get; private set; }

        public void Bump(DateTimeOffset at)
        {
            SeenCount += 1;
            if (at > LastSeen) LastSeen = at;
        }
    }

    private sealed class EndpointAccumulator(string address)
    {
        public string Address { get; } = address;
        public int Hits { get; set; }
    }
}
