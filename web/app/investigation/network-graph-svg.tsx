"use client";

import { useMemo } from "react";

type Node = {
  id: string;
  label: string;
  kind: "host" | "endpoint";
  weight: number;
};

type Edge = {
  source_id: string;
  target_id: string;
  weight: number;
};

/**
 * Lightweight bipartite force-style layout: hosts on the left, endpoints on
 * the right. Positions are deterministic (based on input order) so the graph
 * doesn't shift between page loads. Good enough for SOC triage without
 * pulling in a full graph layout library.
 */
export function NetworkGraphSvg({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  const layout = useMemo(() => buildLayout(nodes), [nodes]);

  if (nodes.length === 0) {
    return (
      <div className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] px-4 py-10 text-center text-sm text-[color:var(--color-muted-foreground)]">
        No network telemetry in the selected window.
      </div>
    );
  }

  const width = 960;
  const height = Math.max(360, layout.maxRow * 28 + 60);
  const maxEdgeWeight = edges.reduce((acc, e) => Math.max(acc, e.weight), 1);

  return (
    <div className="overflow-x-auto rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-card)] p-4">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Host to endpoint graph" className="w-full">
        {edges.map((edge) => {
          const source = layout.positions.get(edge.source_id);
          const target = layout.positions.get(edge.target_id);
          if (!source || !target) return null;
          const strokeWidth = 0.5 + (edge.weight / maxEdgeWeight) * 4;
          return (
            <line
              key={`${edge.source_id}->${edge.target_id}`}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="var(--color-accent)"
              strokeOpacity={0.35}
              strokeWidth={strokeWidth}
            />
          );
        })}
        {nodes.map((node) => {
          const pos = layout.positions.get(node.id);
          if (!pos) return null;
          const isHost = node.kind === "host";
          return (
            <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`}>
              <circle
                r={isHost ? 8 : 5}
                fill={isHost ? "var(--color-accent)" : "var(--color-warning)"}
                stroke="var(--color-card)"
                strokeWidth={1.5}
              />
              <text
                x={isHost ? -12 : 10}
                y={4}
                textAnchor={isHost ? "end" : "start"}
                className="fill-[color:var(--color-foreground)] text-[10px]"
              >
                {node.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function buildLayout(nodes: Node[]): { positions: Map<string, { x: number; y: number }>; maxRow: number } {
  const hosts = nodes.filter((n) => n.kind === "host");
  const endpoints = nodes.filter((n) => n.kind === "endpoint");
  const positions = new Map<string, { x: number; y: number }>();
  const rowSpacing = 24;
  const hostX = 180;
  const endpointX = 780;

  hosts.forEach((node, idx) => {
    positions.set(node.id, { x: hostX, y: 40 + idx * rowSpacing });
  });
  endpoints.forEach((node, idx) => {
    positions.set(node.id, { x: endpointX, y: 40 + idx * rowSpacing });
  });

  return {
    positions,
    maxRow: Math.max(hosts.length, endpoints.length),
  };
}
