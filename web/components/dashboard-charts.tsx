"use client";

import {
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type StatusPoint = {
  name: string;
  value: number;
  color: string;
};

type VolumePoint = {
  bucket_start: string;
  count: number;
};

export function StatusDonut({ data }: { data: StatusPoint[] }) {
  const total = data.reduce((sum, point) => sum + point.value, 0);
  if (total === 0) {
    return (
      <div className="grid h-56 place-items-center rounded-lg border border-dashed border-[color:var(--color-border)] text-sm text-[color:var(--color-muted-foreground)]">
        No agents enrolled.
      </div>
    );
  }

  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={86} paddingAngle={2}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "var(--color-background)",
              border: "1px solid var(--color-border)",
              borderRadius: 8,
              color: "var(--color-foreground)",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function VolumeSparkline({ data }: { data: VolumePoint[] }) {
  const empty = data.every((point) => point.count === 0);
  if (empty) {
    return (
      <div className="grid h-56 place-items-center rounded-lg border border-dashed border-[color:var(--color-border)] text-sm text-[color:var(--color-muted-foreground)]">
        No events in the last 24 hours.
      </div>
    );
  }

  const chartData = data.map((point) => ({
    ...point,
    hour: new Date(point.bucket_start).toLocaleTimeString([], { hour: "numeric" }),
  }));

  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData} margin={{ top: 12, right: 10, bottom: 0, left: -28 }}>
          <XAxis dataKey="hour" tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: "var(--color-muted-foreground)" }} />
          <YAxis hide domain={[0, "dataMax"]} />
          <Tooltip
            contentStyle={{
              background: "var(--color-background)",
              border: "1px solid var(--color-border)",
              borderRadius: 8,
              color: "var(--color-foreground)",
            }}
            labelFormatter={(value) => `Hour ${value}`}
          />
          <Line
            type="monotone"
            dataKey="count"
            stroke="var(--color-accent)"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, fill: "var(--color-accent)" }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
