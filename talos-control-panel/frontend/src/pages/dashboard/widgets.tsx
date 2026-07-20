import { Link } from "react-router-dom";
import { ReactNode } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export function PanelShell({
  title,
  to,
  children,
  badge,
  className = "",
}: {
  title: string;
  to?: string;
  children: ReactNode;
  badge?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel flex flex-col min-h-0 ${className}`}>
      <header className="flex items-center justify-between gap-2 px-4 pt-3 pb-2 border-b border-base-300/80">
        {to ? (
          <Link
            to={to}
            className="text-sm font-semibold tracking-wide uppercase text-base-content/80 hover:text-primary transition-colors"
          >
            {title}
          </Link>
        ) : (
          <h2 className="text-sm font-semibold tracking-wide uppercase text-base-content/80">
            {title}
          </h2>
        )}
        {badge}
      </header>
      <div className="p-4 flex-1 flex flex-col gap-3">{children}</div>
    </section>
  );
}

export function Stat({
  value,
  label,
  accent,
  size = "md",
}: {
  value: ReactNode;
  label: string;
  accent?: "default" | "success" | "warning" | "error" | "info";
  size?: "sm" | "md" | "lg";
}) {
  const accentCls =
    accent === "success"
      ? "text-success"
      : accent === "warning"
        ? "text-warning"
        : accent === "error"
          ? "text-error"
          : accent === "info"
            ? "text-info"
            : "text-base-content";
  const sizeCls =
    size === "lg" ? "text-3xl" : size === "sm" ? "text-lg" : "text-2xl";
  return (
    <div className="min-w-0">
      <div className={`${sizeCls} font-semibold tabular-nums leading-none ${accentCls}`}>
        {value}
      </div>
      <div className="text-[11px] uppercase tracking-wide text-base-content/50 mt-1">
        {label}
      </div>
    </div>
  );
}

export function StatusDot({
  tone,
  pulse,
  label,
}: {
  tone: "ok" | "warn" | "bad" | "idle";
  pulse?: boolean;
  label?: string;
}) {
  const color =
    tone === "ok"
      ? "bg-success"
      : tone === "warn"
        ? "bg-warning"
        : tone === "bad"
          ? "bg-error"
          : "bg-base-content/30";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-base-content/70">
      <span
        className={`inline-block w-2 h-2 rounded-full ${color} ${
          pulse ? "animate-pulse" : ""
        }`}
      />
      {label}
    </span>
  );
}

export function CoverageMeter({
  label,
  pct,
}: {
  label: string;
  pct: number;
}) {
  const v = Math.max(0, Math.min(100, pct || 0));
  const bar =
    v >= 70 ? "bg-success" : v >= 40 ? "bg-warning" : "bg-base-content/30";
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px] text-base-content/60">
        <span>{label}</span>
        <span className="tabular-nums mono">{v}%</span>
      </div>
      <div className="h-1.5 rounded-full bg-base-200 overflow-hidden">
        <div className={`h-full ${bar} transition-all`} style={{ width: `${v}%` }} />
      </div>
    </div>
  );
}

export function QueueFillBar({
  pct,
  active,
  max,
}: {
  pct: number;
  active: number;
  max: number;
}) {
  const v = Math.max(0, Math.min(100, pct || 0));
  const bar = v >= 90 ? "bg-error" : v >= 70 ? "bg-warning" : "bg-info";
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px] text-base-content/60">
        <span>Queue fill</span>
        <span className="tabular-nums mono">
          {active}/{max} · {v}%
        </span>
      </div>
      <div className="h-2 rounded-full bg-base-200 overflow-hidden">
        <div className={`h-full ${bar} transition-all`} style={{ width: `${v}%` }} />
      </div>
    </div>
  );
}

const CHART_COLORS = [
  "oklch(var(--p))",
  "oklch(var(--su))",
  "oklch(var(--wa))",
  "oklch(var(--er))",
  "oklch(var(--in))",
  "oklch(var(--bc) / 0.45)",
];

// Fallback solid colors if oklch CSS vars fail in SVG
const FALLBACK = ["#6366f1", "#22c55e", "#f59e0b", "#ef4444", "#06b6d4", "#94a3b8"];

export function MiniDonut({
  data,
  height = 120,
}: {
  data: { name: string; value: number }[];
  height?: number;
}) {
  const filtered = data.filter((d) => d.value > 0);
  if (!filtered.length) {
    return (
      <div
        className="flex items-center justify-center text-xs text-base-content/40"
        style={{ height }}
      >
        No data
      </div>
    );
  }
  return (
    <div style={{ height, width: "100%" }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={filtered}
            dataKey="value"
            nameKey="name"
            innerRadius="55%"
            outerRadius="80%"
            paddingAngle={2}
            stroke="none"
          >
            {filtered.map((_, i) => (
              <Cell key={i} fill={FALLBACK[i % FALLBACK.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "hsl(var(--b1))",
              border: "1px solid hsl(var(--b3))",
              borderRadius: 8,
              fontSize: 12,
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function MiniBars({
  data,
  height = 110,
  layout = "horizontal",
}: {
  data: { name: string; value: number; fill?: string }[];
  height?: number;
  layout?: "horizontal" | "vertical";
}) {
  const filtered = data.filter((d) => d.value > 0);
  if (!filtered.length) {
    return (
      <div
        className="flex items-center justify-center text-xs text-base-content/40"
        style={{ height }}
      >
        No data
      </div>
    );
  }
  return (
    <div style={{ height, width: "100%" }}>
      <ResponsiveContainer>
        <BarChart
          data={filtered}
          layout={layout === "vertical" ? "vertical" : "horizontal"}
          margin={{ top: 4, right: 8, left: 0, bottom: 0 }}
        >
          {layout === "vertical" ? (
            <>
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="name"
                width={64}
                tick={{ fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
            </>
          ) : (
            <>
              <XAxis
                dataKey="name"
                tick={{ fontSize: 10 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis hide />
            </>
          )}
          <Tooltip
            contentStyle={{
              background: "hsl(var(--b1))",
              border: "1px solid hsl(var(--b3))",
              borderRadius: 8,
              fontSize: 12,
            }}
          />
          <Bar dataKey="value" radius={[3, 3, 0, 0]} maxBarSize={28}>
            {filtered.map((d, i) => (
              <Cell
                key={i}
                fill={d.fill || FALLBACK[i % FALLBACK.length]}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SegmentLegend({
  items,
}: {
  items: { name: string; value: number; color?: string }[];
}) {
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-1">
      {items.map((it, i) => (
        <span
          key={it.name}
          className="inline-flex items-center gap-1 text-[11px] text-base-content/60"
        >
          <span
            className="w-2 h-2 rounded-sm"
            style={{ background: it.color || FALLBACK[i % FALLBACK.length] }}
          />
          {it.name}
          <span className="tabular-nums mono text-base-content/80">{it.value}</span>
        </span>
      ))}
    </div>
  );
}

export function SkeletonPanel() {
  return (
    <div className="panel p-4 space-y-3 animate-pulse">
      <div className="h-3 w-24 bg-base-300 rounded" />
      <div className="h-8 w-16 bg-base-300 rounded" />
      <div className="h-20 w-full bg-base-300 rounded" />
    </div>
  );
}

// silence unused if tree-shaken poorly
void CHART_COLORS;
