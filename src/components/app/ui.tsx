import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { ScanStatus, Severity } from "@/lib/api/types";

export const SEVERITIES: Exclude<Severity, "info">[] = ["critical", "high", "medium", "low"];

const sevClass: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  info: "bg-sev-info/15 text-sev-info border-sev-info/30",
};
export const sevDot: Record<Severity, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low", info: "bg-sev-info",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium capitalize", sevClass[severity], className)}>
      <span className={cn("size-1.5 rounded-full", sevDot[severity])} />
      {severity}
    </span>
  );
}

const statusClass: Record<ScanStatus, string> = {
  running: "bg-primary/15 text-primary border-primary/30",
  completed: "bg-success/15 text-success border-success/30",
  // Some scanners completed, others failed: neither a success nor a total failure.
  partial: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  queued: "bg-muted text-muted-foreground border-border",
  failed: "bg-destructive/15 text-destructive border-destructive/30",
};
const statusTitle: Partial<Record<ScanStatus, string>> = {
  partial: "Some scanners completed, others failed",
};
export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      title={statusTitle[status]}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        statusClass[status] ?? statusClass.queued,
      )}
    >
      {status === "running" && <span className="size-1.5 animate-pulse rounded-full bg-primary" />}
      {status}
    </span>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold text-foreground sm:text-3xl">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({ title, action, children, className }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("panel p-5", className)}>
      {title && (
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatCard({ label, value, hint, icon, tone = "default" }: { label: string; value: ReactNode; hint?: ReactNode; icon: ReactNode; tone?: "default" | "critical" }) {
  return (
    <div className="panel p-5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</span>
        <span className={cn("rounded-lg p-2", tone === "critical" ? "bg-sev-critical/15 text-sev-critical" : "bg-primary/10 text-primary")}>{icon}</span>
      </div>
      <div className="mt-3 font-display text-3xl font-semibold text-foreground">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}

export function RiskGauge({ score }: { score: number }) {
  const r = 64, c = 2 * Math.PI * r, arc = c * 0.75;
  const color = score >= 75 ? "var(--sev-critical)" : score >= 50 ? "var(--sev-high)" : score >= 25 ? "var(--sev-medium)" : "var(--success)";
  const label = score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Moderate" : "Low";
  return (
    <div className="relative mx-auto size-44">
      <svg viewBox="0 0 160 160" className="size-full rotate-[135deg]">
        <circle cx="80" cy="80" r={r} fill="none" stroke="var(--muted)" strokeWidth="12" strokeDasharray={`${arc} ${c}`} strokeLinecap="round" />
        <circle cx="80" cy="80" r={r} fill="none" stroke={color} strokeWidth="12" strokeDasharray={`${(arc * score) / 100} ${c}`} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display text-4xl font-semibold text-foreground">{score}</span>
        <span className="text-xs font-medium" style={{ color }}>{label} risk</span>
      </div>
    </div>
  );
}

/** Placeholder for a value the backend did not provide; `reason` explains why on hover. */
export function Unavailable({ label = "—", reason }: { label?: string; reason?: string }) {
  return (
    <span className="text-muted-foreground" title={reason}>
      {label}
    </span>
  );
}

export function fmtDate(iso: string) {
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
}
