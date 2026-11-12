import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Circle, Loader2, ArrowLeft } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api/services";
import { PageHeader, Panel, SEVERITIES, StatusBadge, fmtDate, sevDot } from "@/components/app/ui";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/scans/$scanId")({
  head: ({ params }) => ({
    meta: [
      { title: `Scan ${params.scanId} — AutoPentest AI` },
      { name: "description", content: "Real-time progress and stages of a security assessment." },
      { property: "og:title", content: `Scan ${params.scanId} — AutoPentest AI` },
      { property: "og:description", content: "Real-time assessment progress." },
    ],
  }),
  component: ScanDetails,
});

function ScanDetails() {
  const { scanId } = Route.useParams();
  // Polls the backend for live progress while the scan runs.
  const { data: scan } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId),
    refetchInterval: (q) => (q.state.data?.status === "running" ? 2000 : false),
  });

  if (!scan) return <div className="space-y-4"><Skeleton className="h-10 w-72" /><Skeleton className="h-40" /><Skeleton className="h-80" /></div>;

  return (
    <>
      <Link to="/scans" className="mb-4 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3" /> All scans</Link>
      <PageHeader title={scan.name} description={scan.target} actions={<StatusBadge status={scan.status} />} />

      <Panel>
        <div className="flex items-end justify-between">
          <div><div className="text-xs uppercase tracking-wider text-muted-foreground">Overall progress</div><div className="font-display text-4xl font-semibold text-foreground">{scan.progress}%</div></div>
          <div className="text-right text-xs text-muted-foreground">Started {fmtDate(scan.startedAt)} UTC<br />Profile: {scan.profile}</div>
        </div>
        <Progress value={scan.progress} className="mt-4 h-2" />
        <div className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Metric label="Requests sent" value={scan.requestsSent.toLocaleString()} />
          <Metric label="Endpoints found" value={scan.endpointsDiscovered} />
          <Metric label="Findings" value={SEVERITIES.reduce((n, k) => n + scan.findings[k], 0)} />
          <Metric label="Risk score" value={scan.riskScore || "—"} />
        </div>
      </Panel>

      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        <Panel title="Assessment stages" className="lg:col-span-2">
          <ol className="space-y-1">
            {scan.stages.map((st, i) => (
              <li key={st.key} className="relative flex gap-3 pb-4">
                {i < scan.stages.length - 1 && <span className={cn("absolute left-[9px] top-6 h-[calc(100%-16px)] w-px", st.status === "done" ? "bg-success/50" : "bg-border")} />}
                {st.status === "done" ? <CheckCircle2 className="size-5 shrink-0 text-success" /> : st.status === "running" ? <Loader2 className="size-5 shrink-0 animate-spin text-primary" /> : <Circle className="size-5 shrink-0 text-muted-foreground/50" />}
                <div>
                  <div className={cn("text-sm font-medium", st.status === "pending" ? "text-muted-foreground" : "text-foreground")}>{st.label}</div>
                  <div className="text-xs text-muted-foreground">{st.description}</div>
                </div>
              </li>
            ))}
          </ol>
        </Panel>

        <div className="space-y-4 lg:col-span-3">
          <Panel title="Findings so far">
            <div className="grid grid-cols-4 gap-2">
              {SEVERITIES.map((k) => (
                <div key={k} className="rounded-lg border border-border p-3 text-center">
                  <div className="font-display text-2xl font-semibold text-foreground">{scan.findings[k]}</div>
                  <div className="mt-1 flex items-center justify-center gap-1.5 text-xs capitalize text-muted-foreground"><span className={`size-1.5 rounded-full ${sevDot[k]}`} />{k}</div>
                </div>
              ))}
            </div>
            <Link to="/vulnerabilities" className="mt-3 inline-block text-xs text-primary hover:underline">View findings →</Link>
          </Panel>
          <Panel title="Live log">
            <div className="max-h-72 overflow-y-auto rounded-lg bg-background p-3 font-mono text-xs">
              {scan.log.map((l, i) => (
                <div key={i} className="flex gap-3 py-0.5">
                  <span className="text-muted-foreground">{l.time}</span>
                  <span className={l.level === "warn" ? "text-sev-medium" : l.level === "finding" ? "text-sev-high" : "text-foreground"}>{l.message}</span>
                </div>
              ))}
              {scan.status === "running" && <div className="mt-1 animate-pulse text-primary">▍</div>}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return <div><div className="text-xs text-muted-foreground">{label}</div><div className="font-mono text-lg text-foreground">{value}</div></div>;
}
