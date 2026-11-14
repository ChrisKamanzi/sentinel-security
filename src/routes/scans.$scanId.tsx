import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Circle, CircleSlash, Loader2, ArrowLeft, XCircle } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { api, scanFindingsQuery } from "@/lib/api/services";
import type { ScanStatus, StageStatus } from "@/lib/api/types";
import { PageHeader, Panel, SEVERITIES, StatusBadge, Unavailable, fmtDate, sevDot } from "@/components/app/ui";
import { cn } from "@/lib/utils";

/** Statuses that can still change, so the page keeps polling. */
const ACTIVE: ScanStatus[] = ["queued", "running"];

function StageIcon({ status }: { status: StageStatus }) {
  switch (status) {
    case "done":
      return <CheckCircle2 className="size-5 shrink-0 text-success" />;
    case "running":
      return <Loader2 className="size-5 shrink-0 animate-spin text-primary" />;
    case "failed":
      return <XCircle className="size-5 shrink-0 text-destructive" aria-label="failed" />;
    case "skipped":
      return <CircleSlash className="size-5 shrink-0 text-muted-foreground" aria-label="skipped" />;
    default:
      return <Circle className="size-5 shrink-0 text-muted-foreground/50" />;
  }
}

export const Route = createFileRoute("/scans/$scanId")({
  head: ({ params }) => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
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
  // Polls the backend while the scan is queued or running.
  const { data: scan, error, isError, refetch } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId),
    refetchInterval: (q) => (q.state.data && ACTIVE.includes(q.state.data.status) ? 2000 : false),
  });
  const findings = useQuery({ ...scanFindingsQuery(scanId), refetchInterval: scan && ACTIVE.includes(scan.status) ? 2000 : false });

  if (isError) return <Panel title="Assessment unavailable"><p role="alert" className="text-sm text-destructive">{error.message}</p><Button variant="outline" className="mt-4" onClick={() => void refetch()}>Retry</Button></Panel>;

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
          <Metric
            label="Requests sent"
            value={scan.requestsSent == null ? <Unavailable label="Not tracked" reason="The backend does not count requests" /> : scan.requestsSent.toLocaleString()}
          />
          <Metric
            label="Endpoints found"
            value={scan.endpointsDiscovered == null ? <Unavailable reason="No discovery scanner has reported yet" /> : scan.endpointsDiscovered}
          />
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
                <StageIcon status={st.status} />
                <div>
                  <div className={cn("text-sm font-medium", st.status === "pending" || st.status === "skipped" ? "text-muted-foreground" : st.status === "failed" ? "text-destructive" : "text-foreground")}>{st.label}</div>
                  <div className="text-xs text-muted-foreground">{st.description}</div>
                </div>
              </li>
            ))}
            {scan.stages.length === 0 && <li className="text-sm text-muted-foreground">{scan.status === "queued" ? "Waiting for scanners to start." : "No scanner stages recorded."}</li>}
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
            {findings.isError && <p role="alert" className="mt-3 text-sm text-destructive">{findings.error.message}</p>}
            <ul className="mt-3 space-y-2">{findings.data?.map((f) => <li key={f.id}><Link to="/vulnerabilities/$findingId" params={{ findingId: f.id }} className="text-sm text-primary hover:underline">{f.title}</Link><span className="ml-2 text-xs capitalize text-muted-foreground">{f.severity}</span></li>)}</ul>
            {!findings.isPending && !findings.isError && !findings.data?.length && <p className="mt-3 text-sm text-muted-foreground">No findings reported for this assessment.</p>}
            <div className="mt-4 flex flex-wrap gap-2"><Button variant="outline" size="sm" asChild><Link to="/analyst" search={{ scan: scanId }}>AI analysis</Link></Button><Button variant="outline" size="sm" asChild><Link to="/reports">Reports</Link></Button></div>
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
