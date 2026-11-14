import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, type ReactNode } from "react";
import { AlertTriangle, Bot, ListChecks, Loader2, ShieldCheck, Sparkles } from "lucide-react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Panel, SeverityBadge, StatusBadge, fmtDate } from "@/components/app/ui";
import { api, assessmentsQuery, findingQuery, scanAnalysisQuery } from "@/lib/api/services";
import type {
  AnalysisResult,
  Assessment,
  OverallRisk,
  ScanAnalysis,
  Severity,
} from "@/lib/api/types";
import { asUtc } from "@/lib/format";
import { cn } from "@/lib/utils";

const ACTIVE_SCAN: Assessment["status"][] = ["queued", "running"];
const riskSeverity = (r: OverallRisk): Severity => (r === "informational" ? "info" : r);
const VALIDITY: Record<string, string> = {
  likely_true_positive: "Likely true positive",
  needs_verification: "Needs verification",
  likely_false_positive: "Likely false positive",
  informational: "Informational",
};

/**
 * AI analysis backed by the existing scan analysis endpoints: pick an
 * assessment, view its latest analysis, or start a new one (with confirmation).
 */
export function ScanAnalysisView({
  scanId: requestedScan,
  findingId,
  onSelectScan,
}: {
  scanId?: string | undefined;
  findingId?: string | undefined;
  onSelectScan: (scanId: string) => void;
}) {
  const assessments = useQuery(assessmentsQuery);
  // A ?finding= link opens that finding's assessment.
  const finding = useQuery({
    ...findingQuery(findingId ?? ""),
    enabled: !!findingId && !requestedScan,
  });
  const list = assessments.data ?? [];
  const scanId =
    requestedScan ??
    finding.data?.assessmentId ??
    list.find((a) => !ACTIVE_SCAN.includes(a.status))?.id ??
    list[0]?.id;
  const selected = list.find((a) => a.id === scanId);

  if (assessments.isLoading) return <Skeleton className="h-40" />;
  if (assessments.isError)
    return (
      <Panel>
        <Notice tone="error">Could not load assessments: {assessments.error.message}</Notice>
      </Panel>
    );
  if (list.length === 0) {
    return (
      <Panel>
        <Notice>
          No assessments yet. Run an assessment first; its findings can then be analyzed.
        </Notice>
      </Panel>
    );
  }

  return (
    <div className="space-y-4">
      <Panel>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <Select value={scanId ?? ""} onValueChange={onSelectScan}>
            <SelectTrigger className="sm:max-w-md" aria-label="Assessment">
              <SelectValue placeholder="Choose an assessment" />
            </SelectTrigger>
            <SelectContent>
              {list.map((a) => (
                <SelectItem key={a.id} value={a.id}>
                  {a.name} · {a.status} · {fmtDate(a.startedAt)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {selected && <StatusBadge status={selected.status} />}
          {selected && <RunAnalysisButton assessment={selected} />}
        </div>
      </Panel>
      {selected && <AnalysisPanel assessment={selected} highlight={findingId} />}
    </div>
  );
}

function useAnalysis(scanId: string) {
  return useQuery({
    ...scanAnalysisQuery(scanId),
    refetchInterval: (q) =>
      q.state.data && ["pending", "running"].includes(q.state.data.status) ? 3000 : false,
  });
}

function RunAnalysisButton({ assessment }: { assessment: Assessment }) {
  const queryClient = useQueryClient();
  const analysis = useAnalysis(assessment.id);
  const start = useMutation({
    mutationFn: () => api.startScanAnalysis(assessment.id),
    onSuccess: (a) => {
      queryClient.setQueryData(scanAnalysisQuery(assessment.id).queryKey, a);
      toast.success("AI analysis queued", { description: assessment.name });
    },
    onError: (e: Error) => toast.error("Could not start analysis", { description: e.message }),
  });
  const scanActive = ACTIVE_SCAN.includes(assessment.status);
  const analysisActive = !!analysis.data && ["pending", "running"].includes(analysis.data.status);
  const reason = scanActive
    ? "Available once the assessment finishes"
    : analysisActive
      ? "An analysis is already in progress"
      : undefined;

  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button className="sm:ml-auto" disabled={!!reason || start.isPending} title={reason}>
          {start.isPending ? <Loader2 className="animate-spin" /> : <Sparkles />}
          {analysis.data ? "Run new analysis" : "Run AI analysis"}
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Run AI analysis?</AlertDialogTitle>
          <AlertDialogDescription>
            The backend sends this assessment&apos;s findings (secrets redacted, highest severity
            first) to Anthropic&apos;s Claude API. Each run uses API credits and can take a few
            minutes. Results are advisory: verify findings before acting on them.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={() => start.mutate()}>Run analysis</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function AnalysisPanel({
  assessment,
  highlight,
}: {
  assessment: Assessment;
  highlight?: string | undefined;
}) {
  const { data: a, isLoading, isError, error } = useAnalysis(assessment.id);

  if (isLoading) return <Skeleton className="h-64" />;
  if (isError)
    return (
      <Panel>
        <Notice tone="error">Could not load the analysis: {error.message}</Notice>
      </Panel>
    );
  if (!a) {
    return (
      <Panel>
        <Notice>
          {ACTIVE_SCAN.includes(assessment.status)
            ? "This assessment is still in progress. Analyze it once it finishes."
            : "This assessment has not been analyzed yet. Use “Run AI analysis” to review its findings with Claude."}
        </Notice>
      </Panel>
    );
  }
  if (a.status === "pending" || a.status === "running") {
    return (
      <Panel>
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          <Loader2 className="size-5 animate-spin text-primary" />
          <span>
            {a.status === "pending"
              ? "Analysis queued"
              : `Claude is analyzing ${a.findings_analyzed || "the"} finding(s)`}
            … started {fmtDate(asUtc(a.started_at ?? a.created_at))} UTC. This page updates
            automatically.
          </span>
        </div>
      </Panel>
    );
  }
  if (a.status === "failed") {
    return (
      <Panel title="Analysis failed">
        <Notice tone="error">
          {a.error_message || "The analysis failed without an error message."}
        </Notice>
        <p className="mt-3 text-xs text-muted-foreground">
          Run {a.id} · {fmtDate(asUtc(a.completed_at ?? a.created_at))} UTC. The scan&apos;s
          findings are unaffected.
        </p>
      </Panel>
    );
  }
  if (!a.result)
    return (
      <Panel>
        <Notice tone="error">The analysis completed but stored no result.</Notice>
      </Panel>
    );
  return <AnalysisReport analysis={a} result={a.result} highlight={highlight} />;
}

function AnalysisReport({
  analysis: a,
  result,
  highlight,
}: {
  analysis: ScanAnalysis;
  result: AnalysisResult;
  highlight?: string | undefined;
}) {
  useEffect(() => {
    if (highlight)
      document
        .getElementById(`analysis-${highlight}`)
        ?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [highlight]);
  const notCovered = !!highlight && !result.findings.some((f) => f.finding_id === highlight);

  return (
    <div className="space-y-4">
      <Panel>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <span className="flex items-center gap-2 text-muted-foreground">
            Overall risk <SeverityBadge severity={riskSeverity(result.overall_risk)} />
          </span>
          <Meta label="Model">
            {a.served_by_model ?? a.model}
            {a.fallback_used ? " (fallback)" : ""}
          </Meta>
          <Meta label="Findings analyzed">
            {a.findings_analyzed} of {a.findings_total}
          </Meta>
          <Meta label="Secrets redacted">{a.redactions}</Meta>
          {a.completed_at && <Meta label="Completed">{fmtDate(asUtc(a.completed_at))} UTC</Meta>}
        </div>
        {a.findings_analyzed < a.findings_total && (
          <p className="mt-3 text-xs text-muted-foreground">
            Only the {a.findings_analyzed} highest-severity findings were sent for analysis (data
            minimization).
          </p>
        )}
        {notCovered && (
          <p className="mt-3 text-xs text-sev-medium">
            The selected finding is not covered by this analysis.
          </p>
        )}
      </Panel>

      <Panel
        title="Executive summary"
        action={<ShieldCheck className="size-4 text-muted-foreground" />}
      >
        <Prose>{result.executive_summary}</Prose>
      </Panel>
      <Panel title="Technical assessment" action={<Bot className="size-4 text-muted-foreground" />}>
        <Prose>{result.technical_assessment}</Prose>
      </Panel>

      {result.remediation_plan.length > 0 && (
        <Panel
          title="Remediation plan"
          action={<ListChecks className="size-4 text-muted-foreground" />}
        >
          <ol className="space-y-3">
            {result.remediation_plan.map((step) => (
              <li key={step.rank} className="flex gap-3 text-sm">
                <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary/15 font-mono text-xs text-primary">
                  {step.rank}
                </span>
                <div>
                  <div className="font-medium text-foreground">
                    {step.title}{" "}
                    <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs capitalize text-muted-foreground">
                      {step.effort} effort
                    </span>
                  </div>
                  <p className="text-foreground/80">{step.rationale}</p>
                  {step.finding_ids.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-2 text-xs">
                      {step.finding_ids.map((id, i) => (
                        <a
                          key={id}
                          href={`#analysis-${id}`}
                          className="font-mono text-primary hover:underline"
                        >
                          {step.finding_refs[i] ?? id.slice(0, 8)}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </Panel>
      )}

      <Panel title={`Findings (${result.findings.length})`}>
        <div className="space-y-3">
          {result.findings.map((f) => (
            <article
              key={f.finding_id}
              id={`analysis-${f.finding_id}`}
              className={cn(
                "rounded-lg border p-4",
                f.finding_id === highlight ? "border-primary ring-1 ring-primary" : "border-border",
              )}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">{f.finding_ref}</span>
                <SeverityBadge severity={f.severity} />
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground">
                  {f.priority}
                </span>
                <span className="text-xs text-muted-foreground">
                  {VALIDITY[f.validity] ?? f.validity}
                </span>
              </div>
              <Link
                to="/vulnerabilities/$findingId"
                params={{ findingId: f.finding_id }}
                className="mt-2 block font-medium text-foreground hover:text-primary"
              >
                {f.title}
              </Link>
              {f.location && (
                <p className="font-mono text-xs text-muted-foreground">{f.location}</p>
              )}
              <div className="mt-3 space-y-2 text-sm text-foreground/90">
                <p>{f.explanation}</p>
                <Labeled label="Technical impact">{f.technical_impact}</Labeled>
                <Labeled label="Business impact">{f.business_impact}</Labeled>
                <Labeled label="Validity">
                  {f.validity_rationale}{" "}
                  <em className="text-muted-foreground">Limitations: {f.confidence_limitations}</em>
                </Labeled>
                <Steps label="Remediation" steps={f.remediation_steps} />
                <Steps label="Verification" steps={f.verification_steps} />
              </div>
            </article>
          ))}
        </div>
      </Panel>

      {(result.scan_limitations.length > 0 || (result.warnings?.length ?? 0) > 0) && (
        <Panel
          title="Limitations"
          action={<AlertTriangle className="size-4 text-muted-foreground" />}
        >
          <ul className="list-disc space-y-1 pl-5 text-sm text-foreground/80">
            {result.scan_limitations.map((l, i) => (
              <li key={`l${i}`}>{l}</li>
            ))}
            {result.warnings?.map((w, i) => (
              <li key={`w${i}`} className="text-muted-foreground">
                {w}
              </li>
            ))}
          </ul>
        </Panel>
      )}
      <p className="text-xs text-muted-foreground">
        AI analysis is advisory. Verify findings before acting on them.
      </p>
    </div>
  );
}

function Notice({ children, tone }: { children: ReactNode; tone?: "error" }) {
  return (
    <p className={cn("text-sm", tone === "error" ? "text-destructive" : "text-muted-foreground")}>
      {children}
    </p>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <span className="text-muted-foreground">
      {label}: <span className="text-foreground">{children}</span>
    </span>
  );
}

function Prose({ children }: { children: string }) {
  return (
    <p className="whitespace-pre-line text-sm leading-relaxed text-foreground/90">{children}</p>
  );
}

function Labeled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <p>
      <span className="font-medium text-foreground">{label}:</span> {children}
    </p>
  );
}

function Steps({ label, steps }: { label: string; steps: string[] }) {
  if (steps.length === 0) return null;
  return (
    <div>
      <div className="font-medium text-foreground">{label}</div>
      <ol className="mt-1 list-decimal space-y-0.5 pl-5">
        {steps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
    </div>
  );
}
