import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { ArrowLeft, Bot, Briefcase, CheckCircle2, Code2, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { findingQuery } from "@/lib/api/services";
import { Panel, SeverityBadge, fmtDate } from "@/components/app/ui";

export const Route = createFileRoute("/vulnerabilities/$findingId")({
  loader: async ({ context, params }) => {
    const f = await context.queryClient.ensureQueryData(findingQuery(params.findingId));
    if (!f) throw notFound();
    return { title: f.title };
  },
  head: ({ loaderData, params }) => ({
    meta: [
      { title: `${loaderData?.title ?? params.findingId} — AutoPentest AI` },
      { name: "description", content: "Technical evidence, business impact and remediation guidance for a security finding." },
      { property: "og:title", content: `${loaderData?.title ?? "Finding"} — AutoPentest AI` },
      { property: "og:description", content: "Security finding details and remediation." },
    ],
  }),
  notFoundComponent: () => <div className="py-20 text-center text-muted-foreground">Finding not found. <Link to="/vulnerabilities" className="text-primary">Back to vulnerabilities</Link></div>,
  component: FindingDetails,
});

function FindingDetails() {
  const { findingId } = Route.useParams();
  const { data: f } = useSuspenseQuery(findingQuery(findingId));
  if (!f) return null;

  return (
    <>
      <Link to="/vulnerabilities" className="mb-4 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3" /> Vulnerabilities</Link>
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><span className="font-mono text-xs text-muted-foreground">{f.id}</span></div>
          <h1 className="mt-2 text-2xl font-semibold text-foreground sm:text-3xl">{f.title}</h1>
          <p className="mt-1 font-mono text-sm text-muted-foreground">{f.target} · {f.endpoint}</p>
        </div>
        <Button variant="outline" asChild><Link to="/analyst" search={{ finding: f.id }}><Bot /> Ask AI analyst</Link></Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Panel title="Description"><p className="text-sm leading-relaxed text-foreground/90">{f.description}</p></Panel>
          <Panel title="Technical evidence" action={<Code2 className="size-4 text-muted-foreground" />}>
            <Tabs defaultValue="request">
              <TabsList><TabsTrigger value="request">Request</TabsTrigger><TabsTrigger value="response">Response</TabsTrigger></TabsList>
              <TabsContent value="request"><pre className="overflow-x-auto rounded-lg bg-background p-4 font-mono text-xs leading-relaxed text-foreground">{f.evidence.request}</pre></TabsContent>
              <TabsContent value="response"><pre className="overflow-x-auto rounded-lg bg-background p-4 font-mono text-xs leading-relaxed text-foreground">{f.evidence.response}</pre></TabsContent>
            </Tabs>
          </Panel>
          <Panel title="Business impact" action={<Briefcase className="size-4 text-muted-foreground" />}><p className="text-sm leading-relaxed text-foreground/90">{f.businessImpact}</p></Panel>
          <Panel title="Remediation" action={<Wrench className="size-4 text-muted-foreground" />}>
            <ol className="space-y-3">
              {f.remediation.map((r, i) => (
                <li key={i} className="flex gap-3 text-sm text-foreground/90"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" />{r}</li>
              ))}
            </ol>
          </Panel>
        </div>
        <Panel title="Details" className="h-fit">
          <dl className="space-y-3 text-sm">
            {[
              ["CVSS score", <span className="font-mono">{f.cvss.toFixed(1)}</span>],
              ["CWE", <span className="font-mono">{f.cwe}</span>],
              ["Category", f.category],
              ["Scanner", f.scanner],
              ["Status", <span className="capitalize">{f.status}</span>],
              ["Discovered", `${fmtDate(f.discoveredAt)} UTC`],
              ["Assessment", <Link to="/scans/$scanId" params={{ scanId: f.assessmentId }} className="font-mono text-primary hover:underline">{f.assessmentId}</Link>],
            ].map(([k, v], i) => (
              <div key={i} className="flex justify-between gap-4 border-b border-border/60 pb-3 last:border-0 last:pb-0"><dt className="text-muted-foreground">{k}</dt><dd className="text-right text-foreground">{v}</dd></div>
            ))}
          </dl>
        </Panel>
      </div>
    </>
  );
}
