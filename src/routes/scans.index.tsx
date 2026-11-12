import { createFileRoute, Link } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { assessmentsQuery } from "@/lib/api/services";
import { PageHeader, StatusBadge, fmtDate } from "@/components/app/ui";

export const Route = createFileRoute("/scans/")({
  head: () => ({
    meta: [
      { title: "Scans — AutoPentest AI" },
      { name: "description", content: "All security assessments and their progress." },
      { property: "og:title", content: "Scans — AutoPentest AI" },
      { property: "og:description", content: "All security assessments and their progress." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(assessmentsQuery),
  component: Scans,
});

function Scans() {
  const { data } = useSuspenseQuery(assessmentsQuery);
  return (
    <>
      <PageHeader title="Scans" description="Every assessment run against your applications." actions={<Button asChild><Link to="/assessments/new"><Plus /> New assessment</Link></Button>} />
      <div className="grid gap-3">
        {data.map((a) => (
          <Link key={a.id} to="/scans/$scanId" params={{ scanId: a.id }} className="panel flex flex-col gap-3 p-4 transition-colors hover:border-primary/50 sm:flex-row sm:items-center">
            <div className="flex-1">
              <div className="flex items-center gap-2"><span className="font-medium text-foreground">{a.name}</span><StatusBadge status={a.status} /></div>
              <div className="font-mono text-xs text-muted-foreground">{a.target}</div>
            </div>
            <div className="w-full sm:w-48"><Progress value={a.progress} className="h-1.5" /><div className="mt-1 text-xs text-muted-foreground">{a.progress}% · {a.profile}</div></div>
            <div className="text-xs text-muted-foreground sm:w-32 sm:text-right">{fmtDate(a.startedAt)}</div>
          </Link>
        ))}
      </div>
    </>
  );
}
