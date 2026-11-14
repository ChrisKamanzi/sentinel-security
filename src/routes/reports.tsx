import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useSuspenseQuery } from "@tanstack/react-query";
import { Download, FileCode, FileJson, FileText, Globe, type LucideIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api, reportsQuery } from "@/lib/api/services";
import type { Report } from "@/lib/api/types";
import { PageHeader, fmtDate } from "@/components/app/ui";
import { fmtSize } from "@/lib/format";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { title: "Reports — AutoPentest AI" },
      { name: "description", content: "Download executive and technical security assessment reports." },
      { property: "og:title", content: "Reports — AutoPentest AI" },
      { property: "og:description", content: "Downloadable security assessment reports." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(reportsQuery),
  component: Reports,
});

const icons: Record<Report["format"], LucideIcon> = { pdf: FileText, html: Globe, json: FileJson, md: FileCode };

function Reports() {
  const { data } = useSuspenseQuery(reportsQuery);
  const download = useMutation({ mutationFn: api.downloadReport, onError: (e: Error) => toast.error(e.message), onSuccess: (blob, id) => {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url; link.download = `assessment-${id}.md`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } });
  return (
    <>
      <PageHeader title="Reports" description="Generated after each completed assessment." />
      {data.length === 0 && <p className="text-sm text-muted-foreground">No reports yet. Complete an assessment first.</p>}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {data.map((r) => {
          const Icon = icons[r.format] ?? FileText;
          return (
            <div key={r.id} className="panel flex flex-col p-5">
              <div className="flex items-start justify-between">
                <span className="rounded-lg bg-accent p-2.5 text-primary"><Icon className="size-5" /></span>
                <span className="rounded bg-muted px-2 py-0.5 font-mono text-xs uppercase text-muted-foreground">{r.format}</span>
              </div>
              <h3 className="mt-4 font-medium text-foreground">{r.title}</h3>
              <p className="font-mono text-xs text-muted-foreground">{r.target}</p>
              <div className="mt-4 flex gap-4 text-xs text-muted-foreground">
                <span>{r.findings} findings</span><span>{fmtSize(r.sizeKb)}</span><span>{fmtDate(r.generatedAt)}</span>
              </div>
              <Button variant="outline" className="mt-5" disabled={download.isPending} onClick={() => download.mutate(r.id)}><Download /> Download</Button>
            </div>
          );
        })}
      </div>
    </>
  );
}
