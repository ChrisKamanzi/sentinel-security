import { createFileRoute, Link } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { findingsQuery } from "@/lib/api/services";
import type { Severity } from "@/lib/api/types";
import { PageHeader, SEVERITIES, SeverityBadge, fmtDate } from "@/components/app/ui";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/vulnerabilities/")({
  head: () => ({
    meta: [
      { title: "Vulnerabilities — AutoPentest AI" },
      { name: "description", content: "Filter security findings by severity, category and scanner." },
      { property: "og:title", content: "Vulnerabilities — AutoPentest AI" },
      { property: "og:description", content: "All security findings across assessments." },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(findingsQuery),
  component: Vulnerabilities,
});

const sevRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function Vulnerabilities() {
  const { data } = useSuspenseQuery(findingsQuery);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<Severity | "all">("all");
  const [cat, setCat] = useState("all");
  const [scanner, setScanner] = useState("all");

  const categories = [...new Set(data.map((f) => f.category))].sort();
  const scanners = [...new Set(data.map((f) => f.scanner))].sort();
  const rows = useMemo(
    () => data
      .filter((f) => (sev === "all" || f.severity === sev) && (cat === "all" || f.category === cat) && (scanner === "all" || f.scanner === scanner) && (`${f.title} ${f.id} ${f.endpoint}`.toLowerCase().includes(q.toLowerCase())))
      .sort((a, b) => sevRank[a.severity] - sevRank[b.severity] || b.cvss - a.cvss),
    [data, q, sev, cat, scanner],
  );

  return (
    <>
      <PageHeader title="Vulnerabilities" description={`${rows.length} of ${data.length} findings`} />
      <div className="mb-4 flex flex-wrap gap-2">
        <button onClick={() => setSev("all")} className={cn("rounded-md border px-3 py-1.5 text-xs", sev === "all" ? "border-primary bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:text-foreground")}>All</button>
        {SEVERITIES.map((s) => (
          <button key={s} onClick={() => setSev(s)} className={cn("rounded-md border px-1 py-1", sev === s ? "border-primary bg-primary/10" : "border-transparent")}>
            <SeverityBadge severity={s} />
            <span className="ml-1.5 mr-1 font-mono text-xs text-muted-foreground">{data.filter((f) => f.severity === s).length}</span>
          </button>
        ))}
      </div>
      <div className="mb-4 grid gap-2 sm:grid-cols-[1fr_200px_200px]">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search title, ID or endpoint" value={q} onChange={(e) => setQ(e.target.value)} className="pl-9" />
        </div>
        <Select value={cat} onValueChange={setCat}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="all">All categories</SelectItem>{categories.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={scanner} onValueChange={setScanner}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent><SelectItem value="all">All scanners</SelectItem>{scanners.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
        </Select>
      </div>

      <div className="panel overflow-x-auto">
        <table className="w-full min-w-[760px] text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="px-4 py-3 font-medium">Severity</th><th className="py-3 font-medium">Finding</th><th className="py-3 font-medium">Category</th><th className="py-3 font-medium">Scanner</th><th className="py-3 font-medium">CVSS</th><th className="py-3 font-medium">Status</th><th className="px-4 py-3 text-right font-medium">Found</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id} className="border-b border-border/60 last:border-0 hover:bg-muted/40">
                <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                <td className="py-3 pr-4">
                  <Link to="/vulnerabilities/$findingId" params={{ findingId: f.id }} className="font-medium text-foreground hover:text-primary">{f.title}</Link>
                  <div className="font-mono text-xs text-muted-foreground">{f.id} · {f.endpoint}</div>
                </td>
                <td className="text-muted-foreground">{f.category}</td>
                <td className="text-muted-foreground">{f.scanner}</td>
                <td className="font-mono text-foreground">{f.cvss.toFixed(1)}</td>
                <td><span className="rounded bg-muted px-2 py-0.5 text-xs capitalize text-muted-foreground">{f.status}</span></td>
                <td className="px-4 text-right text-xs text-muted-foreground">{fmtDate(f.discoveredAt)}</td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={7} className="py-12 text-center text-muted-foreground">No findings match these filters.</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}
