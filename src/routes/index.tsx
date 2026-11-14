import { createFileRoute, Link } from "@tanstack/react-router";
import { useSuspenseQuery } from "@tanstack/react-query";
import { Activity, AlertOctagon, Bug, FileText, Plus, Radar, ShieldAlert } from "lucide-react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Button } from "@/components/ui/button";
import { assessmentsQuery, dashboardQuery } from "@/lib/api/services";
import { isDemoMode } from "@/lib/api/client";
import { PageHeader, Panel, RiskGauge, SEVERITIES, StatCard, StatusBadge, fmtDate, sevDot } from "@/components/app/ui";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { title: "Dashboard — AutoPentest AI" },
      { name: "description", content: "Security posture overview: risk score, vulnerabilities, critical findings and scan activity." },
      { property: "og:title", content: "Dashboard — AutoPentest AI" },
      { property: "og:description", content: "Security posture overview across your web application assessments." },
    ],
  }),
  loader: ({ context }) => Promise.all([context.queryClient.ensureQueryData(dashboardQuery), context.queryClient.ensureQueryData(assessmentsQuery)]),
  component: Dashboard,
});

const tooltipStyle = { background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--foreground)", fontSize: 12 };

function Dashboard() {
  const { data: s } = useSuspenseQuery(dashboardQuery);
  const { data: assessments } = useSuspenseQuery(assessmentsQuery);
  const total = SEVERITIES.reduce((n, k) => n + s.breakdown[k], 0);

  return (
    <>
      <PageHeader
        title="Security overview"
        description={isDemoMode ? "Northwind Bank · sample workspace" : "All registered applications"}
        actions={<Button asChild><Link to="/assessments/new"><Plus /> New assessment</Link></Button>}
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total scans" value={s.totalScans} hint={`${s.activeScans} running now`} icon={<Radar className="size-4" />} />
        <StatCard label="Vulnerabilities" value={s.totalVulnerabilities} hint="Open across all targets" icon={<Bug className="size-4" />} />
        <StatCard label="Critical findings" value={s.criticalFindings} hint="Require immediate action" icon={<AlertOctagon className="size-4" />} tone="critical" />
        <StatCard label="Risk trend" value={`${s.riskTrend > 0 ? "+" : ""}${s.riskTrend}%`} hint="vs. previous 30 days" icon={<Activity className="size-4" />} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="Risk score">
          <RiskGauge score={s.riskScore} />
          <div className="mt-4 space-y-2.5">
            {SEVERITIES.map((k) => (
              <div key={k}>
                <div className="mb-1 flex justify-between text-xs">
                  <span className="flex items-center gap-2 capitalize text-muted-foreground"><span className={`size-2 rounded-full ${sevDot[k]}`} />{k}</span>
                  <span className="font-mono text-foreground">{s.breakdown[k]}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <div className={`h-full rounded-full ${sevDot[k]}`} style={{ width: `${total ? (s.breakdown[k] / total) * 100 : 0}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Security findings · last 6 months" className="lg:col-span-2">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={s.findingsOverTime} margin={{ left: -20, right: 8 }}>
                <defs>
                  {SEVERITIES.map((k) => (
                    <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={`var(--sev-${k})`} stopOpacity={0.35} />
                      <stop offset="100%" stopColor={`var(--sev-${k})`} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis dataKey="date" stroke="var(--muted-foreground)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--muted-foreground)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                {[...SEVERITIES].reverse().map((k) => (
                  <Area key={k} type="monotone" dataKey={k} stackId="1" stroke={`var(--sev-${k})`} fill={`url(#g-${k})`} strokeWidth={2} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="Recent assessments" className="lg:col-span-2" action={<Link to="/scans" className="text-xs text-primary hover:underline">View all</Link>}>
          <div className="-mx-5 overflow-x-auto">
            <table className="w-full min-w-[560px] text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-5 pb-2 font-medium">Target</th><th className="pb-2 font-medium">Status</th><th className="pb-2 font-medium">Findings</th><th className="pb-2 font-medium">Risk</th><th className="px-5 pb-2 text-right font-medium">Started</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((a) => (
                  <tr key={a.id} className="border-b border-border/60 last:border-0 hover:bg-muted/40">
                    <td className="px-5 py-3">
                      <Link to="/scans/$scanId" params={{ scanId: a.id }} className="font-medium text-foreground hover:text-primary">{a.name}</Link>
                      <div className="font-mono text-xs text-muted-foreground">{new URL(a.target).host}</div>
                    </td>
                    <td><StatusBadge status={a.status} /></td>
                    <td>
                      <div className="flex gap-1">
                        {SEVERITIES.map((k) => (
                          <span key={k} className={`min-w-6 rounded px-1.5 py-0.5 text-center font-mono text-xs ${a.findings[k] ? `${sevDot[k]} text-primary-foreground` : "bg-muted text-muted-foreground"}`}>{a.findings[k]}</span>
                        ))}
                      </div>
                    </td>
                    <td className="font-mono">{a.riskScore || "—"}</td>
                    <td className="px-5 text-right text-xs text-muted-foreground">{fmtDate(a.startedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="flex flex-col gap-4">
          <Panel title="Scan activity · this week">
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={s.scanActivity} margin={{ left: -28, right: 0 }}>
                  <XAxis dataKey="day" stroke="var(--muted-foreground)" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis stroke="var(--muted-foreground)" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--muted)" }} />
                  <Bar dataKey="scans" fill="var(--primary)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Panel>
          <Panel title="Recent activity">
            <ul className="space-y-3">
              {s.recentActivity.map((e) => {
                const Icon = e.type === "scan" ? Radar : e.type === "finding" ? ShieldAlert : FileText;
                return (
                  <li key={e.id} className="flex gap-3 text-sm">
                    <span className="mt-0.5 rounded-md bg-accent p-1.5 text-primary"><Icon className="size-3.5" /></span>
                    <div><p className="text-foreground">{e.message}</p><p className="text-xs text-muted-foreground">{e.time}</p></div>
                  </li>
                );
              })}
            </ul>
          </Panel>
        </div>
      </div>
    </>
  );
}
