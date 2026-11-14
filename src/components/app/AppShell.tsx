import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { Bot, FileText, LayoutDashboard, Radar, ShieldAlert, ShieldCheck, Plus, Globe } from "lucide-react";
import { isDemoMode } from "@/lib/api/client";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/assessments/new", label: "New Assessment", icon: Plus },
  { to: "/scans", label: "Scans", icon: Radar },
  { to: "/targets", label: "Targets", icon: Globe },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { to: "/analyst", label: "AI Analyst", icon: Bot },
  { to: "/reports", label: "Reports", icon: FileText },
] as const;

function Logo() {
  return (
    <Link to="/" className="flex items-center gap-2.5">
      <span className="bg-brand flex size-8 items-center justify-center rounded-lg text-primary-foreground"><ShieldCheck className="size-4.5" /></span>
      <span className="font-display text-base font-semibold text-foreground">AutoPentest <span className="text-brand">AI</span></span>
    </Link>
  );
}

const linkCls = "flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground";
const activeCls = "bg-sidebar-accent text-sidebar-accent-foreground font-medium";

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <aside className="fixed inset-y-0 left-0 hidden w-60 flex-col border-r border-sidebar-border bg-sidebar p-4 lg:flex">
        <div className="px-2 py-2"><Logo /></div>
        <nav className="mt-8 flex flex-1 flex-col gap-1">
          {nav.map(({ to, label, icon: Icon }) => (
            <Link key={to} to={to} className={linkCls} activeProps={{ className: activeCls }} activeOptions={{ exact: to === "/" }}>
              <Icon className="size-4" /> {label}
            </Link>
          ))}
        </nav>
        <div className="rounded-lg border border-sidebar-border p-3 text-xs text-muted-foreground">
          <div className="flex items-center gap-2 font-medium text-foreground">
            <span className={isDemoMode ? "size-2 rounded-full bg-sev-medium" : "size-2 rounded-full bg-success"} />
            {isDemoMode ? "Demo data" : "Live API mode"}
          </div>
          <p className="mt-1">{isDemoMode ? "Sample workspace · no live scans" : "Results from configured FastAPI"}</p>
        </div>
      </aside>

      <header className="sticky top-0 z-20 border-b border-border bg-sidebar/95 backdrop-blur lg:hidden">
        <div className="flex h-14 items-center px-4"><Logo /></div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-2">
          {nav.map(({ to, label, icon: Icon }) => (
            <Link key={to} to={to} className={linkCls + " shrink-0"} activeProps={{ className: activeCls }} activeOptions={{ exact: to === "/" }}>
              <Icon className="size-4" /> {label}
            </Link>
          ))}
        </nav>
      </header>

      <main className="lg:pl-60">
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">{children}</div>
      </main>
    </div>
  );
}
