import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Plus, ShieldCheck, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, projectsQuery } from "@/lib/api/services";
import { isDemoMode } from "@/lib/api/client";
import { validTargetUrl } from "@/lib/api/assessment-config";
import { PageHeader, Panel } from "@/components/app/ui";

export const Route = createFileRoute("/targets")({
  head: () => ({ meta: [
    { title: "Targets — AutoPentest AI" },
    { name: "description", content: "Register authorized assessment targets and manage project scope." },
    { property: "og:title", content: "Targets — AutoPentest AI" },
    { property: "og:description", content: "Manage registered security assessment targets." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: Targets,
});

function Targets() {
  const qc = useQueryClient();
  const projects = useQuery(projectsQuery);
  const [project, setProject] = useState("");
  const projectId = project || projects.data?.[0]?.id || "";
  const targets = useQuery({ queryKey: ["targets", projectId], queryFn: () => api.listTargets(projectId), enabled: !!projectId });
  const [projectName, setProjectName] = useState("");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const fail = (e: Error) => toast.error(e.message);
  const createProject = useMutation({ mutationFn: () => api.createProject(projectName.trim()), onError: fail, onSuccess: (p) => { setProject(p.id); setProjectName(""); void qc.invalidateQueries({ queryKey: ["projects"] }); toast.success("Project created"); } });
  const createTarget = useMutation({ mutationFn: () => api.createTarget(projectId, { name: name.trim() || new URL(url).hostname, host: new URL(url).hostname.replace(/^\[|\]$/g, ""), base_url: url.trim(), is_authorized: authorized }), onError: fail, onSuccess: () => { setUrl(""); setName(""); setAuthorized(false); void qc.invalidateQueries({ queryKey: ["targets"] }); toast.success("Target registered"); } });
  const revoke = useMutation({ mutationFn: (id: string) => api.updateTarget(id, false), onError: fail, onSuccess: () => { void qc.invalidateQueries({ queryKey: ["targets"] }); toast.success("Authorization revoked"); } });
  return <>
    <PageHeader title="Targets" description="Registered applications and authorized assessment scope." />
    {isDemoMode && <p role="status" className="mb-4 text-sm text-sev-medium">Demo mode — connect the FastAPI backend to register targets.</p>}
    {projects.isError && <p role="alert" className="mb-4 text-sm text-destructive">{projects.error.message}</p>}
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="space-y-5">
        <Panel title="Project">
          <Select value={projectId} onValueChange={setProject} disabled={isDemoMode || projects.isPending}><SelectTrigger aria-label="Project"><SelectValue placeholder="Choose a project" /></SelectTrigger><SelectContent>{projects.data?.map((p) => <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>)}</SelectContent></Select>
          <form className="mt-4 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (projectName.trim()) createProject.mutate(); }}><Input aria-label="New project name" placeholder="New project name" maxLength={120} value={projectName} onChange={(e) => setProjectName(e.target.value)} /><Button aria-label="Create project" size="icon" disabled={isDemoMode || !projectName.trim() || createProject.isPending}><Plus /></Button></form>
        </Panel>
        <Panel title="Register target">
          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (projectId && validTargetUrl(url) && authorized) createTarget.mutate(); }}>
            <div className="space-y-2"><Label htmlFor="target-name">Target name</Label><Input id="target-name" maxLength={120} value={name} onChange={(e) => setName(e.target.value)} placeholder="Customer portal" /></div>
            <div className="space-y-2"><Label htmlFor="target-url">Authorized base URL</Label><Input id="target-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://app.example.com" />{url && !validTargetUrl(url) && <p className="text-xs text-destructive">Enter an http(s) URL without embedded credentials.</p>}</div>
            <label className="flex items-start gap-3 text-sm"><Checkbox checked={authorized} onCheckedChange={(v) => setAuthorized(v === true)} />I own this target or have written authorization for security testing of this host and its services.</label>
            <Button disabled={isDemoMode || !projectId || !validTargetUrl(url) || !authorized || createTarget.isPending}>{createTarget.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />}Register authorized target</Button>
          </form>
        </Panel>
      </div>
      <Panel title="Registered targets">
        {targets.isError && <p role="alert" className="text-sm text-destructive">{targets.error.message}</p>}
        {targets.isFetching && <p className="text-sm text-muted-foreground">Loading targets…</p>}
        {!targets.isFetching && !targets.data?.length && <p className="text-sm text-muted-foreground">No registered targets in this project.</p>}
        <ul className="divide-y divide-border">{targets.data?.map((t) => <li key={t.id} className="space-y-2 py-4"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium">{t.name}</span><span className={t.is_authorized ? "text-xs text-success" : "text-xs text-muted-foreground"}>{t.is_authorized ? "Authorized" : "Not authorized"}</span></div><p className="break-all font-mono text-xs text-muted-foreground">{t.base_url || t.host}</p>{t.is_authorized && <div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" asChild><Link to="/assessments/new">New assessment</Link></Button><Button variant="ghost" size="sm" disabled={revoke.isPending} onClick={() => { if (window.confirm(`Revoke scanning authorization for ${t.name}?`)) revoke.mutate(t.id); }}>Revoke authorization</Button></div>}</li>)}</ul>
      </Panel>
    </div>
  </>;
}