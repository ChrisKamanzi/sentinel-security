import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Globe, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Slider } from "@/components/ui/slider";
import { api, assessmentsQuery } from "@/lib/api/services";
import type { NewAssessmentInput } from "@/lib/api/types";
import { PageHeader, Panel } from "@/components/app/ui";
import { isDemoMode } from "@/lib/api/client";
import { profileScanners, validTargetUrl } from "@/lib/api/assessment-config";
import { Link } from "@tanstack/react-router";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/assessments/new")({
  head: () => ({
    meta: [
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { title: "New Assessment — AutoPentest AI" },
      { name: "description", content: "Configure and launch an authorized automated web application security assessment." },
      { property: "og:title", content: "New Assessment — AutoPentest AI" },
      { property: "og:description", content: "Launch an authorized AI-driven security assessment." },
    ],
  }),
  component: NewAssessment,
});

const profiles = [
  { key: "quick", label: "Quick", desc: "Nmap + Nuclei" },
  { key: "standard", label: "Standard", desc: "Nmap + FFUF + Nuclei" },
  { key: "deep", label: "Deep", desc: "Standard + ZAP passive baseline" },
] as const;



function NewAssessment() {
  const navigate = useNavigate();
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<NewAssessmentInput["profile"]>("standard");
  const queryClient = useQueryClient();
  const tools = useQuery({ queryKey: ["tools"], queryFn: api.listTools, enabled: !isDemoMode });
  const unavailable = !isDemoMode && tools.data ? profileScanners[profile].filter((name) => !tools.data.some((tool) => tool.name === name && tool.available && tool.implemented)) : [];
  const [maxRps, setMaxRps] = useState(10);
  const [authorized, setAuthorized] = useState(false);

  const validUrl = validTargetUrl(target);
  const mutation = useMutation({
    mutationFn: api.createAssessment,
    onSuccess: (a) => {
      toast.success("Assessment accepted", { description: a.target });
      void queryClient.invalidateQueries({ queryKey: assessmentsQuery.queryKey });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      navigate({ to: "/scans/$scanId", params: { scanId: a.id } });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validUrl || !authorized || isDemoMode || unavailable.length) return;
    mutation.mutate({ target: target.trim(), name: "", authorized, profile, modules: [], maxRps });
  };

  return (
    <form onSubmit={submit}>
      <PageHeader title="New assessment" description="Scans run on the AutoPentest backend. Only test systems you own or are authorized to test." />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Panel title="Target">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target">Application URL</Label>
                <div className="relative">
                  <Globe className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input id="target" placeholder="https://app.example.com" value={target} onChange={(e) => setTarget(e.target.value)} className="pl-9 font-mono" />
                </div>
                {target && !validUrl && <p className="text-xs text-destructive">Enter a valid http(s) URL.</p>}
              </div>
              <p className="text-xs text-muted-foreground">Use a registered, approved target URL. <Link to="/targets" className="text-primary hover:underline">Manage targets</Link></p>
            </div>
          </Panel>

          <Panel title="Scan profile">
            <div className="grid gap-3 sm:grid-cols-3">
              {profiles.map((p) => (
                <Button variant="outline" type="button" key={p.key} onClick={() => setProfile(p.key)}
                  className={cn("h-auto flex-col items-stretch whitespace-normal rounded-lg border p-4 text-left transition-colors", profile === p.key ? "border-primary bg-primary/10" : "border-border hover:border-muted-foreground/40")}>
                  <div className="flex items-center justify-between"><span className="font-medium text-foreground">{p.label}</span></div>
                  <p className="mt-1 text-xs text-muted-foreground">{p.desc}</p>
                </Button>
              ))}
            </div>
          </Panel>

          <Panel title="Scanner readiness">
            {isDemoMode ? <p className="text-sm text-muted-foreground">Demo data only. No scans can be launched without the FastAPI backend.</p> : tools.isError ? <p role="alert" className="text-sm text-destructive">{tools.error.message}</p> : tools.isPending ? <p className="text-sm text-muted-foreground">Checking installed scanners…</p> : <ul className="space-y-2 text-sm">{profileScanners[profile].map((name) => <li key={name} className="flex justify-between"><span className="uppercase">{name}</span><span className={unavailable.includes(name) ? "text-destructive" : "text-success"}>{unavailable.includes(name) ? "Not available" : "Ready"}</span></li>)}</ul>}
          </Panel>
          <Panel title="Request limits">
            <div className="space-y-5">
              <div>
                <div className="mb-3 flex justify-between"><Label>FFUF / Nuclei requests per second</Label><span className="font-mono text-sm text-foreground">{maxRps}</span></div>
                <Slider min={1} max={50} step={1} value={[maxRps]} onValueChange={(v) => setMaxRps(v[0] ?? 10)} />
              </div>
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Authorization" className="border-primary/30">
            <div className="flex gap-3 rounded-lg bg-primary/10 p-3 text-xs text-muted-foreground">
              <ShieldCheck className="size-5 shrink-0 text-primary" />
              Active testing sends attack payloads. Running it against systems without permission may be illegal.
            </div>
            <label className="mt-4 flex cursor-pointer gap-3 text-sm text-foreground">
              <Checkbox checked={authorized} onCheckedChange={(c) => setAuthorized(!!c)} className="mt-0.5" />
              I confirm I own this application or have written authorization to perform security testing against it.
            </label>
          </Panel>
          <Panel title="Summary">
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between"><dt className="text-muted-foreground">Profile</dt><dd className="capitalize text-foreground">{profile}</dd></div>
              <div className="flex justify-between"><dt className="text-muted-foreground">Scanners</dt><dd className="text-foreground">{profileScanners[profile].length}</dd></div>
              <div className="flex justify-between"><dt className="text-muted-foreground">Rate limit</dt><dd className="text-foreground">{maxRps} req/s</dd></div>
            </dl>
            <Button type="submit" className="mt-5 w-full" disabled={isDemoMode || !validUrl || !authorized || unavailable.length > 0 || tools.isPending || tools.isError || mutation.isPending}>
              {mutation.isPending && <Loader2 className="animate-spin" />} Launch assessment
            </Button>
          </Panel>
        </div>
      </div>
    </form>
  );
}
