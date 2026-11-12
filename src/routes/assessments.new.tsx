import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Globe, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { api } from "@/lib/api/services";
import type { NewAssessmentInput } from "@/lib/api/types";
import { PageHeader, Panel } from "@/components/app/ui";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/assessments/new")({
  head: () => ({
    meta: [
      { title: "New Assessment — AutoPentest AI" },
      { name: "description", content: "Configure and launch an authorized automated web application security assessment." },
      { property: "og:title", content: "New Assessment — AutoPentest AI" },
      { property: "og:description", content: "Launch an authorized AI-driven security assessment." },
    ],
  }),
  component: NewAssessment,
});

const profiles = [
  { key: "quick", label: "Quick", time: "~15 min", desc: "Passive checks and top OWASP risks" },
  { key: "standard", label: "Standard", time: "~1 hour", desc: "Full crawl with active injection testing" },
  { key: "deep", label: "Deep", time: "~3 hours", desc: "Authenticated, exhaustive, AI-validated" },
] as const;

const modules = ["Injection (SQLi, SSTI, CMDi)", "Cross-site scripting", "Access control / IDOR", "Authentication & sessions", "Security misconfiguration", "Sensitive data exposure"];

function NewAssessment() {
  const navigate = useNavigate();
  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const [profile, setProfile] = useState<NewAssessmentInput["profile"]>("standard");
  const [selected, setSelected] = useState<string[]>(modules);
  const [useAuth, setUseAuth] = useState(false);
  const [authHeader, setAuthHeader] = useState("");
  const [maxRps, setMaxRps] = useState(10);
  const [authorized, setAuthorized] = useState(false);

  const validUrl = /^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(target);
  const mutation = useMutation({
    mutationFn: api.createAssessment,
    onSuccess: (a) => {
      toast.success("Assessment queued", { description: a.target });
      navigate({ to: "/scans/$scanId", params: { scanId: a.id } });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate({ target, name: name || new URL(target).host, authorized, profile, modules: selected, authHeader: useAuth ? authHeader : undefined, maxRps });
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
              <div className="space-y-2">
                <Label htmlFor="name">Assessment name <span className="text-muted-foreground">(optional)</span></Label>
                <Input id="name" placeholder="Customer portal — Q4" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
            </div>
          </Panel>

          <Panel title="Scan profile">
            <div className="grid gap-3 sm:grid-cols-3">
              {profiles.map((p) => (
                <button type="button" key={p.key} onClick={() => setProfile(p.key)}
                  className={cn("rounded-lg border p-4 text-left transition-colors", profile === p.key ? "border-primary bg-primary/10" : "border-border hover:border-muted-foreground/40")}>
                  <div className="flex items-center justify-between"><span className="font-medium text-foreground">{p.label}</span><span className="text-xs text-muted-foreground">{p.time}</span></div>
                  <p className="mt-1 text-xs text-muted-foreground">{p.desc}</p>
                </button>
              ))}
            </div>
          </Panel>

          <Panel title="Test modules">
            <div className="grid gap-3 sm:grid-cols-2">
              {modules.map((m) => (
                <label key={m} className="flex cursor-pointer items-center gap-3 rounded-lg border border-border p-3 text-sm hover:bg-muted/40">
                  <Checkbox checked={selected.includes(m)} onCheckedChange={(c) => setSelected((s) => (c ? [...s, m] : s.filter((x) => x !== m)))} />
                  {m}
                </label>
              ))}
            </div>
          </Panel>

          <Panel title="Advanced">
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <div><Label>Authenticated scan</Label><p className="text-xs text-muted-foreground">Send a session header with every request</p></div>
                <Switch checked={useAuth} onCheckedChange={setUseAuth} />
              </div>
              {useAuth && <Input placeholder="Authorization: Bearer eyJ..." value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} className="font-mono" />}
              <div>
                <div className="mb-3 flex justify-between"><Label>Max requests per second</Label><span className="font-mono text-sm text-foreground">{maxRps}</span></div>
                <Slider min={1} max={50} step={1} value={[maxRps]} onValueChange={(v) => setMaxRps(v[0])} />
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
              <div className="flex justify-between"><dt className="text-muted-foreground">Modules</dt><dd className="text-foreground">{selected.length} / {modules.length}</dd></div>
              <div className="flex justify-between"><dt className="text-muted-foreground">Authenticated</dt><dd className="text-foreground">{useAuth ? "Yes" : "No"}</dd></div>
              <div className="flex justify-between"><dt className="text-muted-foreground">Rate limit</dt><dd className="text-foreground">{maxRps} req/s</dd></div>
            </dl>
            <Button type="submit" className="mt-5 w-full" disabled={!validUrl || !authorized || selected.length === 0 || mutation.isPending}>
              {mutation.isPending && <Loader2 className="animate-spin" />} Launch assessment
            </Button>
          </Panel>
        </div>
      </div>
    </form>
  );
}
