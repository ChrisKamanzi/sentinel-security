import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowUp, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api/services";
import type { ChatMessage } from "@/lib/api/types";
import { PageHeader } from "@/components/app/ui";

export const Route = createFileRoute("/analyst")({
  validateSearch: (s: Record<string, unknown>): { finding?: string | undefined } => ({ finding: typeof s["finding"] === "string" ? s["finding"] : undefined }),
  head: () => ({
    meta: [
      { title: "AI Security Analyst — AutoPentest AI" },
      { name: "description", content: "Ask an AI security analyst to explain findings, prioritize fixes and suggest remediation." },
      { property: "og:title", content: "AI Security Analyst — AutoPentest AI" },
      { property: "og:description", content: "Conversational analysis of your security findings." },
    ],
  }),
  component: Analyst,
});

const suggestions = ["What should we fix first?", "Explain the SQL injection finding", "How do I fix the XSS issue?", "Summarize our risk for executives"];

// Minimal formatter for **bold**, `code` and line breaks.
function Rich({ text }: { text: string }) {
  return (
    <>
      {text.split("\n").map((line, i) => (
        <p key={i} className="min-h-[0.75em]">
          {line.split(/(\*\*[^*]+\*\*|`[^`]+`|_[^_]+_)/g).map((part, j): ReactNode => {
            if (part.startsWith("**")) return <strong key={j} className="font-semibold text-foreground">{part.slice(2, -2)}</strong>;
            if (part.startsWith("`")) return <code key={j} className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-primary">{part.slice(1, -1)}</code>;
            if (part.startsWith("_") && part.endsWith("_") && part.length > 2) return <em key={j} className="text-muted-foreground">{part.slice(1, -1)}</em>;
            return part;
          })}
        </p>
      ))}
    </>
  );
}

function Analyst() {
  const { finding } = Route.useSearch();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState(finding ? `Explain finding ${finding} and how to fix it` : "");
  const endRef = useRef<HTMLDivElement>(null);

  const ask = useMutation({
    mutationFn: (msgs: ChatMessage[]) => api.askAnalyst(msgs, finding),
    onSuccess: (reply) => setMessages((m) => [...m, reply]),
    onError: (e: Error) => setMessages((m) => [...m, { role: "assistant", content: `**Error:** ${e.message}` }]),
  });

  useEffect(() => endRef.current?.scrollIntoView({ behavior: "smooth" }), [messages, ask.isPending]);

  const send = (text: string) => {
    const t = text.trim();
    if (!t || ask.isPending) return;
    const next = [...messages, { role: "user" as const, content: t }];
    setMessages(next);
    setInput("");
    ask.mutate(next);
  };

  return (
    <div className="flex h-[calc(100vh-10rem)] flex-col lg:h-[calc(100vh-4rem)]">
      <PageHeader title="AI Security Analyst" description="Ask questions about your findings, risk and remediation." />
      <div className="panel flex min-h-0 flex-1 flex-col">
        <div className="flex-1 space-y-6 overflow-y-auto p-5">
          {messages.length === 0 && (
            <div className="flex h-full flex-col items-center justify-center text-center">
              <span className="bg-brand flex size-12 items-center justify-center rounded-xl text-primary-foreground"><ShieldCheck className="size-6" /></span>
              <h2 className="mt-4 text-lg font-semibold text-foreground">How can I help secure your apps?</h2>
              <p className="mt-1 max-w-md text-sm text-muted-foreground">I have context on every assessment and finding in your workspace.</p>
              <div className="mt-6 grid w-full max-w-lg gap-2 sm:grid-cols-2">
                {suggestions.map((s) => (
                  <button key={s} onClick={() => send(s)} className="rounded-lg border border-border p-3 text-left text-sm text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground">{s}</button>
                ))}
              </div>
            </div>
          )}
          {messages.map((m, i) =>
            m.role === "user" ? (
              <div key={i} className="flex justify-end"><div className="max-w-[80%] rounded-2xl rounded-br-sm bg-primary px-4 py-2.5 text-sm text-primary-foreground">{m.content}</div></div>
            ) : (
              <div key={i} className="flex gap-3">
                <span className="bg-brand flex size-7 shrink-0 items-center justify-center rounded-lg text-primary-foreground"><ShieldCheck className="size-4" /></span>
                <div className="max-w-[85%] space-y-1 text-sm leading-relaxed text-foreground/90"><Rich text={m.content} /></div>
              </div>
            ),
          )}
          {ask.isPending && <div className="flex items-center gap-2 pl-10 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> Analyzing findings…</div>}
          <div ref={endRef} />
        </div>
        <form onSubmit={(e) => { e.preventDefault(); send(input); }} className="border-t border-border p-3">
          <div className="flex items-end gap-2 rounded-xl border border-input bg-background p-2 focus-within:border-primary">
            <Textarea value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }}
              placeholder="Ask about a vulnerability, risk or fix…" rows={1} className="max-h-40 min-h-10 resize-none border-0 bg-transparent shadow-none focus-visible:ring-0" />
            <Button type="submit" size="icon" disabled={!input.trim() || ask.isPending} aria-label="Send"><ArrowUp /></Button>
          </div>
        </form>
      </div>
    </div>
  );
}
