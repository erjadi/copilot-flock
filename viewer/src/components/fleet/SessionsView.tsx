import { useEffect, useRef, useState } from "react";
import { ArrowLeft, Eye, GitBranch, Search, Send, Wrench } from "lucide-react";
import type { Ctx } from "./Console";
import type { Session, Transcript } from "@/lib/fleet/types";
import { envelope, fetchTranscript, messageAdmissionConfirmed, post } from "@/lib/fleet/api";
import { Btn, Dot, Input, Md, PageHeading, Panel, Select, SmartMessage, Toggle, rel } from "./ui";

export function SessionsView({ ctx, selected, setSelected }: { ctx: Ctx; selected: Session | null; setSelected: (s: Session | null) => void }) {
  const [q, setQ] = useState("");
  const [machine, setMachine] = useState("*");
  const [runningOnly, setRunningOnly] = useState(false);
  const ql = q.toLowerCase();
  const list = ctx.data.sessions.filter((s) => (machine === "*" || s.machineId === machine) && (!runningOnly || s.is_running) &&
    (!ql || [s.title, s.repo, s.branch, s.machineId].join(" ").toLowerCase().includes(ql))).sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  const sel = selected ?? list[0] ?? null;
  return <div>
    <div className={selected ? "hidden lg:block" : ""}><PageHeading title="Sessions" description="Read a thread or steer it without leaving the fleet." /></div>
    <div className="grid gap-5 lg:grid-cols-[340px_minmax(0,1fr)]">
      <Panel className={`${selected ? "hidden lg:flex" : "flex"} h-[calc(100dvh-236px-env(safe-area-inset-bottom))] min-h-[320px] flex-col overflow-hidden lg:h-[calc(100dvh-205px)] lg:min-h-[500px]`}>
        <div className="space-y-3 p-3"><div className="relative"><Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" /><Input className="pl-9" placeholder="Search sessions" value={q} onChange={(e) => setQ(e.target.value)} /></div><div className="flex items-center gap-2"><Select value={machine} onChange={(e) => setMachine(e.target.value)} className="min-w-0 flex-1" aria-label="Filter by machine"><option value="*">All machines</option>{ctx.data.members.map((m) => <option key={m.machineId}>{m.machineId}</option>)}</Select><Toggle on={runningOnly} onChange={setRunningOnly} label="Running" /></div></div>
        <div className="mx-4 h-px bg-border/60" />
        <div className="flex-1 overflow-y-auto p-2">{list.map((s) => <Btn key={s.session_id} onClick={() => setSelected(s)} className={`mb-1 block h-auto md:h-auto min-h-16 w-full rounded-lg px-3 py-3 text-left transition ${sel?.session_id === s.session_id ? "bg-accent/70" : "hover:bg-accent/35"}`}><div className="flex items-center gap-2.5"><Dot tone={s.is_running ? "busy" : "muted"} /><span className="truncate text-xs font-medium">{s.title}</span></div><div className="mt-2 flex items-center justify-between gap-2 pl-4 font-mono text-[9px] text-muted-foreground"><span className="truncate">{s.machineId}</span><span className="shrink-0">{rel(s.updated_at)}</span></div></Btn>)}</div>
      </Panel>
      {sel ? <div className={`min-w-0 ${selected ? "block" : "hidden lg:block"}`}><TranscriptPane key={sel.session_id} ctx={ctx} s={sel} onBack={() => setSelected(null)} /></div> : <Panel className="grid min-h-[600px] place-items-center text-sm text-muted-foreground">Select a session to begin.</Panel>}
    </div>
  </div>;
}

function TranscriptPane({ ctx, s, onBack }: { ctx: Ctx; s: Session; onBack: () => void }) {
  const [t, setT] = useState<Transcript | null>(null);
  const [transcriptError, setTranscriptError] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const [mode, setMode] = useState<"immediate" | "enqueue">("immediate");
  const [wait, setWait] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ kind: "preview" | "sent" | "unknown" | "error"; text: string } | null>(null);
  const pendingTranscript = useRef<{ key: string; promise: Promise<Transcript> } | null>(null);
  useEffect(() => {
    let active = true;
    const key = JSON.stringify([ctx.base, ctx.mode, s.machineId, s.session_id]);
    let read = pendingTranscript.current;
    if (!read || read.key !== key) {
      setT(null); setTranscriptError(null);
      read = { key, promise: fetchTranscript(ctx.base, ctx.mode, s) };
      pendingTranscript.current = read;
    }
    const currentRead = read;
    currentRead.promise
      .then((transcript) => { if (active) setT(transcript); })
      .catch((error) => { if (active) setTranscriptError(error instanceof Error ? error.message : String(error)); })
      .finally(() => { if (pendingTranscript.current === currentRead) pendingTranscript.current = null; });
    return () => { active = false; };
  }, [s, ctx.base, ctx.mode]);

  const send = async (dryRun: boolean) => {
    setBusy(true); setResult(null);
    try {
      const body = { toMachine: s.machineId, toSession: s.session_id, message: msg, mode, waitForReply: wait, dryRun };
      const r = await post<Record<string, unknown>>(ctx.base, ctx.mode, "/api/send", body, () => dryRun
        ? { envelopePreview: envelope("fleet-console", s.machineId, s.session_id, msg, mode) }
        : { ok: true, status: "delivered", dispatchedToRuntime: true, requestId: `req-${Date.now().toString(16)}`, ...(wait ? { reply: "Acknowledged — I'll incorporate that steer on the next turn." } : {}) });
      if (dryRun) setResult({ kind: "preview", text: String(r.envelopePreview ?? JSON.stringify(r, null, 2)) });
      else if (!messageAdmissionConfirmed(r)) {
        setResult({ kind: "unknown", text: `Admission UNKNOWN; do not blindly resend. No transcript update or task execution is confirmed.\n${JSON.stringify(r, null, 2)}` });
      }
      else {
        setResult({ kind: "sent", text: JSON.stringify(r, null, 2) });
        ctx.pushEvents([{ id: `evt-${Date.now()}`, timestamp: new Date().toISOString(), type: "outbox", target: s.machineId, fromMachine: ctx.data.hub.machineId, toMachine: s.machineId, action: "send_message", requestId: String(r.requestId ?? ""), summary: `send_message → ${s.machineId} · ${s.title}`, payload: body }]);
        if (t) setT({ ...t, messages: [...t.messages, { role: "user", messageId: `m${Date.now()}`, turnId: "steer", timestamp: new Date().toISOString(), content: msg }, ...(r.reply ? [{ role: "assistant" as const, messageId: `r${Date.now()}`, turnId: "steer", timestamp: new Date().toISOString(), content: String(r.reply) }] : [])] });
        setMsg("");
      }
    } catch (e) { setResult({ kind: "error", text: String(e) }); }
    setBusy(false);
  };

  return <Panel className="flex h-[calc(100dvh-170px-env(safe-area-inset-bottom))] min-h-[360px] flex-col overflow-hidden lg:h-[calc(100dvh-205px)] lg:min-h-[500px]">
    <div className="border-b border-border/60 px-4 py-3 lg:px-6 lg:py-5"><Btn onClick={onBack} className="mb-2 -ml-2 lg:hidden"><ArrowLeft className="h-4 w-4" />Sessions</Btn><div className="flex min-w-0 items-center gap-2.5"><Dot tone={s.is_running ? "busy" : "muted"} pulse={s.is_running} /><h3 className="truncate text-sm font-medium">{s.title}</h3></div><div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 pl-4 font-mono text-[9px] text-muted-foreground"><span>{s.machineId}</span><span className="flex items-center gap-1"><GitBranch className="h-3 w-3" />{s.repo ? s.repo.split("/").pop() : "No repository"}{s.branch ? `:${s.branch}` : ""}</span><span>{s.mode} · {s.model}</span></div></div>
    <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-5 lg:px-8"><div className="mx-auto max-w-3xl space-y-8">{transcriptError ? <div role="alert" className="text-sm text-destructive">Unable to load transcript: {transcriptError}</div> : !t && <div className="text-sm text-muted-foreground">Loading transcript…</div>}{t?.messages.map((m) => <article key={m.messageId} className="relative border-l border-border/70 pl-5"><span className={`absolute -left-[3px] top-1.5 h-[5px] w-[5px] rounded-full ${m.role === "user" ? "bg-info" : "bg-online"}`} /><div className="mb-2 flex items-center gap-3 font-mono text-[9px] uppercase tracking-widest text-muted-foreground"><span className={m.role === "user" ? "text-info" : "text-online"}>{m.role}</span><span>{m.turnId}</span><span className="ml-auto normal-case tracking-normal">{rel(m.timestamp)}</span></div><Md text={m.content} />{m.toolCalls && <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[9px] text-muted-foreground">{m.toolCalls.map((c) => <span key={c} className="flex items-center gap-1"><Wrench className="h-3 w-3" />{c}</span>)}</div>}</article>)}</div></div>
    <div className="border-t border-border/60 bg-background/25 p-4 lg:px-6"><div className="mx-auto max-w-3xl"><textarea value={msg} onChange={(e) => setMsg(e.target.value)} rows={2} placeholder="Steer this session…" className="w-full resize-none rounded-xl border border-border/70 bg-panel/60 p-3 text-xs leading-5 outline-none placeholder:text-muted-foreground/60 focus:border-ring/50" /><div className="mt-2 grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-2 gap-y-3 sm:flex sm:flex-wrap sm:gap-3"><div className="flex min-w-0 gap-1">{(["immediate", "enqueue"] as const).map((x) => <button key={x} onClick={() => setMode(x)} className={`rounded-md px-2 py-1 font-mono text-[9px] ${mode === x ? "bg-accent text-foreground" : "text-muted-foreground"}`}>{x}</button>)}</div><Toggle on={wait} onChange={setWait} label="Wait for reply" /><div className="col-span-2 flex justify-end gap-2 sm:ml-auto"><Btn disabled={busy || !msg} onClick={() => send(true)}><Eye className="h-3.5 w-3.5" />Preview</Btn><Btn variant="primary" disabled={busy || !msg} onClick={() => send(false)}><Send className="h-3.5 w-3.5" />Send</Btn></div></div>{result && (result.kind === "preview" ? <div className="mt-3 max-h-48 overflow-auto rounded-lg border border-border/60 p-3"><SmartMessage text={result.text} compact /></div> : <pre className={`mt-3 max-h-36 overflow-auto rounded-lg border p-3 font-mono text-[10px] ${result.kind === "error" ? "border-destructive/30 text-destructive" : "border-online/20 text-online"}`}>{result.text}</pre>)}</div></div>
  </Panel>;
}
