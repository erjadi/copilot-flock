import { useState } from "react";
import { ChevronDown, Eye, Radio, Send } from "lucide-react";
import type { Ctx } from "./Console";
import { matchMembers, type BroadcastFilter } from "@/lib/fleet/match";
import { envelope, post } from "@/lib/fleet/api";
import { Btn, Dot, Input, Label, PageHeading, Panel, SmartMessage, Toggle, gpuLabel } from "./ui";

interface Row { machineId: string; ok: boolean; latencyMs: number; detail: string }

export function BroadcastView({ ctx }: { ctx: Ctx }) {
  const [f, setF] = useState<BroadcastFilter>({ machines: "", exclude: "", scope: ctx.scope, githubUser: "", gpu: "", minRamGb: 0, minFreeDiskGb: 0, hasRepo: "" });
  const [toSession, setToSession] = useState("");
  const [newSession, setNewSession] = useState(false);
  const [title, setTitle] = useState("");
  const [repo, setRepo] = useState("");
  const [message, setMessage] = useState("");
  const [wait, setWait] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof BroadcastFilter>(k: K, v: BroadcastFilter[K]) => setF((p) => ({ ...p, [k]: v }));
  const matched = matchMembers(ctx.data.members, ctx.data.sessions, f);

  const run = async (dryRun: boolean) => {
    setBusy(true);
    const body = { ...f, machines: f.machines || "*", toSession, newSession, title, repo, message, dryRun, waitForReply: wait };
    const r = await post<{ results?: Row[]; envelopePreview?: string }>(ctx.base, ctx.mode, "/api/broadcast", body, () => dryRun
      ? { envelopePreview: matched.map((m) => envelope("fleet-console", m.machineId, newSession ? "<new>" : toSession || "<coordinator>", message, "immediate")).join("\n\n") }
      : { results: matched.map((m) => ({ machineId: m.machineId, ok: Math.random() > 0.08, latencyMs: 60 + Math.floor(Math.random() * 500), detail: newSession ? `created "${title || "Broadcast session"}"` : wait ? "reply: ack" : "delivered" })) });
    if (dryRun) { setPreview(r.envelopePreview ?? JSON.stringify(r, null, 2)); setRows(null); }
    else { setRows(r.results ?? []); setPreview(null); ctx.pushEvents([{ id: `evt-${Date.now()}`, timestamp: new Date().toISOString(), type: "outbox", target: "broadcast", fromMachine: ctx.data.hub.machineId, toMachine: matched.map((m) => m.machineId).join(","), action: "send_message", summary: `broadcast → ${matched.length} machines`, payload: body }]); }
    setBusy(false);
  };

  return <div>
    <PageHeading title="Broadcast" description="Compose once, target precisely, inspect before sending." />
    <div className="grid min-w-0 items-start gap-6 xl:grid-cols-[minmax(360px,440px)_minmax(0,1fr)]">
      <Panel className="p-4 sm:p-5 lg:p-6">
        <div className="flex items-center justify-between"><div className="flex items-center gap-2 text-xs font-medium"><Radio className="h-3.5 w-3.5 text-muted-foreground" />Audience</div><span className="font-mono text-[10px] text-muted-foreground">{matched.length} matched</span></div>
        <div className="mt-4 flex gap-1 rounded-lg bg-muted/30 p-1">{(["all", "personal", "work"] as const).map((s) => <button key={s} onClick={() => set("scope", s)} className={`flex-1 rounded-md px-2 py-1.5 text-[11px] capitalize transition ${f.scope === s ? "bg-accent text-foreground" : "text-muted-foreground"}`}>{s}</button>)}</div>
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2"><div><Label>Machines</Label><Input value={f.machines} onChange={(e) => set("machines", e.target.value)} placeholder="All machines" /></div><div><Label>Exclude</Label><Input value={f.exclude} onChange={(e) => set("exclude", e.target.value)} placeholder="Optional glob" /></div></div>
        <details className="group mt-4 border-y border-border/50 py-3"><summary className="flex cursor-pointer items-center text-[11px] text-muted-foreground group-open:text-foreground">Advanced targeting<ChevronDown className="ml-auto h-3.5 w-3.5 transition-transform group-open:rotate-180" /></summary><div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2"><div><Label>GitHub user</Label><Input value={f.githubUser} onChange={(e) => set("githubUser", e.target.value)} placeholder="@erjadi" /></div><div><Label>GPU contains</Label><Input value={f.gpu} onChange={(e) => set("gpu", e.target.value)} placeholder="RTX" /></div><div><Label>Minimum RAM · GB</Label><Input type="number" value={f.minRamGb} onChange={(e) => set("minRamGb", +e.target.value)} /></div><div><Label>Minimum free disk · GB</Label><Input type="number" value={f.minFreeDiskGb} onChange={(e) => set("minFreeDiskGb", +e.target.value)} /></div><div className="sm:col-span-2"><Label>Repository</Label><Input value={f.hasRepo} onChange={(e) => set("hasRepo", e.target.value)} placeholder="copilot-flock" /></div></div></details>
        <div className="mt-5"><div className="mb-4 flex items-center justify-between"><span className="text-xs font-medium">Destination</span><Toggle on={newSession} onChange={setNewSession} label="New session" /></div>{newSession ? <div className="grid grid-cols-1 gap-3 sm:grid-cols-2"><div><Label>Title</Label><Input value={title} onChange={(e) => setTitle(e.target.value)} /></div><div><Label>Repository</Label><Input value={repo} onChange={(e) => setRepo(e.target.value)} /></div></div> : <Input value={toSession} onChange={(e) => setToSession(e.target.value)} placeholder="Coordinator (default)" aria-label="Destination session" />}</div>
        <div className="mt-5"><Label>Message</Label><textarea rows={6} value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Write a message for every matched machine…" className="w-full resize-none rounded-xl border border-border/70 bg-background/40 p-3 text-xs leading-6 outline-none placeholder:text-muted-foreground/60 focus:border-ring/50" /></div>
        <div className="mt-4 grid min-w-0 gap-3 sm:flex sm:items-center"><Toggle on={wait} onChange={setWait} label="Wait for replies" /><div className="ml-auto flex gap-2"><Btn disabled={busy || !matched.length} onClick={() => run(true)}><Eye className="h-3.5 w-3.5" />Preview</Btn><Btn variant="primary" disabled={busy || !matched.length || !message} onClick={() => run(false)}><Send className="h-3.5 w-3.5" />Send to {matched.length}</Btn></div></div>
      </Panel>

      <div className="space-y-5">
        <Panel className="p-4 sm:p-5 lg:p-6"><div className="mb-5 flex items-center justify-between"><h3 className="text-xs font-medium">Live match preview</h3><span className="font-mono text-[10px] text-muted-foreground">{matched.length} / {ctx.data.members.length} machines</span></div><div className="divide-y divide-border/50">{ctx.data.members.map((m) => { const on = matched.includes(m); const gpus = m.specs.gpus.map(gpuLabel).join(" · "); return <div key={m.machineId} className={`flex items-center gap-3 py-3 transition-opacity ${on ? "" : "opacity-30"}`}><Dot tone={on ? "online" : "muted"} /><span className="min-w-0 truncate font-mono text-[11px]">{m.machineId}</span><span className="ml-auto hidden text-right text-[10px] text-muted-foreground sm:block">{m.specs.memory.totalGb} GB{gpus ? ` · ${gpus}` : ""}</span><span className="w-12 shrink-0 text-right font-mono text-[9px] capitalize text-muted-foreground">{m.scope}</span></div>; })}</div></Panel>
        {preview && <Panel className="enter-up p-5 lg:p-6"><div className="mb-4 text-xs font-medium">Envelope preview</div><div className="max-h-96 min-w-0 space-y-5 overflow-auto">{(preview.match(/<cross_session_message\b[\s\S]*?<\/cross_session_message>/gi) ?? [preview]).map((text, i) => <SmartMessage key={i} text={text} compact />)}</div></Panel>}
        {rows && <Panel className="enter-up overflow-x-auto overscroll-contain"><div className="border-b border-border/60 px-5 py-4 text-xs font-medium">Delivery results</div><table className="w-full min-w-[580px] text-xs"><thead className="text-left font-mono text-[9px] uppercase tracking-widest text-muted-foreground"><tr><th className="px-5 py-3 font-normal">Machine</th><th className="px-5 py-3 font-normal">Status</th><th className="px-5 py-3 text-right font-normal">Latency</th><th className="px-5 py-3 font-normal">Detail</th></tr></thead><tbody className="divide-y divide-border/50">{rows.map((r) => <tr key={r.machineId}><td className="px-5 py-3 font-mono text-[10px]">{r.machineId}</td><td className="px-5 py-3"><span className={`flex items-center gap-2 text-[11px] ${r.ok ? "text-online" : "text-destructive"}`}><Dot tone={r.ok ? "online" : "muted"} />{r.ok ? "Delivered" : "Failed"}</span></td><td className="px-5 py-3 text-right font-mono text-[10px] text-muted-foreground">{r.latencyMs}ms</td><td className="px-5 py-3 text-[11px] text-muted-foreground">{r.ok ? r.detail : "Response timed out"}</td></tr>)}</tbody></table></Panel>}
      </div>
    </div>
  </div>;
}
