import { useMemo, useState } from "react";
import { ChevronRight, Pause, Play, Search } from "lucide-react";
import type { Ctx } from "./Console";
import type { WireEvent } from "@/lib/fleet/types";
import { Btn, Dot, Input, PageHeading, Panel, Select, SmartMessage } from "./ui";

function wireMessage(payload: unknown): string | null {
  if (typeof payload === "string") return payload;
  if (!payload || typeof payload !== "object") return null;
  const data = payload as Record<string, unknown>;
  for (const key of ["message", "content", "text", "envelopePreview", "envelope", "body"]) {
    if (typeof data[key] === "string") return data[key];
  }
  for (const key of ["args", "payload", "data"]) {
    if (data[key] && typeof data[key] === "object") {
      const message = wireMessage(data[key]);
      if (message) return message;
    }
  }
  return null;
}

const ACTIONS = ["all", "presence", "ping", "list_sessions", "get_transcript", "send_message", "create_session", "diagnose", "self_update", "transfer_file", "clarify"];
const tone = (t: WireEvent["type"]): "online" | "info" | "busy" | "work" => t === "bridgePresence" ? "online" : t === "bridgeRpcRequest" ? "info" : t === "bridgeRpcResponse" ? "busy" : "work";

export function WireView({ ctx }: { ctx: Ctx }) {
  const [machine, setMachine] = useState("");
  const [action, setAction] = useState("all");
  const [open, setOpen] = useState<string | null>(null);
  const [paused, setPaused] = useState<WireEvent[] | null>(null);
  const src = paused ?? ctx.events;
  const reqTimes = useMemo(() => { const m = new Map<string, number>(); src.forEach((e) => e.type === "bridgeRpcRequest" && e.requestId && m.set(e.requestId, new Date(e.timestamp).getTime())); return m; }, [src]);
  const list = src.filter((e) => (action === "all" || e.action === action) && (!machine || `${e.fromMachine} ${e.toMachine}`.toLowerCase().includes(machine.toLowerCase())));
  return <div>
    <PageHeading title="Live wire" description={`${list.length} packets · request and response latency correlated by ID`}>
      <div className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-2 sm:flex sm:flex-wrap"><div className="relative col-span-2 min-w-0 sm:w-60"><Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" /><Input className="pl-9" placeholder="Filter machines" value={machine} onChange={(e) => setMachine(e.target.value)} /></div><Select value={action} onChange={(e) => setAction(e.target.value)} aria-label="Filter by action">{ACTIONS.map((a) => <option key={a} value={a}>{a === "all" ? "All actions" : a}</option>)}</Select><Btn variant="outline" onClick={() => setPaused(paused ? null : ctx.events)}>{paused ? <><Play className="h-3.5 w-3.5" />Resume</> : <><Pause className="h-3.5 w-3.5" />Pause</>}</Btn></div>
    </PageHeading>
    <Panel className="overflow-hidden">
      <div className="hidden grid-cols-[100px_170px_130px_minmax(260px,1fr)_90px] gap-4 border-b border-border/60 px-5 py-3 font-mono text-[9px] uppercase tracking-widest text-muted-foreground lg:grid"><span>Time</span><span>Packet</span><span>Action</span><span>Route</span><span className="text-right">Latency</span></div>
      <div className="max-h-[calc(100dvh-280px)] min-h-[320px] overflow-y-auto overscroll-contain lg:min-h-[560px]">{list.map((e) => {
        const requestAt = e.requestId ? reqTimes.get(e.requestId) : undefined;
        const message = wireMessage(e.payload);
        const lat = e.type === "bridgeRpcResponse" && requestAt !== undefined ? new Date(e.timestamp).getTime() - requestAt : null;
        return <div key={e.id} className="border-b border-border/45 last:border-0"><button onClick={() => setOpen(open === e.id ? null : e.id)} className="grid min-w-0 w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-2 px-4 py-3.5 text-left transition hover:bg-accent/30 lg:grid-cols-[100px_170px_130px_minmax(260px,1fr)_90px] lg:gap-4">
          <span className="font-mono text-[10px] text-muted-foreground">{new Date(e.timestamp).toLocaleTimeString()}</span>
          <span className="flex min-w-0 items-center gap-2 font-mono text-[10px]"><ChevronRight className={`h-3 w-3 text-muted-foreground transition-transform ${open === e.id ? "rotate-90" : ""}`} /><Dot tone={tone(e.type)} /><span className="truncate">{e.type.replace("bridge", "")}</span></span>
          <span className="font-mono text-[10px] text-foreground/75">{e.action}</span>
          <span className="col-span-2 min-w-0 truncate font-mono text-[10px] lg:col-span-1"><span>{e.fromMachine}</span><span className="mx-2 text-muted-foreground">→</span><span>{e.toMachine}</span><span className="ml-3 text-muted-foreground/70">{e.summary}</span></span>
          <span className={`text-right font-mono text-[10px] ${lat !== null && lat > 300 ? "text-gpu" : "text-muted-foreground"}`}>{lat !== null ? `${lat}ms` : "—"}</span>
        </button>{open === e.id && <div className="enter-up min-w-0 border-t border-border/40 bg-background/35 px-6 py-5 lg:px-12"><div className="mb-3 flex flex-wrap break-all gap-x-5 gap-y-1 font-mono text-[9px] text-muted-foreground"><span>{e.id}</span>{e.requestId && <span>request {e.requestId}</span>}</div>{message && <div className="mb-4 max-w-3xl"><SmartMessage text={message} compact /></div>}<details open={!message}><summary className="cursor-pointer text-[10px] text-muted-foreground">Raw packet</summary><pre className="mt-3 max-w-full overflow-x-auto font-mono text-[10px] leading-6 text-busy/85">{JSON.stringify(e, null, 2)}</pre></details></div>}</div>;
      })}{!list.length && <div className="grid min-h-[400px] place-items-center text-sm text-muted-foreground">No packets match these filters.</div>}</div>
    </Panel>
  </div>;
}
