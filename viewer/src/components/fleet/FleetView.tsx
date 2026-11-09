import { useState } from "react";
import { ChevronDown, ChevronRight, Cpu, HardDrive, Search } from "lucide-react";
import type { Ctx } from "./Console";
import type { Member } from "@/lib/fleet/types";
import { Btn, Dot, Input, Meter, PageHeading, Panel, Select, Toggle, rel, gpuLabel, ReplayHealth } from "./ui";

export function FleetView({ ctx }: { ctx: Ctx }) {
  const [q, setQ] = useState("");
  const [gpuOnly, setGpuOnly] = useState(false);
  const [minRam, setMinRam] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const ql = q.toLowerCase();
  const list = ctx.data.members.filter((m) =>
    (!ql || [m.machineId, m.specs.cpu.model, m.specs.model, ...m.specs.gpus.map((g) => g.name)].join(" ").toLowerCase().includes(ql)) &&
    (!gpuOnly || m.specs.gpus.some((g) => /nvidia|rtx|radeon rx/i.test(g.name))) && m.specs.memory.totalGb >= minRam);

  return <div>
    <PageHeading title="Fleet" description={`${list.length} machines · ${list.filter((m) => m.online).length} online`}>
      <div className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-2 sm:flex sm:flex-wrap"><div className="relative col-span-2 min-w-0 sm:w-64"><Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-muted-foreground" /><Input className="pl-9" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search machines or hardware" /></div><Select value={minRam} onChange={(e) => setMinRam(+e.target.value)} aria-label="Minimum RAM"><option value={0}>Any RAM</option><option value={16}>16+ GB RAM</option><option value={32}>32+ GB RAM</option><option value={64}>64+ GB RAM</option></Select><div className="px-2"><Toggle on={gpuOnly} onChange={setGpuOnly} label="Discrete GPU" /></div></div>
    </PageHeading>
    <Panel className="overflow-hidden">
      <div className="hidden grid-cols-[minmax(220px,1.2fr)_minmax(240px,1.5fr)_120px_100px_36px] gap-5 border-b border-border/60 px-5 py-3 text-[9px] uppercase tracking-[0.16em] text-muted-foreground lg:grid"><span>Machine</span><span>Hardware</span><span>Memory</span><span>Sessions</span><span /></div>
      {list.map((m) => <MachineRow key={m.machineId} m={m} ctx={ctx} open={open === m.machineId} toggle={() => setOpen(open === m.machineId ? null : m.machineId)} />)}
      {!list.length && <div className="p-12 text-center text-sm text-muted-foreground">No machines match these filters.</div>}
    </Panel>
  </div>;
}

function MachineRow({ m, ctx, open, toggle }: { m: Member; ctx: Ctx; open: boolean; toggle: () => void }) {
  const mem = m.specs.memory;
  const sessions = ctx.data.sessions.filter((s) => s.machineId === m.machineId);
  const running = sessions.filter((s) => s.is_running).length;
  const gpuSummary = m.specs.gpus.map(gpuLabel).join(" · ");
  return <div className="border-b border-border/50 last:border-0">
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-4 py-5 lg:grid-cols-[minmax(220px,1.2fr)_minmax(240px,1.5fr)_120px_100px_36px] lg:gap-5">
      <button onClick={toggle} className="flex min-w-0 items-center gap-3 text-left"><Dot tone={m.online ? "online" : "muted"} pulse={m.online} /><div className="min-w-0"><div className="truncate font-mono text-xs font-medium">{m.machineId}</div><div className="mt-1 truncate text-[11px] text-muted-foreground">{m.specs.model} · <span className="capitalize">{m.scope}</span></div></div></button>
      <div className="col-span-2 min-w-0 pl-5 lg:col-span-1 lg:pl-0"><div className="truncate text-xs text-foreground/85">{m.specs.cpu.model}</div><div className="mt-1 break-words font-mono text-[10px] leading-4 text-muted-foreground">{m.specs.cpu.logicalCores} threads{gpuSummary ? ` · ${gpuSummary}` : " · integrated graphics"}</div></div>
      <div className="col-span-2 pl-5 lg:hidden"><ReplayHealth member={m} /></div>
      <div className="min-w-0 pl-5 lg:pl-0"><div className="mb-2 flex flex-wrap justify-between gap-1 font-mono text-[10px]"><span>{mem.totalGb} GB</span><span className="text-muted-foreground">{mem.freeGb} free</span></div><Meter value={(mem.totalGb - mem.freeGb) / mem.totalGb} /></div>
      <button onClick={() => sessions[0] && ctx.openSession(sessions[0])} className="pl-5 text-left lg:pl-0"><div className="font-mono text-xs">{sessions.length}</div><div className="mt-1 text-[10px] text-muted-foreground">{running} running</div></button>
      <Btn variant="ghost" className="hidden h-8 w-8 px-0 lg:inline-flex" onClick={toggle} aria-label={`${open ? "Collapse" : "Expand"} ${m.machineId}`}><ChevronDown className={`h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} /></Btn>
    </div>
    {open && <div className="enter-up grid gap-8 border-t border-border/50 bg-background/25 px-5 py-6 md:grid-cols-2 lg:pl-14">
      <div><div className="mb-4 space-y-2 text-xs text-muted-foreground">{m.specs.gpus.map((g) => <div key={g.name}>{gpuLabel(g)}</div>)}<ReplayHealth member={m} /></div><div className="mb-4 flex items-center gap-2 text-[10px] uppercase tracking-widest text-muted-foreground"><HardDrive className="h-3.5 w-3.5" />Storage</div><div className="space-y-4">{m.specs.disks.map((d) => <div key={d.mount}><div className="mb-2 flex flex-wrap justify-between gap-1 font-mono text-[10px]"><span>{d.mount} <span className="text-muted-foreground">{d.label}</span></span><span className="text-muted-foreground">{d.freeGb} / {d.totalGb} GB free</span></div><Meter tone={d.type === "network" ? "work" : "busy"} value={1 - d.freeGb / d.totalGb} /></div>)}</div><Btn variant="outline" className="mt-6" onClick={() => ctx.inspect(m.machineId)}>Inspect machine<ChevronRight className="h-3.5 w-3.5" /></Btn></div>
      <div><div className="mb-4 flex items-center gap-2 text-[10px] uppercase tracking-widest text-muted-foreground"><Cpu className="h-3.5 w-3.5" />Recent sessions</div><div className="space-y-1">{sessions.slice(0, 5).map((s) => <button key={s.session_id} onClick={() => ctx.openSession(s)} className="flex min-w-0 w-full items-center gap-3 rounded-lg px-2 py-2 text-left hover:bg-accent/45"><Dot tone={s.is_running ? "busy" : "muted"} /><span className="truncate text-xs">{s.title}</span><span className="ml-auto shrink-0 font-mono text-[9px] text-muted-foreground">{rel(s.updated_at)}</span></button>)}</div><div className="mt-4 font-mono text-[9px] text-muted-foreground">@{m.githubUser} · v{m.version}{m.specs.keyFingerprint ? ` · ed25519:${m.specs.keyFingerprint.slice(0, 10)}…` : ""} · seen {rel(m.lastSeenAt)}</div></div>
    </div>}
  </div>;
}
