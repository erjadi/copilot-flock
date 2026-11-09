import { useEffect, useState } from "react";
import { FolderGit2, Plus, X } from "lucide-react";
import type { Ctx } from "./Console";
import { fetchProjects, post, viewerMachine } from "@/lib/fleet/api";
import type { Project } from "@/lib/fleet/types";
import { Btn, Dot, GlassPanel, IconBtn, Input, Label, Select, Toggle, rel } from "./ui";

export function NewSessionModal({ ctx, onClose }: { ctx: Ctx; onClose: () => void }) {
  const [toMachine, setTo] = useState(ctx.data.members[0]?.machineId ?? "");
  const [title, setTitle] = useState("");
  const [repo, setRepo] = useState("");
  const [workspaceType, setWt] = useState<"branch" | "worktree">("branch");
  const [branch, setBranch] = useState("main");
  const [message, setMessage] = useState("");
  const [wait, setWait] = useState(false);
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true);
    const fromHost = viewerMachine(ctx.data.hub.viewerHost);
    const body = { toMachine, title, repo, workspaceType, branch, message, waitForReply: wait };
    try {
      const r = await post(ctx.base, ctx.mode, "/api/create-session", body, () => ({ ok: true, session_id: `ses-${Date.now().toString(16)}`, toMachine, title }));
      setOut(JSON.stringify(r, null, 2));
      ctx.pushEvents([{ id: `evt-${Date.now()}`, timestamp: new Date().toISOString(), type: "outbox", target: toMachine, fromMachine: fromHost, toMachine, action: "create_session", summary: `create_session → ${toMachine} · ${title}`, payload: body }]);
    } catch (e) { setOut(String(e)); }
    setBusy(false);
  };
  return <div className="fixed inset-0 z-50 grid place-items-center bg-background/70 p-4 backdrop-blur-md" onClick={onClose}>
    <GlassPanel className="enter-up max-h-[calc(100dvh-32px)] w-full max-w-lg overflow-y-auto overscroll-contain rounded-2xl p-4 sm:p-6" >
      <div onClick={(e) => e.stopPropagation()}>
        <div className="mb-6 flex items-start justify-between"><div><h2 className="text-base font-medium tracking-tight">New remote session</h2><p className="mt-1 text-xs text-muted-foreground">Start work on any connected machine.</p></div><IconBtn onClick={onClose} aria-label="Close"><X className="h-4 w-4" /></IconBtn></div>
        <div className="space-y-4"><div><Label>Target machine</Label><Select value={toMachine} onChange={(e) => setTo(e.target.value)} className="w-full font-mono">{ctx.data.members.map((m) => <option key={m.machineId}>{m.machineId}</option>)}</Select></div><div><Label>Session title</Label><Input autoFocus value={title} onChange={(e) => setTitle(e.target.value)} placeholder="What should this session work on?" /></div><div className="grid grid-cols-1 gap-3 sm:grid-cols-2"><div><Label>Repository</Label><Input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="owner/repository" /></div><div><Label>Branch</Label><Input value={branch} onChange={(e) => setBranch(e.target.value)} /></div></div><div><Label>Workspace</Label><div className="flex gap-1 rounded-lg bg-muted/30 p-1">{(["branch", "worktree"] as const).map((w) => <button key={w} onClick={() => setWt(w)} className={`flex-1 rounded-md px-2 py-1.5 text-[11px] capitalize ${workspaceType === w ? "bg-accent text-foreground" : "text-muted-foreground"}`}>{w}</button>)}</div></div><div><Label>Initial message <span className="normal-case tracking-normal opacity-60">· optional</span></Label><textarea rows={3} value={message} onChange={(e) => setMessage(e.target.value)} className="w-full resize-none rounded-xl border border-border/70 bg-background/40 p-3 text-xs leading-5 outline-none focus:border-ring/50" /></div></div>
        <div className="mt-6 flex flex-wrap items-center justify-between gap-3"><Toggle on={wait} onChange={setWait} label="Wait for reply" /><Btn variant="primary" disabled={busy || !title} onClick={submit}><Plus className="h-3.5 w-3.5" />{busy ? "Creating…" : "Create session"}</Btn></div>
        {out && <pre className="mt-4 max-h-40 overflow-auto rounded-lg border border-online/20 bg-online/5 p-3 font-mono text-[10px] text-online">{out}</pre>}
      </div>
    </GlassPanel>
  </div>;
}

export function InspectDrawer({ ctx, machineId, onClose }: { ctx: Ctx; machineId: string; onClose: () => void }) {
  const m = ctx.data.members.find((x) => x.machineId === machineId);
  const [projects, setProjects] = useState<Project[] | null>(null);
  useEffect(() => { if (m) fetchProjects(ctx.base, ctx.mode, machineId, ctx.data.sessions, m.scope).then((r) => setProjects(r.projects)); }, [machineId]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!m) return null;
  const sessions = ctx.data.sessions.filter((s) => s.machineId === machineId);
  return <div className="fixed inset-0 z-50 flex justify-end bg-background/60 backdrop-blur-sm" onClick={onClose}>
    <aside className="enter-up absolute inset-x-0 bottom-0 max-h-[68dvh] w-full overflow-y-auto overscroll-contain rounded-t-2xl border-t border-border/70 bg-background/95 p-5 shadow-2xl md:relative md:inset-auto md:h-full md:max-h-none md:max-w-md md:rounded-none md:border-t-0 md:border-l md:p-6" onClick={(e) => e.stopPropagation()}>
      <div className="mx-auto mb-4 h-1 w-8 rounded-full bg-border md:hidden" /><div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3"><div className="flex min-w-0 items-center gap-3"><Dot pulse={m.online} tone={m.online ? "online" : "muted"} /><h2 className="truncate font-mono text-sm font-medium">{m.machineId}</h2></div><IconBtn className="ml-auto" onClick={onClose} aria-label="Close"><X className="h-4 w-4" /></IconBtn></div>
      <p className="mt-2 pl-4 text-xs text-muted-foreground">{m.specs.model} · {m.specs.os}</p>
      <div className="mt-8 grid grid-cols-3 gap-5 border-y border-border/60 py-5"><div><div className="font-mono text-lg">{m.specs.memory.totalGb}<span className="text-xs text-muted-foreground"> GB</span></div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Memory</div></div><div><div className="font-mono text-lg">{m.specs.cpu.logicalCores}</div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Threads</div></div><div><div className="font-mono text-lg">{sessions.length}</div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Sessions</div></div></div>
      <section className="mt-7"><div className="mb-3 text-[10px] uppercase tracking-widest text-muted-foreground">Active sessions</div><div className="space-y-1">{sessions.map((s) => <button key={s.session_id} onClick={() => ctx.openSession(s)} className="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left hover:bg-accent/40"><Dot tone={s.is_running ? "busy" : "muted"} /><span className="truncate text-xs">{s.title}</span><span className="ml-auto font-mono text-[9px] text-muted-foreground">{s.branch}</span></button>)}</div></section>
      <section className="mt-8"><div className="mb-3 text-[10px] uppercase tracking-widest text-muted-foreground">Git projects</div>{!projects ? <div className="text-xs text-muted-foreground">Loading projects…</div> : <div className="space-y-4">{projects.map((p) => <div key={p.project_id} className="border-l border-border pl-4"><div className="flex min-w-0 items-center gap-2 text-xs"><FolderGit2 className="h-3.5 w-3.5 text-muted-foreground" /><span className="min-w-0 truncate">{p.name}</span><span className="ml-auto font-mono text-[9px] text-muted-foreground">{p.default_branch}</span></div><div className="mt-1.5 break-all font-mono text-[9px] leading-5 text-muted-foreground">{p.repo}<br />{p.path}</div></div>)}</div>}</section>
      <div className="mt-8 font-mono text-[9px] text-muted-foreground">v{m.version}{m.specs.keyFingerprint ? ` · ed25519:${m.specs.keyFingerprint.slice(0, 12)}…` : ""} · registered {rel(m.registeredAt)}</div>
    </aside>
  </div>;
}
