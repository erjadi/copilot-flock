import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Command, Plus, RefreshCw, Settings2, Network, Server, MessagesSquare, Radio, Activity, ShieldCheck, Layers, Sun, Moon } from "lucide-react";
import { resolveTheme, THEME_KEY, type Theme } from "@/lib/fleet/theme";
import { fetchOverview, getSeed, normalizeLegacyScopes, type Mode } from "@/lib/fleet/api";
import { fakeEvent } from "@/lib/fleet/seed";
import type { Overview, Session, WireEvent } from "@/lib/fleet/types";
import { Btn, Dot, IconBtn, Input, Toggle, Select } from "./ui";
import { FleetView } from "./FleetView";
import { SessionsView } from "./SessionsView";
import { BroadcastView } from "./BroadcastView";
import { WireView } from "./WireView";
import { TopologyView } from "./TopologyView";
import { GovernanceView } from "./GovernanceView";
import { FlocksView } from "./FlocksView";
import { NewSessionModal, InspectDrawer } from "./Modals";
import { fetchFlocks, filterFlock, seedFlocks, type FlockState } from "@/lib/fleet/flocks";

export type ScopeFilter = "all" | "personal" | "work";
export interface Ctx {
  base: string; mode: Mode; flockId: string; data: Overview; scope: ScopeFilter; events: WireEvent[];
  pushEvents: (e: WireEvent[]) => void; openSession: (s: Session) => void; inspect: (id: string) => void;
}

const TABS = [
  { id: "topology", label: "Topology", icon: Network },
  { id: "flocks", label: "Flocks", icon: Layers },
  { id: "fleet", label: "Fleet", icon: Server },
  { id: "sessions", label: "Sessions", icon: MessagesSquare },
  { id: "broadcast", label: "Broadcast", icon: Radio },
  { id: "wire", label: "Wire", icon: Activity },
  { id: "governance", label: "Governance", icon: ShieldCheck },
] as const;

export function Console() {
  const [theme, setTheme] = useState<Theme>("dark");
  useEffect(() => {
    let saved: Theme = "dark";
    try { saved = resolveTheme(localStorage.getItem(THEME_KEY)); } catch { /* Storage may be disabled. */ }
    setTheme(saved);
    document.documentElement.classList.remove("light", "dark");
    document.documentElement.classList.add(saved);
  }, []);
  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.classList.remove("light", "dark");
    document.documentElement.classList.add(next);
    try { localStorage.setItem(THEME_KEY, next); } catch { /* The toggle still works without storage. */ }
  };
  const [flockId, setFlockId] = useState("erjadi");
  const [flocks, setFlocks] = useState<FlockState>(() => seedFlocks(getSeed().members));
  const [flockError, setFlockError] = useState<string | null>(null);
  const [clock, setClock] = useState(Date.now());
  const [base, setBase] = useState("");
  const [baseDraft, setBaseDraft] = useState("");
  const [mode, setMode] = useState<Mode>("seed");
  const [data, setData] = useState<Overview>(() => getSeed());
  const [events, setEvents] = useState<WireEvent[]>(() => getSeed().events);
  const [scope, setScope] = useState<ScopeFilter>("all");
  const [auto, setAuto] = useState(true);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<(typeof TABS)[number]["id"]>("topology");
  const [selected, setSelected] = useState<Session | null>(null);
  const [inspectId, setInspectId] = useState<string | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  const [settings, setSettings] = useState(false);
  const [sse, setSse] = useState<"connected" | "simulated" | "connecting">("connecting");
  const dataRef = useRef(data); dataRef.current = data;

  const pushEvents = useCallback((e: WireEvent[]) => setEvents((p) => [...e, ...p].slice(0, 500)), []);
  const refresh = useCallback(async () => {
    setLoading(true);
    const r = await fetchOverview(base);
    setMode(r.mode); setData(r.data);
    if (r.mode === "live") setEvents((p) => { const ids = new Set(p.map((x) => x.id)); return [...r.data.events.filter((x) => !ids.has(x.id)), ...p].slice(0, 500); });
    setLoading(false);
  }, [base]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    if (data.hub?.viewerHost) {
      document.title = `Copilot Flock Console · ${data.hub.viewerHost}`;
    }
  }, [data.hub?.viewerHost]);
  useEffect(() => { if (!auto) return; const t = setInterval(refresh, 10000); return () => clearInterval(t); }, [auto, refresh]);
  useEffect(() => {
    if (mode === "live") {
      setSse("connecting");
      const es = new EventSource(`${base.replace(/\/$/, "")}/api/stream`);
      const handle = (ev: MessageEvent) => {
        try {
          const d = normalizeLegacyScopes(JSON.parse(ev.data));
          const list = (Array.isArray(d) ? d : [d.event ?? d]).filter((x) => x && typeof x.id === "string" && typeof x.toMachine === "string");
          if (list.length) pushEvents(list);
        } catch { /* ignore malformed packets */ }
      };
      es.onopen = () => setSse("connected");
      es.onmessage = handle;
      es.addEventListener("wire_event", handle as EventListener);
      es.addEventListener("presence", handle as EventListener);
      es.onerror = () => setSse("connecting");
      return () => es.close();
    }
    setSse("simulated");
    const t = setInterval(() => pushEvents(fakeEvent(dataRef.current.members, dataRef.current.sessions).reverse()), 3500);
    return () => clearInterval(t);
  }, [mode, base, pushEvents]);

  const refreshFlocks = useCallback(async () => {
    if (mode === "seed") { setFlockError(null); return; }
    try { const next = await fetchFlocks(base); setFlocks(next); setFlockError(null); setFlockId((current) => next.flocks.some((f) => f.flockId === current) ? current : next.flocks[0]?.flockId ?? ""); }
    catch (error) { setFlocks(seedFlocks(dataRef.current.members)); setFlockError(`v3 flock data fallback: ${error instanceof Error ? error.message : "request failed"}`); }
  }, [base, mode]);
  useEffect(() => { void refreshFlocks(); }, [refreshFlocks]);
  useEffect(() => { if (mode === "seed") setFlocks(seedFlocks(getSeed().members)); }, [mode, base]);
  useEffect(() => { const timer = setInterval(() => { setClock(Date.now()); if (auto) void refreshFlocks(); }, 10000); return () => clearInterval(timer); }, [auto, refreshFlocks]);
  const view = useMemo<Overview>(() => {
    const active = filterFlock(data, flocks.flocks.find((f) => f.flockId === flockId) ?? flocks.flocks[0], flocks.sharedThreads, clock);
    return scope === "all" ? active : { ...active, members: active.members.filter((m) => m.scope === scope), sessions: active.sessions.filter((s) => s.scope === scope) };
  }, [data, flocks, flockId, scope, clock]);
  const visibleEvents = useMemo(() => {
    const active = flocks.flocks.find((f) => f.flockId === flockId) ?? flocks.flocks[0];
    if (!active || active.sessionVisibility !== "all") return [];
    const ids = new Set(view.members.map((m) => m.machineId));
    return events.filter((e) => ids.has(e.fromMachine) && (e.toMachine || "").split(",").every((id) => ids.has(id) || id === "*"));
  }, [events, flocks, flockId, view.members]);
  const online = view.members.filter((m) => m.online).length;
  const ctx: Ctx = { base, mode, flockId, data: view, scope, events: visibleEvents, pushEvents,
    openSession: (s) => { setSelected(s); setTab("sessions"); setInspectId(null); }, inspect: setInspectId };

  return (
    <div className="min-h-dvh pb-[calc(64px+env(safe-area-inset-bottom))] xl:pb-0">
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/85 backdrop-blur-xl">
        <div className="grid min-h-16 grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-4 lg:flex lg:gap-3 lg:px-6">
          <Btn onClick={() => setTab("topology")} className="min-w-0 justify-start gap-2.5 px-0 md:shrink-0" aria-label="Copilot Flock Console home">
            <span className="relative grid h-7 w-7 place-items-center rounded-lg border border-border bg-panel"><Command className="h-3.5 w-3.5 text-busy" /><span className="absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full bg-online" /></span>
            <span className="truncate text-sm font-medium text-foreground">Copilot <span className="text-muted-foreground">Flock</span></span>
          </Btn>

          <nav className="hidden min-w-0 flex-1 items-center gap-0.5 xl:flex" aria-label="Console views">
            {TABS.map(({ id, label }) => <Btn key={id} onClick={() => setTab(id)} aria-current={tab === id ? "page" : undefined} className={`relative shrink-0 px-2 lg:px-2 ${tab === id ? "text-foreground" : "text-muted-foreground"}`}>{label}{tab === id && <span className="absolute inset-x-3 -bottom-4 h-px bg-foreground" />}</Btn>)}
          </nav>

          <div className="hidden items-center gap-3 font-mono text-[10px] text-muted-foreground 2xl:flex">
            <span className="flex items-center gap-1.5"><Dot pulse={mode === "live"} tone={mode === "live" ? "online" : "muted"} /><span className="text-foreground/80">{online}/{view.members.length}</span> online</span>
            <span><span className="text-foreground/80">{view.sessions.length}</span> sessions</span>
            <span><span className="text-foreground/80">{visibleEvents.length}</span> events</span>
          </div>

          <div className="order-3 col-span-2 min-w-0 pb-2 lg:order-none lg:pb-0">
            <Select className="w-full lg:w-48" aria-label="Active flock" value={flockId} onChange={(e) => { setFlockId(e.target.value); setSelected(null); setInspectId(null); }}>
              {!flocks.flocks.length && <option value={flockId}>Flocks unavailable</option>}
              {flocks.flocks.map((f) => <option key={f.flockId} value={f.flockId}>{f.flockId}{f.kind === "owner_root" ? " · All PCs" : ""}</option>)}
            </Select>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            <IconBtn onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`} title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}>{theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</IconBtn>
            <div className="relative">
              <IconBtn onClick={() => setSettings(!settings)} aria-label="Connection settings" aria-expanded={settings}><Settings2 className="h-4 w-4" /></IconBtn>
              {settings && <>
                <button className="fixed inset-0 z-10 cursor-default" onClick={() => setSettings(false)} aria-label="Close settings" />
                <div className="glass enter-up fixed right-3 top-[68px] z-20 max-h-[calc(100dvh-152px)] w-[min(320px,calc(100vw-24px))] overflow-y-auto rounded-xl p-4 md:absolute md:right-0 md:top-10">
                  <div className="mb-4 flex items-center justify-between"><div><div className="text-sm font-medium">Connection</div><div className="mt-0.5 text-[11px] text-muted-foreground">{mode === "live" ? "Live hub" : "Preview seed"} · SSE {sse}</div></div><Dot pulse={mode === "live"} tone={mode === "live" ? "online" : "muted"} /></div>
                  <form onSubmit={(e) => { e.preventDefault(); setBase(baseDraft.trim()); setSettings(false); }}>
                    <label className="mb-1.5 block text-[10px] uppercase tracking-widest text-muted-foreground" htmlFor="api-base">API base</label>
                    <div className="flex gap-2"><Input id="api-base" placeholder="Relative to this app" value={baseDraft} onChange={(e) => setBaseDraft(e.target.value)} /><Btn variant="outline" type="submit">Set</Btn></div>
                  </form>
                  <div className="my-4 h-px bg-border/70" />
                  <div className="flex items-center justify-between"><span className="text-xs text-muted-foreground">Scope</span><div className="flex gap-1">{(["all", "personal", "work"] as const).map((s) => <button key={s} onClick={() => setScope(s)} className={`rounded-md px-2 py-1 text-[11px] capitalize ${scope === s ? "bg-accent text-foreground" : "text-muted-foreground"}`}>{s}</button>)}</div></div>
                  <div className="mt-4 flex items-center justify-between"><Toggle on={auto} onChange={setAuto} label="Refresh every 10s" /><IconBtn onClick={refresh} disabled={loading} aria-label="Refresh now"><RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /></IconBtn></div>
                  <div className="mt-4 truncate font-mono text-[9px] text-muted-foreground/70">{data.hub.endpoint} · {data.hub.hub}</div>
                </div>
              </>}
            </div>
            <Btn variant="primary" onClick={() => setNewOpen(true)} className="ml-1 h-10 min-w-10 md:h-8" aria-label="New session"><Plus className="h-3.5 w-3.5" /><span className="hidden lg:inline">New session</span></Btn>
          </div>
        </div>
      </header>

      <nav className="fixed inset-x-0 bottom-0 z-40 grid grid-cols-7 border-t border-border/60 bg-background/95 px-1 pt-1 pb-[calc(4px+env(safe-area-inset-bottom))] backdrop-blur-xl xl:hidden" aria-label="Mobile console views">
        {TABS.map(({ id, label, icon: Icon }) => <Btn key={id} onClick={() => { setTab(id); setSettings(false); }} aria-current={tab === id ? "page" : undefined} className={`h-14 min-w-0 flex-col gap-1 px-0 text-[8px] ${tab === id ? "text-foreground" : "text-muted-foreground"}`}><Icon className={`h-4 w-4 shrink-0 ${tab === id ? "text-busy" : ""}`} /><span>{label}</span></Btn>)}
      </nav>

      <main className={tab === "topology" ? "p-2 md:p-3 lg:p-4" : "mx-auto min-w-0 max-w-[1500px] px-3 py-5 sm:px-5 lg:px-8 lg:py-9"}>
        {tab === "topology" && <TopologyView key={flockId} ctx={ctx} flocks={flocks.flocks} flockError={flockError} />}
        {tab === "flocks" && <FlocksView ctx={ctx} state={flocks} setState={setFlocks} refresh={refreshFlocks} error={flockError} />}
        {tab === "fleet" && <FleetView ctx={ctx} />}
        {tab === "sessions" && <SessionsView key={flockId} ctx={ctx} selected={selected} setSelected={setSelected} />}
        {tab === "broadcast" && <BroadcastView key={flockId} ctx={ctx} />}
        {tab === "wire" && <WireView ctx={ctx} />}
        {tab === "governance" && <GovernanceView key={flockId} ctx={ctx} />}
      </main>

      {newOpen && <NewSessionModal ctx={ctx} onClose={() => setNewOpen(false)} />}
      {inspectId && <InspectDrawer ctx={ctx} machineId={inspectId} onClose={() => setInspectId(null)} />}
    </div>
  );
}
