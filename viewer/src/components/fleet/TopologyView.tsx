import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, Crosshair, Grid3x3, History, Maximize2, Minus, Network, Orbit, Play, Plus, Send, X, Layers } from "lucide-react";
import type { Flock } from "@/lib/fleet/flocks";
import { FlockMembershipGraph } from "./FlockOverlap";
import type { Ctx } from "./Console";
import { post } from "@/lib/fleet/api";
import { HUB_ID, deriveTopology, edgeKey, edgeTone, weight, type LinkMessage, type TopoEdge, type TopoNode } from "@/lib/fleet/topology";
import type { Member, Overview, WireEvent } from "@/lib/fleet/types";
import { Btn, Dot, GlassPanel, IconBtn, Input, SmartMessage, rel, gpuLabel, ReplayHealth } from "./ui";

const DESKTOP_W = 1200, DESKTOP_H = 760;
type Mode = "mesh" | "orbital" | "flocks" | "matrix";
type Pt = { x: number; y: number };
type Burst = { id: string; from: string; to: string; tone: string; delay: number };
const TONE: Record<string, string> = { online: "var(--online)", busy: "var(--busy)", work: "var(--work)", gpu: "var(--gpu)", info: "var(--info)" };
let bid = 0;

function layout(mode: Mode, nodes: TopoNode[], hub: boolean, W: number, H: number, portrait: boolean): Record<string, Pt> {
  const CX = W / 2, CY = H / 2;
  const pos: Record<string, Pt> = {};
  const sorted = [...nodes].sort((a, b) => b.activity - a.activity);
  const max = Math.max(1, ...nodes.map((n) => n.activity));
  if (portrait) {
    // Two vertical rails keep full machine identifiers readable on narrow canvases.
    if (hub) pos[HUB_ID] = { x: CX, y: CY + 12 };
    const rows = Math.ceil(sorted.length / 2);
    sorted.forEach((n, i) => {
      const row = Math.floor(i / 2);
      const y = 190 + row * ((H - 405) / Math.max(1, rows - 1));
      pos[n.id] = { x: i % 2 === 0 ? W * 0.24 : W * 0.76, y };
    });
    return pos;
  }
  if (mode === "orbital") {
    pos[HUB_ID] = { x: CX, y: CY };
    const groups = { personal: sorted.filter((n) => n.scope === "personal"), work: sorted.filter((n) => n.scope === "work") };
    (["personal", "work"] as const).forEach((s) => {
      const g = groups[s]; const [a0, a1] = s === "personal" ? [110, 250] : [-60, 60];
      g.forEach((n, i) => {
        const ang = ((a0 + (g.length === 1 ? (a1 - a0) / 2 : ((a1 - a0) * i) / (g.length - 1))) * Math.PI) / 180;
        const r = 285 - (n.activity / max) * 90;
        pos[n.id] = { x: CX + Math.cos(ang) * r * 1.55, y: CY + Math.sin(ang) * r };
      });
    });
    return pos;
  }
  const ring = hub ? sorted : sorted.slice(1);
  if (hub) pos[HUB_ID] = { x: CX, y: CY }; else if (sorted[0]) pos[sorted[0].id] = { x: CX, y: CY };
  ring.forEach((n, i) => {
    const ang = (i / ring.length) * Math.PI * 2 - Math.PI / 2;
    pos[n.id] = { x: CX + Math.cos(ang) * 455, y: CY + Math.sin(ang) * 275 };
  });
  return pos;
}

const curve = (a: Pt, b: Pt, bend = 0.1) => {
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2, dx = b.x - a.x, dy = b.y - a.y;
  return { x: mx - dy * bend, y: my + dx * bend };
};
const sortedCurve = (pos: Record<string, Pt>, x: string, y: string) => { const [lo, hi] = [x, y].sort(); return curve(pos[lo], pos[hi]); };
const pathD = (a: Pt, b: Pt, c: Pt) => `M${a.x},${a.y} Q${c.x},${c.y} ${b.x},${b.y}`;

function BurstDot({ d, tone, delay, onDone }: { d: string; tone: string; delay: number; onDone: () => void }) {
  const ref = useRef<SVGAnimateMotionElement>(null);
  useEffect(() => {
    const t1 = setTimeout(() => ref.current?.beginElement(), delay);
    const t2 = setTimeout(onDone, delay + 1100);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return <circle r={4} fill={tone} opacity={0.95} cx={-999} filter="url(#node-glow)"><animateMotion ref={ref} begin="indefinite" dur="0.95s" fill="freeze" path={d} /></circle>;
}

export function TopologyView({ ctx, flocks, flockError }: { ctx: Ctx; flocks: Flock[]; flockError: string | null }) {
  const containerRef = useRef<HTMLElement>(null);
  const [canvas, setCanvas] = useState({ W: DESKTOP_W, H: DESKTOP_H, portrait: false });
  const { W, H, portrait } = canvas;
  const CX = W / 2, CY = H / 2;
  useEffect(() => {
    const el = containerRef.current; if (!el) return;
    const observer = new ResizeObserver(([entry]) => {
      if (!entry) return;
      const { width, height } = entry.contentRect;
      if (!width || !height) return;
      const narrow = width < 700 || width / height < 0.9;
      setCanvas({ W: narrow ? 480 : DESKTOP_W, H: narrow ? Math.max(640, 480 * height / width) : DESKTOP_H, portrait: narrow });
      setView({ x: 0, y: 0, k: 1 });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  const members = ctx.data.members;
  const topo = useMemo(() => deriveTopology(ctx.data as Overview & { topology?: never }, ctx.events, members), [ctx.data, ctx.events, members]);
  const [extra, setExtra] = useState<Record<string, LinkMessage[]>>({});
  const [mode, setMode] = useState<Mode>("mesh");
  const [hub, setHub] = useState(false);
  const [highOnly, setHighOnly] = useState(false);
  const [selNode, setSelNode] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<string | null>(null);
  const [overrides, setOverrides] = useState<Record<string, Record<string, Pt>>>({});
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [bursts, setBursts] = useState<Burst[]>([]);
  const [shocks, setShocks] = useState<{ id: string; node: string }[]>([]);
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{ kind: "node" | "pan"; id?: string | undefined; sx: number; sy: number; vx: number; vy: number; moved: boolean } | null>(null);

  const showHub = hub || mode === "orbital";
  const lkey = `${mode}-${showHub}-${portrait}`;
  const nodeIds = topo.nodes.map((n) => n.id).join();
  const base = useMemo(() => layout(mode, topo.nodes, showHub, W, H, portrait), [mode, showHub, nodeIds, W, H, portrait]); // eslint-disable-line react-hooks/exhaustive-deps
  const pos = { ...base, ...(overrides[lkey] ?? {}) };
  const mById = useMemo(() => Object.fromEntries(members.map((m) => [m.machineId, m])), [members]);
  const maxW = Math.max(1, ...topo.edges.map(weight));
  const maxA = Math.max(1, ...topo.nodes.map((n) => n.activity));
  const edges = topo.edges.filter((e) => !highOnly || weight(e) >= maxW * 0.35);
  const neighbors = useMemo(() => { const s = new Set<string>(); if (selNode) topo.edges.forEach((e) => { if (e.a === selNode) s.add(e.b); if (e.b === selNode) s.add(e.a); }); return s; }, [selNode, topo.edges]);
  const totalMessages = topo.edges.reduce((a, e) => a + e.ab + e.ba, 0);
  const fire = (list: Omit<Burst, "id">[]) => setBursts((b) => [...b, ...list.map((x) => ({ ...x, id: `b${++bid}` }))].slice(-80));

  const lastId = useRef(ctx.events[0]?.id);
  useEffect(() => {
    const fresh: WireEvent[] = [];
    for (const e of ctx.events) { if (e.id === lastId.current) break; fresh.push(e); }
    lastId.current = ctx.events[0]?.id;
    fire(fresh.flatMap((e, i) => {
      const tos = e.toMachine.split(",").filter((t) => mById[t]);
      if (mById[e.fromMachine]) return tos.map((to) => ({ from: e.fromMachine, to, tone: e.type === "bridgeRpcRequest" ? "var(--gpu)" : TONE[edgeTone(mById[e.fromMachine].scope, mById[to].scope)], delay: i * 120 }));
      if (showHub && e.type !== "bridgePresence") return tos.map((to) => ({ from: HUB_ID, to, tone: "var(--info)", delay: i * 120 }));
      if (showHub && e.type === "bridgePresence" && mById[e.fromMachine]) return [{ from: e.fromMachine, to: HUB_ID, tone: "var(--online)", delay: 0 }];
      return [];
    }));
  }, [ctx.events]); // eslint-disable-line react-hooks/exhaustive-deps

  const pointFromClient = (cx: number, cy: number) => {
    const el = svgRef.current;
    if (!el) return { x: 0, y: 0 };
    const r = el.getBoundingClientRect();
    const scale = Math.min(r.width / W, r.height / H);
    const ox = (r.width - W * scale) / 2, oy = (r.height - H * scale) / 2;
    return { x: (cx - r.left - ox) / scale, y: (cy - r.top - oy) / scale };
  };

  useEffect(() => {
    const el = svgRef.current; if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const { x: px, y: py } = pointFromClient(e.clientX, e.clientY);
      const dy = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 100 : 1);
      setView((v) => { const k = Math.min(4, Math.max(0.35, v.k * Math.exp(-dy * 0.0015))); const f = k / v.k; return { k, x: px - (px - v.x) * f, y: py - (py - v.y) * f }; });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [mode, W, H]);
  const zoomBy = (f: number) => setView((v) => { const k = Math.min(4, Math.max(0.35, v.k * f)); const g = k / v.k; return { k, x: CX - (CX - v.x) * g, y: CY - (CY - v.y) * g }; });
  const toSvg = pointFromClient;
  const onDown = (e: React.PointerEvent, id?: string) => {
    e.stopPropagation(); (e.target as Element).setPointerCapture?.(e.pointerId);
    const p = toSvg(e.clientX, e.clientY);
    drag.current = { kind: id ? "node" : "pan", id, sx: p.x, sy: p.y, vx: view.x, vy: view.y, moved: false };
  };
  const onMove = (e: React.PointerEvent) => {
    const d = drag.current; if (!d) return;
    const p = toSvg(e.clientX, e.clientY);
    if (Math.hypot(p.x - d.sx, p.y - d.sy) > 3) d.moved = true;
    if (!d.moved) return;
    if (d.kind === "pan") setView((v) => ({ ...v, x: d.vx + p.x - d.sx, y: d.vy + p.y - d.sy }));
    else if (d.id) {
      const id = d.id;
      setOverrides((o) => ({ ...o, [lkey]: { ...(o[lkey] ?? {}), [id]: { x: (p.x - view.x) / view.k, y: (p.y - view.y) / view.k } } }));
    }
  };
  const onUp = () => {
    const d = drag.current; drag.current = null;
    if (d && !d.moved) { if (d.kind === "node" && d.id && d.id !== HUB_ID) { setSelNode(d.id); setSelEdge(null); } else if (d.kind === "pan") { setSelNode(null); setSelEdge(null); } }
  };

  const simulate = () => {
    const pool = topo.edges.flatMap((e) => Array(Math.ceil(weight(e) / 6)).fill(e) as TopoEdge[]);
    if (!pool.length) return;
    const list = Array.from({ length: 24 }, (_, i) => { const e = pool[Math.floor(Math.random() * pool.length)]; const f = Math.random() < 0.55; const [from, to] = f ? [e.a, e.b] : [e.b, e.a];
      return { from, to, tone: Math.random() < 0.25 ? "var(--gpu)" : TONE[edgeTone(mById[from].scope, mById[to].scope)], delay: i * 90 }; });
    fire(list);
    setTimeout(() => ctx.pushEvents(list.slice(0, 8).map((b, i) => ({ id: `sim-${Date.now()}-${i}`, timestamp: new Date().toISOString(), type: "outbox", target: b.to, fromMachine: b.from, toMachine: b.to, action: "send_message", summary: `simulated burst ${b.from} → ${b.to}`, payload: { simulated: true } }))), 2400);
  };
  const replay = () => {
    const hist = topo.edges.flatMap((e) => e.messages).concat(Object.values(extra).flat()).sort((a, b) => a.timestamp.localeCompare(b.timestamp)).slice(-30);
    fire(hist.filter((m) => mById[m.from] && mById[m.to]).map((m, i) => ({ from: m.from, to: m.to, tone: TONE[edgeTone(mById[m.from].scope, mById[m.to].scope)], delay: i * 160 })));
  };
  const ping = async (id: string) => {
    setShocks((s) => [...s, { id: `s${++bid}`, node: id }]);
    fire(topo.edges.filter((e) => e.a === id || e.b === id).map((e, i) => ({ from: id, to: e.a === id ? e.b : e.a, tone: "var(--gpu)", delay: 150 + i * 60 })));
    const t0 = performance.now();
    const s = ctx.data.sessions.find((x) => x.machineId === id);
    const r = await post(ctx.base, ctx.mode, "/api/send", { toMachine: id, toSession: s?.session_id, message: "[ping] Fleet console test pulse", mode: "immediate", waitForReply: false, dryRun: true }, () => ({ ok: true }));
    const lat = Math.round(performance.now() - t0);
    const rid = `req-ping-${Date.now()}`;
    ctx.pushEvents([
      { id: `${rid}-r`, timestamp: new Date().toISOString(), type: "bridgeRpcResponse", target: "LINUX-CONSOLE", fromMachine: id, toMachine: "LINUX-CONSOLE", action: "ping", requestId: rid, summary: `ping ok · ${lat}ms`, payload: { ...r, ok: true, latencyMs: lat } },
      { id: `${rid}-q`, timestamp: new Date(Date.now() - lat).toISOString(), type: "bridgeRpcRequest", target: id, fromMachine: "LINUX-CONSOLE", toMachine: id, action: "ping", requestId: rid, summary: `ping → ${id}`, payload: { requestId: rid } },
    ]);
    return lat;
  };

  const edgeSel = selEdge ? topo.edges.find((e) => edgeKey(e.a, e.b) === selEdge) : undefined;
  const nodeSel = selNode ? topo.nodes.find((n) => n.id === selNode) : undefined;
  const reset = () => { setView({ x: 0, y: 0, k: 1 }); setOverrides((o) => ({ ...o, [lkey]: {} })); };

  return (
    <section ref={containerRef} className="topology-canvas relative overflow-hidden rounded-xl border border-border/60 bg-background/40" aria-label="Interactive fleet topology">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,color-mix(in_oklab,var(--busy)_4%,transparent),transparent_65%)]" />
      <div className="absolute left-5 top-5 z-20 hidden items-center gap-2 text-[10px] uppercase tracking-[0.18em] text-muted-foreground xl:flex"><Dot pulse={ctx.mode === "live"} tone={ctx.mode === "live" ? "online" : "muted"} />Connection graph</div>

      <GlassPanel className="absolute left-1/2 top-3 z-30 flex max-w-[calc(100%-16px)] -translate-x-1/2 items-center gap-0.5 rounded-full p-1 md:top-4">
        {([["mesh", "Mesh", Network], ["orbital", "Hub", Orbit], ["flocks", "Flocks", Layers], ["matrix", "Matrix", Grid3x3]] as const).map(([m, l, I]) => (
          <Btn key={m} aria-pressed={mode === m} onClick={() => { setMode(m); setSelEdge(null); setSelNode(null); }} className={`flex items-center gap-1 h-10 rounded-full px-2.5 text-[11px] transition md:h-8 ${mode === m ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground"}`}><I className="h-3.5 w-3.5 shrink-0" />{l}</Btn>
        ))}
      </GlassPanel>

      {mode !== "flocks" && <GlassPanel className="absolute left-1/2 top-[68px] z-30 flex w-max max-w-[calc(100%-16px)] -translate-x-1/2 items-center gap-0.5 rounded-full p-1 md:top-16 xl:left-auto xl:right-4 xl:top-4 xl:translate-x-0">
        {mode === "mesh" && <Btn onClick={() => setHub(!hub)} className={`h-10 rounded-full px-2.5 text-[11px] md:h-8 ${hub ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"}`}>Relay</Btn>}
        <Btn onClick={() => setHighOnly(!highOnly)} className={`h-10 rounded-full px-2.5 text-[11px] md:h-8 ${highOnly ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"}`}>High traffic</Btn>
        <span className="mx-0.5 h-4 w-px bg-border" />
        <IconBtn onClick={simulate} className="h-10 w-10 rounded-full md:h-8 md:w-8" aria-label="Simulate live traffic" title="Simulate live traffic"><Play className="h-3 w-3" /></IconBtn>
        <IconBtn onClick={replay} className="h-10 w-10 rounded-full md:h-8 md:w-8" aria-label="Replay recent history" title="Replay recent history"><History className="h-3 w-3" /></IconBtn>
      </GlassPanel>}

      {mode === "flocks" ? <FlockMembershipGraph flocks={flocks} error={flockError} W={W} H={H} portrait={portrait} /> : mode === "matrix" ? <Matrix topo={topo} onPick={(k) => { setSelEdge(k); setSelNode(null); }} sel={selEdge} /> : (
        <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} className="relative block h-full w-full cursor-grab touch-none select-none active:cursor-grabbing"
          onPointerDown={(e) => onDown(e)} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp} role="img" aria-label="Fleet connection graph. Line brightness and thickness show communication volume.">
          <defs>
            <filter id="edge-glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.5" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
            <filter id="node-glow" x="-150%" y="-150%" width="400%" height="400%"><feGaussianBlur stdDeviation="2" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
            <radialGradient id="aura-personal"><stop offset="0%" stopColor="var(--online)" stopOpacity="var(--graph-halo-opacity)" /><stop offset="100%" stopColor="var(--online)" stopOpacity="0" /></radialGradient>
            <radialGradient id="aura-work"><stop offset="0%" stopColor="var(--work)" stopOpacity="var(--graph-halo-opacity)" /><stop offset="100%" stopColor="var(--work)" stopOpacity="0" /></radialGradient>
            <radialGradient id="aura-hub"><stop offset="0%" stopColor="var(--busy)" stopOpacity="var(--graph-halo-opacity)" /><stop offset="100%" stopColor="var(--busy)" stopOpacity="0" /></radialGradient>
            <pattern id="graph-grid" width="48" height="48" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="0.65" fill="var(--border)" opacity="0.55" /></pattern>
          </defs>
          <rect width={W} height={H} fill="url(#graph-grid)" opacity={0.45} />
          <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {mode === "orbital" && !portrait && [150, 240, 330].map((r) => <ellipse key={r} cx={CX} cy={CY} rx={r * 1.55} ry={r} fill="none" stroke="var(--border)" strokeOpacity="0.45" strokeWidth="0.6" />)}
            {showHub && pos[HUB_ID] && topo.nodes.map((n) => pos[n.id] && (
              <g key={`hub-${n.id}`} opacity={selNode && selNode !== n.id ? 0.06 : 0.32}>
                <line x1={pos[HUB_ID].x} y1={pos[HUB_ID].y} x2={pos[n.id].x} y2={pos[n.id].y} stroke="var(--info)" strokeWidth="0.7" strokeDasharray="2 7" />
                <circle r={1.5} fill="var(--info)"><animateMotion dur={`${7 - (n.activity / maxA) * 3}s`} repeatCount="indefinite" path={`M${pos[n.id].x},${pos[n.id].y} L${pos[HUB_ID].x},${pos[HUB_ID].y}`} /></circle>
              </g>
            ))}
            {edges.map((e) => {
              const pa = pos[e.a], pb = pos[e.b]; if (!pa || !pb) return null;
              const k = edgeKey(e.a, e.b), r = weight(e) / maxW, c = sortedCurve(pos, e.a, e.b);
              const hot = Date.now() - new Date(e.lastActiveAt).getTime() < 6000;
              const tone = hot ? "var(--gpu)" : TONE[edgeTone(mById[e.a].scope, mById[e.b].scope)];
              const inc = !selNode || e.a === selNode || e.b === selNode;
              const active = selEdge === k;
              const fwd = pathD(pa, pb, c), back = pathD(pb, pa, c);
              const streams: [string, number][] = [[fwd, e.ab], [back, e.ba]];
              return (
                <g key={k} opacity={inc ? 1 : 0.06} className="cursor-pointer" role="button" tabIndex={0} aria-label={`Inspect corridor ${e.a} and ${e.b}`} onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { setSelEdge(k); setSelNode(null); } }} onPointerDown={(ev) => ev.stopPropagation()} onClick={() => { setSelEdge(k); setSelNode(null); }}>
                  <path d={fwd} stroke="transparent" strokeWidth={20} fill="none" />
                  <path d={fwd} stroke={tone} strokeWidth={0.7 + r * 5.8} strokeOpacity={0.1 + r * 0.48} fill="none" filter={r > 0.55 || active ? "url(#edge-glow)" : undefined} strokeLinecap="round" />
                  {active && <path d={fwd} stroke="var(--foreground)" strokeOpacity="0.7" strokeWidth="0.8" strokeDasharray="3 6" fill="none" />}
                  {streams.map(([d, n], si) => {
                    const count = Math.max(1, Math.min(4, Math.ceil(n / 5))); const dur = Math.max(2, 7 - n * 0.25);
                    return Array.from({ length: n ? count : 0 }, (_, i) => <circle key={`${si}-${i}`} r={1 + r * 1.6} fill={tone} opacity={0.45 + r * 0.45} filter={r > 0.65 ? "url(#edge-glow)" : undefined}><animateMotion dur={`${dur}s`} begin={`${(-i * dur) / count}s`} repeatCount="indefinite" path={d} /></circle>);
                  })}
                </g>
              );
            })}
            {bursts.map((b) => { const pa = pos[b.from], pb = pos[b.to]; if (!pa || !pb) return null;
              return <BurstDot key={b.id} d={pathD(pa, pb, b.from === HUB_ID || b.to === HUB_ID ? { x: (pa.x + pb.x) / 2, y: (pa.y + pb.y) / 2 } : sortedCurve(pos, b.from, b.to))} tone={b.tone} delay={b.delay} onDone={() => setBursts((x) => x.filter((y) => y.id !== b.id))} />; })}
            {showHub && pos[HUB_ID] && (
              <g transform={`translate(${pos[HUB_ID].x},${pos[HUB_ID].y})`} onPointerDown={(e) => onDown(e, HUB_ID)} className="cursor-move">
                <circle r={85} fill="url(#aura-hub)" />
                <g className="orbit-spin"><circle r={38} fill="none" stroke="var(--busy)" strokeOpacity="0.25" strokeWidth="0.8" strokeDasharray="2 9" /></g>
                <circle r={24} fill="var(--background)" stroke="var(--busy)" strokeOpacity="0.75" strokeWidth="1.2" filter="url(#node-glow)" />
                <circle r={5} fill="var(--busy)" opacity="0.9" />
                <text y={52} textAnchor="middle" className="fill-foreground font-mono text-[11px]">copilot-flock</text>
                <text y={67} textAnchor="middle" className="fill-muted-foreground font-mono text-[8px]">SignalR relay</text>
              </g>
            )}
            {topo.nodes.map((n) => {
              const p = pos[n.id]; if (!p) return null;
              const ratio = n.activity / maxA, r = portrait ? 18 + 10 * Math.sqrt(ratio) : 9 + 11 * Math.sqrt(ratio);
              const dim = selNode && selNode !== n.id && !neighbors.has(n.id);
              const toneVar = n.scope === "personal" ? "var(--online)" : "var(--work)";
              return (
                <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim ? 0.16 : 1} className="cursor-pointer outline-none" role="button" tabIndex={0} aria-label={`Inspect node ${n.id}`} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { setSelNode(n.id); setSelEdge(null); } }} onPointerDown={(e) => onDown(e, n.id)}>
                  <circle r={r * (2.5 + ratio)} fill={`url(#aura-${n.scope})`} opacity={0.45 + ratio * 0.55} />
                  {ratio > 0.7 && <g className="orbit-spin"><circle r={r + 9} fill="none" stroke={toneVar} strokeOpacity="0.3" strokeWidth="0.7" strokeDasharray="2 8" /></g>}
                  {shocks.filter((s) => s.node === n.id).map((s) => <circle key={s.id} r={r} fill="none" stroke="var(--gpu)" className="shockwave" onAnimationEnd={() => setShocks((x) => x.filter((y) => y.id !== s.id))} />)}
                  <circle r={r + 5} fill="var(--background)" fillOpacity="0.65" stroke={toneVar} strokeOpacity="0.09" />
                  <circle r={r} fill="var(--panel)" stroke={toneVar} strokeOpacity={selNode === n.id ? 1 : 0.65} strokeWidth={selNode === n.id ? 2 : 1.1} filter={ratio > 0.55 ? "url(#node-glow)" : undefined} />
                  <circle r={2.5 + ratio * 2.5} fill={toneVar} opacity={0.65 + ratio * 0.35} />
                  <text y={r + 24} textAnchor="middle" className={`fill-foreground font-mono font-medium ${portrait ? "text-[15px]" : "text-[10px]"}`}>{portrait && n.id.startsWith("DESKTOP-") ? <><tspan x={0}>DESKTOP-</tspan><tspan x={0} dy={18}>{n.id.slice(8)}</tspan></> : portrait && n.id.startsWith("LAPTOP-") ? <><tspan x={0}>LAPTOP-</tspan><tspan x={0} dy={18}>{n.id.slice(7)}</tspan></> : n.id}</text>
                  <text y={r + (portrait ? 66 : 36)} textAnchor="middle" className={`fill-muted-foreground font-mono ${portrait ? "text-[12px]" : "text-[8px]"}`}>{n.activity} messages</text>
                </g>
              );
            })}
          </g>
        </svg>
      )}

      {mode !== "flocks" && <div className="pointer-events-none absolute bottom-16 left-4 z-10 flex items-center gap-3 md:bottom-5 md:left-5 md:gap-4 font-mono text-[9px] text-muted-foreground"><span>{topo.edges.length} corridors</span><span>{totalMessages} messages</span><span className="hidden sm:inline">Thickness = traffic</span></div>}
      {mode !== "matrix" && mode !== "flocks" && <GlassPanel className="absolute bottom-4 right-4 z-20 flex items-center gap-0.5 rounded-full p-1">
        <IconBtn onClick={() => zoomBy(0.8)} className="h-10 w-10 rounded-full md:h-7 md:w-7" aria-label="Zoom out"><Minus className="h-3 w-3" /></IconBtn>
        <span className="w-10 text-center font-mono text-[9px] text-muted-foreground">{Math.round(view.k * 100)}%</span>
        <IconBtn onClick={() => zoomBy(1.25)} className="h-10 w-10 rounded-full md:h-7 md:w-7" aria-label="Zoom in"><Plus className="h-3 w-3" /></IconBtn>
        <IconBtn onClick={reset} className="h-10 w-10 rounded-full md:h-7 md:w-7" aria-label="Reset view"><Maximize2 className="h-3 w-3" /></IconBtn>
      </GlassPanel>}
      {mode !== "flocks" && !nodeSel && !edgeSel && <div className="pointer-events-none absolute bottom-5 left-1/2 z-10 hidden -translate-x-1/2 items-center gap-2 text-[10px] text-muted-foreground/70 lg:flex"><Activity className="h-3 w-3" />Select a machine or corridor to inspect</div>}

      {nodeSel && <NodeInspector ctx={ctx} n={nodeSel} m={mById[nodeSel.id]} topo={topo} onClose={() => setSelNode(null)} onPing={ping} onEdge={(k) => { setSelEdge(k); setSelNode(null); }} />}
      {edgeSel && <CorridorInspector ctx={ctx} e={edgeSel} extra={extra[edgeKey(edgeSel.a, edgeSel.b)] ?? []} onClose={() => setSelEdge(null)}
        onSent={(msg) => { setExtra((x) => ({ ...x, [edgeKey(msg.from, msg.to)]: [msg, ...(x[edgeKey(msg.from, msg.to)] ?? [])] })); fire([{ from: msg.from, to: msg.to, tone: "var(--gpu)", delay: 0 }, { from: msg.from, to: msg.to, tone: "var(--gpu)", delay: 150 }]); }} />}
    </section>
  );
}

function InspectorShell({ title, subtitle, onClose, children }: { title: string; subtitle?: string; onClose: () => void; children: React.ReactNode }) {
  return <GlassPanel className="graph-inspector enter-up z-40 flex min-w-0 flex-col overflow-hidden bg-background/95" >
    <div className="flex items-start gap-3 border-b border-border/60 p-5" onPointerDown={(e) => e.stopPropagation()}><div className="min-w-0"><h3 className="break-words font-mono text-xs font-medium">{title}</h3>{subtitle && <p className="mt-1 text-[10px] text-muted-foreground">{subtitle}</p>}</div><IconBtn onClick={onClose} className="ml-auto -mr-2 -mt-2" aria-label="Close inspector"><X className="h-4 w-4" /></IconBtn></div>
    <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-5" onPointerDown={(e) => e.stopPropagation()}>{children}</div>
  </GlassPanel>;
}

function NodeInspector({ ctx, n, m, topo, onClose, onPing, onEdge }: { ctx: Ctx; n: TopoNode; m: Member; topo: ReturnType<typeof deriveTopology>; onClose: () => void; onPing: (id: string) => Promise<number>; onEdge: (k: string) => void }) {
  const [lat, setLat] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const peers = topo.edges.filter((e) => e.a === n.id || e.b === n.id).map((e) => ({ id: e.a === n.id ? e.b : e.a, v: e.ab + e.ba, k: edgeKey(e.a, e.b) })).sort((a, b) => b.v - a.v);
  const maxP = Math.max(1, ...peers.map((p) => p.v));
  const sessions = ctx.data.sessions.filter((s) => s.machineId === n.id);
  return <InspectorShell title={n.id} subtitle={`${n.scope} · ${n.activeSessionCount} active sessions`} onClose={onClose}>
    <div className="grid grid-cols-3 gap-4 pb-5"><div><div className="font-mono text-lg">{n.sent}</div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Sent</div></div><div><div className="font-mono text-lg">{n.received}</div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Received</div></div><div><div className="font-mono text-lg">{n.broadcasts}</div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Broadcast</div></div></div>
    <Btn variant="outline" className="w-full" disabled={busy} onClick={async () => { setBusy(true); setLat(await onPing(n.id)); setBusy(false); }}><Crosshair className="h-3.5 w-3.5" />{busy ? "Pinging…" : "Send test pulse"}</Btn>
    {lat !== null && <div className="mt-2 text-center font-mono text-[10px] text-online">Acknowledged in {lat}ms {ctx.mode === "seed" && "· simulated"}</div>}
    <div className="mt-6"><div className="mb-3 text-[10px] uppercase tracking-widest text-muted-foreground">Strongest connections</div><div className="space-y-3">{peers.map((p) => <button key={p.id} onClick={() => onEdge(p.k)} className="block w-full text-left"><div className="flex justify-between font-mono text-[10px]"><span className="truncate">{p.id}</span><span className="text-muted-foreground">{p.v}</span></div><div className="mt-1.5 h-px bg-muted"><div className="h-px bg-busy" style={{ width: `${(p.v / maxP) * 100}%` }} /></div></button>)}</div></div>
    <ReplayHealth member={m} />
    <details className="group mt-6 border-t border-border/60 pt-4"><summary className="cursor-pointer text-xs text-muted-foreground group-open:text-foreground">Hardware</summary><div className="mt-3 space-y-2 text-[11px] leading-5 text-muted-foreground"><div>{m.specs.cpu.model} · {m.specs.cpu.logicalCores} threads</div><div>{m.specs.memory.totalGb} GB RAM · {m.specs.memory.freeGb} GB free</div><div>{m.specs.gpus.map(gpuLabel).join(", ") || "No GPU"}</div></div></details>
    <details className="group mt-4 border-t border-border/60 pt-4"><summary className="cursor-pointer text-xs text-muted-foreground group-open:text-foreground">Sessions <span className="font-mono text-[10px]">{sessions.length}</span></summary><div className="mt-2 space-y-1">{sessions.map((s) => <button key={s.session_id} onClick={() => ctx.openSession(s)} className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-[11px] hover:bg-accent/50"><Dot tone={s.is_running ? "busy" : "muted"} /><span className="truncate">{s.title}</span></button>)}</div></details>
  </InspectorShell>;
}

function CorridorInspector({ ctx, e, extra, onClose, onSent }: { ctx: Ctx; e: TopoEdge; extra: LinkMessage[]; onClose: () => void; onSent: (m: LinkMessage) => void }) {
  const [dir, setDir] = useState<"ab" | "ba">("ab");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [from, to] = dir === "ab" ? [e.a, e.b] : [e.b, e.a];
  const msgs = [...extra, ...e.messages].sort((x, y) => y.timestamp.localeCompare(x.timestamp));
  const send = async () => {
    setBusy(true);
    const pair = e.threadPairs[0];
    const target = ctx.data.sessions.find((s) => s.machineId === to && pair && (s.title === pair[0] || s.title === pair[1])) ?? ctx.data.sessions.find((s) => s.machineId === to);
    const body = { toMachine: to, toSession: target?.session_id, message: text, mode: "immediate", waitForReply: false, dryRun: false, fromMachine: from };
    await post(ctx.base, ctx.mode, "/api/send", body, () => ({ ok: true, delivered: true }));
    const msg: LinkMessage = { id: `lm-${Date.now()}`, from, to, fromThread: "Fleet console", toThread: target?.title ?? "—", text, timestamp: new Date().toISOString() };
    onSent(msg);
    ctx.pushEvents([{ id: `evt-${Date.now()}`, timestamp: msg.timestamp, type: "outbox", target: to, fromMachine: from, toMachine: to, action: "send_message", summary: `corridor send ${from} → ${to}`, payload: body }]);
    setText(""); setBusy(false);
  };
  return <InspectorShell title={`${e.a} ↔ ${e.b}`} subtitle={`${e.ab + e.ba} messages · ${e.rpc} RPC calls`} onClose={onClose}>
    <div className="grid grid-cols-2 gap-5"><div><div className="font-mono text-lg">{e.ab}<span className="ml-1 text-xs text-muted-foreground">/ {e.ba}</span></div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Forward / return</div></div><div><div className="font-mono text-lg">{e.avgLatencyMs}<span className="ml-1 text-xs text-muted-foreground">ms</span></div><div className="mt-1 text-[9px] uppercase tracking-widest text-muted-foreground">Average latency</div></div></div>
    <div className="mt-6"><div className="mb-3 text-[10px] uppercase tracking-widest text-muted-foreground">Send across corridor</div><div className="mb-2 flex gap-1">{(["ab", "ba"] as const).map((d) => <button key={d} onClick={() => setDir(d)} className={`flex-1 truncate rounded-lg px-2 py-2 font-mono text-[9px] ${dir === d ? "bg-accent text-foreground" : "text-muted-foreground"}`}>{d === "ab" ? `${e.a} →` : `${e.b} →`}</button>)}</div><div className="flex gap-2"><Input value={text} onChange={(ev) => setText(ev.target.value)} placeholder={`Message ${to}`} /><Btn variant="primary" disabled={!text || busy} onClick={send} aria-label="Send corridor message"><Send className="h-3.5 w-3.5" /></Btn></div></div>
    {e.threadPairs.length > 0 && <details className="group mt-6 border-t border-border/60 pt-4"><summary className="cursor-pointer text-xs text-muted-foreground group-open:text-foreground">Thread pairs</summary><div className="mt-3 space-y-2">{e.threadPairs.map(([x, y]) => <div key={x + y} className="text-[11px] leading-5 text-muted-foreground">{x}<br /><span className="text-busy">↕</span> {y}</div>)}</div></details>}
    <details className="group mt-4 border-t border-border/60 pt-4" open={msgs.length < 4}><summary className="cursor-pointer text-xs text-muted-foreground group-open:text-foreground">Recent messages <span className="font-mono text-[10px]">{msgs.length}</span></summary><div className="mt-3 space-y-5">{msgs.map((m) => <article key={m.id} className="min-w-0 border-b border-border/40 pb-4 last:border-0"><div className="flex items-start justify-between gap-2 font-mono text-[9px] text-muted-foreground"><span className="min-w-0 break-words">{m.from} → {m.to}</span><span className="shrink-0">{rel(m.timestamp)}</span></div><div className="mb-3 mt-1.5 text-[10px] leading-4 text-muted-foreground">{m.fromThread} <span className="text-info">→</span> {m.toThread}</div><SmartMessage text={m.text} compact /></article>)}</div></details>
  </InspectorShell>;
}

function Matrix({ topo, onPick, sel }: { topo: ReturnType<typeof deriveTopology>; onPick: (k: string) => void; sel: string | null }) {
  const ids = [...topo.nodes].sort((a, b) => b.activity - a.activity).map((n) => n.id);
  const cell = (f: string, t: string) => { const e = topo.edges.find((x) => edgeKey(x.a, x.b) === edgeKey(f, t)); return e ? { e, v: e.a === f ? e.ab : e.ba } : null; };
  const max = Math.max(1, ...topo.edges.flatMap((e) => [e.ab, e.ba]));
  return <div className="no-scrollbar h-full overflow-auto overscroll-contain px-3 pt-36 pb-24 md:flex md:items-center md:px-6"><table className="mx-auto min-w-[850px] border-separate border-spacing-1 font-mono text-[11px]"><thead><tr><th />{ids.map((id) => <th key={id} className="w-28 max-w-28 truncate px-2 pb-3 text-left font-normal text-muted-foreground">{id}</th>)}</tr></thead><tbody>{ids.map((f) => <tr key={f}><th className="sticky left-0 z-10 bg-background pr-4 text-right font-normal text-muted-foreground">{f}</th>{ids.map((t) => { if (f === t) return <td key={t} className="h-14 w-28 rounded-lg bg-muted/15" />; const c = cell(f, t); return <td key={t} onClick={() => c && onPick(edgeKey(f, t))} className={`h-14 w-28 cursor-pointer rounded-lg border text-center transition ${sel === edgeKey(f, t) ? "border-foreground/60" : "border-border/40 hover:border-border"}`} style={{ background: c ? `color-mix(in oklab, var(--busy) ${Math.round((c.v / max) * 45)}%, transparent)` : undefined }}>{c ? <><div className="text-sm text-foreground">{c.v}</div><div className="mt-1 text-muted-foreground">{c.e.avgLatencyMs}ms</div></> : <span className="text-muted-foreground/30">·</span>}</td>; })}</tr>)}</tbody></table></div>;
}
