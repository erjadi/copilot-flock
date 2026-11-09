import type { Member, Overview, Scope, WireEvent } from "./types";

export interface LinkMessage { id: string; from: string; to: string; fromThread: string; toThread: string; text: string; timestamp: string }
export interface TopoEdge {
  a: string; b: string; ab: number; ba: number; rpc: number; avgLatencyMs: number; peakAt: string;
  threadPairs: [string, string][]; messages: LinkMessage[]; lastActiveAt: string;
}
export interface TopoNode { id: string; scope: Scope; sent: number; received: number; broadcasts: number; activeSessionCount: number; activity: number; online: boolean }
export interface Topology { nodes: TopoNode[]; edges: TopoEdge[] }

export const HUB_ID = "copilot-flock";
export const edgeKey = (a: string, b: string) => [a, b].sort().join("|");
export const weight = (e: TopoEdge) => e.ab + e.ba + e.rpc * 0.5;

type Seed = [string, string, number, number, number, number, [string, string][]];
const SEED: Seed[] = [
  ["MAIN-WORKSTATION", "3D-STUDIO-PC", 18, 14, 46, 92, [["Robotics stage coordination", "Copilot Flock Coordinator"], ["Rendering pipeline", "Lumen shader consultation"]]],
  ["MAIN-WORKSTATION", "MINI-SERVER-PC", 14, 11, 30, 120, [["SignalR bridge internal viewer", "Copilot Flock Coordinator"]]],
  ["MAIN-WORKSTATION", "ARM64-LAPTOP", 10, 8, 22, 160, [["Stage event routing", "SignalR bridge setup"], ["SignalR bridge internal viewer", "Copilot Flock Coordinator"]]],
  ["MAIN-WORKSTATION", "CLOUD-DEV-VM", 7, 6, 18, 210, [["Bridge presence heartbeat", "Copilot Flock Coordinator"]]],
  ["MAIN-WORKSTATION", "LINUX-GPU-HOST", 8, 5, 20, 70, [["Robotics stage coordination", "Robotics simulation"]]],
  ["ARM64-LAPTOP", "CLOUD-DEV-VM", 9, 7, 16, 140, [["Cross-channel messaging gateway", "Service API and Azure analysis"], ["Copilot PC specs", "Product identifier service"]]],
  ["3D-STUDIO-PC", "LINUX-GPU-HOST", 5, 4, 12, 80, [["Robotics simulation status", "Robotics simulation"]]],
  ["3D-STUDIO-PC", "MINI-SERVER-PC", 3, 3, 8, 110, [["Copilot Flock Coordinator", "Copilot Flock Coordinator"]]],
  ["3D-STUDIO-PC", "ARM64-LAPTOP", 3, 2, 6, 180, [["Signalr bridge transcript tail fix", "Copilot Flock Coordinator"]]],
  ["MINI-SERVER-PC", "CLOUD-DEV-VM", 2, 1, 4, 230, [["Copilot Flock Coordinator", "Copilot Flock Coordinator"]]],
  ["LINUX-GPU-HOST", "ARM64-LAPTOP", 1, 1, 2, 250, [["Robotics simulation", "Copilot PC specs"]]],
  ["MAIN-WORKSTATION", "LINUX-CONSOLE", 6, 4, 14, 48, [["SignalR bridge internal viewer", "Copilot Flock Console"]]],
  ["3D-STUDIO-PC", "LINUX-CONSOLE", 3, 2, 10, 52, [["Copilot Flock Coordinator", "Copilot Flock Console"]]],
];
const TEXTS = ["Status sync: can you confirm your branch is green?", "Pushed the fix — please pull and re-run the transcript tail.", "Ack. Picking it up on the next turn.", "Here are the latest render timings, see attached summary.", "Heads-up: bumping bridge to 1.7.0 on this node.", "Done. Reply envelope attached."];

function seedEdges(): TopoEdge[] {
  return SEED.map(([a, b, ab, ba, rpc, lat, pairs], i) => {
    const [ca, cb] = [a, b].sort();
    const isSorted = ca === a;
    const normAb = isSorted ? ab : ba;
    const normBa = isSorted ? ba : ab;
    const messages: LinkMessage[] = Array.from({ length: Math.min(6, Math.ceil((ab + ba) / 4)) }, (_, j) => {
      const fwd = j % 2 === 0; const [ta, tb] = pairs[j % pairs.length];
      return { id: `lm-${i}-${j}`, from: fwd ? a : b, to: fwd ? b : a, fromThread: fwd ? ta : tb, toThread: fwd ? tb : ta, text: TEXTS[(i + j) % TEXTS.length], timestamp: new Date(Date.now() - (j * 11 + i * 3 + 2) * 60000).toISOString() };
    });
    return { a: ca, b: cb, ab: normAb, ba: normBa, rpc, avgLatencyMs: lat, peakAt: `${String(9 + (i % 9)).padStart(2, "0")}:${i % 2 ? "30" : "00"}`, threadPairs: pairs, messages, lastActiveAt: messages[0].timestamp };
  });
}

/** Builds topology from backend `topology` when present, otherwise seed corridors + live peer events. */
export function deriveTopology(data: Overview & { topology?: Topology }, events: WireEvent[], members: Member[]): Topology {
  const ids = new Set(members.map((m) => m.machineId));
  const map = new Map<string, TopoEdge>();
  for (const e of (data.topology?.edges ?? seedEdges())) {
    if (ids.has(e.a) && ids.has(e.b)) {
      const [ca, cb] = [e.a, e.b].sort();
      const isSorted = ca === e.a;
      map.set(edgeKey(e.a, e.b), {
        ...e,
        a: ca,
        b: cb,
        ab: isSorted ? e.ab : e.ba,
        ba: isSorted ? e.ba : e.ab,
        messages: [...(e.messages || [])],
      });
    }
  }
  const reqAt = new Map<string, number>();
  for (const ev of [...events].reverse()) {
    if (!ids.has(ev.fromMachine)) continue;
    const targets = (ev.toMachine || "").split(",").filter((t) => ids.has(t) && t !== ev.fromMachine);
    for (const to of targets) {
      const k = edgeKey(ev.fromMachine, to);
      let e = map.get(k);
      if (!e) { const [a, b] = [ev.fromMachine, to].sort(); e = { a, b, ab: 0, ba: 0, rpc: 0, avgLatencyMs: 0, peakAt: "—", threadPairs: [], messages: [], lastActiveAt: ev.timestamp }; map.set(k, e); }
      if (ev.type === "bridgeRpcRequest") { e.rpc++; if (ev.requestId) reqAt.set(ev.requestId, new Date(ev.timestamp).getTime()); }
      if (ev.type === "bridgeRpcResponse" && ev.requestId && reqAt.has(ev.requestId)) {
        const lat = Math.max(1, new Date(ev.timestamp).getTime() - reqAt.get(ev.requestId)!);
        e.avgLatencyMs = e.avgLatencyMs ? Math.round(e.avgLatencyMs * 0.8 + lat * 0.2) : lat;
      }
      if (ev.type === "outbox" || ev.action === "send_message") { if (ev.fromMachine === e.a) e.ab++; else e.ba++; }
      e.lastActiveAt = ev.timestamp;
    }
  }
  const edges = [...map.values()];
  const nodes: TopoNode[] = members.map((m) => {
    const sent = edges.reduce((s, e) => s + (e.a === m.machineId ? e.ab : e.b === m.machineId ? e.ba : 0), 0);
    const received = edges.reduce((s, e) => s + (e.a === m.machineId ? e.ba : e.b === m.machineId ? e.ab : 0), 0);
    const broadcasts = events.filter((ev) => ev.fromMachine === m.machineId && (ev.toMachine || "").includes(",")).length;
    return { id: m.machineId, scope: m.scope, sent, received, broadcasts, activeSessionCount: m.activeSessionCount, activity: sent + received + m.activeSessionCount, online: m.online };
  });
  return { nodes, edges };
}

export const edgeTone = (sa?: Scope, sb?: Scope) => (sa === sb ? (sa === "personal" ? "online" : "work") : "busy");
