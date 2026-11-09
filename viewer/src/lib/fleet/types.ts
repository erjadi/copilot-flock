export type Scope = "personal" | "work";
export interface Gpu { name: string; vramGb: number | null; vramFreeGb?: number | null; utilizationPct?: number | null }
export interface Disk { mount: string; label: string | null; type: "fixed" | "network"; totalGb: number; freeGb: number }
export interface Specs {
  model: string | null; os: string;
  publicKey?: string | null; keyFingerprint?: string | null;
  cpu: { model: string; logicalCores: number; physicalCores: number | null; arch: string };
  memory: { totalGb: number; freeGb: number };
  gpus: Gpu[]; disks: Disk[];
}
export interface Session {
  machineId: string; scope: Scope; githubUser: string; session_id: string; workspace_id: string | null;
  title: string; session_type: string; is_running: boolean; mode: string; model: string | null;
  repo: string | null; branch: string | null; path: string | null; updated_at: string;
}
export interface Member {
  offlineReplay?: { processedCount: number; pendingAckCount: number; inFlightCount: number; ambiguousCount: number };
  machineId: string; online: boolean; githubUser: string; githubName: string | null; scope: Scope; version: string;
  copilotDesktopRunning: boolean; wsPort: number | null; activeSessionCount: number;
  registeredAt: string | null; lastSeenAt: string | null; recentSessions: { session_id: string; title: string }[]; specs: Specs;
}
export interface WireEvent {
  id: string; timestamp: string; type: "bridgePresence" | "bridgeRpcRequest" | "bridgeRpcResponse" | "inbox" | "outbox";
  target: string; fromMachine: string; toMachine: string; action: string; requestId?: string; summary: string; payload: unknown;
}
export interface Hub { endpoint: string; hub: string; version: string; viewerHost: string; connected: boolean; lastUpdatedAt: string }
export interface Overview { hub: Hub; members: Member[]; sessions: Session[]; events: WireEvent[]; topology?: import("./topology").Topology }
export interface Message { role: "user" | "assistant"; messageId: string; turnId: string | null; timestamp: string | null; content: string; toolCalls?: string[] }
export interface Transcript { machineId: string; session: Pick<Session, "session_id" | "title" | "repo" | "branch" | "session_type" | "is_running">; messages: Message[] }
export interface Project { project_id: string; name: string; repo: string; container_kind: string; path: string | null; default_branch: string | null }
