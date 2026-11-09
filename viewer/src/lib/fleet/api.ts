import { buildSeed, seedProjects, seedTranscript } from "./seed";
import type { Overview, Session } from "./types";

export type Mode = "live" | "seed";

export async function req<T>(base: string, path: string, init?: RequestInit, timeout = 8000): Promise<T> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(`${base.replace(/\/$/, "")}${path}`, {
      ...init,
      signal: ctl.signal,
      headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    });
    if (!r.ok) throw new Error(`${r.status}`);
    const ct = r.headers.get("content-type") || "";
    if (!ct.includes("json")) throw new Error("not json");
    return (await r.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

let seedCache: Overview | null = null;
export const getSeed = () => (seedCache ??= buildSeed());

export function emptyOverview(): Overview {
  return { hub: { machineId: "", endpoint: "", hub: "", version: "", viewerHost: "", connected: false, lastUpdatedAt: "" }, members: [], sessions: [], events: [] };
}

export async function fetchOverview(base: string, mode: Mode = "live"): Promise<{ data: Overview; mode: Mode }> {
  if (mode === "seed") return { data: getSeed(), mode };
  if (mode !== "live") throw new Error("Select live or explicit preview mode.");
  const data = await req<Overview>(base, "/api/overview", undefined, 10000);
  if (!Array.isArray(data?.members) || !Array.isArray(data.sessions) || !Array.isArray(data.events) ||
      typeof data.hub?.machineId !== "string" || !data.hub.machineId.trim()) throw new Error("Incomplete live overview or missing local machine identity.");
  return { data: normalizeLegacyScopes(data), mode };
}

export async function fetchTranscript(base: string, mode: Mode, s: Session) {
  if (mode === "live") {
    return await req<ReturnType<typeof seedTranscript>>(
        base,
        `/api/transcript?machine=${encodeURIComponent(s.machineId)}&session=${encodeURIComponent(s.session_id)}&limit=20`,
        undefined,
        15000
    );
  }
  return { ...seedTranscript(s), simulated: true };
}

export async function fetchProjects(base: string, mode: Mode, machineId: string, sessions: Session[], scope: "personal" | "work") {
  if (mode === "live") {
    return await req<ReturnType<typeof seedProjects>>(
        base,
        `/api/projects?machine=${encodeURIComponent(machineId)}`,
        undefined,
        15000
    );
  }
  return { ...seedProjects(machineId, sessions, scope), simulated: true };
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function post<T = Record<string, unknown>>(
  base: string,
  mode: Mode,
  path: string,
  body: Record<string, unknown>,
  simulate: () => T,
  timeout = 120000
): Promise<T & { simulated?: boolean }> {
  if (mode === "live") {
    return (await req<T>(base, path, { method: "POST", body: JSON.stringify(body) }, timeout)) as T & { simulated?: boolean };
  }
  if (mode !== "seed") throw new Error("Simulation requires explicitly selected preview mode.");
  await delay(400 + Math.random() * 600);
  return { ...simulate(), simulated: true };
}

export const isExpectedCommit = (value: string) => /^[0-9a-f]{40}$/.test(value);

export interface VoteResult { expectedCommit: string; approvedForMerge: boolean; accepted: number; total: number }
export function readVoteResult(value: unknown, expectedCommit: string): VoteResult {
  if (!isExpectedCommit(expectedCommit) || !value || typeof value !== "object" ||
      !("expectedCommit" in value) || value.expectedCommit !== expectedCommit ||
      !("approvedForMerge" in value) || typeof value.approvedForMerge !== "boolean" ||
      !("accepted" in value) || typeof value.accepted !== "number" || !Number.isSafeInteger(value.accepted) ||
      !("total" in value) || typeof value.total !== "number" || !Number.isSafeInteger(value.total) ||
      value.accepted < 0 || value.total < value.accepted ||
      (value.approvedForMerge && (value.total === 0 || value.accepted !== value.total))) {
    throw new Error("Malformed or mismatched exact-source vote result; merge remains blocked.");
  }
  return { expectedCommit, approvedForMerge: value.approvedForMerge, accepted: value.accepted, total: value.total };
}

export function envelope(fromSession: string, toMachine: string, toSession: string, message: string, mode: string) {
  return `<cross_session_message from_machine="LINUX-CONSOLE" from_session="${fromSession}" to_machine="${toMachine}" to_session="${toSession}" delivery="${mode}" sent_at="${new Date().toISOString()}">\n${message}\n</cross_session_message>`;
}

/** Normalize only scope fields; raw technical payloads and unrelated prose remain intact. */
export function normalizeLegacyScopes<T>(value: T): T {
  if (Array.isArray(value)) return value.map(normalizeLegacyScopes) as T;
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, /^(scope|from_scope|to_scope)$/i.test(key) && item === "private" ? "personal" : normalizeLegacyScopes(item)])) as T;
  return value;
}
