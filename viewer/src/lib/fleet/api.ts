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

export async function fetchOverview(base: string): Promise<{ data: Overview; mode: Mode }> {
  try {
    const data = await req<Overview>(base, "/api/overview", undefined, 10000);
    if (!data?.members) throw new Error("bad");
    return { data: normalizeLegacyScopes(data), mode: "live" };
  } catch {
    const s = getSeed();
    s.hub.lastUpdatedAt = new Date().toISOString();
    return { data: { ...s }, mode: "seed" };
  }
}

export async function fetchTranscript(base: string, mode: Mode, s: Session) {
  if (mode === "live") {
    try {
      return await req<ReturnType<typeof seedTranscript>>(
        base,
        `/api/transcript?machine=${encodeURIComponent(s.machineId)}&session=${encodeURIComponent(s.session_id)}&limit=20`,
        undefined,
        15000
      );
    } catch (err) {
      const fallback = seedTranscript(s);
      return {
        ...fallback,
        simulated: true,
        fallbackReason: err instanceof Error ? err.message : String(err),
      };
    }
  }
  return { ...seedTranscript(s), simulated: true };
}

export async function fetchProjects(base: string, mode: Mode, machineId: string, sessions: Session[], scope: "personal" | "work") {
  if (mode === "live") {
    try {
      return await req<ReturnType<typeof seedProjects>>(
        base,
        `/api/projects?machine=${encodeURIComponent(machineId)}`,
        undefined,
        15000
      );
    } catch (err) {
      return {
        ...seedProjects(machineId, sessions, scope),
        simulated: true,
        fallbackReason: err instanceof Error ? err.message : String(err),
      };
    }
  }
  return { ...seedProjects(machineId, sessions, scope), simulated: true };
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function post<T = Record<string, unknown>>(
  base: string,
  mode: Mode,
  path: string,
  body: Record<string, unknown>,
  simulate: () => T
): Promise<T & { simulated?: boolean }> {
  if (mode === "live") {
    return (await req<T>(base, path, { method: "POST", body: JSON.stringify(body) }, 120000)) as T & { simulated?: boolean };
  }
  await delay(400 + Math.random() * 600);
  return { ...simulate(), simulated: true };
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
