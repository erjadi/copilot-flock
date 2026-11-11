import { normalizeLegacyScopes, req, type Mode } from "./api";
import type { Member, Overview } from "./types";

export interface FlockMember { machineId: string; peerId: string; membershipExpiresAt: string | null }
export interface Flock {
  flockId: string; flockUuid: string; hubName: string; rosterEpoch: number;
  kind: "owner_root" | "owner_scope" | "collaborator" | "guest";
  trustTier: "owner" | "collaborator" | "guest";
  sessionVisibility: "all" | "explicit_opt_in_only"; members: FlockMember[];
}
export interface SharedThread { sessionId: string; title: string; machineId: string; sharingMode: "approved-snapshot" | "dedicated-collaborator-session"; boundFlockId: string }
export interface FlockState { flocks: Flock[]; sharedThreads: SharedThread[]; maintainer: Record<string, unknown> }
export interface FlockSnapshot { base: string; mode: Mode; state: FlockState; error: string | null }
export interface InviteInput { targetPath: string; githubHandle: string; durationMinutes: number | null; maxDevices: number }
export interface InviteResult { copilotPrompt: string; enrollment: Record<string, unknown>; simulated?: boolean }
export const GUEST_DURATIONS = [120, 480, 1440] as const;
export const HARD_WALLS = ["Pre-LLM Daemon Enforcement", "Owner-Only Auto-Trackers", "HMAC boundFlockId Taint-Tagging", "Flock-Partitioned Storage & Live Eviction"];

export function currentFlocks(snapshot: FlockSnapshot | null, base: string, mode: Mode, overviewBase: string | null): { state: FlockState; error: string | null } {
  if (overviewBase !== base || !snapshot || snapshot.base !== base || snapshot.mode !== mode) {
    return { state: { flocks: [], sharedThreads: [], maintainer: {} }, error: "Loading flock authority..." };
  }
  return { state: snapshot.state, error: snapshot.error };
}

export function seedFlocks(members: Member[]): FlockState {
  const paths = ["erjadi", "example/personal", "example/work", "example/studio-team", "example/work/CLOUD-DEV-VM"];
  const flocks = paths.map((flockId, i): Flock => {
    const flockUuid = `00000000-0000-4000-8000-00000000000${i + 1}`;
    const roster = members.filter((m) => i === 0 || (i === 1 && m.scope === "personal") || (i === 2 && m.scope === "work") || (i === 3 && ["CLOUD-DEV-VM", "ARM64-LAPTOP", "LINUX-GPU-HOST"].includes(m.machineId)) || (i === 4 && m.machineId === "CLOUD-DEV-VM"));
    return { flockId, flockUuid, hubName: `v3_flock_${flockUuid.replace(/-/g, "")}`, rosterEpoch: 7,
      kind: i === 0 ? "owner_root" : i < 3 ? "owner_scope" : i === 3 ? "collaborator" : "guest",
      trustTier: i < 3 ? "owner" : i === 3 ? "collaborator" : "guest", sessionVisibility: i < 3 ? "all" : "explicit_opt_in_only",
      members: roster.map((m, j) => ({ machineId: m.machineId, peerId: `demo-owner:${m.specs.keyFingerprint || `demo-fingerprint-${j + 1}`}`, membershipExpiresAt: i === 4 ? new Date(Date.now() + 120 * 60000).toISOString() : null })) };
  });
  return { flocks, sharedThreads: [], maintainer: { owner: "erjadi", activeFlocks: flocks.length, status: "Preview fixture" } };
}

// Membership-only projection: never attach sessions, messages or live event histories.
export function flockMemberships(flocks: Flock[], now = Date.now()) {
  const ids = [...new Set(flocks.flatMap((f) => f.members.filter((m) => !m.membershipExpiresAt || Date.parse(m.membershipExpiresAt) > now).map((m) => m.machineId)))];
  return ids.map((machineId) => {
    const memberships = flocks.filter((f) => f.members.some((m) => m.machineId === machineId && (!m.membershipExpiresAt || Date.parse(m.membershipExpiresAt) > now)));
    const scopes = memberships.filter((f) => f.kind !== "owner_root");
    return { machineId, memberships, overlap: scopes.length > 1 };
  }).sort((a, b) => Number(b.overlap) - Number(a.overlap) || b.memberships.length - a.memberships.length || a.machineId.localeCompare(b.machineId));
}

export async function fetchFlocks(base: string): Promise<FlockState> {
  const [roster, maintainer, audit] = await Promise.all([
    req<{ flocks?: Flock[]; ownedFlocks?: Flock[]; joinedFlocks?: Flock[] } | Flock[]>(base, "/api/v3/my-flocks"),
    req<Record<string, unknown>>(base, "/api/v3/maintainer/overview"),
    req<{ threads?: SharedThread[]; sharedThreads?: SharedThread[] } | SharedThread[]>(base, "/api/v3/shared-threads"),
  ]);
  const flocks = Array.isArray(roster) ? roster : (roster.flocks ?? roster.ownedFlocks ?? []);
  const sharedThreads = Array.isArray(audit) ? audit : (audit.threads ?? audit.sharedThreads ?? []);
  if (!Array.isArray(flocks) || !Array.isArray(sharedThreads) || flocks.some((f) => !Array.isArray(f.members))) throw new Error("Incomplete v3 roster or sharing audit response");
  return normalizeLegacyScopes({ flocks, sharedThreads, maintainer });
}

export function filterFlock(data: Overview, flock: Flock | undefined, threads: SharedThread[], now = Date.now()): Overview {
  if (!flock) return { ...data, members: [], sessions: [], events: [], topology: { nodes: [], edges: [] } };
  const ids = new Set(flock.members.filter((m) => !m.membershipExpiresAt || new Date(m.membershipExpiresAt).getTime() > now).map((m) => m.machineId));
  const permitted = new Set(threads.filter((t) => t.boundFlockId === flock.flockId).map((t) => t.sessionId));
  const external = flock.sessionVisibility !== "all";
  const sessions = data.sessions.filter((s) => ids.has(s.machineId) && (!external || permitted.has(s.session_id)));
  return { ...data, members: data.members.filter((m) => ids.has(m.machineId)).map((m) => external ? { ...m, recentSessions: m.recentSessions.filter((s) => permitted.has(s.session_id)), activeSessionCount: sessions.filter((s) => s.machineId === m.machineId).length } : m), sessions, events: external ? [] : data.events.filter((e) => ids.has(e.fromMachine) && (e.toMachine || "").split(",").every((id) => ids.has(id) || id === "*")), ...(external ? { topology: { nodes: [], edges: [] } } : {}) };
}

export function revokeMember(state: FlockState, flockId: string, peerId: string): FlockState {
  return { ...state, flocks: state.flocks.map((f) => f.flockId === flockId ? { ...f, rosterEpoch: f.rosterEpoch + 1, members: f.members.filter((m) => m.peerId !== peerId) } : f) };
}
export function validateInvite(input: InviteInput): string | null {
  if (!/^[\w-]+\/[\w-]+(?:\/[\w.-]+)?$/.test(input.targetPath)) return "Enter an owner/flock path with an optional machine ID.";
  if (!/^@?[a-z\d](?:[a-z\d-]{0,38})$/i.test(input.githubHandle)) return "Enter a valid GitHub handle.";
  if (!Number.isInteger(input.maxDevices) || input.maxDevices < 1) return "Device limit must be a positive whole number.";
  if (input.durationMinutes !== null && !GUEST_DURATIONS.some((n) => n === input.durationMinutes)) return "Choose a supported guest duration.";
  return null;
}
export function previewInvite(input: InviteInput): InviteResult {
  const enrollment = { v: 3, flockId: input.targetPath, invitedUser: input.githubHandle.replace(/^@/, ""), maxDevices: input.maxDevices, membershipExpiresAt: input.durationMinutes === null ? null : new Date(Date.now() + input.durationMinutes * 60000).toISOString(), signature: null, previewOnly: true };
  return { enrollment, simulated: true, copilotPrompt: `Enroll this PC in ${input.targetPath} as @${enrollment.invitedUser} using copilot-flock v3.1.0 (erjadi/copilot-flock).\nVerify the owner's signed enrollment before joining.\n\n${JSON.stringify(enrollment, null, 2)}` };
}
export async function generateInvite(base: string, mode: Mode, input: InviteInput): Promise<InviteResult> {
  const error = validateInvite(input); if (error) throw new Error(error);
  if (mode === "seed") return previewInvite(input);
  const result = await req<InviteResult>(base, "/api/v3/flocks/invite", { method: "POST", body: JSON.stringify(input) });
  if (!result.copilotPrompt || !result.enrollment) throw new Error("Invite response did not include a prompt and signed enrollment.");
  return result;
}
