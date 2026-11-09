import type { Member, Session } from "./types";

export function globToRegex(glob: string) {
  return new RegExp("^" + glob.trim().replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");
}
const list = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

export interface BroadcastFilter {
  machines: string; exclude: string; scope: "all" | "personal" | "work"; githubUser: string; gpu: string;
  minRamGb: number; minFreeDiskGb: number; hasRepo: string;
}

export function matchMembers(members: Member[], sessions: Session[], f: BroadcastFilter): Member[] {
  const inc = list(f.machines).map(globToRegex);
  const exc = list(f.exclude).map(globToRegex);
  return members.filter((m) => {
    if (!m.online) return false;
    if (inc.length && !inc.some((r) => r.test(m.machineId))) return false;
    if (exc.some((r) => r.test(m.machineId))) return false;
    if (f.scope !== "all" && m.scope !== f.scope) return false;
    if (f.githubUser && (m.githubUser || "").toLowerCase() !== f.githubUser.replace(/^@/, "").toLowerCase()) return false;
    if (f.gpu && !m.specs.gpus.some((g) => g.name.toLowerCase().includes(f.gpu.toLowerCase()))) return false;
    if (m.specs.memory.totalGb < f.minRamGb) return false;
    if (f.minFreeDiskGb > 0 && !m.specs.disks.some((d) => d.type === "fixed" && d.freeGb >= f.minFreeDiskGb)) return false;
    if (f.hasRepo && !sessions.some((s) => s.machineId === m.machineId && (s.repo || "").toLowerCase().includes(f.hasRepo.toLowerCase()))) return false;
    return true;
  });
}
