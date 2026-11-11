export function authoritativeFlocks(raw, githubUser) {
  if (!raw || typeof raw !== "object" || raw.ok === false ||
      (!Array.isArray(raw.ownedFlocks) && !Array.isArray(raw.joinedFlocks)) ||
      (raw.ownedFlocks !== undefined && !Array.isArray(raw.ownedFlocks)) ||
      (raw.joinedFlocks !== undefined && !Array.isArray(raw.joinedFlocks))) {
    throw new Error("Authoritative flock roster unavailable or incomplete.");
  }
  const byId = new Map();
  for (const f of [...(raw.ownedFlocks || []), ...(raw.joinedFlocks || [])]) {
    if (!f || typeof f.flockId !== "string" || !f.flockId ||
        !Array.isArray(f.members) ||
        f.members.some((m) => !m || typeof m.machineId !== "string" || !m.machineId)) {
      throw new Error("Authoritative flock roster contains an incomplete membership record.");
    }
    if (byId.has(f.flockId)) continue;
    const kind = f.flockType === "owner_root" ? "owner_root"
      : f.flockType === "owner_scope" ? "owner_scope"
      : f.targetMachineId ? "guest" : "collaborator";
    const trustTier = typeof f.ownerGitHubUser === "string" &&
      f.ownerGitHubUser.toLowerCase() === String(githubUser || "").toLowerCase() &&
      (kind === "owner_root" || kind === "owner_scope") ? "owner"
      : kind === "guest" ? "guest" : "collaborator";
    byId.set(f.flockId, {
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      hubName: f.hubName,
      rosterEpoch: Number(f.rosterEpoch) || 1,
      kind,
      trustTier,
      sessionVisibility: trustTier === "owner" ? "all" : "explicit_opt_in_only",
      members: f.members.map((m) => ({
        machineId: m.machineId,
        peerId: m.peerId,
        membershipExpiresAt: m.membershipExpiresAt || null,
      })),
    });
  }
  return [...byId.values()];
}
