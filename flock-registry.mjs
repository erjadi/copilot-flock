import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { atomicJson, assertNoLinks } from "./flock-lifecycle.mjs";
import { canonical, ownerFingerprint, signedControl, verifyControl } from "./flock-protocol.mjs";

export const REGISTRY_SCHEMA_VERSION = 1;
export const REGISTRY_TYPE = "copilot-flock-registry-v1";
export const DEFAULT_STALE_AFTER_MS = 300000;
export const DEFAULT_PRESENCE_TTL_MS = 60000;

function registryError(code, message) {
  return Object.assign(new Error(message), { code });
}

const sha256Hex = (value) =>
  crypto.createHash("sha256").update(typeof value === "string" ? value : canonical(value)).digest("hex");

export function normalizeRegistryFlockId(flockId) {
  const clean = String(flockId || "").trim().replace(/^\/+|\/+$/g, "").toLowerCase();
  if (!clean || clean.length > 128 || clean.includes("..") ||
      !/^[a-z0-9._-]+(?:\/[a-z0-9._-]+)?$/.test(clean)) {
    throw registryError("ROSTER_FLOCK_INVALID", `Invalid flock identifier for membership registry: "${flockId}"`);
  }
  return clean;
}

export function deriveKeyFingerprint(publicKeyPem) {
  return ownerFingerprint(publicKeyPem);
}

function tryDeriveKeyFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== "string" || !publicKeyPem.trim()) return "";
  try {
    return deriveKeyFingerprint(publicKeyPem);
  } catch {
    return "";
  }
}

export function compareRosterVersion(left, right) {
  const leftEpoch = Number(left?.epoch ?? left?.rosterEpoch) || 0;
  const rightEpoch = Number(right?.epoch ?? right?.rosterEpoch) || 0;
  if (leftEpoch !== rightEpoch) return leftEpoch < rightEpoch ? -1 : 1;
  const leftRev = Number(left?.revision ?? left?.rosterRevision) || 0;
  const rightRev = Number(right?.revision ?? right?.rosterRevision) || 0;
  if (leftRev !== rightRev) return leftRev < rightRev ? -1 : 1;
  return 0;
}

export function resolveMemberIdentityKey(member, { protocol = "v3-broker" } = {}) {
  if (!member || typeof member !== "object") {
    throw registryError("ROSTER_IDENTITY_REQUIRED", "Member object is required");
  }
  const pubPem = member.deviceEd25519Pub || member.publicKey || null;
  if (protocol === "broker-free-v34") {
    const computedFp = pubPem ? deriveKeyFingerprint(pubPem) : "";
    const rawPeerId = String(member.peerId || member.keyFingerprint || computedFp || "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(rawPeerId)) {
      throw registryError(
        "ROSTER_IDENTITY_REQUIRED",
        "Broker-free member requires a 64-hex Ed25519 peerId/keyFingerprint; hostname-only records are rejected"
      );
    }
    if (computedFp && computedFp !== rawPeerId) {
      throw registryError("ROSTER_KEY_MISMATCH", "Broker-free member public key fingerprint does not match peerId");
    }
    if (member.keyFingerprint && String(member.keyFingerprint).trim().toLowerCase() !== rawPeerId) {
      throw registryError("ROSTER_KEY_MISMATCH", "Broker-free member keyFingerprint does not match peerId");
    }
    return {
      identityKey: rawPeerId,
      peerId: rawPeerId,
      keyFingerprint: rawPeerId,
      deviceId: rawPeerId,
    };
  }

  const computedFp = tryDeriveKeyFingerprint(pubPem);
  const rawPeerId = String(member.peerId || "").trim().toLowerCase();
  const rawDeviceId = String(member.deviceId || "").trim().toLowerCase();
  const rawKeyFp = String(member.keyFingerprint || rawDeviceId || computedFp || "").trim().toLowerCase();
  if (!rawPeerId && !rawKeyFp) {
    throw registryError(
      "ROSTER_IDENTITY_REQUIRED",
      "Cryptographic member identity (peerId, keyFingerprint, deviceId, or publicKey) is required; hostname-only records are rejected"
    );
  }
  const keyFingerprint = rawKeyFp || (rawPeerId.includes(":") ? rawPeerId.split(":").slice(1).join(":") : rawPeerId);
  if (!keyFingerprint) {
    throw registryError(
      "ROSTER_IDENTITY_REQUIRED",
      "Cryptographic keyFingerprint/deviceId could not be resolved; hostname-only records are rejected"
    );
  }
  const cleanUser = String(member.githubUser || "").replace(/^@/, "").trim().toLowerCase();
  const peerId = rawPeerId || `${cleanUser || "device"}:${keyFingerprint}`;
  const identityKey =
    peerId === keyFingerprint || peerId.endsWith(`:${keyFingerprint}`)
      ? peerId
      : `${peerId}#${keyFingerprint}`;
  return {
    identityKey,
    peerId,
    keyFingerprint,
    deviceId: rawDeviceId || keyFingerprint,
  };
}

function normalizeScopeValue(scope) {
  const s = String(scope || "").trim().toLowerCase();
  if (s === "personal" || s === "private") return "personal";
  return "work";
}

function normalizeRoleValue(role) {
  const r = String(role || "").trim().toLowerCase();
  if (r === "owner" || r === "collaborator" || r === "guest") return r;
  return "collaborator";
}

function toOptionalSafeInt(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
}

function canonicalizeMemberForHash(entry) {
  return {
    identityKey: entry.identityKey,
    peerId: entry.peerId,
    keyFingerprint: entry.keyFingerprint,
    machineId: entry.machineId,
    githubUser: entry.githubUser,
    role: entry.role,
    scope: entry.scope,
    membershipExpiresAtMs: entry.membershipExpiresAtMs,
    certIssuedAtMs: entry.certIssuedAtMs,
    certExpiresAtMs: entry.certExpiresAtMs,
    deviceEd25519Pub: entry.deviceEd25519Pub || null,
    addedAtEpoch: entry.addedAtEpoch,
    addedAtRevision: entry.addedAtRevision,
    updatedAtRevision: entry.updatedAtRevision,
  };
}

function canonicalizeTombstoneForHash(entry) {
  return {
    identityKey: entry.identityKey,
    peerId: entry.peerId,
    keyFingerprint: entry.keyFingerprint,
    machineId: entry.machineId,
    githubUser: entry.githubUser,
    removedAtMs: entry.removedAtMs,
    removedAtEpoch: entry.removedAtEpoch,
    removedAtRevision: entry.removedAtRevision,
    reason: entry.reason,
    operationId: entry.operationId || null,
  };
}

export function computeRosterHash({
  flockId,
  protocol,
  rosterEpoch,
  rosterRevision,
  members = {},
  tombstones = {},
}) {
  const cleanFlockId = normalizeRegistryFlockId(flockId);
  const memberList = (Array.isArray(members) ? members : Object.values(members))
    .map(canonicalizeMemberForHash)
    .sort((a, b) => (a.identityKey < b.identityKey ? -1 : a.identityKey > b.identityKey ? 1 : 0));
  const tombstoneList = (Array.isArray(tombstones) ? tombstones : Object.values(tombstones))
    .map(canonicalizeTombstoneForHash)
    .sort((a, b) => (a.identityKey < b.identityKey ? -1 : a.identityKey > b.identityKey ? 1 : 0));
  return sha256Hex({
    v: REGISTRY_SCHEMA_VERSION,
    flockId: cleanFlockId,
    protocol,
    rosterEpoch,
    rosterRevision,
    members: memberList,
    tombstones: tombstoneList,
  });
}

function normalizeMemberRecord(raw, {
  protocol,
  epoch,
  revision,
  previous = null,
}) {
  const ids = resolveMemberIdentityKey(raw, { protocol });
  const machineId = String(raw.machineId || previous?.machineId || "").trim();
  if (!machineId || machineId.length > 128 || !/^[A-Za-z0-9._-]+$/.test(machineId)) {
    throw registryError("ROSTER_MACHINE_INVALID", `Invalid machineId "${raw.machineId}" for member "${ids.identityKey}"`);
  }
  const githubUserRaw = raw.githubUser ?? previous?.githubUser ?? null;
  const githubUser = githubUserRaw ? String(githubUserRaw).replace(/^@/, "").trim().toLowerCase() || null : null;
  const githubUserId = Number.isSafeInteger(Number(raw.githubUserId)) && Number(raw.githubUserId) > 0
    ? Number(raw.githubUserId)
    : (previous?.githubUserId ?? null);
  const role = normalizeRoleValue(raw.role || raw.trustTier || previous?.role || "collaborator");
  const scope = normalizeScopeValue(raw.scope || previous?.scope || "work");
  const membershipExpiresAtMs = raw.membershipExpiresAtMs !== undefined
    ? toOptionalSafeInt(raw.membershipExpiresAtMs)
    : raw.membershipExpiresAt !== undefined
      ? toOptionalSafeInt(raw.membershipExpiresAt)
      : (previous?.membershipExpiresAtMs ?? null);
  const certIssuedAtMs = raw.certIssuedAtMs !== undefined
    ? toOptionalSafeInt(raw.certIssuedAtMs)
    : (previous?.certIssuedAtMs ?? null);
  const certExpiresAtMs = raw.certExpiresAtMs !== undefined
    ? toOptionalSafeInt(raw.certExpiresAtMs)
    : (previous?.certExpiresAtMs ?? null);
  const deviceEd25519Pub = raw.deviceEd25519Pub || raw.publicKey || previous?.deviceEd25519Pub || null;
  const deviceX25519Pub = raw.deviceX25519Pub || previous?.deviceX25519Pub || null;
  if (protocol === "broker-free-v34") {
    if (!deviceEd25519Pub || deriveKeyFingerprint(deviceEd25519Pub) !== ids.peerId) {
      throw registryError("ROSTER_KEY_MISMATCH", `Broker-free member "${ids.peerId}" requires a matching Ed25519 public key`);
    }
  }
  const addedAtEpoch = Number.isSafeInteger(raw.addedAtEpoch) && raw.addedAtEpoch >= 1
    ? raw.addedAtEpoch
    : (previous?.addedAtEpoch ?? epoch);
  const addedAtRevision = Number.isSafeInteger(raw.addedAtRevision) && raw.addedAtRevision >= 1
    ? raw.addedAtRevision
    : (previous?.addedAtRevision ?? revision);
  const updatedAtRevision = Number.isSafeInteger(raw.updatedAtRevision) && raw.updatedAtRevision >= 1
    ? raw.updatedAtRevision
    : revision;
  return {
    identityKey: ids.identityKey,
    peerId: ids.peerId,
    keyFingerprint: ids.keyFingerprint,
    deviceId: ids.deviceId,
    machineId,
    githubUser,
    githubUserId,
    githubName: raw.githubName ?? previous?.githubName ?? null,
    role,
    scope,
    deviceEd25519Pub,
    deviceX25519Pub,
    specs: raw.specs ?? previous?.specs ?? null,
    version: raw.version ?? previous?.version ?? null,
    platform: raw.platform ?? previous?.platform ?? null,
    joinedAtMs: toOptionalSafeInt(raw.joinedAtMs ?? raw.joinedAt ?? raw.registeredAt) ?? previous?.joinedAtMs ?? null,
    membershipExpiresAtMs,
    certIssuedAtMs,
    certExpiresAtMs,
    addedAtEpoch,
    addedAtRevision,
    updatedAtRevision,
  };
}

function normalizeTombstoneRecord(raw, {
  protocol,
  defaultEpoch = 1,
  defaultRevision = 1,
  now = Date.now(),
  previous = null,
}) {
  const ids = resolveMemberIdentityKey(raw, { protocol });
  const removedAtEpoch = Number.isSafeInteger(raw.removedAtEpoch) && raw.removedAtEpoch >= 1
    ? raw.removedAtEpoch
    : (previous?.removedAtEpoch ?? defaultEpoch);
  const removedAtRevision = Number.isSafeInteger(raw.removedAtRevision) && raw.removedAtRevision >= 1
    ? raw.removedAtRevision
    : (previous?.removedAtRevision ?? defaultRevision);
  const removedAtMs = toOptionalSafeInt(raw.removedAtMs) ?? previous?.removedAtMs ?? Math.trunc(now);
  const machineId = raw.machineId ?? previous?.machineId ?? null;
  const githubUserRaw = raw.githubUser ?? previous?.githubUser ?? null;
  const githubUser = githubUserRaw ? String(githubUserRaw).replace(/^@/, "").trim().toLowerCase() || null : null;
  return {
    identityKey: ids.identityKey,
    peerId: ids.peerId,
    keyFingerprint: ids.keyFingerprint,
    machineId: machineId ? String(machineId).trim() : null,
    githubUser,
    removedAtMs,
    removedAtEpoch,
    removedAtRevision,
    reason: String(raw.reason || previous?.reason || "removed"),
    operationId: raw.operationId ?? previous?.operationId ?? null,
  };
}

function serializeBrokerFreeMemberWire(entry) {
  return {
    identityKey: entry.identityKey,
    peerId: entry.peerId,
    keyFingerprint: entry.keyFingerprint,
    deviceEd25519Pub: entry.deviceEd25519Pub,
    deviceX25519Pub: entry.deviceX25519Pub || null,
    machineId: entry.machineId,
    githubUser: entry.githubUser || null,
    role: entry.role,
    scope: entry.scope,
    membershipExpiresAtMs: entry.membershipExpiresAtMs ?? null,
    certIssuedAtMs: entry.certIssuedAtMs ?? null,
    certExpiresAtMs: entry.certExpiresAtMs ?? null,
    addedAtEpoch: entry.addedAtEpoch,
    addedAtRevision: entry.addedAtRevision,
    updatedAtRevision: entry.updatedAtRevision,
  };
}

function serializeBrokerFreeTombstoneWire(entry) {
  return {
    identityKey: entry.identityKey,
    peerId: entry.peerId,
    keyFingerprint: entry.keyFingerprint,
    machineId: entry.machineId || null,
    githubUser: entry.githubUser || null,
    removedAtMs: entry.removedAtMs,
    removedAtEpoch: entry.removedAtEpoch,
    removedAtRevision: entry.removedAtRevision,
    reason: entry.reason,
    operationId: entry.operationId || null,
  };
}

export function createSignedRosterSnapshot({
  flockId,
  ownerIdentity,
  epoch,
  minAcceptedEpoch = epoch,
  rotationHash = null,
  revision,
  previousRosterHash = null,
  members = [],
  tombstones = [],
  issuedAt = Date.now(),
}) {
  const cleanFlockId = normalizeRegistryFlockId(flockId);
  const ownerPub = ownerIdentity?.ed25519?.publicKey;
  if (!ownerPub) throw registryError("ROSTER_OWNER_MISMATCH", "Owner Ed25519 identity required to sign roster snapshot");
  const ownerFp = deriveKeyFingerprint(ownerPub);
  if (!Number.isSafeInteger(epoch) || epoch < 1 || !Number.isSafeInteger(revision) || revision < 1) {
    throw registryError("ROSTER_VERSION_INVALID", "Snapshot epoch and revision must be positive safe integers");
  }
  const tombstonesMap = {};
  for (const rawTomb of Array.isArray(tombstones) ? tombstones : Object.values(tombstones)) {
    const tomb = normalizeTombstoneRecord(rawTomb, {
      protocol: "broker-free-v34",
      defaultEpoch: epoch,
      defaultRevision: revision,
      now: issuedAt,
    });
    tombstonesMap[tomb.identityKey] = tomb;
  }
  const membersMap = {};
  for (const rawMember of Array.isArray(members) ? members : Object.values(members)) {
    const m = normalizeMemberRecord(rawMember, { protocol: "broker-free-v34", epoch, revision });
    const tomb = tombstonesMap[m.identityKey];
    if (tomb && compareRosterVersion(
      { epoch: m.addedAtEpoch, revision: m.updatedAtRevision },
      { epoch: tomb.removedAtEpoch, revision: tomb.removedAtRevision }
    ) <= 0) {
      throw registryError(
        "ROSTER_RESURRECTION_REJECTED",
        `Cannot include tombstoned member "${m.identityKey}" without a newer epoch/revision`
      );
    }
    delete tombstonesMap[m.identityKey];
    membersMap[m.identityKey] = m;
  }
  const wireMembers = Object.values(membersMap)
    .map(serializeBrokerFreeMemberWire)
    .sort((a, b) => (a.identityKey < b.identityKey ? -1 : a.identityKey > b.identityKey ? 1 : 0));
  const wireTombstones = Object.values(tombstonesMap)
    .map(serializeBrokerFreeTombstoneWire)
    .sort((a, b) => (a.identityKey < b.identityKey ? -1 : a.identityKey > b.identityKey ? 1 : 0));
  const rosterHash = computeRosterHash({
    flockId: cleanFlockId,
    protocol: "broker-free-v34",
    rosterEpoch: epoch,
    rosterRevision: revision,
    members: wireMembers,
    tombstones: wireTombstones,
  });
  const body = {
    v: 34,
    flockId: cleanFlockId,
    ownerFingerprint: ownerFp,
    epoch,
    minAcceptedEpoch: Math.trunc(minAcceptedEpoch),
    rotationHash: rotationHash || null,
    revision,
    previousRosterHash: previousRosterHash || null,
    rosterHash,
    issuedAt: Math.trunc(issuedAt),
    members: wireMembers,
    tombstones: wireTombstones,
  };
  return signedControl("roster-snapshot", body, ownerIdentity);
}

export function verifySignedRosterSnapshot(snapshot, ownerPublicKey, {
  expectedFlockId = null,
  expectedOwnerFingerprint = null,
  minAcceptedEpoch = 1,
} = {}) {
  if (!snapshot || typeof snapshot !== "object") {
    throw registryError("ROSTER_INVALID_SNAPSHOT", "Missing signed roster snapshot");
  }
  const ownerFp = deriveKeyFingerprint(ownerPublicKey);
  if (expectedOwnerFingerprint && ownerFp !== String(expectedOwnerFingerprint).trim().toLowerCase()) {
    throw registryError("ROSTER_OWNER_MISMATCH", "Owner public key does not match pinned owner fingerprint");
  }
  const body = verifyControl(snapshot, ownerPublicKey, "roster-snapshot");
  if (body.v !== 34 || body.ownerFingerprint !== ownerFp) {
    throw registryError("ROSTER_OWNER_MISMATCH", "Roster snapshot owner fingerprint mismatch");
  }
  const cleanFlockId = normalizeRegistryFlockId(body.flockId);
  if (expectedFlockId && cleanFlockId !== normalizeRegistryFlockId(expectedFlockId)) {
    throw registryError("ROSTER_FLOCK_MISMATCH", `Roster snapshot is bound to "${cleanFlockId}", expected "${expectedFlockId}"`);
  }
  if (!Number.isSafeInteger(body.epoch) || body.epoch < 1 ||
      !Number.isSafeInteger(body.minAcceptedEpoch) || body.minAcceptedEpoch < 1 ||
      body.epoch < minAcceptedEpoch ||
      !Number.isSafeInteger(body.revision) || body.revision < 1 ||
      !Number.isSafeInteger(body.issuedAt) ||
      !Array.isArray(body.members) || !Array.isArray(body.tombstones)) {
    throw registryError("ROSTER_ROLLBACK_REJECTED", "Roster snapshot version or epoch floor rejected");
  }
  const membersMap = {};
  for (const m of body.members) {
    const norm = normalizeMemberRecord(m, { protocol: "broker-free-v34", epoch: body.epoch, revision: body.revision });
    if (membersMap[norm.identityKey]) {
      throw registryError("ROSTER_INVALID_SNAPSHOT", `Duplicate member "${norm.identityKey}" in roster snapshot`);
    }
    membersMap[norm.identityKey] = norm;
  }
  const tombstonesMap = {};
  for (const t of body.tombstones) {
    const norm = normalizeTombstoneRecord(t, {
      protocol: "broker-free-v34",
      defaultEpoch: body.epoch,
      defaultRevision: body.revision,
      now: body.issuedAt,
    });
    if (membersMap[norm.identityKey]) {
      throw registryError("ROSTER_RESURRECTION_REJECTED", `Member "${norm.identityKey}" cannot be both active and tombstoned`);
    }
    tombstonesMap[norm.identityKey] = norm;
  }
  const expectedHash = computeRosterHash({
    flockId: cleanFlockId,
    protocol: "broker-free-v34",
    rosterEpoch: body.epoch,
    rosterRevision: body.revision,
    members: membersMap,
    tombstones: tombstonesMap,
  });
  if (expectedHash !== body.rosterHash) {
    throw registryError("ROSTER_HASH_CONFLICT", "Roster snapshot canonical hash mismatch");
  }
  return { body, membersMap, tombstonesMap, ownerFingerprint: ownerFp };
}

export function createSignedRosterDelta({
  flockId,
  ownerIdentity,
  baseEpoch,
  baseRevision,
  baseRosterHash,
  epoch,
  minAcceptedEpoch = epoch,
  rotationHash = null,
  revision,
  upserts = [],
  removals = [],
  resultingMembers,
  resultingTombstones = [],
  issuedAt = Date.now(),
}) {
  const cleanFlockId = normalizeRegistryFlockId(flockId);
  const ownerPub = ownerIdentity?.ed25519?.publicKey;
  if (!ownerPub) throw registryError("ROSTER_OWNER_MISMATCH", "Owner Ed25519 identity required to sign roster delta");
  const ownerFp = deriveKeyFingerprint(ownerPub);
  if (compareRosterVersion({ epoch, revision }, { epoch: baseEpoch, revision: baseRevision }) <= 0) {
    throw registryError("ROSTER_VERSION_INVALID", "Roster delta target version must advance beyond base version");
  }
  if (typeof baseRosterHash !== "string" || !/^[a-f0-9]{64}$/.test(baseRosterHash)) {
    throw registryError("ROSTER_INVALID_DELTA", "Roster delta requires a 64-hex baseRosterHash");
  }
  const wireUpserts = upserts
    .map((raw) => serializeBrokerFreeMemberWire(normalizeMemberRecord(raw, { protocol: "broker-free-v34", epoch, revision })))
    .sort((a, b) => (a.identityKey < b.identityKey ? -1 : a.identityKey > b.identityKey ? 1 : 0));
  const wireRemovals = removals
    .map((raw) => serializeBrokerFreeTombstoneWire(normalizeTombstoneRecord(raw, {
      protocol: "broker-free-v34",
      defaultEpoch: epoch,
      defaultRevision: revision,
      now: issuedAt,
    })))
    .sort((a, b) => (a.identityKey < b.identityKey ? -1 : a.identityKey > b.identityKey ? 1 : 0));
  const fullMembers = (Array.isArray(resultingMembers) ? resultingMembers : Object.values(resultingMembers || {}))
    .map((raw) => normalizeMemberRecord(raw, { protocol: "broker-free-v34", epoch, revision }));
  const fullTombstones = (Array.isArray(resultingTombstones) ? resultingTombstones : Object.values(resultingTombstones || {}))
    .map((raw) => normalizeTombstoneRecord(raw, {
      protocol: "broker-free-v34",
      defaultEpoch: epoch,
      defaultRevision: revision,
      now: issuedAt,
    }));
  const rosterHash = computeRosterHash({
    flockId: cleanFlockId,
    protocol: "broker-free-v34",
    rosterEpoch: epoch,
    rosterRevision: revision,
    members: fullMembers,
    tombstones: fullTombstones,
  });
  const body = {
    v: 34,
    flockId: cleanFlockId,
    ownerFingerprint: ownerFp,
    baseEpoch,
    baseRevision,
    baseRosterHash,
    epoch,
    minAcceptedEpoch: Math.trunc(minAcceptedEpoch),
    rotationHash: rotationHash || null,
    revision,
    rosterHash,
    issuedAt: Math.trunc(issuedAt),
    upserts: wireUpserts,
    removals: wireRemovals,
  };
  return signedControl("roster-delta", body, ownerIdentity);
}

export function verifySignedRosterDelta(delta, ownerPublicKey, {
  expectedFlockId = null,
  expectedOwnerFingerprint = null,
  minAcceptedEpoch = 1,
} = {}) {
  if (!delta || typeof delta !== "object") {
    throw registryError("ROSTER_INVALID_DELTA", "Missing signed roster delta");
  }
  const ownerFp = deriveKeyFingerprint(ownerPublicKey);
  if (expectedOwnerFingerprint && ownerFp !== String(expectedOwnerFingerprint).trim().toLowerCase()) {
    throw registryError("ROSTER_OWNER_MISMATCH", "Owner public key does not match pinned owner fingerprint");
  }
  const body = verifyControl(delta, ownerPublicKey, "roster-delta");
  if (body.v !== 34 || body.ownerFingerprint !== ownerFp) {
    throw registryError("ROSTER_OWNER_MISMATCH", "Roster delta owner fingerprint mismatch");
  }
  const cleanFlockId = normalizeRegistryFlockId(body.flockId);
  if (expectedFlockId && cleanFlockId !== normalizeRegistryFlockId(expectedFlockId)) {
    throw registryError("ROSTER_FLOCK_MISMATCH", `Roster delta is bound to "${cleanFlockId}", expected "${expectedFlockId}"`);
  }
  if (!Number.isSafeInteger(body.baseEpoch) || body.baseEpoch < 1 ||
      !Number.isSafeInteger(body.baseRevision) || body.baseRevision < 1 ||
      typeof body.baseRosterHash !== "string" || !/^[a-f0-9]{64}$/.test(body.baseRosterHash) ||
      !Number.isSafeInteger(body.epoch) || body.epoch < minAcceptedEpoch ||
      !Number.isSafeInteger(body.revision) || body.revision < 1 ||
      compareRosterVersion({ epoch: body.epoch, revision: body.revision },
        { epoch: body.baseEpoch, revision: body.baseRevision }) <= 0 ||
      !Array.isArray(body.upserts) || !Array.isArray(body.removals)) {
    throw registryError("ROSTER_ROLLBACK_REJECTED", "Roster delta version or epoch floor rejected");
  }
  const upserts = body.upserts.map((m) =>
    normalizeMemberRecord(m, { protocol: "broker-free-v34", epoch: body.epoch, revision: body.revision })
  );
  const removals = body.removals.map((t) =>
    normalizeTombstoneRecord(t, {
      protocol: "broker-free-v34",
      defaultEpoch: body.epoch,
      defaultRevision: body.revision,
      now: body.issuedAt,
    })
  );
  return { body, upserts, removals, ownerFingerprint: ownerFp };
}

function pickNewerTombstone(existing, incoming) {
  if (!existing) return incoming;
  if (!incoming) return existing;
  return compareRosterVersion(
    { epoch: incoming.removedAtEpoch, revision: incoming.removedAtRevision },
    { epoch: existing.removedAtEpoch, revision: existing.removedAtRevision }
  ) >= 0
    ? incoming
    : existing;
}

export class FlockMembershipRegistry {
  constructor(rootOrFilename, {
    clock = Date.now,
    staleAfterMs = DEFAULT_STALE_AFTER_MS,
    presenceTtlMs = DEFAULT_PRESENCE_TTL_MS,
  } = {}) {
    const resolved = assertNoLinks(path.resolve(String(rootOrFilename)));
    if (resolved.endsWith(".json")) {
      this.filename = resolved;
      this.root = path.dirname(resolved);
    } else {
      this.root = resolved;
      this.filename = path.join(resolved, "flock-registry.json");
    }
    this.clock = clock;
    this.staleAfterMs = staleAfterMs;
    this.presenceTtlMs = presenceTtlMs;
  }

  read() {
    assertNoLinks(this.filename);
    if (!fs.existsSync(this.filename)) {
      return {
        schema: REGISTRY_SCHEMA_VERSION,
        type: REGISTRY_TYPE,
        updatedAtMs: 0,
        flocks: {},
      };
    }
    const parsed = JSON.parse(fs.readFileSync(this.filename, "utf8"));
    if (!parsed || parsed.type !== REGISTRY_TYPE || parsed.schema !== REGISTRY_SCHEMA_VERSION ||
        !parsed.flocks || typeof parsed.flocks !== "object" || Array.isArray(parsed.flocks)) {
      throw registryError("ROSTER_CORRUPT_STORE", `Invalid flock membership registry store: ${this.filename}`);
    }
    return parsed;
  }

  save(data) {
    fs.mkdirSync(this.root, { recursive: true });
    data.schema = REGISTRY_SCHEMA_VERSION;
    data.type = REGISTRY_TYPE;
    data.updatedAtMs = Math.trunc(this.clock());
    atomicJson(this.filename, data);
    return data;
  }

  hasFlock(flockId) {
    const clean = normalizeRegistryFlockId(flockId);
    return Boolean(this.read().flocks[clean]);
  }

  listFlockIds() {
    return Object.keys(this.read().flocks).sort();
  }

  applySignedSnapshot(snapshot, {
    ownerPublicKey,
    expectedFlockId = null,
    expectedOwnerFingerprint = null,
    minAcceptedEpoch = 1,
    now = this.clock(),
  } = {}) {
    const verified = verifySignedRosterSnapshot(snapshot, ownerPublicKey, {
      expectedFlockId,
      expectedOwnerFingerprint,
      minAcceptedEpoch,
    });
    const { body, membersMap, tombstonesMap, ownerFingerprint: ownerFp } = verified;
    const data = this.read();
    const stored = data.flocks[body.flockId];

    if (stored) {
      if (stored.protocol !== "broker-free-v34") {
        throw registryError("ROSTER_PROTOCOL_MISMATCH", `Flock "${body.flockId}" is registered under protocol "${stored.protocol}"`);
      }
      if (stored.ownerFingerprint && stored.ownerFingerprint !== ownerFp) {
        throw registryError("ROSTER_OWNER_MISMATCH", `Owner fingerprint pin mismatch for flock "${body.flockId}"`);
      }
      const cmp = compareRosterVersion(
        { epoch: body.epoch, revision: body.revision },
        { epoch: stored.rosterEpoch, revision: stored.rosterRevision }
      );
      if (cmp < 0) {
        throw registryError(
          "ROSTER_ROLLBACK_REJECTED",
          `Stale roster snapshot (${body.epoch}:${body.revision}) rejected; current is (${stored.rosterEpoch}:${stored.rosterRevision})`
        );
      }
      if (cmp === 0) {
        if (stored.rosterHash !== body.rosterHash) {
          throw registryError("ROSTER_HASH_CONFLICT", `Conflicting roster snapshot hash at (${body.epoch}:${body.revision})`);
        }
        stored.syncedAtMs = Math.trunc(now);
        stored.needsSnapshotSync = false;
        stored.lastSignedSnapshot = snapshot;
        this.save(data);
        return { applied: false, idempotent: true, flockId: body.flockId, rosterEpoch: stored.rosterEpoch, rosterRevision: stored.rosterRevision, rosterHash: stored.rosterHash };
      }
      // Enforce local tombstone floor: an incoming snapshot cannot silently drop tombstones or resurrect a member without a newer addition version.
      for (const [idKey, prevTomb] of Object.entries(stored.tombstones || {})) {
        const candidateMember = membersMap[idKey];
        if (candidateMember && compareRosterVersion(
          { epoch: candidateMember.addedAtEpoch, revision: candidateMember.updatedAtRevision },
          { epoch: prevTomb.removedAtEpoch, revision: prevTomb.removedAtRevision }
        ) <= 0) {
          throw registryError(
            "ROSTER_RESURRECTION_REJECTED",
            `Snapshot attempted to resurrect tombstoned member "${idKey}" without a newer epoch/revision`
          );
        }
        if (!candidateMember && !tombstonesMap[idKey]) {
          throw registryError(
            "ROSTER_TOMBSTONE_OMITTED",
            `Snapshot omitted retained removal tombstone for "${idKey}"`
          );
        }
      }
    }

    const retainedPresence = {};
    for (const [idKey, pres] of Object.entries(stored?.presence || {})) {
      if (membersMap[idKey]) retainedPresence[idKey] = pres;
    }

    data.flocks[body.flockId] = {
      flockId: body.flockId,
      protocol: "broker-free-v34",
      flockType: stored?.flockType || "shared",
      ownerGitHubUser: body.flockId.includes("/") ? body.flockId.split("/")[0] : body.flockId,
      ownerFingerprint: ownerFp,
      ownerPublicKey,
      rosterEpoch: body.epoch,
      minAcceptedEpoch: Math.max(stored?.minAcceptedEpoch || 1, body.minAcceptedEpoch),
      rotationHash: body.rotationHash || null,
      rosterRevision: body.revision,
      previousRosterHash: body.previousRosterHash || null,
      rosterHash: body.rosterHash,
      syncedAtMs: Math.trunc(now),
      staleAfterMs: stored?.staleAfterMs || this.staleAfterMs,
      needsSnapshotSync: false,
      members: membersMap,
      tombstones: tombstonesMap,
      presence: retainedPresence,
      lastSignedSnapshot: snapshot,
    };
    this.save(data);
    return {
      applied: true,
      idempotent: false,
      flockId: body.flockId,
      rosterEpoch: body.epoch,
      rosterRevision: body.revision,
      rosterHash: body.rosterHash,
    };
  }

  applySignedDelta(delta, {
    ownerPublicKey,
    expectedFlockId = null,
    expectedOwnerFingerprint = null,
    minAcceptedEpoch = 1,
    now = this.clock(),
  } = {}) {
    const verified = verifySignedRosterDelta(delta, ownerPublicKey, {
      expectedFlockId,
      expectedOwnerFingerprint,
      minAcceptedEpoch,
    });
    const { body, upserts, removals, ownerFingerprint: ownerFp } = verified;
    const data = this.read();
    const stored = data.flocks[body.flockId];

    if (!stored) {
      throw registryError(
        "ROSTER_DELTA_GAP",
        `Cannot apply roster delta for "${body.flockId}" without a base snapshot`
      );
    }
    if (stored.protocol !== "broker-free-v34") {
      throw registryError("ROSTER_PROTOCOL_MISMATCH", `Flock "${body.flockId}" is registered under protocol "${stored.protocol}"`);
    }
    if (stored.ownerFingerprint && stored.ownerFingerprint !== ownerFp) {
      throw registryError("ROSTER_OWNER_MISMATCH", `Owner fingerprint pin mismatch for flock "${body.flockId}"`);
    }

    const cmp = compareRosterVersion(
      { epoch: body.epoch, revision: body.revision },
      { epoch: stored.rosterEpoch, revision: stored.rosterRevision }
    );
    if (cmp < 0) {
      throw registryError(
        "ROSTER_ROLLBACK_REJECTED",
        `Stale roster delta (${body.epoch}:${body.revision}) rejected; current is (${stored.rosterEpoch}:${stored.rosterRevision})`
      );
    }
    if (cmp === 0) {
      if (stored.rosterHash !== body.rosterHash) {
        throw registryError("ROSTER_HASH_CONFLICT", `Conflicting roster delta hash at (${body.epoch}:${body.revision})`);
      }
      stored.syncedAtMs = Math.trunc(now);
      this.save(data);
      return { applied: false, idempotent: true, flockId: body.flockId, rosterEpoch: stored.rosterEpoch, rosterRevision: stored.rosterRevision, rosterHash: stored.rosterHash };
    }

    if (stored.rosterEpoch !== body.baseEpoch ||
        stored.rosterRevision !== body.baseRevision ||
        stored.rosterHash !== body.baseRosterHash) {
      stored.needsSnapshotSync = true;
      this.save(data);
      throw registryError(
        "ROSTER_DELTA_GAP",
        `Missed roster delta for "${body.flockId}": expected base (${body.baseEpoch}:${body.baseRevision}:${body.baseRosterHash.slice(0, 12)}), stored (${stored.rosterEpoch}:${stored.rosterRevision}:${stored.rosterHash.slice(0, 12)})`
      );
    }

    const nextMembers = structuredClone(stored.members || {});
    const nextTombstones = structuredClone(stored.tombstones || {});
    const nextPresence = structuredClone(stored.presence || {});

    for (const tomb of removals) {
      delete nextMembers[tomb.identityKey];
      delete nextPresence[tomb.identityKey];
      nextTombstones[tomb.identityKey] = pickNewerTombstone(nextTombstones[tomb.identityKey], tomb);
    }
    for (const member of upserts) {
      const existingTomb = nextTombstones[member.identityKey];
      if (existingTomb && compareRosterVersion(
        { epoch: member.addedAtEpoch, revision: member.updatedAtRevision },
        { epoch: existingTomb.removedAtEpoch, revision: existingTomb.removedAtRevision }
      ) <= 0) {
        throw registryError(
          "ROSTER_RESURRECTION_REJECTED",
          `Delta attempted to resurrect tombstoned member "${member.identityKey}" without a newer epoch/revision`
        );
      }
      delete nextTombstones[member.identityKey];
      nextMembers[member.identityKey] = normalizeMemberRecord(member, {
        protocol: "broker-free-v34",
        epoch: body.epoch,
        revision: body.revision,
        previous: nextMembers[member.identityKey] || null,
      });
    }

    const computedHash = computeRosterHash({
      flockId: body.flockId,
      protocol: "broker-free-v34",
      rosterEpoch: body.epoch,
      rosterRevision: body.revision,
      members: nextMembers,
      tombstones: nextTombstones,
    });
    if (computedHash !== body.rosterHash) {
      throw registryError("ROSTER_HASH_CONFLICT", "Resulting state after applying roster delta did not match signed rosterHash");
    }

    data.flocks[body.flockId] = {
      ...stored,
      rosterEpoch: body.epoch,
      minAcceptedEpoch: Math.max(stored.minAcceptedEpoch || 1, body.minAcceptedEpoch),
      rotationHash: body.rotationHash || stored.rotationHash || null,
      rosterRevision: body.revision,
      previousRosterHash: stored.rosterHash,
      rosterHash: computedHash,
      syncedAtMs: Math.trunc(now),
      needsSnapshotSync: false,
      members: nextMembers,
      tombstones: nextTombstones,
      presence: nextPresence,
    };
    this.save(data);
    return {
      applied: true,
      idempotent: false,
      flockId: body.flockId,
      rosterEpoch: body.epoch,
      rosterRevision: body.revision,
      rosterHash: computedHash,
    };
  }

  reconcileV3BrokerFlock(flockSummary, {
    bootstrapMembers = [],
    removedPeers = [],
    now = this.clock(),
  } = {}) {
    if (!flockSummary || !flockSummary.flockId) {
      throw registryError("ROSTER_FLOCK_INVALID", "v3 broker flock summary requires flockId");
    }
    const flockId = normalizeRegistryFlockId(flockSummary.flockId);
    const incomingEpoch = Math.max(1, Math.trunc(Number(flockSummary.rosterEpoch) || 1));
    const data = this.read();
    const stored = data.flocks[flockId];

    if (stored) {
      if (stored.protocol !== "v3-broker") {
        throw registryError("ROSTER_PROTOCOL_MISMATCH", `Flock "${flockId}" is registered under protocol "${stored.protocol}"`);
      }
      if (incomingEpoch < stored.rosterEpoch) {
        throw registryError(
          "ROSTER_ROLLBACK_REJECTED",
          `Stale v3 broker rosterEpoch ${incomingEpoch} for "${flockId}" rejected; stored epoch is ${stored.rosterEpoch}`
        );
      }
    }

    const bootstrapByFp = new Map();
    const bootstrapByUserAndMachine = new Map();
    for (const bm of Array.isArray(bootstrapMembers) ? bootstrapMembers : []) {
      if (!bm || typeof bm !== "object") continue;
      const bmFp = String(bm.keyFingerprint || tryDeriveKeyFingerprint(bm.publicKey) || "").trim().toLowerCase();
      if (bmFp) bootstrapByFp.set(bmFp, bm);
      if (bm.githubUser && bm.machineId) {
        const key = `${String(bm.githubUser).replace(/^@/, "").trim().toLowerCase()}::${String(bm.machineId).trim().toLowerCase()}`;
        if (!bootstrapByUserAndMachine.has(key)) bootstrapByUserAndMachine.set(key, bm);
      }
    }

    const baseRevision = stored?.rosterRevision || 0;
    const provisionalRevision = baseRevision + 1;
    const nextTombstones = structuredClone(stored?.tombstones || {});
    const nextPresence = structuredClone(stored?.presence || {});

    for (const removed of Array.isArray(removedPeers) ? removedPeers : []) {
      const tomb = normalizeTombstoneRecord(removed, {
        protocol: "v3-broker",
        defaultEpoch: incomingEpoch,
        defaultRevision: provisionalRevision,
        now,
        previous: null,
      });
      nextTombstones[tomb.identityKey] = pickNewerTombstone(nextTombstones[tomb.identityKey], tomb);
      delete nextPresence[tomb.identityKey];
    }

    const incomingMembersMap = {};
    for (const rawMember of Array.isArray(flockSummary.members) ? flockSummary.members : []) {
      const ids = resolveMemberIdentityKey(rawMember, { protocol: "v3-broker" });
      const existingTomb = nextTombstones[ids.identityKey];
      // At the same or older epoch, a tombstoned member cannot be resurrected by merging/replaying a cache.
      if (existingTomb && incomingEpoch <= existingTomb.removedAtEpoch) {
        continue;
      }
      if (existingTomb && incomingEpoch > existingTomb.removedAtEpoch) {
        delete nextTombstones[ids.identityKey];
      }
      const matchedBm = bootstrapByFp.get(ids.keyFingerprint) || (() => {
        const userKey = `${String(rawMember.githubUser || "").replace(/^@/, "").trim().toLowerCase()}::${String(rawMember.machineId || "").trim().toLowerCase()}`;
        const candidate = bootstrapByUserAndMachine.get(userKey);
        if (!candidate) return null;
        const candidateFp = String(candidate.keyFingerprint || tryDeriveKeyFingerprint(candidate.publicKey) || "").trim().toLowerCase();
        if (candidateFp && candidateFp !== ids.keyFingerprint) return null;
        return candidate;
      })();

      const previous = stored?.members?.[ids.identityKey] || null;
      const mergedRaw = {
        ...rawMember,
        specs: rawMember.specs ?? matchedBm?.specs ?? previous?.specs ?? null,
        version: rawMember.version ?? matchedBm?.version ?? previous?.version ?? null,
        platform: rawMember.platform ?? matchedBm?.platform ?? previous?.platform ?? null,
        githubName: rawMember.githubName ?? matchedBm?.githubName ?? previous?.githubName ?? null,
        joinedAt: rawMember.joinedAt ?? matchedBm?.registeredAt ?? previous?.joinedAtMs ?? null,
      };
      const normalized = normalizeMemberRecord(mergedRaw, {
        protocol: "v3-broker",
        epoch: incomingEpoch,
        revision: previous ? previous.updatedAtRevision : provisionalRevision,
        previous,
      });
      // Bump member's updatedAtRevision only if canonical member fields changed
      if (previous && canonical(canonicalizeMemberForHash({ ...normalized, updatedAtRevision: previous.updatedAtRevision })) !==
          canonical(canonicalizeMemberForHash(previous))) {
        normalized.updatedAtRevision = provisionalRevision;
      }
      incomingMembersMap[ids.identityKey] = normalized;

      const metaLastSeen = toOptionalSafeInt(rawMember.lastSeenAt ?? matchedBm?.lastSeenAt);
      if (metaLastSeen !== null) {
        const prevPres = nextPresence[ids.identityKey];
        if (!prevPres || metaLastSeen >= (prevPres.lastSeenAtMs || 0)) {
          nextPresence[ids.identityKey] = {
            lastSeenAtMs: metaLastSeen,
            lastSeenAt: new Date(metaLastSeen).toISOString(),
            liveVerified: Boolean(prevPres?.liveVerified && prevPres?.lastSeenAtMs === metaLastSeen),
            version: normalized.version || prevPres?.version || null,
            activeSessionCount: prevPres?.activeSessionCount ?? null,
            copilotDesktopRunning: prevPres?.copilotDesktopRunning ?? null,
          };
        }
      }
    }

    // Detect members removed since the stored snapshot when broker rosterEpoch advanced
    if (stored && incomingEpoch > stored.rosterEpoch) {
      for (const [prevKey, prevMember] of Object.entries(stored.members || {})) {
        if (!incomingMembersMap[prevKey]) {
          nextTombstones[prevKey] = pickNewerTombstone(nextTombstones[prevKey], {
            identityKey: prevKey,
            peerId: prevMember.peerId,
            keyFingerprint: prevMember.keyFingerprint,
            machineId: prevMember.machineId,
            githubUser: prevMember.githubUser,
            removedAtMs: Math.trunc(now),
            removedAtEpoch: incomingEpoch,
            removedAtRevision: provisionalRevision,
            reason: "broker_reconciled",
            operationId: null,
          });
          delete nextPresence[prevKey];
        }
      }
    } else if (stored && incomingEpoch === stored.rosterEpoch) {
      // At equal epoch, retain previously known active members that have NOT been tombstoned
      // (so partial single-device enrollment payloads cannot silently drop offline collaborators).
      for (const [prevKey, prevMember] of Object.entries(stored.members || {})) {
        if (!incomingMembersMap[prevKey] && !nextTombstones[prevKey]) {
          incomingMembersMap[prevKey] = prevMember;
        }
      }
    }

    const candidateHashAtSameRev = stored
      ? computeRosterHash({
          flockId,
          protocol: "v3-broker",
          rosterEpoch: incomingEpoch,
          rosterRevision: stored.rosterRevision,
          members: incomingMembersMap,
          tombstones: nextTombstones,
        })
      : null;

    const unchanged = Boolean(
      stored &&
      incomingEpoch === stored.rosterEpoch &&
      candidateHashAtSameRev === stored.rosterHash
    );
    const finalRevision = unchanged ? stored.rosterRevision : provisionalRevision;
    const finalHash = unchanged
      ? stored.rosterHash
      : computeRosterHash({
          flockId,
          protocol: "v3-broker",
          rosterEpoch: incomingEpoch,
          rosterRevision: finalRevision,
          members: incomingMembersMap,
          tombstones: nextTombstones,
        });

    data.flocks[flockId] = {
      flockId,
      protocol: "v3-broker",
      flockType: flockSummary.flockType || stored?.flockType || (flockId.includes("/") ? "shared" : "owner_root"),
      ownerGitHubUser: String(flockSummary.ownerGitHubUser || stored?.ownerGitHubUser || flockId.split("/")[0]).toLowerCase(),
      ownerFingerprint: null,
      ownerPublicKey: null,
      rosterEpoch: incomingEpoch,
      minAcceptedEpoch: incomingEpoch,
      rotationHash: null,
      rosterRevision: finalRevision,
      previousRosterHash: unchanged ? stored.previousRosterHash : (stored?.rosterHash || null),
      rosterHash: finalHash,
      syncedAtMs: Math.trunc(now),
      staleAfterMs: stored?.staleAfterMs || this.staleAfterMs,
      needsSnapshotSync: false,
      members: incomingMembersMap,
      tombstones: nextTombstones,
      presence: nextPresence,
    };
    this.save(data);
    return {
      applied: !unchanged,
      idempotent: unchanged,
      flockId,
      rosterEpoch: incomingEpoch,
      rosterRevision: finalRevision,
      rosterHash: finalHash,
    };
  }

  reconcileV3Broker({
    myFlocksResponse = null,
    enrolledFlocks = [],
    bootstrapMembers = [],
    now = this.clock(),
  } = {}) {
    const summaries = [
      ...(Array.isArray(enrolledFlocks) ? enrolledFlocks : []),
      ...(Array.isArray(myFlocksResponse?.ownedFlocks) ? myFlocksResponse.ownedFlocks : []),
      ...(Array.isArray(myFlocksResponse?.joinedFlocks) ? myFlocksResponse.joinedFlocks : []),
      ...(Array.isArray(myFlocksResponse?.collaboratorFlocks) ? myFlocksResponse.collaboratorFlocks : []),
      ...(Array.isArray(myFlocksResponse?.guestFlocks) ? myFlocksResponse.guestFlocks : []),
    ];
    const byFlock = new Map();
    for (const s of summaries) {
      if (!s?.flockId) continue;
      const fid = normalizeRegistryFlockId(s.flockId);
      const prev = byFlock.get(fid);
      if (!prev || (Number(s.rosterEpoch) || 1) >= (Number(prev.rosterEpoch) || 1)) {
        byFlock.set(fid, s);
      }
    }
    const results = [];
    for (const summary of byFlock.values()) {
      results.push(this.reconcileV3BrokerFlock(summary, { bootstrapMembers, now }));
    }
    return results;
  }

  recordRemovalTombstone(flockId, removal, { now = this.clock() } = {}) {
    const cleanFlockId = normalizeRegistryFlockId(flockId);
    const data = this.read();
    const stored = data.flocks[cleanFlockId];
    if (!stored) {
      throw registryError("ROSTER_FLOCK_NOT_FOUND", `Flock "${cleanFlockId}" not found in membership registry`);
    }
    const nextEpoch = Number.isSafeInteger(removal?.removedAtEpoch) && removal.removedAtEpoch >= stored.rosterEpoch
      ? removal.removedAtEpoch
      : stored.rosterEpoch;
    if (Number.isSafeInteger(removal?.removedAtEpoch) && removal.removedAtEpoch < stored.rosterEpoch) {
      throw registryError("ROSTER_ROLLBACK_REJECTED", "Removal tombstone epoch cannot roll back stored rosterEpoch");
    }
    const nextRevision = stored.rosterRevision + 1;
    const tomb = normalizeTombstoneRecord(removal, {
      protocol: stored.protocol,
      defaultEpoch: nextEpoch,
      defaultRevision: nextRevision,
      now,
      previous: null,
    });
    delete stored.members[tomb.identityKey];
    delete stored.presence?.[tomb.identityKey];
    stored.tombstones ||= {};
    stored.tombstones[tomb.identityKey] = pickNewerTombstone(stored.tombstones[tomb.identityKey], tomb);
    stored.previousRosterHash = stored.rosterHash;
    stored.rosterEpoch = nextEpoch;
    stored.minAcceptedEpoch = Math.max(stored.minAcceptedEpoch || 1, nextEpoch);
    stored.rosterRevision = nextRevision;
    stored.rosterHash = computeRosterHash({
      flockId: cleanFlockId,
      protocol: stored.protocol,
      rosterEpoch: nextEpoch,
      rosterRevision: nextRevision,
      members: stored.members,
      tombstones: stored.tombstones,
    });
    stored.syncedAtMs = Math.trunc(now);
    this.save(data);
    return stored.tombstones[tomb.identityKey];
  }

  mergeRegistryCache(incomingStore, {
    flockId = null,
    allowOlderFlockSkip = false,
    now = this.clock(),
  } = {}) {
    if (!incomingStore || typeof incomingStore !== "object" || !incomingStore.flocks) {
      throw registryError("ROSTER_CORRUPT_STORE", "Invalid registry cache payload for merge");
    }
    const targetFlockId = flockId ? normalizeRegistryFlockId(flockId) : null;
    const data = this.read();
    const mergedFlockIds = [];

    for (const [rawId, incoming] of Object.entries(incomingStore.flocks)) {
      const fid = normalizeRegistryFlockId(rawId);
      if (targetFlockId && fid !== targetFlockId) continue;
      const stored = data.flocks[fid];
      if (!stored) {
        const verifiedHash = computeRosterHash({
          flockId: fid,
          protocol: incoming.protocol,
          rosterEpoch: incoming.rosterEpoch,
          rosterRevision: incoming.rosterRevision,
          members: incoming.members || {},
          tombstones: incoming.tombstones || {},
        });
        if (verifiedHash !== incoming.rosterHash) {
          throw registryError("ROSTER_HASH_CONFLICT", `Incoming cache hash mismatch for flock "${fid}"`);
        }
        data.flocks[fid] = structuredClone(incoming);
        mergedFlockIds.push(fid);
        continue;
      }

      if (stored.protocol !== incoming.protocol) {
        throw registryError("ROSTER_PROTOCOL_MISMATCH", `Protocol mismatch while merging cache for "${fid}"`);
      }
      if (stored.ownerFingerprint && incoming.ownerFingerprint && stored.ownerFingerprint !== incoming.ownerFingerprint) {
        throw registryError("ROSTER_OWNER_MISMATCH", `Owner fingerprint mismatch while merging cache for "${fid}"`);
      }

      const cmp = compareRosterVersion(
        { epoch: incoming.rosterEpoch, revision: incoming.rosterRevision },
        { epoch: stored.rosterEpoch, revision: stored.rosterRevision }
      );
      if (cmp < 0) {
        if (allowOlderFlockSkip) continue;
        throw registryError(
          "ROSTER_ROLLBACK_REJECTED",
          `Cannot merge older roster cache (${incoming.rosterEpoch}:${incoming.rosterRevision}) over (${stored.rosterEpoch}:${stored.rosterRevision}) for "${fid}"`
        );
      }
      if (cmp === 0) {
        if (incoming.rosterHash !== stored.rosterHash) {
          throw registryError("ROSTER_HASH_CONFLICT", `Conflicting cache hash at (${stored.rosterEpoch}:${stored.rosterRevision}) for "${fid}"`);
        }
        continue;
      }

      const incomingVerifiedHash = computeRosterHash({
        flockId: fid,
        protocol: incoming.protocol,
        rosterEpoch: incoming.rosterEpoch,
        rosterRevision: incoming.rosterRevision,
        members: incoming.members || {},
        tombstones: incoming.tombstones || {},
      });
      if (incomingVerifiedHash !== incoming.rosterHash) {
        throw registryError("ROSTER_HASH_CONFLICT", `Incoming cache hash mismatch for flock "${fid}"`);
      }

      // Union tombstones and guarantee no previously tombstoned member is resurrected without a strictly newer addition version.
      const unionTombstones = structuredClone(incoming.tombstones || {});
      for (const [idKey, prevTomb] of Object.entries(stored.tombstones || {})) {
        const candidateMember = incoming.members?.[idKey];
        if (candidateMember) {
          if (compareRosterVersion(
            { epoch: candidateMember.addedAtEpoch, revision: candidateMember.updatedAtRevision },
            { epoch: prevTomb.removedAtEpoch, revision: prevTomb.removedAtRevision }
          ) <= 0) {
            throw registryError(
              "ROSTER_RESURRECTION_REJECTED",
              `Incoming cache attempted to resurrect tombstoned member "${idKey}" in "${fid}"`
            );
          }
        } else {
          unionTombstones[idKey] = pickNewerTombstone(unionTombstones[idKey], prevTomb);
        }
      }

      data.flocks[fid] = {
        ...structuredClone(incoming),
        tombstones: unionTombstones,
        presence: { ...(stored.presence || {}), ...(incoming.presence || {}) },
        syncedAtMs: Math.max(stored.syncedAtMs || 0, incoming.syncedAtMs || 0, Math.trunc(now)),
      };
      // Recompute hash if retained local tombstones augmented incoming tombstones
      const postMergeHash = computeRosterHash({
        flockId: fid,
        protocol: data.flocks[fid].protocol,
        rosterEpoch: data.flocks[fid].rosterEpoch,
        rosterRevision: data.flocks[fid].rosterRevision,
        members: data.flocks[fid].members,
        tombstones: data.flocks[fid].tombstones,
      });
      if (postMergeHash !== incoming.rosterHash) {
        throw registryError(
          "ROSTER_TOMBSTONE_OMITTED",
          `Incoming cache for "${fid}" omitted retained removal tombstones`
        );
      }
      mergedFlockIds.push(fid);
    }

    if (mergedFlockIds.length > 0) this.save(data);
    return { mergedFlockIds };
  }

  recordPresence(flockId, observations, { now = this.clock() } = {}) {
    const cleanFlockId = normalizeRegistryFlockId(flockId);
    const data = this.read();
    const stored = data.flocks[cleanFlockId];
    if (!stored) {
      throw registryError("ROSTER_FLOCK_NOT_FOUND", `Flock "${cleanFlockId}" not found in membership registry`);
    }
    stored.presence ||= {};
    const list = Array.isArray(observations) ? observations : [observations];
    let updatedCount = 0;

    for (const obs of list) {
      if (!obs || typeof obs !== "object") continue;
      const targetKey = this._matchObservationToMemberKey(stored, obs);
      if (!targetKey || stored.tombstones?.[targetKey] || !stored.members?.[targetKey]) continue;
      const seenMs = toOptionalSafeInt(obs.observedAtMs ?? obs.respondedAt ?? obs.lastSeenAt) ?? Math.trunc(now);
      stored.presence[targetKey] = {
        lastSeenAtMs: seenMs,
        lastSeenAt: new Date(seenMs).toISOString(),
        liveVerified: obs.liveVerified !== false,
        version: obs.version ?? stored.presence[targetKey]?.version ?? null,
        activeSessionCount: obs.activeSessionCount ?? stored.presence[targetKey]?.activeSessionCount ?? null,
        copilotDesktopRunning: obs.copilotDesktopRunning ?? stored.presence[targetKey]?.copilotDesktopRunning ?? null,
      };
      updatedCount++;
    }
    if (updatedCount > 0) this.save(data);
    return { updatedCount };
  }

  _matchObservationToMemberKey(stored, obs) {
    if (obs.identityKey && stored.members[String(obs.identityKey).toLowerCase()]) {
      return String(obs.identityKey).toLowerCase();
    }
    try {
      const ids = resolveMemberIdentityKey(obs, { protocol: stored.protocol });
      if (stored.members[ids.identityKey]) return ids.identityKey;
      const byFp = Object.values(stored.members).filter((m) => m.keyFingerprint === ids.keyFingerprint);
      if (byFp.length === 1) return byFp[0].identityKey;
    } catch {}
    // Only allow hostname fallback for live presence matching when unambiguous within this flock
    if (obs.machineId) {
      const mLower = String(obs.machineId).trim().toLowerCase();
      const uLower = obs.githubUser ? String(obs.githubUser).replace(/^@/, "").trim().toLowerCase() : null;
      const candidates = Object.values(stored.members).filter(
        (m) => m.machineId.toLowerCase() === mLower && (!uLower || m.githubUser === uLower)
      );
      if (candidates.length === 1) return candidates[0].identityKey;
    }
    return null;
  }

  getFlockView(flockId, {
    includeRemoved = false,
    livePeers = null,
    now = this.clock(),
    staleAfterMs = null,
    presenceTtlMs = null,
  } = {}) {
    const cleanFlockId = normalizeRegistryFlockId(flockId);
    const stored = this.read().flocks[cleanFlockId];
    if (!stored) {
      throw registryError("ROSTER_FLOCK_NOT_FOUND", `Flock "${cleanFlockId}" not found in membership registry`);
    }
    const effectiveStaleMs = Number.isSafeInteger(staleAfterMs) && staleAfterMs > 0
      ? staleAfterMs
      : (stored.staleAfterMs || this.staleAfterMs);
    const effectivePresenceTtl = Number.isSafeInteger(presenceTtlMs) && presenceTtlMs > 0
      ? presenceTtlMs
      : this.presenceTtlMs;

    const liveOverlay = new Map();
    if (Array.isArray(livePeers)) {
      for (const peer of livePeers) {
        const key = this._matchObservationToMemberKey(stored, peer);
        if (key) liveOverlay.set(key, peer);
      }
    }

    const members = [];
    for (const m of Object.values(stored.members || {})) {
      const pres = stored.presence?.[m.identityKey] || null;
      const overlay = liveOverlay.get(m.identityKey) || null;
      const overlaySeenMs = overlay
        ? (toOptionalSafeInt(overlay.observedAtMs ?? overlay.respondedAt ?? overlay.lastSeenAt) ?? Math.trunc(now))
        : null;
      const lastSeenAtMs = overlaySeenMs ?? pres?.lastSeenAtMs ?? null;
      const isLiveOnline = Boolean(
        overlay ||
        (pres?.liveVerified === true && lastSeenAtMs !== null && now - lastSeenAtMs <= effectivePresenceTtl)
      );

      const membershipStatus = m.membershipExpiresAtMs !== null && m.membershipExpiresAtMs <= now
        ? "expired"
        : "active";

      const certStatus = m.certExpiresAtMs !== null
        ? ((m.certIssuedAtMs === null || m.certIssuedAtMs <= now + 30000) && m.certExpiresAtMs > now
            ? "valid"
            : "expired")
        : "not_applicable";

      members.push({
        flockId: cleanFlockId,
        identityKey: m.identityKey,
        peerId: m.peerId,
        keyFingerprint: m.keyFingerprint,
        deviceId: m.deviceId,
        machineId: m.machineId,
        githubUser: m.githubUser,
        githubName: m.githubName || null,
        role: m.role,
        scope: m.scope,
        specs: overlay?.specs ?? m.specs ?? null,
        version: overlay?.version ?? pres?.version ?? m.version ?? null,
        platform: m.platform || null,
        joinedAt: m.joinedAtMs !== null ? new Date(m.joinedAtMs).toISOString() : null,
        membershipExpiresAtMs: m.membershipExpiresAtMs,
        membershipExpiresAt: m.membershipExpiresAtMs !== null ? new Date(m.membershipExpiresAtMs).toISOString() : null,
        expiresAt: m.certExpiresAtMs ?? m.membershipExpiresAtMs ?? null,
        removed: false,
        membershipStatus,
        presenceStatus: isLiveOnline ? "online" : "unknown",
        lastSeenAt: lastSeenAtMs !== null ? new Date(lastSeenAtMs).toISOString() : null,
        certIssuedAtMs: m.certIssuedAtMs,
        certExpiresAtMs: m.certExpiresAtMs,
        certStatus,
        sharedThreadsExposed: false,
      });
    }

    if (includeRemoved) {
      for (const t of Object.values(stored.tombstones || {})) {
        members.push({
          flockId: cleanFlockId,
          identityKey: t.identityKey,
          peerId: t.peerId,
          keyFingerprint: t.keyFingerprint,
          deviceId: t.keyFingerprint,
          machineId: t.machineId,
          githubUser: t.githubUser,
          githubName: null,
          role: null,
          scope: null,
          specs: null,
          version: null,
          platform: null,
          joinedAt: null,
          membershipExpiresAtMs: null,
          membershipExpiresAt: null,
          expiresAt: null,
          removed: true,
          removedAtMs: t.removedAtMs,
          removedAt: new Date(t.removedAtMs).toISOString(),
          removedAtEpoch: t.removedAtEpoch,
          removedAtRevision: t.removedAtRevision,
          removalReason: t.reason,
          membershipStatus: "removed",
          presenceStatus: "unknown",
          lastSeenAt: null,
          certIssuedAtMs: null,
          certExpiresAtMs: null,
          certStatus: "not_applicable",
          sharedThreadsExposed: false,
        });
      }
    }

    members.sort((a, b) => (a.identityKey < b.identityKey ? -1 : a.identityKey > b.identityKey ? 1 : 0));
    const activeCount = members.filter((m) => m.membershipStatus === "active").length;
    const onlineKnownCount = members.filter((m) => !m.removed && m.presenceStatus === "online").length;

    return {
      flockId: cleanFlockId,
      protocol: stored.protocol,
      flockType: stored.flockType,
      ownerGitHubUser: stored.ownerGitHubUser,
      ownerFingerprint: stored.ownerFingerprint,
      rosterEpoch: stored.rosterEpoch,
      rosterRevision: stored.rosterRevision,
      rosterHash: stored.rosterHash,
      syncedAtMs: stored.syncedAtMs,
      syncedAt: stored.syncedAtMs ? new Date(stored.syncedAtMs).toISOString() : null,
      isStale: Boolean(stored.needsSnapshotSync || !stored.syncedAtMs || now - stored.syncedAtMs > effectiveStaleMs),
      needsSnapshotSync: Boolean(stored.needsSnapshotSync),
      sharedThreadVisibility: "isolated",
      totalMembers: activeCount,
      onlineKnownCount,
      tombstoneCount: Object.keys(stored.tombstones || {}).length,
      members,
    };
  }

  listMembers(flockId, options = {}) {
    return this.getFlockView(flockId, options).members;
  }
}
