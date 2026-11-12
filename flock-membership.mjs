import crypto from "node:crypto";

export function matchesMember(member, selectors) {
  const checks = [
    [selectors.targetUser, member.githubUser, true],
    [selectors.targetGitHubUserId, member.githubUserId, false],
    [selectors.targetDeviceId, member.deviceId, true],
    [selectors.targetMachineId, member.machineId, true],
  ].filter(([selector]) => selector !== null && selector !== undefined && selector !== "");
  if (!checks.length) throw new Error("At least one explicit member selector is required");
  return checks.every(([selector, value, fold]) => fold
    ? String(selector).replace(/^@/, "").toLowerCase() === String(value).replace(/^@/, "").toLowerCase()
    : String(selector) === String(value));
}

export function canonicalLeave(request) {
  return JSON.stringify(["copilot-flock/leave/v1", request.flockId, request.deviceId,
    request.machineId, request.requestId, request.timestamp]);
}

export function signLeave({ flockId, deviceId, machineId, requestId = crypto.randomUUID() }, privateKey, now = Date.now()) {
  const request = { flockId, deviceId, machineId, requestId,
    timestamp: new Date(now).toISOString() };
  return { ...request, signature: crypto.sign(null, Buffer.from(canonicalLeave(request)), privateKey).toString("base64") };
}

export function verifyLeave(request, publicKey, now = Date.now()) {
  if (![request.flockId, request.deviceId, request.machineId, request.requestId, request.timestamp,
    request.signature].every((value) => typeof value === "string" && value.length > 0 && value.length < 4096) ||
      !Number.isFinite(Date.parse(request.timestamp)) ||
      Math.abs(now - Date.parse(request.timestamp)) > 300000 ||
      !crypto.verify(null, Buffer.from(canonicalLeave(request)), publicKey, Buffer.from(request.signature, "base64"))) {
    throw new Error("Invalid or expired signed device leave");
  }
}

export function normalizeLogin(rawUser) {
  const clean = String(rawUser || "").replace(/^@+/, "").trim().toLowerCase();
  if (!clean || !/^[a-z0-9](?:[a-z0-9-]{0,38})$/.test(clean)) return null;
  return clean;
}

export function parseCanonicalFlockAddress(targetStr, defaultOwner = null) {
  const raw = String(targetStr || "").trim().replace(/^\/+|\/+$/g, "");
  if (!raw || raw.includes("..")) {
    throw new Error(`Invalid flock address: "${targetStr}"`);
  }
  const parts = raw.split("/").map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0 || parts.length > 3) {
    throw new Error(`Invalid flock address "${targetStr}". Expected <owner>/<flock>[/<machineId>]`);
  }
  for (const seg of parts) {
    if (!/^[A-Za-z0-9._-]+$/.test(seg)) {
      throw new Error(`Invalid segment "${seg}" in flock address "${targetStr}"`);
    }
  }
  if (parts.length === 1) {
    const owner = parts[0].toLowerCase();
    return {
      owner,
      flockName: null,
      flockId: owner,
      machineId: null,
      isOwnerRoot: true,
      isBuiltInScope: true,
      canonicalPath: owner,
    };
  }
  const owner = (parts[0] || defaultOwner || "").toLowerCase();
  const flockName = parts[1].toLowerCase() === "private" ? "personal" : parts[1].toLowerCase();
  const machineId = parts.length === 3 ? parts[2] : null;
  const flockId = `${owner}/${flockName}`;
  const isBuiltInScope = flockName === "personal" || flockName === "work";
  return {
    owner,
    flockName,
    flockId,
    machineId,
    isOwnerRoot: false,
    isBuiltInScope,
    canonicalPath: machineId ? `${flockId}/${machineId}` : flockId,
  };
}

export function isSyntheticBuiltInFlock(flock) {
  return Boolean(!flock || typeof flock !== "object" || String(flock.flockUuid || "").startsWith("builtin-"));
}

export function isPrincipalRevokedInFlock(flock, { githubUser, githubUserId, peerId, deviceId } = {}) {
  if (!flock || typeof flock !== "object") return false;
  if (flock.revoked === true) return true;
  const revoked = flock.revokedPrincipals;
  if (!revoked || typeof revoked !== "object") return false;
  const login = normalizeLogin(githubUser);
  const uid = Number(githubUserId);
  const peer = String(peerId || "").trim();
  const dev = String(deviceId || "").trim().toLowerCase();
  return Boolean(
    (Number.isSafeInteger(uid) && uid > 0 && revoked[String(uid)]) ||
    (login && revoked[login]) ||
    (peer && revoked[peer]) ||
    (dev && revoked[dev])
  );
}

export function hasVerifiedOwnerAuthority(flock, auth = {}) {
  const principal = normalizeLogin(auth?.githubUser);
  const principalId = Number(auth?.githubUserId);
  const deviceId = String(auth?.deviceId || "").trim().toLowerCase();
  const expectedPeerId = `${principalId}:${deviceId}`;
  const peerId = String(auth?.peerId ?? expectedPeerId).trim();
  const now = Number.isFinite(auth?.now) ? auth.now : Date.now();

  if (
    !flock ||
    typeof flock !== "object" ||
    isSyntheticBuiltInFlock(flock) ||
    !principal ||
    !Number.isSafeInteger(principalId) ||
    principalId <= 0 ||
    !deviceId ||
    !peerId ||
    peerId !== expectedPeerId
  ) {
    return false;
  }

  let address;
  try {
    address = parseCanonicalFlockAddress(flock.flockId);
  } catch {
    return false;
  }
  if (address.machineId || flock.targetMachineId) return false;
  if (flock.trustTier !== "owner") return false;
  if (address.owner !== principal) return false;
  if (normalizeLogin(flock.ownerGitHubUser) !== principal) return false;
  if (flock.ownerGitHubUserId != null && Number(flock.ownerGitHubUserId) !== principalId) {
    return false;
  }
  const validBuiltInType =
    (address.isOwnerRoot && flock.flockType === "owner_root") ||
    (!address.isOwnerRoot && address.isBuiltInScope && flock.flockType === "owner_scope");
  if (!validBuiltInType) return false;
  if (isPrincipalRevokedInFlock(flock, { githubUser: principal, githubUserId: principalId, peerId, deviceId })) {
    return false;
  }
  if (flock.expiresAtMs != null && Number(flock.expiresAtMs) <= now) return false;
  if (flock.membershipExpiresAtMs != null || flock.membershipExpiresAt != null) return false;
  if (!Array.isArray(flock.members) || flock.members.length === 0) return false;

  const ownerMember = flock.members.find(
    (member) =>
      member &&
      member.peerId === peerId &&
      Number(member.githubUserId) === principalId &&
      normalizeLogin(member.githubUser) === principal &&
      String(member.deviceId || "").trim().toLowerCase() === deviceId &&
      member.trustTier === "owner" &&
      member.membershipExpiresAtMs == null &&
      member.membershipExpiresAt == null
  );
  return Boolean(ownerMember);
}

export function verifyAuthoritativeFlockRecord(flock, auth = {}, { requireMemberProof = true } = {}) {
  const principal = normalizeLogin(auth?.githubUser);
  const principalId = Number(auth?.githubUserId);
  const deviceId = String(auth?.deviceId || "").trim().toLowerCase();
  const expectedPeerId = `${principalId}:${deviceId}`;
  const peerId = String(auth?.peerId ?? expectedPeerId).trim();
  const now = Number.isFinite(auth?.now) ? auth.now : Date.now();

  if (
    !principal ||
    !Number.isSafeInteger(principalId) ||
    principalId <= 0 ||
    !deviceId ||
    !peerId
  ) {
    const err = new Error("Authenticated GitHub principal, user ID, and device ID are required");
    err.code = "UNAUTHENTICATED_AUTHORITY";
    throw err;
  }

  if (!flock || typeof flock !== "object") {
    const err = new Error("Authoritative flock record must be an object");
    err.code = "INVALID_FLOCK_RECORD";
    throw err;
  }

  const address = parseCanonicalFlockAddress(flock.flockId);
  if (address.machineId) {
    throw new Error("Enrollment response must identify a flock, not a machine");
  }
  if (isSyntheticBuiltInFlock(flock)) {
    const err = new Error(`Unverified synthetic local record cannot confer authority for "${address.flockId}"`);
    err.code = "UNVERIFIED_AUTHORITY";
    throw err;
  }

  if (isPrincipalRevokedInFlock(flock, { githubUser: principal, githubUserId: principalId, peerId, deviceId })) {
    const err = new Error(`Authoritative membership for "${address.flockId}" has been revoked`);
    err.code = "REVOKED_AUTHORITY";
    throw err;
  }

  if (flock.expiresAtMs != null && (!Number.isFinite(Number(flock.expiresAtMs)) || Number(flock.expiresAtMs) <= now)) {
    const err = new Error(`Flock "${address.flockId}" has expired`);
    err.code = "EXPIRED_AUTHORITY";
    throw err;
  }

  const parsedExpiryMs =
    flock.membershipExpiresAtMs != null
      ? Number(flock.membershipExpiresAtMs)
      : flock.membershipExpiresAt != null
        ? Date.parse(String(flock.membershipExpiresAt))
        : null;
  if (parsedExpiryMs != null && (!Number.isFinite(parsedExpiryMs) || parsedExpiryMs <= now)) {
    const err = new Error(`Membership authority for "${address.flockId}" has expired`);
    err.code = "EXPIRED_AUTHORITY";
    throw err;
  }

  if (flock.rosterEpoch !== undefined) {
    const rawEpoch = Number(flock.rosterEpoch);
    if (!Number.isSafeInteger(rawEpoch) || rawEpoch < 1) {
      const err = new Error(`Invalid rosterEpoch for "${address.flockId}"`);
      err.code = "INVALID_ROSTER_EPOCH";
      throw err;
    }
  }

  const normalizedFlock = { ...flock, flockId: address.flockId };
  const isOwner = hasVerifiedOwnerAuthority(normalizedFlock, {
    githubUser: principal,
    githubUserId: principalId,
    peerId,
    deviceId,
    now,
  });

  if (flock.trustTier === "owner") {
    if (!isOwner) {
      const err = new Error(`Enrollment response has unverified owner authority for "${address.flockId}"`);
      err.code = "UNVERIFIED_OWNER_AUTHORITY";
      throw err;
    }
    return { flock: normalizedFlock, address, isOwner: true };
  }

  if (flock.trustTier !== "collaborator" && flock.trustTier !== "guest") {
    const err = new Error(`Enrollment response has unverified owner authority for "${address.flockId}"`);
    err.code = "UNVERIFIED_OWNER_AUTHORITY";
    throw err;
  }

  if (peerId !== expectedPeerId) {
    const err = new Error(`Mismatched peer identity "${peerId}" for "${address.flockId}"`);
    err.code = "FORGED_AUTHORITY";
    throw err;
  }

  if (flock.ownerGitHubUser != null && normalizeLogin(flock.ownerGitHubUser) !== address.owner) {
    const err = new Error(`Forged ownerGitHubUser "${flock.ownerGitHubUser}" for "${address.flockId}"`);
    err.code = "FORGED_AUTHORITY";
    throw err;
  }

  if (requireMemberProof || Array.isArray(flock.members)) {
    if (requireMemberProof && (!Array.isArray(flock.members) || flock.members.length === 0)) {
      const err = new Error(`Authoritative member roster proof is required to reconcile "${address.flockId}"`);
      err.code = "UNVERIFIED_AUTHORITY";
      throw err;
    }
    const matchingMember = Array.isArray(flock.members)
      ? flock.members.find(
          (member) =>
            member &&
            member.peerId === peerId &&
            Number(member.githubUserId) === principalId &&
            normalizeLogin(member.githubUser) === principal &&
            String(member.deviceId || "").trim().toLowerCase() === deviceId
        )
      : null;
    if (requireMemberProof && !matchingMember) {
      const err = new Error(`Principal "${principal}" (${peerId}) is not in the authoritative roster for "${address.flockId}"`);
      err.code = "UNVERIFIED_AUTHORITY";
      throw err;
    }
    if (matchingMember) {
      if (matchingMember.trustTier !== flock.trustTier) {
        const err = new Error(
          `Forged or mismatched role "${flock.trustTier}" (authoritative roster has "${matchingMember.trustTier}") for "${address.flockId}"`
        );
        err.code = "FORGED_AUTHORITY";
        throw err;
      }
      const memberExpMs =
        matchingMember.membershipExpiresAtMs != null
          ? Number(matchingMember.membershipExpiresAtMs)
          : matchingMember.membershipExpiresAt != null
            ? Date.parse(String(matchingMember.membershipExpiresAt))
            : null;
      if (memberExpMs != null && (!Number.isFinite(memberExpMs) || memberExpMs <= now)) {
        const err = new Error(`Member roster entry for "${address.flockId}" has expired`);
        err.code = "EXPIRED_AUTHORITY";
        throw err;
      }
    }
  }

  return { flock: normalizedFlock, address, isOwner: false };
}
