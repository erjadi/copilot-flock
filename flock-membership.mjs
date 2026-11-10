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
