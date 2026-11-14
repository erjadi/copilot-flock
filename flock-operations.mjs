import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { atomicJson, inspectProcess } from "./flock-lifecycle.mjs";

const TERMINAL_STATES = new Set(["completed", "failed", "cancelled"]);
const TRANSITIONS = Object.freeze({
  accepted: new Set(["delivered", "failed", "cancelled"]),
  delivered: new Set(["running", "failed", "cancelled"]),
  running: new Set(["completed", "failed", "cancelled"]),
  completed: new Set(),
  failed: new Set(),
  cancelled: new Set(),
});

function clone(value) {
  return value == null ? value : structuredClone(value);
}

function boundedText(value, max = 4096) {
  const text = String(value || "");
  return text.length <= max ? text : `${text.slice(0, max)}...`;
}

function requesterKey({
  flockId = null,
  requesterMachine,
  requesterSession = null,
  requesterGitHubUser = null,
  requesterPeerId = null,
}) {
  return [
    String(flockId || "").toLowerCase(),
    String(requesterMachine || "").toLowerCase(),
    String(requesterSession || "").toLowerCase(),
    String(requesterGitHubUser || "").toLowerCase(),
    String(requesterPeerId || "").toLowerCase(),
  ].join("|");
}

function redactOperationContent(value, max = 8192) {
  return boundedText(value, max)
    .replace(/-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----/gi, "[REDACTED PRIVATE KEY]")
    .replace(/\b(AccessKey|SharedAccessKey|SharedAccessSignature|sig)=([^;\s&]+)/gi, "$1=[REDACTED]")
    .replace(/\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, "[REDACTED TOKEN]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED JWT]");
}

function terminateVerifiedProcessTree(identity, inspectProcessFn = inspectProcess, platform = process.platform) {
  if (!identity?.pid || identity.start == null) return false;
  const live = inspectProcessFn(identity.pid);
  if (!live || live.start !== identity.start) return false;
  if (platform === "win32") {
    execFileSync("taskkill.exe", ["/PID", String(identity.pid), "/T", "/F"], {
      windowsHide: true,
      stdio: "ignore",
    });
    return true;
  }
  const rows = execFileSync("ps", ["-eo", "pid=,ppid="], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  const childrenByParent = new Map();
  for (const line of String(rows).split(/\r?\n/)) {
    const match = line.trim().match(/^(\d+)\s+(\d+)$/);
    if (!match) continue;
    const pid = Number(match[1]);
    const ppid = Number(match[2]);
    const children = childrenByParent.get(ppid) || [];
    children.push(pid);
    childrenByParent.set(ppid, children);
  }
  const descendants = [];
  const visit = (pid) => {
    for (const childPid of childrenByParent.get(pid) || []) {
      visit(childPid);
      descendants.push(childPid);
    }
  };
  visit(Number(identity.pid));
  for (const pid of [...descendants, Number(identity.pid)]) {
    try {
      process.kill(pid, "SIGTERM");
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  }
  return true;
}

export class PersistentOperationStore {
  constructor(root, { clock = Date.now, maxOperations = 500 } = {}) {
    this.root = path.resolve(root);
    this.filename = path.join(this.root, "operations.json");
    this.clock = clock;
    this.maxOperations = Math.max(50, Number(maxOperations) || 500);
  }

  read() {
    if (!fs.existsSync(this.filename)) {
      return { type: "copilot-flock-operations-v1", operations: {} };
    }
    const data = JSON.parse(fs.readFileSync(this.filename, "utf8"));
    if (data?.type !== "copilot-flock-operations-v1" || !data.operations) {
      throw new Error("Invalid remote operation state");
    }
    return data;
  }

  save(data) {
    fs.mkdirSync(this.root, { recursive: true });
    const ordered = Object.values(data.operations || {}).sort(
      (a, b) => Number(b.updatedAtMs) - Number(a.updatedAtMs)
    );
    data.operations = Object.fromEntries(
      ordered.slice(0, this.maxOperations).map((operation) => [operation.operationId, operation])
    );
    data.updatedAt = new Date(this.clock()).toISOString();
    atomicJson(this.filename, data);
  }

  admit({
    operationId = crypto.randomUUID(),
    correlationId = operationId,
    action,
    flockId = null,
    requesterMachine,
    requesterSession = null,
    requesterGitHubUser = null,
    requesterPeerId = null,
    targetMachine,
    targetSession = null,
    metadata = null,
  }) {
    const data = this.read();
    const existing = data.operations[operationId];
    const ownerKey = requesterKey({
      flockId,
      requesterMachine,
      requesterSession,
      requesterGitHubUser,
      requesterPeerId,
    });
    if (existing) {
      if (
        existing.requesterKey !== ownerKey ||
        existing.action !== action ||
        existing.targetMachine !== targetMachine ||
        existing.targetSession !== targetSession
      ) {
        const error = new Error(`Operation ID "${operationId}" was replayed with different authorization or dispatch parameters`);
        error.code = "OPERATION_REPLAY_CONFLICT";
        throw error;
      }
      return { operation: clone(existing), replayed: true };
    }
    const now = this.clock();
    const operation = {
      operationId,
      correlationId,
      action,
      flockId,
      requesterMachine,
      requesterSession,
      requesterGitHubUser,
      requesterPeerId,
      requesterKey: ownerKey,
      targetMachine,
      targetSession,
      state: "accepted",
      waitState: null,
      cancellationRequested: false,
      createdAt: new Date(now).toISOString(),
      createdAtMs: now,
      updatedAt: new Date(now).toISOString(),
      updatedAtMs: now,
      metadata: metadata ? clone(metadata) : null,
      history: [{ state: "accepted", at: new Date(now).toISOString() }],
    };
    data.operations[operationId] = operation;
    this.save(data);
    return { operation: clone(operation), replayed: false };
  }

  get(operationId) {
    const operation = this.read().operations[String(operationId || "")];
    return operation ? clone(operation) : null;
  }

  transition(operationId, state, detail = {}) {
    const data = this.read();
    const operation = data.operations[operationId];
    if (!operation) throw new Error(`Unknown operation "${operationId}"`);
    if (operation.state === state) return clone(operation);
    if (!TRANSITIONS[operation.state]?.has(state)) {
      throw new Error(`Invalid operation transition ${operation.state} -> ${state}`);
    }
    const now = this.clock();
    operation.state = state;
    operation.updatedAt = new Date(now).toISOString();
    operation.updatedAtMs = now;
    if (detail.processIdentity !== undefined) operation.processIdentity = clone(detail.processIdentity);
    if (detail.result !== undefined) operation.result = clone(detail.result);
    if (detail.error !== undefined) operation.error = boundedText(detail.error);
    if (detail.deliveryStage !== undefined) operation.deliveryStage = detail.deliveryStage;
    if (detail.runtime !== undefined) operation.runtime = clone(detail.runtime);
    operation.history = [
      ...(operation.history || []),
      {
        state,
        at: operation.updatedAt,
        ...(detail.deliveryStage ? { deliveryStage: detail.deliveryStage } : {}),
      },
    ].slice(-24);
    data.operations[operationId] = operation;
    this.save(data);
    return clone(operation);
  }

  markWaitTimedOut(operationId) {
    const data = this.read();
    const operation = data.operations[operationId];
    if (!operation) throw new Error(`Unknown operation "${operationId}"`);
    const now = this.clock();
    operation.waitState = "timed_out_waiting";
    operation.waitTimedOutAt = new Date(now).toISOString();
    operation.updatedAt = operation.waitTimedOutAt;
    operation.updatedAtMs = now;
    data.operations[operationId] = operation;
    this.save(data);
    return clone(operation);
  }

  reconcile(operationId, { inspectProcessFn = inspectProcess } = {}) {
    const operation = this.get(operationId);
    if (!operation || operation.state !== "running") return operation;
    if (operation.processIdentity?.pid && operation.processIdentity.start != null) {
      const live = inspectProcessFn(operation.processIdentity.pid);
      if (live && live.start === operation.processIdentity.start) return operation;
    }
    const eventPath = operation.runtime?.eventsPath;
    const startOffset = Math.max(0, Number(operation.runtime?.startByteOffset) || 0);
    if (eventPath && fs.existsSync(eventPath)) {
      const bytes = fs.readFileSync(eventPath);
      const text = bytes.subarray(Math.min(startOffset, bytes.length)).toString("utf8");
      const events = text.split(/\r?\n/).filter(Boolean).flatMap((line) => {
        try {
          return [JSON.parse(line)];
        } catch {
          return [];
        }
      });
      const assistant = [...events].reverse().find((event) => event?.type === "assistant.message");
      if (assistant) {
        const content = assistant.data?.content ?? assistant.content ?? "";
        return this.transition(operationId, "completed", {
          deliveryStage: "assistant_completed_after_reconciliation",
          result: { completed: true, content: boundedText(content, 16384) },
        });
      }
    }
    return this.transition(operationId, operation.cancellationRequested ? "cancelled" : "failed", {
      error: operation.cancellationRequested
        ? "Cancelled operation process exited"
        : "Tracked runtime process exited without a persisted assistant completion",
    });
  }

  assertRequester(operation, requester) {
    if (!operation || operation.requesterKey !== requesterKey(requester)) {
      const error = new Error("Operation cancellation/query is not authorized for this flock requester");
      error.code = "OPERATION_REQUESTER_MISMATCH";
      error.statusCode = 403;
      throw error;
    }
  }

  requestCancellation(operationId, requester) {
    const data = this.read();
    const operation = data.operations[operationId];
    this.assertRequester(operation, requester);
    if (TERMINAL_STATES.has(operation.state)) {
      return { operation: clone(operation), alreadyTerminal: true };
    }
    const now = this.clock();
    operation.cancellationRequested = true;
    operation.cancellationRequestedAt = new Date(now).toISOString();
    operation.updatedAt = operation.cancellationRequestedAt;
    operation.updatedAtMs = now;
    data.operations[operationId] = operation;
    this.save(data);
    return { operation: clone(operation), alreadyTerminal: false };
  }

  list({ offset = 0, limit = 25 } = {}) {
    const safeLimit = Math.min(100, Math.max(1, Number(limit) || 25));
    const safeOffset = Math.max(0, Number(offset) || 0);
    const all = Object.values(this.read().operations || {}).sort(
      (a, b) => Number(b.updatedAtMs) - Number(a.updatedAtMs)
    );
    return {
      total: all.length,
      offset: safeOffset,
      limit: safeLimit,
      operations: clone(all.slice(safeOffset, safeOffset + safeLimit)),
      nextOffset: safeOffset + safeLimit < all.length ? safeOffset + safeLimit : null,
    };
  }
}

export class HeadlessSessionSupervisor {
  constructor(root, {
    clock = Date.now,
    inspectProcessFn = inspectProcess,
    terminateProcessTreeFn = terminateVerifiedProcessTree,
    maxQueueDepth = 32,
    leaseTtlMs = 10 * 60 * 1000,
  } = {}) {
    this.root = path.resolve(root);
    this.clock = clock;
    this.inspectProcess = inspectProcessFn;
    this.terminateProcessTree = terminateProcessTreeFn;
    this.maxQueueDepth = Math.max(1, Number(maxQueueDepth) || 32);
    this.leaseTtlMs = Math.max(1000, Number(leaseTtlMs) || 600000);
    this.leasePath = path.join(this.root, "cli-leases.json");
    this.queues = new Map();
    this.children = new Map();
  }

  readLeases() {
    if (!fs.existsSync(this.leasePath)) return { type: "copilot-flock-headless-leases-v1", leases: {} };
    const data = JSON.parse(fs.readFileSync(this.leasePath, "utf8"));
    if (data?.type !== "copilot-flock-headless-leases-v1" || !data.leases) {
      throw new Error("Invalid headless session lease state");
    }
    return data;
  }

  saveLeases(data) {
    fs.mkdirSync(this.root, { recursive: true });
    atomicJson(this.leasePath, data);
  }

  processIdentityIsLive(identity) {
    if (!identity?.pid || identity.start == null) return false;
    const live = this.inspectProcess(identity.pid);
    return Boolean(live && live.start === identity.start);
  }

  reconcile() {
    const data = this.readLeases();
    let changed = false;
    for (const [sessionId, lease] of Object.entries(data.leases)) {
      if (
        Number(lease.expiresAtMs) <= this.clock() ||
        (lease.processIdentity && !this.processIdentityIsLive(lease.processIdentity))
      ) {
        delete data.leases[sessionId];
        changed = true;
      }
    }
    if (changed) this.saveLeases(data);
    return data;
  }

  activeSessionIds() {
    return new Set(Object.keys(this.reconcile().leases));
  }

  isRunning(sessionId) {
    return this.activeSessionIds().has(String(sessionId));
  }

  acquire(sessionId, operationId) {
    const data = this.reconcile();
    const existing = data.leases[sessionId];
    if (existing && existing.operationId !== operationId) {
      throw new Error(`Session "${sessionId}" already has an active headless turn`);
    }
    const now = this.clock();
    data.leases[sessionId] = {
      sessionId,
      operationId,
      acquiredAt: existing?.acquiredAt || new Date(now).toISOString(),
      renewedAt: new Date(now).toISOString(),
      expiresAtMs: now + this.leaseTtlMs,
      processIdentity: existing?.processIdentity || null,
    };
    this.saveLeases(data);
  }

  bindProcess(sessionId, operationId, processIdentity) {
    const data = this.readLeases();
    const lease = data.leases[sessionId];
    if (!lease || lease.operationId !== operationId) throw new Error("Headless lease ownership changed");
    lease.processIdentity = clone(processIdentity);
    lease.expiresAtMs = this.clock() + this.leaseTtlMs;
    this.saveLeases(data);
  }

  release(sessionId, operationId) {
    const data = this.readLeases();
    if (data.leases[sessionId]?.operationId === operationId) {
      delete data.leases[sessionId];
      this.saveLeases(data);
    }
    this.children.delete(operationId);
  }

  enqueue(sessionId, operationId, task) {
    const key = String(sessionId);
    const current = this.queues.get(key) || { tail: Promise.resolve(), depth: 0 };
    if (current.depth >= this.maxQueueDepth) {
      const error = new Error(`Headless session queue is full for "${key}"`);
      error.code = "HEADLESS_QUEUE_FULL";
      throw error;
    }
    current.depth++;
    const run = current.tail.then(async () => {
      this.acquire(key, operationId);
      try {
        return await task({
          bindProcess: (identity, child = null) => {
            this.bindProcess(key, operationId, identity);
            if (child) this.children.set(operationId, { child, identity });
          },
        });
      } finally {
        this.release(key, operationId);
      }
    });
    current.tail = run.catch(() => {}).finally(() => {
      current.depth--;
      if (current.depth === 0) this.queues.delete(key);
    });
    this.queues.set(key, current);
    return run;
  }

  cancel(operationId) {
    const active = this.children.get(operationId);
    if (!active || !this.processIdentityIsLive(active.identity)) return false;
    return Boolean(this.terminateProcessTree(active.identity, this.inspectProcess));
  }
}

export class PresenceStateTracker {
  constructor({ clock = Date.now, reconnectGraceMs = 20000, expiryMs = 90000 } = {}) {
    this.clock = clock;
    this.reconnectGraceMs = Math.max(0, Number(reconnectGraceMs) || 0);
    this.expiryMs = Math.max(this.reconnectGraceMs + 1, Number(expiryMs) || 90000);
  }

  classify({
    transportOnline,
    lastSeenAt = null,
    desktopReachable = null,
    headlessCliAvailable = null,
    coordinatorHealthy = null,
    trackerHealthy = null,
    reason = null,
    removed = false,
    revoked = false,
    tombstoned = false,
    membershipExpiresAtMs = null,
  }) {
    const now = this.clock();
    const seenMs = lastSeenAt == null
      ? null
      : typeof lastSeenAt === "number"
        ? lastSeenAt
        : Date.parse(String(lastSeenAt));
    const ageMs = Number.isFinite(seenMs) ? Math.max(0, now - seenMs) : null;
    const expired = membershipExpiresAtMs != null && Number(membershipExpiresAtMs) <= now;
    if (removed || revoked || tombstoned || expired) {
      const stateReason = removed || tombstoned
        ? "membership_removed"
        : revoked
          ? "membership_revoked"
          : "membership_expired";
      return {
        state: "offline",
        lastSeenAt: seenMs == null ? null : new Date(seenMs).toISOString(),
        ageMs,
        reason: stateReason,
        layer: "authorization",
      };
    }
    if (!transportOnline) {
      if (ageMs != null && ageMs <= this.reconnectGraceMs) {
        return { state: "reconnecting", lastSeenAt: new Date(seenMs).toISOString(), ageMs, reason: reason || "signalr_reconnect_grace", layer: "transport" };
      }
      return { state: "offline", lastSeenAt: seenMs == null ? null : new Date(seenMs).toISOString(), ageMs, reason: reason || (ageMs != null && ageMs > this.expiryMs ? "presence_expired" : "transport_unavailable"), layer: "transport" };
    }
    const runtimeViable = desktopReachable === true || headlessCliAvailable === true;
    const runtimeKnown = desktopReachable !== null || headlessCliAvailable !== null;
    if ((runtimeKnown && !runtimeViable) || coordinatorHealthy === false || trackerHealthy === false) {
      return { state: "degraded", lastSeenAt: seenMs == null ? new Date(now).toISOString() : new Date(seenMs).toISOString(), ageMs, reason: reason || (!runtimeViable ? "desktop_ws_and_cli_unavailable" : "coordination_layer_degraded"), layer: !runtimeViable ? "execution" : "coordination" };
    }
    return { state: "online", lastSeenAt: seenMs == null ? new Date(now).toISOString() : new Date(seenMs).toISOString(), ageMs, reason: null, layer: null };
  }
}

export function compactOperation(operation) {
  if (!operation) return null;
  return {
    operationId: operation.operationId,
    correlationId: operation.correlationId,
    state: operation.state,
    waitState: operation.waitState || null,
    action: operation.action,
    flockId: operation.flockId || null,
    targetMachine: operation.targetMachine,
    targetSession: operation.targetSession || null,
    deliveryStage: operation.deliveryStage || null,
    cancellationRequested: Boolean(operation.cancellationRequested),
    createdAt: operation.createdAt,
    updatedAt: operation.updatedAt,
    ...(operation.result !== undefined
      ? {
          result: {
            completed: Boolean(operation.result?.completed),
            ...(typeof operation.result?.content === "string"
              ? { content: redactOperationContent(operation.result.content) }
              : {}),
            contentBytes:
              typeof operation.result?.content === "string"
                ? Buffer.byteLength(operation.result.content, "utf8")
                : 0,
          },
        }
      : {}),
    ...(operation.error ? { error: operation.error } : {}),
  };
}
