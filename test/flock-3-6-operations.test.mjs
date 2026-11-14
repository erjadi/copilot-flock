import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import {
  HeadlessSessionSupervisor,
  PersistentOperationStore,
  PresenceStateTracker,
} from "../flock-operations.mjs";
import { inspectProcess } from "../flock-lifecycle.mjs";
import {
  classifyLayeredPresence,
  executeMcpTool,
  handleRpcAction,
  isProtectedRpcAction,
  queryLocalSessionsFromDb,
  resolveDefaultOperationFlockSelector,
  signRpcRequest,
} from "../flock.mjs";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-ops-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test("operation replay is idempotent and wait timeout does not cancel remote work", async (t) => {
  const root = fixture(t);
  let now = 1000;
  const store = new PersistentOperationStore(root, { clock: () => now });
  const input = {
    operationId: "op-1",
    correlationId: "corr-1",
    action: "send_message",
    flockId: "owner/work",
    requesterMachine: "CALLER",
    requesterSession: "caller-session",
    targetMachine: "REMOTE",
    targetSession: "remote-session",
  };
  const first = store.admit(input);
  const replay = store.admit(input);
  assert.equal(first.replayed, false);
  assert.equal(replay.replayed, true);
  store.transition("op-1", "delivered");
  store.transition("op-1", "running");
  now += 90000;
  const timedOut = store.markWaitTimedOut("op-1");
  assert.equal(timedOut.state, "running");
  assert.equal(timedOut.waitState, "timed_out_waiting");
  store.transition("op-1", "completed", { result: { content: "done" } });
  assert.equal(store.get("op-1").state, "completed");
});

test("operation cancellation is authorization-bound", (t) => {
  const store = new PersistentOperationStore(fixture(t));
  store.admit({
    operationId: "op-auth",
    action: "send_message",
    flockId: "owner/team",
    requesterMachine: "CALLER",
    requesterSession: "s1",
    targetMachine: "REMOTE",
    targetSession: "s2",
  });

  assert.throws(
    () => store.requestCancellation("op-auth", {
      flockId: "owner/other",
      requesterMachine: "CALLER",
      requesterSession: "s1",
    }),
    (error) => error.code === "OPERATION_REQUESTER_MISMATCH"
  );
  assert.equal(store.requestCancellation("op-auth", {
    flockId: "owner/team",
    requesterMachine: "CALLER",
    requesterSession: "s1",
  }).operation.cancellationRequested, true);
});

test("persisted running operation reconciles by PID creation identity and events offset", (t) => {
  const root = fixture(t);
  const eventsPath = path.join(root, "events.jsonl");
  fs.writeFileSync(eventsPath, `${JSON.stringify({ type: "user.message" })}\n`);
  const offset = fs.statSync(eventsPath).size;
  const store = new PersistentOperationStore(root);
  store.admit({
    operationId: "op-reconcile",
    action: "send_message",
    flockId: "owner/work",
    requesterMachine: "CALLER",
    requesterSession: "s1",
    targetMachine: "REMOTE",
    targetSession: "s2",
  });
  store.transition("op-reconcile", "delivered");
  store.transition("op-reconcile", "running", {
    processIdentity: { pid: 77, start: 100 },
    runtime: { eventsPath, startByteOffset: offset },
  });
  assert.equal(store.reconcile("op-reconcile", {
    inspectProcessFn: () => ({ pid: 77, start: 100 }),
  }).state, "running");
  fs.appendFileSync(eventsPath, `${JSON.stringify({
    type: "assistant.message",
    data: { content: "recovered completion" },
  })}\n`);
  const reconciled = store.reconcile("op-reconcile", {
    inspectProcessFn: () => ({ pid: 77, start: 200 }),
  });
  assert.equal(reconciled.state, "completed");
  assert.equal(reconciled.result.content, "recovered completion");
});

test("headless supervisor serializes FIFO and recovers stale leases without trusting reused PID", async (t) => {
  const root = fixture(t);
  const live = new Map([[42, { pid: 42, start: 200 }]]);
  const supervisor = new HeadlessSessionSupervisor(root, {
    inspectProcessFn: (pid) => live.get(pid) || null,
  });

  const order = [];
  const first = supervisor.enqueue("session-1", "op-1", async ({ bindProcess }) => {
    bindProcess({ pid: 42, start: 200 }, { kill() {} });
    order.push("first-start");
    await new Promise((resolve) => setTimeout(resolve, 20));
    order.push("first-end");
  });
  const second = supervisor.enqueue("session-1", "op-2", async () => {
    order.push("second");
  });
  await Promise.all([first, second]);
  assert.deepEqual(order, ["first-start", "first-end", "second"]);

  fs.writeFileSync(supervisor.leasePath, JSON.stringify({
    type: "copilot-flock-headless-leases-v1",
    leases: {
      "session-2": {
        sessionId: "session-2",
        operationId: "stale",
        expiresAtMs: Date.now() + 60000,
        processIdentity: { pid: 42, start: 100 },
      },
    },
  }));
  assert.equal(supervisor.isRunning("session-2"), false);
});

test("headless supervisor runs three concurrent turns with maximum process concurrency one", async (t) => {
  const supervisor = new HeadlessSessionSupervisor(fixture(t), {
    inspectProcessFn: (pid) => ({ pid, start: pid }),
  });
  let active = 0;
  let maxActive = 0;
  const order = [];
  const turns = [1, 2, 3].map((number) =>
    supervisor.enqueue("shared-session", `op-${number}`, async ({ bindProcess }) => {
      bindProcess({ pid: number, start: number }, { kill() {} });
      active++;
      maxActive = Math.max(maxActive, active);
      order.push(`start-${number}`);
      await new Promise((resolve) => setTimeout(resolve, 10));
      order.push(`end-${number}`);
      active--;
    })
  );
  await Promise.all(turns);
  assert.equal(maxActive, 1);
  assert.deepEqual(order, [
    "start-1", "end-1",
    "start-2", "end-2",
    "start-3", "end-3",
  ]);
});

test("headless cancellation terminates only the verified process tree identity", async (t) => {
  const terminated = [];
  const supervisor = new HeadlessSessionSupervisor(fixture(t), {
    inspectProcessFn: (pid) => ({ pid, start: 321 }),
    terminateProcessTreeFn: (identity) => {
      terminated.push(identity);
      return true;
    },
  });
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const running = supervisor.enqueue("cancel-session", "op-cancel-tree", async ({ bindProcess }) => {
    bindProcess({ pid: 77, start: 321 }, {});
    await blocked;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(supervisor.cancel("op-cancel-tree"), true);
  assert.deepEqual(terminated, [{ pid: 77, start: 321 }]);
  release();
  await running;
});

test("presence state uses reconnect grace, deterministic expiry, and degraded viable layers", () => {
  let now = Date.parse("2026-11-14T18:00:30Z");
  const tracker = new PresenceStateTracker({
    clock: () => now,
    reconnectGraceMs: 20000,
    expiryMs: 60000,
  });

  assert.equal(tracker.classify({
    transportOnline: false,
    lastSeenAt: now - 10000,
  }).state, "reconnecting");
  now += 60000;
  assert.equal(tracker.classify({
    transportOnline: false,
    lastSeenAt: now - 70000,
  }).state, "offline");
  assert.equal(tracker.classify({
    transportOnline: true,
    lastSeenAt: now,
    desktopReachable: false,
    headlessCliAvailable: true,
    coordinatorHealthy: false,
  }).state, "degraded");
  assert.equal(tracker.classify({
    transportOnline: false,
    lastSeenAt: now,
    revoked: true,
  }).state, "offline");
  assert.equal(classifyLayeredPresence({
    online: false,
    member: { lastSeenAt: new Date(now).toISOString(), removed: true },
    nowMs: now,
  }).presenceLayers.authorization.state, "denied");
});

test("runningOnly discovery merges live headless lease state instead of stale database flags", (t) => {
  const root = fixture(t);
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  t.after(() => {
    if (previous === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previous;
  });
  const flockRoot = path.join(root, "flock");
  fs.mkdirSync(flockRoot, { recursive: true });
  fs.writeFileSync(path.join(flockRoot, "cli-sessions.json"), JSON.stringify([{
    session_id: "headless-active",
    title: "Active headless",
    session_type: "cli",
    is_running: false,
    updated_at: new Date().toISOString(),
  }]));
  const identity = inspectProcess(process.pid);
  fs.writeFileSync(path.join(flockRoot, "cli-leases.json"), JSON.stringify({
    type: "copilot-flock-headless-leases-v1",
    leases: {
      "headless-active": {
        sessionId: "headless-active",
        operationId: "op-running",
        expiresAtMs: Date.now() + 60000,
        processIdentity: identity,
      },
    },
  }));
  const sessions = queryLocalSessionsFromDb({ runningOnly: true });
  assert.deepEqual(sessions.map((session) => session.session_id), ["headless-active"]);
  assert.equal(sessions[0].is_running, true);
});

test("broker-free operation tools default to the same-owner flock containing the target", (t) => {
  const root = fixture(t);
  const previousCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  t.after(() => {
    if (previousCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previousCopilotHome;
  });
  const flockHome = path.join(root, "flock");
  fs.mkdirSync(flockHome, { recursive: true });
  fs.writeFileSync(path.join(flockHome, "broker-free.json"), JSON.stringify({
    schema: 34,
    pendingJoins: {},
    flocks: {
      "owner/work": {
        flockId: "owner/work",
        cert: { body: { role: "owner", machineId: "CALLER-PC" } },
        members: {
          target: { cert: { body: { machineId: "REMOTE-PC", role: "owner" } } },
        },
      },
      "owner/team": {
        flockId: "owner/team",
        cert: { body: { role: "owner", machineId: "CALLER-PC" } },
        members: {
          target: { cert: { body: { machineId: "REMOTE-PC", role: "owner" } } },
        },
      },
    },
  }));
  assert.equal(resolveDefaultOperationFlockSelector({
    protocol: "broker-free-v34",
    githubUser: "owner",
    scope: "work",
  }, "REMOTE-PC"), "owner/work");
});

test("protected operation MCP/RPC resumes timed-out work, rejects spoofed peers, cancels queued work, and preserves delegated identity", async (t) => {
  const root = fixture(t);
  const previousCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  t.after(() => {
    if (previousCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previousCopilotHome;
  });

  const makeIdentity = (deviceId) => {
    const pair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return { ...pair, deviceId };
  };
  const callerKey = makeIdentity("caller-device");
  const otherKey = makeIdentity("other-device");
  const registryMembers = [
    {
      machineId: "CALLER-PC",
      githubUser: "owner",
      githubUserId: 1001,
      deviceId: callerKey.deviceId,
      peerId: `1001:${callerKey.deviceId}`,
      scope: "work",
      publicKey: callerKey.publicKey,
    },
    {
      machineId: "OTHER-PC",
      githubUser: "owner",
      githubUserId: 1001,
      deviceId: otherKey.deviceId,
      peerId: `1001:${otherKey.deviceId}`,
      scope: "work",
      publicKey: otherKey.publicKey,
    },
    {
      machineId: "REMOTE-PC",
      githubUser: "owner",
      githubUserId: 1001,
      deviceId: "remote-device",
      peerId: "1001:remote-device",
      scope: "work",
      publicKey: callerKey.publicKey,
    },
  ];
  const policy = {
    flockId: "owner/work",
    ownerGitHubUser: "owner",
    flockType: "owner_scope",
    trustTier: "owner",
    allowedScopes: ["work"],
    sessionVisibility: "all",
    members: registryMembers,
  };
  const callerFlocksPath = path.join(root, "caller-flocks.json");
  const remoteFlocksPath = path.join(root, "remote-flocks.json");
  fs.writeFileSync(callerFlocksPath, JSON.stringify({ flocks: { "owner/work": policy } }));
  fs.writeFileSync(remoteFlocksPath, JSON.stringify({ flocks: { "owner/work": policy } }));
  const flockHome = path.join(root, "flock");
  fs.mkdirSync(flockHome, { recursive: true });
  fs.writeFileSync(path.join(flockHome, "cli-sessions.json"), JSON.stringify([{
    session_id: "remote-session",
    title: "Remote worker",
    session_type: "cli",
    mode: "autopilot",
    path: root,
    updated_at: new Date().toISOString(),
  }]));

  let nextPid = 5000;
  const spawnedPrompts = [];
  const spawnHeadlessProcess = (_command, args) => {
    const child = new EventEmitter();
    child.pid = nextPid++;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    const prompt = String(args[1] || "");
    spawnedPrompts.push(prompt);
    const delay = prompt.includes("HOLD") ? 80 : prompt.includes("TIMEOUT") ? 35 : 0;
    setTimeout(() => {
      child.stdout.write(
        prompt.includes("TIMEOUT")
          ? "completed with ghp_123456789012345678901234567890"
          : `completed:${prompt.includes("DELEGATE") ? "delegate" : "hold"}`
      );
      child.stdout.end();
      child.stderr.end();
      child.emit("close", 0);
    }, delay);
    return child;
  };
  const remoteCfg = {
    machineId: "REMOTE-PC",
    githubUser: "owner",
    scope: "work",
    flocksConfigPath: remoteFlocksPath,
    copilotCliBin: "synthetic-copilot",
    spawnHeadlessProcess,
    inspectHeadlessProcess: () => null,
  };
  const rpcTransport = async (payload) => {
    try {
      const result = await handleRpcAction(remoteCfg, {
        ...payload,
        registryMembers,
        enforceSignature: true,
      });
      return [{ requestId: payload.requestId, fromMachine: "REMOTE-PC", result }];
    } catch (error) {
      return [{
        requestId: payload.requestId,
        fromMachine: "REMOTE-PC",
        error: error.message,
        code: error.code,
        statusCode: error.statusCode,
      }];
    }
  };
  const callerCfg = {
    machineId: "CALLER-PC",
    githubUser: "owner",
    scope: "work",
    identity: callerKey,
    flocksConfigPath: callerFlocksPath,
    rpcTransport,
  };
  const toolOptions = { ensureDaemon: async () => ({ running: true }) };

  assert.equal(isProtectedRpcAction("get_operation"), true);
  assert.equal(isProtectedRpcAction("cancel_operation"), true);

  const timedOut = await executeMcpTool(callerCfg, "send_remote_session_message", {
    flock: "owner/work",
    to_machine: "REMOTE-PC",
    to_session: "remote-session",
    from_session: "origin-session",
    message: "TIMEOUT then finish",
    operation_id: "op-timeout-e2e",
    wait_for_reply: true,
    wait_timeout_ms: 5,
  }, toolOptions);
  assert.equal(timedOut.status, "timed_out_waiting");
  assert.equal(timedOut.operationId, "op-timeout-e2e");
  await new Promise((resolve) => setTimeout(resolve, 70));

  const completed = await executeMcpTool(callerCfg, "get_remote_operation", {
    to_machine: "REMOTE-PC",
    operation_id: "op-timeout-e2e",
    from_session: "origin-session",
  }, toolOptions);
  assert.equal(completed.operation.state, "completed");
  assert.match(completed.operation.result.content, /^completed with /);
  assert.doesNotMatch(completed.operation.result.content, /ghp_/);
  assert.match(completed.operation.result.content, /REDACTED TOKEN/);

  const spoofParams = {
    flock: "owner/work",
    operationId: "op-timeout-e2e",
    fromMachine: "CALLER-PC",
    fromSessionId: "origin-session",
  };
  const spoofRequestId = crypto.randomUUID();
  const spoofSentAt = new Date().toISOString();
  await assert.rejects(
    handleRpcAction(remoteCfg, {
      requestId: spoofRequestId,
      sentAt: spoofSentAt,
      toMachine: "REMOTE-PC",
      action: "get_operation",
      params: spoofParams,
      auth: signRpcRequest({
        requestId: spoofRequestId,
        sentAt: spoofSentAt,
        fromMachine: "OTHER-PC",
        toMachine: "REMOTE-PC",
        action: "get_operation",
        params: spoofParams,
        identity: otherKey,
      }),
      registryMembers,
      enforceSignature: true,
    }),
    (error) => error.code === "OPERATION_REQUESTER_MISMATCH"
  );

  await executeMcpTool(callerCfg, "send_remote_session_message", {
    flock: "owner/work",
    to_machine: "REMOTE-PC",
    to_session: "remote-session",
    from_session: "origin-session",
    message: "HOLD queue",
    operation_id: "op-hold",
  }, toolOptions);
  await executeMcpTool(callerCfg, "send_remote_session_message", {
    flock: "owner/work",
    to_machine: "REMOTE-PC",
    to_session: "remote-session",
    from_session: "origin-session",
    message: "MUST_NOT_SPAWN",
    operation_id: "op-queued-cancel",
  }, toolOptions);
  assert.equal(resolveDefaultOperationFlockSelector(callerCfg, "REMOTE-PC"), "owner/work");
  const cancelled = await executeMcpTool(callerCfg, "cancel_remote_operation", {
    to_machine: "REMOTE-PC",
    operation_id: "op-queued-cancel",
    from_session: "origin-session",
  }, toolOptions);
  assert.equal(cancelled.operation.state, "cancelled");
  await new Promise((resolve) => setTimeout(resolve, 120));
  assert.equal(spawnedPrompts.some((prompt) => prompt.includes("MUST_NOT_SPAWN")), false);

  const delegated = await executeMcpTool(callerCfg, "send_remote_session_message", {
    flock: "owner/work",
    to_machine: "REMOTE-PC",
    to_session: "new-worker",
    from_session: "origin-session",
    message: "DELEGATE identity",
    operation_id: "op-delegate",
    delegate: true,
    wait_for_reply: true,
    wait_timeout_ms: 100,
  }, toolOptions);
  assert.equal(delegated.operationId, "op-delegate");
  const operations = JSON.parse(fs.readFileSync(path.join(flockHome, "operations.json"), "utf8")).operations;
  assert.equal(operations["op-delegate"].correlationId, "op-delegate");
  assert.equal(Object.keys(operations).filter((id) => id === "op-delegate").length, 1);
});
