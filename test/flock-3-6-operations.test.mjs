import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  HeadlessSessionSupervisor,
  PersistentOperationStore,
  PresenceStateTracker,
} from "../flock-operations.mjs";
import { inspectProcess } from "../flock-lifecycle.mjs";
import { queryLocalSessionsFromDb } from "../flock.mjs";

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
