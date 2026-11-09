import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import vm from "node:vm";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import * as flock from "../flock.mjs";
import * as bridge from "../bridge.mjs";
import { legacyAdmissionOperation, LEGACY_ADMISSION_CAPACITY, LEGACY_REPLAY_CLOCK_ALLOWANCE_MS } from "../legacy-rpc-admissions.mjs";

function identity(fingerprint) {
  return { ...crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  }), fingerprint };
}

async function fixture(api, { shared = false, expired = false, target = null } = {}) {
  const senderKey = identity("sender"), receiverKey = identity("receiver"), attackerKey = identity("attacker");
  const sender = {
    peerId: `${shared ? 2002 : 1001}:sender`, deviceId: "sender", machineId: "ORIGIN",
    githubUser: shared ? "guest" : "example", githubUserId: shared ? 2002 : 1001,
    trustTier: shared ? "collaborator" : "owner", scope: "work",
    publicKey: senderKey.publicKey.trim(), active: true, membershipExpiresAtMs: null,
  };
  const receiver = {
    peerId: "1001:receiver", deviceId: "receiver", machineId: "VICTIM",
    githubUser: "example", githubUserId: 1001, trustTier: "owner", scope: "work",
    publicKey: receiverKey.publicKey.trim(), active: true, membershipExpiresAtMs: null,
  };
  const record = {
    flockId: shared ? "example/studio-team" : "example",
    flockUuid: "00000000-0000-4000-8000-000000000001",
    hubName: "v3-fixture", flockType: shared ? "collaborator" : "owner_root",
    ownerGitHubUserId: 1001, allowedScopes: ["personal", "work"], rosterEpoch: 3,
    expiresAtMs: null, targetMachineId: null, members: [sender, receiver],
  };
  const cfg = {
    machineId: "VICTIM", githubUser: "example", scope: "work",
    bootstrapUrl: "https://broker.invalid/api/bootstrap", bootstrapOriginPin: "https://broker.invalid",
    hub: shared ? "v3-fixture" : "copilotbridge", specs: { cpu: { model: "Synthetic CPU" } },
  };
  const grants = { flocks: { [record.flockId]: {
    flockUuid: record.flockUuid, sharedSessionIds: ["shared"],
    sharedSnapshots: { shared: { mode: "approved-snapshot", title: "Approved",
      summarySnapshot: "Exactly the approved summary", sharedAt: new Date().toISOString() } },
  } } };
  const authority = { ok: true, githubUserId: 1001, legacyHubName: "copilotbridge", joinedFlocks: [record] };
  const receiving = await api.loadTrustedRpcContext(cfg, { authority, identity: receiverKey, localFlocks: grants });
  const sending = await api.loadTrustedRpcContext({ ...cfg, machineId: "ORIGIN", githubUser: sender.githubUser }, {
    authority: { ...authority, githubUserId: sender.githubUserId }, identity: senderKey, localFlocks: grants,
  });
  if (expired) receiving.policy.membershipExpiresAtMs = Date.now() - 1;
  if (target) receiving.policy.targetMachineId = target;
  const replies = [], rejected = [];
  const callback = api.createRpcInvocationHandler(cfg, {
    contextProvider: async () => receiving,
    sendResponse: async (replyUserId, response) => replies.push({ replyUserId, response }),
    logger: (code) => rejected.push(code),
  });
  let admissionLedgerId = crypto.randomUUID();
  const initializeAdmissions = () => {
    const initialized = api.initializeLegacyRpcAdmissions(receiverKey, { allowFirstInitialization: true });
    admissionLedgerId = initialized.ledgerId;
    return initialized;
  };
  const request = (action = "acquire_lock", params = { resource: "synthetic-dummy-lock" }) =>
    api.createSignedRpcRequest({ ...cfg, machineId: "ORIGIN" }, sending, { toMachine: "VICTIM", action, params, admissionLedgerId });
  return { cfg, receiving, sending, senderKey, receiverKey, attackerKey, request, callback, replies, rejected,
    initializeAdmissions, get admissionLedgerId() { return admissionLedgerId; } };
}

test("actual network callback rejects caller authority and unbound identities before dummy lock dispatch", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-rpc-boundary-"));
  const previousHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  try {
    for (const api of [flock, bridge]) {
      const f = await fixture(api);
      const attacks = [
        (req) => { delete req.auth; return req; },
        (req) => { delete req.flockId; return req; },
        (req) => ({ ...req, flockId: "unknown/flock" }),
        (req) => ({ ...req, registryMembers: [{ machineId: "ORIGIN", githubUser: "example", publicKey: f.attackerKey.publicKey }] }),
        (req) => ({ ...req, registryMembers: [] }),
        (req) => ({ ...req, flockPolicy: { trustTier: "owner" } }),
        (req) => ({ ...req, receiverContext: { source: "local" } }),
        (req) => ({ ...req, auth: { ...req.auth, publicKey: f.attackerKey.publicKey } }),
        (req) => ({ ...req, auth: { ...req.auth, signature: "AAAA" } }),
        (req) => ({ ...req, replyUserId: "rpc-altered" }),
        (req) => ({ ...req, toMachine: "OTHER" }),
      ];
      for (const mutate of attacks) {
        const outcome = await f.callback(mutate(f.request()));
        assert.equal(outcome.status, "rejected");
        assert.equal(api.listLocalResourceLocks(f.cfg).locks.length, 0);
      }
      const unregistered = f.request();
      unregistered.auth = api.signV3RpcEnvelope({
        flockUuid: f.receiving.policy.flockUuid, rosterEpoch: 3,
        requestId: unregistered.requestId, timestamp: unregistered.sentAt,
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        fromPeerId: "1001:unregistered", toPeerId: f.receiving.localMember.peerId,
        actionOrStatus: unregistered.action,
        payload: { flockId: unregistered.flockId, fromMachine: unregistered.fromMachine,
          toMachine: unregistered.toMachine, replyUserId: unregistered.replyUserId,
          sentAt: unregistered.sentAt, params: unregistered.params },
        identity: f.attackerKey,
      });
      assert.equal((await f.callback(unregistered)).status, "rejected");
      assert.equal(api.listLocalResourceLocks(f.cfg).locks.length, 0);
      await assert.rejects(() => api.handleRpcAction(f.cfg,
        { action: "acquire_lock", params: { resource: "missing-context" } }), { code: "RPC_CONTEXT_REQUIRED" });
      f.initializeAdmissions();
      const accepted = await f.callback(f.request());
      assert.equal(accepted.status, "accepted");
      assert.equal(accepted.result.acquired, true);
      assert.equal(f.replies.length, 1);
      api.verifySignedRpcResponse({ ...f.cfg, machineId: "ORIGIN" }, f.replies[0].response,
        { requestId: f.replies[0].response.requestId, replyUserId: f.replies[0].replyUserId,
          auth: { toPeerId: f.receiving.localMember.peerId } }, f.sending);
      api.releaseLocalResourceLock(f.cfg, { resource: "synthetic-dummy-lock", force: true, ownerMachine: "ORIGIN" });
    }
  } finally {
    if (previousHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("accepted signed privileged RPC cannot be replayed against a later resource lease", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-rpc-replay-"));
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  try {
    for (const api of [flock, bridge]) {
      const f = await fixture(api);
      f.initializeAdmissions();
      const resource = "synthetic-replay-resource";
      api.acquireLocalResourceLock(f.cfg, { resource, ownerMachine: "FIRST-OWNER", ttlSeconds: 60 });
      const request = f.request("release_lock", { resource, force: true });
      assert.equal((await f.callback(request)).status, "accepted");
      api.acquireLocalResourceLock(f.cfg, { resource, ownerMachine: "LATER-OWNER", ttlSeconds: 60 });
      assert.equal((await f.callback(request)).status, "rejected");
      assert.equal(api.listLocalResourceLocks(f.cfg).locks.length, 1);
      api.releaseLocalResourceLock(f.cfg, { resource, force: true });
    }
  } finally {
    if (previous === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function isolatedProfile(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  t.after(() => {
    if (previous === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return root;
}

test("registered-owner pre-domain mutations reject cryptographically before any new admission", async (t) => {
  isolatedProfile(t, "flock-old-domain-");
  for (const api of [flock, bridge]) {
    const f = await fixture(api);
    f.initializeAdmissions();
    const old = f.request("release_lock", { resource: "old-domain", force: true });
    delete old.admissionLedgerId;
    const payload = { flockId: old.flockId, fromMachine: old.fromMachine, toMachine: old.toMachine,
      replyUserId: old.replyUserId, sentAt: old.sentAt, params: old.params };
    old.auth = api.signV3RpcEnvelope({
      flockUuid: f.sending.policy.flockUuid, rosterEpoch: f.sending.policy.rosterEpoch,
      requestId: old.requestId, timestamp: old.sentAt, expiresAt: old.auth.expiresAt,
      fromPeerId: f.sending.localMember.peerId, toPeerId: f.receiving.localMember.peerId,
      actionOrStatus: old.action, payload, identity: f.senderKey,
    });
    assert.equal(api.verifyV3RpcEnvelope({ envelope: old.auth, requestId: old.requestId,
      actionOrStatus: old.action, payload, publicKey: f.senderKey.publicKey }).valid, true);
    const rejected = await f.callback(old);
    assert.equal(rejected.status, "rejected");
    assert.equal(rejected.code, "RPC_SIGNATURE_INVALID");
    const read = f.request("list_locks", {});
    assert.equal(read.admissionLedgerId, undefined);
    assert.equal((await f.callback(read)).status, "accepted");
    const missing = f.request("release_lock", { resource: "missing-incarnation", force: true });
    delete missing.admissionLedgerId;
    missing.auth = api.signV3RpcEnvelope({
      flockUuid: f.sending.policy.flockUuid, rosterEpoch: f.sending.policy.rosterEpoch,
      requestId: missing.requestId, timestamp: missing.sentAt, expiresAt: missing.auth.expiresAt,
      fromPeerId: f.sending.localMember.peerId, toPeerId: f.receiving.localMember.peerId,
      actionOrStatus: missing.action, payload: { admissionProtocol: api.LEGACY_MUTATION_PROTOCOL,
        flockId: missing.flockId, fromMachine: missing.fromMachine, toMachine: missing.toMachine,
        replyUserId: missing.replyUserId, sentAt: missing.sentAt, params: missing.params },
      identity: f.senderKey,
    });
    assert.equal((await f.callback(missing)).code, "RPC_ADMISSION_INPUT_INVALID");
  }
});

test("legacy admissions survive callback restart and concurrent online/offline delivery with independent ACK recovery", async (t) => {
  const root = isolatedProfile(t, "flock-cross-delivery-");
  for (const [index, api] of [flock, bridge].entries()) {
    const f = await fixture(api);
    f.initializeAdmissions();
    const resource = `cross-${index}`;
    api.acquireLocalResourceLock(f.cfg, { resource, ownerMachine: "FIRST-OWNER", ttlSeconds: 60 });
    const request = f.request("release_lock", { resource, force: true });
    const both = await Promise.all([
      f.callback(request),
      api.handleRpcAction(f.cfg, request, { ...f.receiving, source: "offline" })
        .then(() => ({ status: "accepted" }), (error) => ({ status: "rejected", code: error.code })),
    ]);
    assert.equal(both.filter((result) => result.status === "accepted").length, 1);
    assert.equal(both.filter((result) => result.code === "RPC_REQUEST_REPLAY").length, 1);
    api.acquireLocalResourceLock(f.cfg, { resource, ownerMachine: "LATER-OWNER", ttlSeconds: 60 });
    const restarted = api.createRpcInvocationHandler(f.cfg, {
      contextProvider: async () => f.receiving, logger() {}, sendResponse: async () => {},
    });
    assert.equal((await restarted(request)).code, "RPC_REQUEST_REPLAY");
    const statePath = path.join(root, `offline-${index}.json`);
    let handling = 0, decodedRequest = null, decodedConfig = null;
    const options = {
      statePath, drainFn: async () => ({ messages: [{ requestId: request.requestId, rpcPayload: request }] }),
      ackFn: async () => ({ ok: false }),
      handleFn: async (cfg, req) => {
        handling++;
        decodedConfig = cfg;
        decodedRequest = req;
        assert.deepEqual(req, request);
        assert.equal(req.action, "release_lock");
        assert.deepEqual(req.params, { resource, force: true });
        return await api.handleRpcAction(cfg, req, { ...f.receiving, source: "offline" });
      },
    };
    await api.drainAndProcessOfflineQueue(f.cfg, options);
    await api.drainAndProcessOfflineQueue(f.cfg, options);
    assert.equal(handling, 1);
    assert.equal(decodedConfig, f.cfg);
    assert.deepEqual(decodedRequest, request);
    assert.ok(api.loadProcessedOfflineState(statePath).ambiguousIds.includes(request.requestId));
    assert.ok(api.loadProcessedOfflineState(statePath).pendingAckIds.includes(request.requestId));
    await api.drainAndProcessOfflineQueue(f.cfg, { ...options, ackFn: async () => ({ ok: true }) });
    assert.equal(handling, 1);
    assert.equal(api.listLocalResourceLocks(f.cfg).locks.length, 1);
    api.releaseLocalResourceLock(f.cfg, { resource, force: true });
  }
});

function admissionChild(input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...flock.zeroBrokerNodeFlags(),
      fileURLToPath(new URL("../legacy-rpc-admissions.mjs", import.meta.url))], {
      stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code !== 0) return reject(new Error(`Synthetic admission helper failed: ${stderr}`));
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
    });
    child.stdin.end(JSON.stringify(input));
  });
}

function primitiveAdmission(root) {
  const receiverKey = crypto.createHash("sha256").update("Synthetic receiver key").digest("hex");
  const initialized = legacyAdmissionOperation({ operation: "initialize", home: root, receiverKey, allowFirstInitialization: true });
  const nowMs = Date.now();
  return { home: root, receiverKey, ledgerId: initialized.ledgerId, flock: crypto.randomUUID(),
    receiver: "synthetic-receiver", sender: "synthetic-owner-key", request: crypto.randomUUID(),
    action: "release_lock", digest: "a".repeat(64), deadline: nowMs + 3600000, nowMs };
}

test("atomic legacy cross-process claims preserve crash UNKNOWN and reject changed signed intent", async (t) => {
  const root = isolatedProfile(t, "flock-admission-processes-");
  const input = primitiveAdmission(root);
  const results = await Promise.all(Array.from({ length: 4 }, () => admissionChild({ ...input, operation: "claim" })));
  assert.equal(results.filter((result) => result.ok && result.admitted).length, 1);
  assert.equal(results.filter((result) => result.code === "RPC_REQUEST_REPLAY").length, 3, JSON.stringify(results));
  const restarted = await admissionChild({ ...input, operation: "claim" });
  assert.equal(restarted.code, "RPC_REQUEST_REPLAY");
  assert.match(restarted.error, /UNKNOWN/);
  const changed = await admissionChild({ ...input, operation: "claim", digest: "b".repeat(64) });
  assert.equal(changed.code, "RPC_ADMISSION_ID_REUSED");
  assert.equal((await admissionChild({ ...input, operation: "complete", outcome: "COMPLETED" })).ok, true);
  assert.match((await admissionChild({ ...input, operation: "claim" })).error, /COMPLETED/);
});

test("legacy admission capacity retains every unexpired claim through signed deadline and clock allowance", (t) => {
  const root = isolatedProfile(t, "flock-admission-capacity-");
  const input = primitiveAdmission(root);
  const file = path.join(root, "legacy-rpc-admissions", input.receiverKey, "state.sqlite");
  const db = new DatabaseSync(file);
  try {
    db.prepare(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?)
      INSERT INTO admissions SELECT 'f','r','s',printf('synthetic-%d',i),'release_lock','digest',?,?, 'UNKNOWN' FROM n`)
      .run(LEGACY_ADMISSION_CAPACITY, input.deadline, input.deadline + LEGACY_REPLAY_CLOCK_ALLOWANCE_MS);
  } finally { db.close(); }
  assert.throws(() => legacyAdmissionOperation({ ...input, operation: "claim" }), { code: "RPC_ADMISSION_CAPACITY" });
  assert.throws(() => legacyAdmissionOperation({ ...input, operation: "claim",
    nowMs: input.deadline + 1, deadline: input.deadline + 60000 }), { code: "RPC_ADMISSION_CAPACITY" });
  legacyAdmissionOperation({ ...input, operation: "claim", nowMs: input.deadline + LEGACY_REPLAY_CLOCK_ALLOWANCE_MS + 1,
    deadline: input.deadline + LEGACY_REPLAY_CLOCK_ALLOWANCE_MS + 60000 });
  const inspected = new DatabaseSync(file);
  try { assert.equal(inspected.prepare("SELECT COUNT(*) AS count FROM admissions").get().count, 1); }
  finally { inspected.close(); }
  assert.throws(() => legacyAdmissionOperation({ ...input, operation: "claim", request: crypto.randomUUID() }),
    { code: "RPC_ADMISSION_CLOCK_ROLLBACK" });
});

test("legacy missing or corrupt anchored ledger never recreates and receiver incarnation rejects old captures after synthetic recovery", async (t) => {
  const root = isolatedProfile(t, "flock-admission-loss-");
  const f = await fixture(flock);
  f.initializeAdmissions();
  const home = flock.getBridgeHome();
  const receiverKey = crypto.createHash("sha256").update(crypto.createPublicKey(f.receiverKey.publicKey)
    .export({ type: "spki", format: "der" })).digest("hex");
  const directory = path.join(home, "legacy-rpc-admissions", receiverKey);
  const anchor = path.join(home, "legacy-rpc-admission-anchors", `${receiverKey}.json`);
  const file = path.join(directory, "state.sqlite");
  const request = f.request("release_lock", { resource: "recovery-resource", force: true });
  const originalPacket = JSON.stringify(request);
  assert.equal((await f.callback(request)).status, "accepted");
  const originalId = f.admissionLedgerId;
  const backup = fs.readFileSync(file);
  fs.unlinkSync(file);
  assert.equal((await f.callback(request)).code, "RPC_ADMISSION_STATE_REQUIRED");
  assert.equal(fs.existsSync(file), false);
  assert.throws(() => f.initializeAdmissions(), { code: "RPC_ADMISSION_STATE_REQUIRED" });
  fs.writeFileSync(file, "Synthetic corrupt SQLite state");
  const corrupt = fs.readFileSync(file);
  assert.equal((await f.callback(request)).code, "RPC_ADMISSION_STORAGE_ERROR");
  assert.deepEqual(fs.readFileSync(file), corrupt);
  fs.writeFileSync(file, backup);
  assert.equal((await f.callback(request)).code, "RPC_REQUEST_REPLAY");
  fs.unlinkSync(anchor);
  fs.rmSync(directory, { recursive: true });
  assert.equal((await f.callback(request)).code, "RPC_ADMISSION_STATE_REQUIRED");
  f.initializeAdmissions();
  assert.notEqual(f.admissionLedgerId, originalId);
  flock.acquireLocalResourceLock(f.cfg, { resource: "recovery-resource", ownerMachine: "LATER-OWNER", ttlSeconds: 60 });
  assert.equal((await f.callback(request)).code, "RPC_ADMISSION_LEDGER_CHANGED");
  await assert.rejects(() => flock.handleRpcAction(f.cfg, request, { ...f.receiving, source: "offline" }),
    { code: "RPC_ADMISSION_LEDGER_CHANGED" });
  assert.equal(JSON.stringify(request), originalPacket, "Queued authority must never be rebound or re-signed after recovery");
  assert.equal(flock.listLocalResourceLocks(f.cfg).locks.length, 1);
  assert.equal((await f.callback(f.request("release_lock", { resource: "recovery-resource", force: true }))).status, "accepted");
  assert.equal(flock.listLocalResourceLocks(f.cfg).locks.length, 0);
  assert.ok(root);
});

test("coherent install gates the new mutation domain without changing prior profile bytes or normal incarnation", async (t) => {
  const root = isolatedProfile(t, "flock-admission-upgrade-");
  const f = await fixture(flock);
  const home = flock.getBridgeHome();
  fs.mkdirSync(home, { recursive: true });
  const sentinels = ["identity.json", "flocks.json", "config.json", "mcp-config.json"];
  for (const name of sentinels) fs.writeFileSync(path.join(home, name), `Synthetic original ${name} bytes`);
  assert.throws(() => flock.prepareLegacyRpcAdmissionUpgrade(f.receiverKey), { code: "RPC_ADMISSION_STATE_REQUIRED" });
  fs.writeFileSync(path.join(home, "flock.mjs"), "// Synthetic prior legacy source without the new domain\n");
  const initialized = flock.prepareLegacyRpcAdmissionUpgrade(f.receiverKey);
  fs.writeFileSync(path.join(home, "flock.mjs"), `// ${flock.LEGACY_MUTATION_PROTOCOL}\n`);
  assert.equal(flock.prepareLegacyRpcAdmissionUpgrade(f.receiverKey).ledgerId, initialized.ledgerId);
  for (const name of sentinels) assert.equal(fs.readFileSync(path.join(home, name), "utf8"), `Synthetic original ${name} bytes`);
  for (const privatePath of ["legacy-rpc-admissions", "legacy-rpc-admission-anchors", "legacy-rpc-bindings"]) {
    assert.throws(() => flock.assertSafeTransferFilePath(path.join(home, privatePath, "state.json")), /Security policy/);
  }
  assert.ok(root);
});

test("receiver incarnation proof is signed, context matched and persisted for offline use without authority promotion", async (t) => {
  isolatedProfile(t, "flock-admission-proof-");
  const f = await fixture(flock);
  f.initializeAdmissions();
  async function proof() {
    const request = f.request("ping", { includeAdmission: true });
    const before = f.replies.length;
    assert.equal((await f.callback(request)).status, "accepted");
    return { request, response: f.replies[before].response };
  }
  const valid = await proof();
  const origin = { ...f.cfg, machineId: "ORIGIN" };
  const binding = await flock.getLegacyReceiverBinding(origin, f.sending, "VICTIM", { fetchProof: async () => valid });
  assert.equal(binding, f.admissionLedgerId);
  assert.equal(await flock.getLegacyReceiverBinding(origin, f.sending, "VICTIM", {
    fetchProof: async () => assert.fail("Known signed incarnation must be usable while the receiver is offline"),
  }), binding);
  for (const mutate of [
    (value) => { value.response.requestId = "wrong-request"; },
    (value) => { value.request.replyUserId = "rpc-wrong-audience"; },
    (value) => { value.response.auth.fromPeerId = "1001:wrong-receiver"; },
    (value) => { value.response.auth.publicKey = f.attackerKey.publicKey; },
    (value) => { value.response.result.legacyAdmission.ledgerId = crypto.randomUUID(); },
    (value) => { value.request.flockId = "different/flock"; },
  ]) {
    const changed = structuredClone(valid);
    mutate(changed);
    await assert.rejects(() => flock.getLegacyReceiverBinding(origin, f.sending, "VICTIM", {
      forceRefresh: true, fetchProof: async () => changed,
    }), { code: "RPC_ADMISSION_BINDING_INVALID" });
  }
  assert.equal(await flock.getLegacyReceiverBinding(origin, f.sending, "VICTIM"), binding);
  await assert.rejects(() => flock.getLegacyReceiverBinding(origin, f.sending, "VICTIM", {
    forceRefresh: true, fetchProof: async () => { throw new Error("Synthetic offline receiver"); },
  }), { code: "RPC_ADMISSION_HANDSHAKE_FAILED" });
  assert.equal(await flock.getLegacyReceiverBinding(origin, f.sending, "VICTIM"), binding);
});

test("actual file-transfer handler rejects canonical and aliased runtime destinations before bytes or completion", async (t) => {
  const root = isolatedProfile(t, "flock-runtime-transfer-");
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "flock-approved-transfer-"));
  const alias = path.join(outside, "profile-alias");
  fs.symlinkSync(root, alias, process.platform === "win32" ? "junction" : "dir");
  t.after(() => {
    if (process.platform === "win32") fs.rmdirSync(alias);
    else fs.unlinkSync(alias);
    fs.rmSync(outside, { recursive: true, force: true });
  });
  process.env.COPILOT_HOME = alias;
  for (const [index, api] of [flock, bridge].entries()) {
    const f = await fixture(api);
    f.initializeAdmissions();
    const home = api.getBridgeHome();
    const physicalHome = fs.realpathSync(home);
    const names = ["legacy-rpc-admissions.mjs", "zero-broker-roster.mjs", "release-policy.mjs", "new-runtime-import.cjs"];
    const original = "Synthetic protected module bytes; never executed";
    for (const name of names) fs.writeFileSync(path.join(home, name), original);
    const state = path.join(outside, `relocated-state-${index}`);
    fs.mkdirSync(state);
    fs.writeFileSync(path.join(state, "transfer-metadata.json"), "Synthetic private control state");
    fs.symlinkSync(state, path.join(home, `private-transfer-state-${index}`), process.platform === "win32" ? "junction" : "dir");
    const linked = path.join(outside, `linked-${index}.data`);
    fs.linkSync(path.join(home, names[0]), linked);
    const receiverKey = crypto.createHash("sha256").update(crypto.createPublicKey(f.receiverKey.publicKey)
      .export({ type: "spki", format: "der" })).digest("hex");
    const ledgerFile = path.join(home, "legacy-rpc-admissions", receiverKey, "state.sqlite");
    const targets = [...names.map((name) => path.join(home, name)),
      path.join(physicalHome, names[0]), path.join(home, "not-created", "future-import.mjs"), linked,
      path.join(home, "legacy-rpc-admissions", receiverKey, "state.sqlite"),
      path.join(state, "transfer-metadata.json"), path.join(state, "not-created", "new-state.json")];
    if (process.platform === "win32") {
      targets.push(path.join(physicalHome, names[0]).toUpperCase());
      const device = `\\\\.\\${path.join(physicalHome, names[0]).replace(/^\\\\\?\\/, "")}`;
      targets.push(device, device.replaceAll("\\", "/"), `${path.join(home, names[0])}:stream`);
      const short = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop'; Add-Type -Namespace FlockFixture -Name Native -MemberDefinition '[System.Runtime.InteropServices.DllImport(\"kernel32.dll\", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)] public static extern uint GetShortPathName(string source, System.Text.StringBuilder target, uint capacity);'; $b=New-Object System.Text.StringBuilder 32768; $n=[FlockFixture.Native]::GetShortPathName($env:FLOCK_OWNED_ALIAS_FILE,$b,[uint32]$b.Capacity); if($n -eq 0){throw 'Owned short-path metadata query failed'}; [Console]::Write($b.ToString())"], {
        encoding: "utf8", windowsHide: true, timeout: 10000,
        env: { ...process.env, FLOCK_OWNED_ALIAS_FILE: path.join(physicalHome, names[0]) },
      }).trim();
      assert.ok(short && fs.existsSync(short), "Short-name query must identify a real owned fixture path");
      targets.push(short);
      const key = (value) => value.replace(/^\\\\\?\\/, "").toLowerCase();
      t.diagnostic(`Physical Windows short-name alias distinct: ${key(short) !== key(path.join(physicalHome, names[0]))}`);
    }
    for (const remotePath of targets) {
      const request = f.request("send_file_chunk", { remotePath, chunkIndex: 0, totalChunks: 1,
        dataBase64: Buffer.from("Synthetic untrusted replacement; never executed").toString("base64") });
      assert.equal((await f.callback(request)).status, "rejected", remotePath);
      for (const name of names) assert.equal(fs.readFileSync(path.join(home, name), "utf8"), original);
      assert.equal(fs.readFileSync(path.join(state, "transfer-metadata.json"), "utf8"), "Synthetic private control state");
      const inspected = new DatabaseSync(ledgerFile);
      try { assert.equal(inspected.prepare("SELECT COUNT(*) AS count FROM admissions").get().count, 0,
        "Protected paths must reject before admission helper or completion dispatch"); }
      finally { inspected.close(); }
    }
    assert.equal(fs.existsSync(path.join(home, "not-created")), false);
    for (const remotePath of ["review-module.mjs", path.join(outside, `approved-${index}.txt`)]) {
      const data = Buffer.from(`Synthetic approved data ${index}`);
      const result = await f.callback(f.request("send_file_chunk", { remotePath, chunkIndex: 0, totalChunks: 1,
        dataBase64: data.toString("base64"), expectedSha256: crypto.createHash("sha256").update(data).digest("hex") }));
      assert.equal(result.status, "accepted");
      assert.deepEqual(fs.readFileSync(result.result.remotePath), data);
    }
    fs.unlinkSync(linked);
  }
});

test("completion refuses changed startup-pinned helper or imports before invoking Node", (t) => {
  const root = isolatedProfile(t, "flock-runtime-integrity-");
  const source = fs.readFileSync(new URL("../flock.mjs", import.meta.url), "utf8");
  for (const name of ["legacy-rpc-admissions.mjs", "zero-broker-roster.mjs", "release-policy.mjs"]) {
    fs.writeFileSync(path.join(root, name), "export const synthetic = true;");
  }
  const claim = primitiveAdmission(root);
  legacyAdmissionOperation({ ...claim, operation: "claim" });
  const snapshot = flock.captureRuntimeModuleIntegrity(root);
  let invoked = 0;
  const context = vm.createContext({
    fs, path, process, __dirname: root, RUNTIME_MODULE_INTEGRITY: snapshot,
    assertRuntimeModuleIntegrity: flock.assertRuntimeModuleIntegrity,
    zeroBrokerNodeFlags: flock.zeroBrokerNodeFlags,
    rpcSecurityError: (code, message) => Object.assign(new Error(message), { code }),
    execFileSync: (_program, _args, options) => {
      invoked++;
      return JSON.stringify({ ok: true, ...legacyAdmissionOperation(JSON.parse(options.input)) });
    },
  });
  vm.runInContext(`${functionSource(source, "localLegacyAdmissionOperation")}\nthis.complete = localLegacyAdmissionOperation;`, context);
  assert.equal(context.complete({ home: root, receiverKey: claim.receiverKey, operation: "inspect" }).ok, true);
  for (const name of ["legacy-rpc-admissions.mjs", "zero-broker-roster.mjs", "release-policy.mjs"]) {
    const filename = path.join(root, name);
    fs.writeFileSync(filename, "Synthetic changed executable bytes; never executed");
    assert.throws(() => context.complete({ ...claim, operation: "complete", outcome: "COMPLETED" }), { code: "RPC_RUNTIME_INTEGRITY_CHANGED" });
    assert.equal(invoked, 1, "Changed code must never be auto-repinned or invoked");
    const inspected = new DatabaseSync(path.join(root, "legacy-rpc-admissions", claim.receiverKey, "state.sqlite"));
    try { assert.equal(inspected.prepare("SELECT outcome FROM admissions").get().outcome, "UNKNOWN"); }
    finally { inspected.close(); }
    fs.writeFileSync(filename, "export const synthetic = true;");
  }
});

test("transfer descriptor recheck precedes truncation when an opened file differs from its checked path", (t) => {
  const root = isolatedProfile(t, "flock-transfer-descriptor-");
  const data = path.join(root, "approved.data"), protectedFile = path.join(root, "protected-module.mjs");
  fs.writeFileSync(data, "Synthetic approved original");
  fs.writeFileSync(protectedFile, "Synthetic protected original");
  const source = fs.readFileSync(new URL("../flock.mjs", import.meta.url), "utf8");
  const context = vm.createContext({
    path, process,
    assertSafeTransferFilePath: (filename) => filename,
    fs: { ...fs, openSync: (_filename, flags) => fs.openSync(protectedFile, flags) },
  });
  for (const name of ["assertTransferDescriptor", "writeVerifiedTransferChunk"]) {
    vm.runInContext(functionSource(source, name), context);
  }
  assert.throws(() => context.writeVerifiedTransferChunk(data, Buffer.from("Synthetic replacement")), /identity changed/);
  assert.equal(fs.readFileSync(protectedFile, "utf8"), "Synthetic protected original");
  assert.equal(fs.readFileSync(data, "utf8"), "Synthetic approved original");
});

test("expired/wrong-target context and absent authority fail closed; guest grants are exact static summaries", async () => {
  for (const api of [flock, bridge]) {
    for (const options of [{ expired: true }, { target: "OTHER" }]) {
      const f = await fixture(api, options);
      assert.equal((await f.callback(f.request())).status, "rejected");
    }
    const f = await fixture(api, { shared: true });
    const rootPolicy = f.request();
    rootPolicy.flockPolicy = { trustTier: "owner" };
    assert.equal((await f.callback(rootPolicy)).status, "rejected");
    assert.equal((await f.callback(f.request())).status, "rejected");
    assert.equal((await f.callback(f.request("get_transcript", { session: "unshared" }))).status, "rejected");
    assert.equal((await f.callback(f.request("send_message", { targetSession: "shared", message: "Run code" }))).status, "rejected");
    const approved = await f.callback(f.request("get_transcript", { session: "shared" }));
    assert.equal(approved.status, "accepted");
    assert.deepEqual(approved.result.messages.map((message) => message.content), ["Exactly the approved summary"]);
    const missing = api.createRpcInvocationHandler(f.cfg, {
      contextProvider: async () => null, logger() {}, sendResponse: async () => assert.fail("No response for unauthenticated context"),
    });
    assert.equal((await missing(f.request())).status, "rejected");
  }
});

function functionSource(source, name) {
  const start = source.search(new RegExp(`(?:export )?(?:async )?function ${name}\\(`));
  assert.ok(start >= 0, name);
  const next = source.slice(start + 1).search(/\n(?:export )?(?:async )?function [A-Za-z]/);
  return source.slice(start, next < 0 ? source.length : start + 1 + next).replace(/^export /, "");
}

test("successful callback rechecks snapshot grants and roster epoch before disclosure", async () => {
  for (const api of [flock, bridge]) {
    for (const change of ["revoke", "replace", "epoch"]) {
      const f = await fixture(api, { shared: true });
      const policy = {
        ...f.receiving.policy,
        sharedSessionIds: change === "revoke" ? [] : [...f.receiving.policy.sharedSessionIds],
        sharedSnapshots: change === "revoke" ? {} : {
          ...f.receiving.policy.sharedSnapshots,
          shared: { ...f.receiving.policy.sharedSnapshots.shared,
            summarySnapshot: change === "replace" ? "Replacement grant" : "Exactly the approved summary" },
        },
        rosterEpoch: f.receiving.policy.rosterEpoch + (change === "epoch" ? 1 : 0),
      };
      let reads = 0;
      const replies = [];
      const callback = api.createRpcInvocationHandler(f.cfg, {
        contextProvider: async () => ++reads === 1 ? f.receiving : { ...f.receiving, policy },
        logger() {}, sendResponse: async (_audience, reply) => replies.push(reply),
      });
      const outcome = await callback(f.request("get_transcript", { session: "shared" }));
      assert.equal(outcome.status, "rejected", change);
      assert.equal(replies.length, 0, "Revoked/replaced/stale content must not be disclosed");
      assert.ok(reads >= 2);
    }
  }
});

test("all legacy token-bearing helpers require independent origin trust before token resolution or request execution", () => {
  for (const filename of ["flock.mjs", "bridge.mjs"]) {
    const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
    let tokens = 0, network = 0;
    const sandbox = vm.createContext({
      URL, Buffer, Date, crypto, os: { hostname: () => "EXAMPLE" },
      process: { env: {}, platform: "win32", execPath: "synthetic-node" },
      DEFAULT_BOOTSTRAP_URL: "", DEFAULT_BOOTSTRAP_ORIGIN: "", BRIDGE_VERSION: "synthetic",
      resolveLocalGitHubToken: () => { tokens++; return "synthetic-token"; },
      isSandboxV3Mode: () => false,
      execFileSync: (_exe, _args, options) => {
        network++;
        const destination = options.env.BOOTSTRAP_URL || options.env.REGISTER_URL ||
          options.env.MEMBERS_URL || options.env.QUEUE_API_URL || options.env.V3_URL;
        assert.equal(new URL(destination).origin, "https://trusted.invalid");
        return '{"ok":true,"members":[],"connectionString":"Endpoint=https://example.invalid;AccessKey=synthetic;"}';
      },
    });

    for (const name of ["validatePinnedBootstrapOrigin", "fetchConnectionStringViaGitHubBootstrap",
      "registerWithBootstrapServer", "fetchBootstrapMembers", "callBootstrapQueueApi", "callBootstrapV3Endpoint"]) {
      vm.runInContext(functionSource(source, name), sandbox);
    }
    const calls = ["fetchConnectionStringViaGitHubBootstrap", "registerWithBootstrapServer", "fetchBootstrapMembers", "callBootstrapQueueApi"];
    for (const name of calls) {
      for (const pin of ["", "https://trusted.invalid"]) {
        assert.throws(() => sandbox[name]({ bootstrapUrl: "https://substituted.invalid/api/bootstrap", bootstrapOriginPin: pin }),
          (error) => error.code === "UNTRUSTED_BOOTSTRAP_ORIGIN");
        assert.equal(tokens, 0); assert.equal(network, 0);
      }
    }
    assert.throws(() => sandbox.callBootstrapV3Endpoint({ bootstrapUrl: "https://substituted.invalid/api/bootstrap" }, "/my-flocks", { method: "GET" }),
      (error) => error.code === "UNTRUSTED_BOOTSTRAP_ORIGIN");
    assert.equal(tokens, 0); assert.equal(network, 0);
    for (const name of calls) sandbox[name]({ bootstrapUrl: "https://trusted.invalid/api/bootstrap", bootstrapOriginPin: "https://trusted.invalid" });
    sandbox.callBootstrapV3Endpoint({ bootstrapUrl: "https://trusted.invalid/api/bootstrap", bootstrapOriginPin: "https://trusted.invalid" }, "/my-flocks", { method: "GET" });
    assert.equal(tokens, 5); assert.equal(network, 5);
  }
});

test("actual single/batch sender functions round-trip context-bound signed requests and responses", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-signed-roundtrip-"));
  const previousHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  try {
    for (const [filename, api] of [["flock.mjs", flock], ["bridge.mjs", bridge]]) {
      const f = await fixture(api);
      f.initializeAdmissions();
      const clients = new Map(), seen = [];
      let closed = 0;
      const callback = api.createRpcInvocationHandler(f.cfg, {
        contextProvider: async () => f.receiving, logger() {},
        sendResponse: async (replyUserId, response) => clients.get(replyUserId)("bridgeRpcResponse", [response]),
      });
      const sandbox = vm.createContext({
        crypto, setTimeout, clearTimeout, Promise,
        loadTrustedRpcContext: async () => f.sending,
        createSignedRpcRequest: api.createSignedRpcRequest,
        verifySignedRpcResponse: api.verifySignedRpcResponse,
        isLegacyRpcMutation: api.isLegacyRpcMutation,
        getLegacyReceiverBinding: api.getLegacyReceiverBinding,
        logDaemon() {},
        connectSignalRClient: async (_cfg, options) => {
          clients.set(options.userId, options.onInvocation);
          return { close: () => { closed++; clients.delete(options.userId); } };
        },
        sendSignalRToUser: async (_cfg, _userId, target, payload) => {
          assert.equal(target, "bridgeRpcRequest");
          assert.equal(payload.auth.v, 3);
          assert.equal(payload.flockId, f.receiving.policy.flockId);
          seen.push(payload);
          await callback(payload);
        },
        sendSignalRBroadcast: async (_cfg, _target, payload) => callback(payload),
      });
      const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
      for (const name of ["invokeRemoteRpc", "invokeRemoteRpcBatch"]) vm.runInContext(functionSource(source, name), sandbox);
      const originCfg = { ...f.cfg, machineId: "ORIGIN" };
      const response = await sandbox.invokeRemoteRpc(originCfg, {
        toMachine: "VICTIM", action: "acquire_lock", params: { resource: `single-${filename}` }, timeoutMs: 100,
      });
      assert.equal(response.result.acquired, true);
      const batch = await sandbox.invokeRemoteRpcBatch(originCfg, [
        { toMachine: "VICTIM", action: "list_locks", params: {} },
        { toMachine: "VICTIM", action: "list_locks", params: {} },
        { toMachine: "VICTIM", action: "acquire_lock", params: { resource: `batch-${filename}` } },
      ], 100);
      assert.equal(batch.length, 3);
      assert.ok(batch.every((entry) => entry.ok && entry.response.auth.v === 3));
      assert.equal(seen.length, 5);
      assert.ok(seen.filter((packet) => api.isLegacyRpcMutation(packet)).every((packet) => packet.admissionLedgerId === f.admissionLedgerId));
      assert.equal(closed, 3);
    }
  } finally {
    if (previousHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("first-use invitation cannot self-pin or bypass loadConfig trust; explicit pin survives configuration loading", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-origin-import-"));
  const envKeys = ["COPILOT_HOME", "COPILOT_BRIDGE_SCOPE", "COPILOT_BRIDGE_BOOTSTRAP_URL",
    "COPILOT_FLOCK_BOOTSTRAP_URL", "COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN", "COPILOT_BRIDGE_ALLOWED_BOOTSTRAP_ORIGIN"];
  const previous = new Map(envKeys.map((key) => [key, process.env[key]]));
  for (const key of envKeys) delete process.env[key];
  try {
    for (const [index, api] of [flock, bridge].entries()) {
      process.env.COPILOT_HOME = path.join(root, String(index));
      await assert.rejects(() => api.installBridge({
        enrollmentJsonArg: { bootstrapUrl: "https://substituted.invalid/api/bootstrap",
          bootstrapOriginPin: "https://substituted.invalid" },
      }), (error) => error.code === "UNTRUSTED_BOOTSTRAP_ORIGIN");
      const home = path.join(process.env.COPILOT_HOME, "flock");
      const configPath = path.join(home, "config.json");
      const config = {
        machineId: "EXAMPLE", scope: "personal", githubUser: "example",
        specs: { cpu: { model: "Synthetic" } },
        bootstrapUrl: "https://substituted.invalid/api/bootstrap",
        connectionString: "Endpoint=https://example.invalid;AccessKey=synthetic;",
      };
      fs.writeFileSync(configPath, JSON.stringify(config));
      assert.throws(() => api.loadConfig({ autoFetchAz: true }),
        (error) => error.code === "UNTRUSTED_BOOTSTRAP_ORIGIN");
      fs.writeFileSync(configPath, JSON.stringify({
        ...config, bootstrapUrl: "https://trusted.invalid/api/bootstrap",
        bootstrapOriginPin: "https://trusted.invalid",
      }));
      assert.equal(api.loadConfig({ autoFetchAz: false }).bootstrapOriginPin, "https://trusted.invalid");
      assert.equal(fs.existsSync(path.join(home, "identity.json")), false);
    }
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});
