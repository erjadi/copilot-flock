import test from "node:test";
import { recordReleaseReviewFailures } from "./release-review-diagnostics.mjs";
recordReleaseReviewFailures(import.meta.url);
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import https from "node:https";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  createBootstrapServer,
  createV3FlockInvite,
  enrollV3Device,
  syncV3DeviceMemberships,
  kickV3FlockMember,
  listV3UserFlocks,
  saveV3FlockStore,
  saveOfflineQueueStore,
  leaveV3Device,
} from "../bootstrap-server.mjs";
import {
  applyV3EnrollmentResult,
  cleanupFlockCredentialVault,
  ensureTokenLocalTransportCredentials,
  handleRpcAction,
  loadFlockCredentialVault,
  openFlockMembershipRegistry,
  resolveLegacyFlockRoster,
  reconcileAuthoritativeFlockMemberships,
  hasVerifiedOwnerAuthority,
  refreshTokenLocalTransportCredentials,
  signV3EnrollmentRequest,
  signV3MembershipSyncRequest,
  signRpcRequest,
  syncFlockMemberships,
  verifyEnrollmentReadiness,
} from "../flock.mjs";
import { createSignedRosterSnapshot, signLeave } from "../flock-membership.mjs";
import { createTlsFixture } from "./openssl.mjs";
import { renameFixtureDirectory } from "./fixture-filesystem.mjs";

function decodeJwtPayload(token) {
  const encoded = String(token || "").split(".")[1];
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
}

async function postJson(url, body, headers = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "X-Flock-Protocol-Version": "36", ...headers },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

function identity() {
  const pair = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    ...pair,
    fingerprint: crypto.createHash("sha256").update(pair.publicKey).digest("hex").slice(0, 32),
  };
}

function signedRequest({ key, machineId, action, params = {}, toMachine = "LOCAL" }) {
  const requestId = crypto.randomUUID();
  const sentAt = new Date().toISOString();
  const auth = signRpcRequest({
    requestId,
    sentAt,
    fromMachine: machineId,
    toMachine,
    action,
    params,
    identity: key,
  });
  return { requestId, sentAt, action, params, toMachine, auth };
}

function ownerRoutingIdentity() {
  const key = identity();
  key.publicKey = key.publicKey.trim();
  key.fingerprint = crypto.createHash("sha256").update(key.publicKey).digest("hex").slice(0, 32);
  return key;
}

function ownerRootRoutingFixture(t, runtime, scope) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "flock-owner-root-routing-"));
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = home;
  t.after(() => {
    if (previous === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previous;
    fs.rmSync(home, { recursive: true, force: true });
  });
  const directory = path.join(home, "flock");
  fs.mkdirSync(directory);
  const flocksPath = path.join(directory, "flocks.json");
  const key = ownerRoutingIdentity();
  const member = (machineId, memberScope, device = key, githubUser = "owner") => ({
    peerId: `1001:${device.fingerprint}`, githubUser, githubUserId: 1001, deviceId: device.fingerprint,
    keyFingerprint: device.fingerprint, publicKey: device.publicKey, machineId, scope: memberScope, trustTier: "owner",
  });
  const self = member(`SELF-${scope.toUpperCase()}`, scope);
  const record = (id, members, extra = {}) => ({ flockId: id, flockUuid: `fixture-${id}`,
    flockType: id === "owner" ? "owner_root" : ["owner/personal", "owner/work"].includes(id) ? "owner_scope" : "shared",
    ownerGitHubUser: id.split("/")[0], ownerGitHubUserId: 1001, trustTier: "owner",
    allowedScopes: id === "owner" ? ["personal", "work"] : [id.split("/")[1]],
    sessionVisibility: "all", rosterEpoch: 12, members, ...extra });
  const syntheticRoot = record("owner", [self], { flockUuid: "builtin-owner" });
  fs.writeFileSync(flocksPath, JSON.stringify({ flocks: { owner: syntheticRoot } }));
  const registry = runtime.openFlockMembershipRegistry(flocksPath);
  registry.reconcileV3BrokerFlock(syntheticRoot);
  const cfg = { machineId: self.machineId, githubUser: "owner", scope, identity: key, flocksConfigPath: flocksPath };
  cfg.fetchOwnerBuiltInFlocksFn = async () => { throw new Error("Fixture owner roster is unavailable"); };
  cfg.syncFlockMembershipsFn = async () => {
    throw Object.assign(new Error("Fixture membership sync is offline"), { code: "FIXTURE_SYNC_OFFLINE" });
  };
  runtime.applyV3EnrollmentResult(cfg, { ok: true, githubUser: "owner", githubUserId: 1001,
    deviceId: key.fingerprint, peerId: self.peerId, completeMembershipSnapshot: true,
    enrolledFlocks: [record(`owner/${scope}`, [self])] }, flocksPath, { requireMemberProof: true });
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(flocksPath)).flocks), [`owner/${scope}`]);
  assert.equal(registry.hasFlock("owner"), false);
  assert.ok(registry.read().retainedFlocks.owner);
  fs.writeFileSync(path.join(directory, "cli-sessions.json"), JSON.stringify([
    { session_id: "fixture-session", title: "Owner session", session_type: "cli",
      updated_at: new Date().toISOString(), is_running: false },
  ]));
  const add = (policy) => {
    const stored = JSON.parse(fs.readFileSync(flocksPath));
    stored.flocks[policy.flockId] = policy;
    fs.writeFileSync(flocksPath, JSON.stringify(stored));
    registry.reconcileV3BrokerFlock(policy);
  };
  const wire = [];
  cfg.rpcTransport = async (request) => {
    wire.push(request);
    return { fromMachine: cfg.machineId, result: await runtime.handleRpcAction(cfg, request) };
  };
  return { home, cfg, key, self, member, record, registry, flocksPath, add, wire };
}

test("Gate8a reconciled personal/work owner self-tests and default protected RPCs verify active scoped pins without restoring root membership", async (t) => {
  for (const filename of ["bridge.mjs", "flock.mjs"]) {
    const runtime = await import(new URL(`../${filename}`, import.meta.url));
    for (const scope of ["personal", "work"]) {
      await t.test(`${filename} ${scope}`, async (t) => {
        const f = ownerRootRoutingFixture(t, runtime, scope);
        const beforeConfig = fs.readFileSync(f.flocksPath);
        const beforeRegistry = fs.readFileSync(f.registry.filename);
        const request = signedRequest({ key: f.key, machineId: f.cfg.machineId, action: "send_message",
          params: { flock: "owner", targetSession: "latest", message: "Self-test", dryRun: true },
          toMachine: f.cfg.machineId });
        assert.equal(runtime.resolveVerifiedSenderIdentity(f.cfg, request).senderVerified, true);
        const sessions = await runtime.invokeRemoteRpc({ ...f.cfg, flockId: "owner" }, {
          toMachine: f.cfg.machineId, action: "list_sessions", params: { limit: 5 }, allowLoopback: true,
        });
        assert.equal(sessions.result.sessions[0].session_id, "fixture-session");
        const drySend = await runtime.invokeRemoteRpc(f.cfg, { toMachine: f.cfg.machineId,
          action: "send_message", params: { targetSession: "latest", message: "Self-test",
            fromScope: scope, fromSessionId: "self-test", dryRun: true }, allowLoopback: true });
        assert.equal(drySend.result.status, "dry_run_verified");
        assert.equal(drySend.result.senderVerified, true);
        const acquired = await runtime.invokeRemoteRpc(f.cfg, { toMachine: f.cfg.machineId,
          action: "acquire_lock", params: { resource: "fixture-resource", ownerSessionId: "fixture-session" } });
        assert.equal(acquired.result.acquired, true);
        const released = await runtime.invokeRemoteRpc(f.cfg, { toMachine: f.cfg.machineId, action: "release_lock",
          params: { resource: "fixture-resource", ownerSessionId: "fixture-session", leaseId: acquired.result.leaseId } });
        assert.equal(released.result.released, true);
        assert.ok(f.wire.every((request) => request.params.flock === "owner"));
        assert.deepEqual(fs.readFileSync(f.flocksPath), beforeConfig);
        assert.deepEqual(fs.readFileSync(f.registry.filename), beforeRegistry);
        assert.equal(f.registry.hasFlock("owner"), false);
        const legacy = JSON.parse(fs.readFileSync(f.flocksPath));
        delete legacy.flocks[`owner/${scope}`].flockType;
        fs.writeFileSync(f.flocksPath, JSON.stringify(legacy));
        const legacyDrySend = await runtime.invokeRemoteRpc(f.cfg, { toMachine: f.cfg.machineId,
          action: "send_message", params: { targetSession: "latest", message: "Legacy built-in policy", dryRun: true } });
        assert.equal(legacyDrySend.result.status, "dry_run_verified");
      });
    }
  }
});

test("Gate8a genuinely reconciled personal/work hosts resolve root pins in memory, rotate keys and retain exact selector isolation", async (t) => {
  const runtime = await import("../flock.mjs");
  const original = process.env.COPILOT_HOME;
  const personal = ownerRootRoutingFixture(t, runtime, "personal");
  if (original === undefined) delete process.env.COPILOT_HOME;
  else process.env.COPILOT_HOME = original;
  const work = ownerRootRoutingFixture(t, runtime, "work");
  const hosts = [personal, work];
  const records = hosts.map((host) => host.record(`owner/${host.cfg.scope}`, [host.self]));
  const brokerRoot = personal.record("owner", []);
  const reconcile = (host) => {
    runtime.applyV3EnrollmentResult(host.cfg, { ok: true, githubUser: "owner", githubUserId: 1001,
      deviceId: host.cfg.identity.fingerprint, peerId: `1001:${host.cfg.identity.fingerprint}`,
      completeMembershipSnapshot: true, enrolledFlocks: [records.find((r) => r.flockId === `owner/${host.cfg.scope}`)],
    }, host.flocksPath, { requireMemberProof: true });
  };
  for (const host of hosts) {
    for (const record of records) host.add(record);
    reconcile(host);
    assert.deepEqual(host.registry.listFlockIds(), [`owner/${host.cfg.scope}`]);
    assert.ok(host.registry.read().retainedFlocks[host.cfg.scope === "personal" ? "owner/work" : "owner/personal"]);
    host.fetches = 0;
    host.cfg.bootstrapUrl = "https://owner-pins.invalid/api/bootstrap";
    host.cfg.fetchOwnerBuiltInFlocksFn = async (cfg) => {
      host.fetches++;
      assert.equal(cfg.identity.fingerprint, host.cfg.identity.fingerprint);
      return { ok: true, githubUser: "owner", githubUserId: 1001, ownedFlocks: structuredClone([brokerRoot, ...records]) };
    };
  }
  const before = hosts.map((host) => [fs.readFileSync(host.flocksPath), fs.readFileSync(host.registry.filename)]);
  const invoke = (caller, receiver, action, params = {}) => runtime.invokeRemoteRpc({
    ...caller.cfg, rpcTransport: async (request) => {
      process.env.COPILOT_HOME = receiver.home;
      return { fromMachine: receiver.cfg.machineId, result: await runtime.handleRpcAction(receiver.cfg, request) };
    },
  }, { toMachine: receiver.cfg.machineId, action, params });
  for (const [caller, receiver] of [[personal, work], [work, personal]]) {
    const dry = await invoke(caller, receiver, "send_message", { targetSession: "latest",
      message: "Genuine post-reconcile cross-scope owner", dryRun: true });
    assert.equal(dry.result.status, "dry_run_verified");
    const acquired = await invoke(caller, receiver, "acquire_lock", { resource: "cross-scope", ownerSessionId: "fixture-session" });
    assert.equal(acquired.result.acquired, true);
    assert.equal((await invoke(caller, receiver, "release_lock", { resource: "cross-scope",
      ownerSessionId: "fixture-session", leaseId: acquired.result.leaseId })).result.released, true);
    assert.equal(receiver.fetches, 1, "A fresh authoritative cache avoids repeated broker calls");
    await assert.rejects(() => invoke(caller, receiver, "send_message", { flock: `owner/${receiver.cfg.scope}`,
      targetSession: "latest", message: "Wrong exact scope", dryRun: true }),
    (error) => error.originalAuthorizationError?.code === "UNPINNED_PEER_KEY");
    assert.equal(receiver.fetches, 1, "Explicit selectors must not use root-alias broker resolution");
  }
  hosts.forEach((host, index) => {
    assert.deepEqual(fs.readFileSync(host.flocksPath), before[index][0]);
    assert.deepEqual(fs.readFileSync(host.registry.filename), before[index][1]);
  });
  records[1].rosterEpoch++;
  reconcile(work);
  const workFetches = work.fetches;
  assert.equal((await invoke(work, work, "send_message", {
    targetSession: "latest", message: "Fresher local epoch must ignore stale cache", dryRun: true })).result.status, "dry_run_verified");
  assert.equal(work.fetches, workFetches);
  const oldWork = { ...work.cfg };
  const oldPeer = work.self;
  const rotated = ownerRoutingIdentity();
  work.cfg.identity = rotated;
  work.self = work.member(work.cfg.machineId, "work", rotated);
  records[1] = work.record("owner/work", [work.self], { rosterEpoch: 14,
    removedMachines: [{ ...oldPeer, removedAtEpoch: 14 }] });
  brokerRoot.removedMachines = [{ ...oldPeer, removedAtEpoch: 14 }];
  reconcile(work);
  const newKeyResult = await invoke(work, personal, "send_message", {
    targetSession: "latest", message: "Rotated key without sleeping", dryRun: true });
  assert.equal(newKeyResult.result.status, "dry_run_verified");
  assert.equal(personal.fetches, 2);
  await assert.rejects(() => invoke({ cfg: oldWork }, personal, "send_message", {
    targetSession: "latest", message: "Old key must stay rejected", dryRun: true }),
  (error) => error.code === "UNPINNED_PEER_KEY" && error.statusCode === 403);
  assert.equal((await invoke(personal, work, "send_message", {
    targetSession: "latest", message: "Reverse direction after rotation", dryRun: true })).result.status, "dry_run_verified");
  hosts.forEach((host) => assert.deepEqual(host.registry.listFlockIds(), [`owner/${host.cfg.scope}`]));
});

test("Gate8a broker owner pin lookup rejects stale floors, retained tombstones and unproven memberships without persisting authority", async (t) => {
  const runtime = await import("../flock.mjs");
  for (const mode of ["retained-root-tombstone", "retained-scope-tombstone", "kicked-local", "stale-epoch",
    "shared-only", "joined-only", "collaborator", "guest", "time-bound", "foreign-user", "foreign-response",
    "forged-fingerprint", "forged-peer-id", "ambiguous-key", "broker-revocation", "broker-removed",
    "legacy-root-removal", "expired-scope"]) {
    await t.test(mode, async (t) => {
      const f = ownerRootRoutingFixture(t, runtime, "personal");
      const key = ownerRoutingIdentity();
      const peer = f.member("WORK-PEER", "work", key);
      let policy = f.record("owner/work", [peer]);
      f.add(policy);
      f.registry.retainFlocks(["owner/work"]);
      if (mode === "retained-root-tombstone" || mode === "retained-scope-tombstone") {
        const id = mode === "retained-root-tombstone" ? "owner" : "owner/work";
        f.registry.reconcileV3BrokerFlock(f.record(id, [peer]));
        f.registry.recordRemovalTombstone(id, peer);
        f.registry.retainFlocks([id]);
      }
      if (mode === "stale-epoch") policy.rosterEpoch--;
      if (mode === "shared-only") policy = f.record("owner/team", [peer]);
      if (mode === "collaborator" || mode === "guest") policy.members[0].trustTier = mode;
      if (mode === "time-bound") policy.members[0].membershipExpiresAtMs = Date.now() + 600000;
      if (mode === "expired-scope") policy.expiresAtMs = Date.now() - 1;
      if (mode === "foreign-user") policy.members[0].githubUser = "alice";
      if (mode === "forged-fingerprint") policy.members[0].keyFingerprint = "0".repeat(32);
      if (mode === "forged-peer-id") policy.members[0].peerId = `2002:${key.fingerprint}`;
      if (mode === "broker-revocation") policy.revokedPrincipals = { [peer.peerId]: true };
      if (mode === "broker-removed") policy.removedMachines = [{ ...peer }];
      if (mode === "kicked-local") {
        f.registry.retainFlocks(["owner/personal"]);
        fs.writeFileSync(f.flocksPath, '{"flocks":{}}');
      }
      let fetches = 0;
      f.cfg.bootstrapUrl = "https://owner-pins.invalid/api/bootstrap";
      f.cfg.fetchOwnerBuiltInFlocksFn = async () => {
        fetches++;
        return { ok: true, githubUser: mode === "foreign-response" ? "other" : "owner", githubUserId: 1001,
          ownedFlocks: mode === "joined-only" ? [] : [policy, ...(mode === "ambiguous-key" ? [
            f.record("owner", [{ ...f.member(peer.machineId, "work", ownerRoutingIdentity()) }]),
          ] : mode === "legacy-root-removal" ? [
            f.record("owner", [], { removedMachines: [{ machineId: peer.machineId }] }),
          ] : [])], joinedFlocks: [policy] };
      };
      const before = [fs.readFileSync(f.flocksPath), fs.readFileSync(f.registry.filename)];
      const request = signedRequest({ key, machineId: peer.machineId, action: "send_message",
        params: { flock: "owner", targetSession: "latest", message: "Must not dispatch", dryRun: true }, toMachine: f.cfg.machineId });
      await assert.rejects(() => runtime.handleRpcAction(f.cfg, request),
        (error) => error.code === "UNPINNED_PEER_KEY" && error.statusCode === 403);
      assert.equal(fetches, mode === "kicked-local" ? 0 : 1);
      assert.deepEqual(fs.readFileSync(f.flocksPath), before[0]);
      assert.deepEqual(fs.readFileSync(f.registry.filename), before[1]);
    });
  }
});

test("Gate8a owner pin refresh is fresh-signature gated, single-flight, burst bounded and expires after sixty seconds", async (t) => {
  const runtime = await import("../flock.mjs");
  const f = ownerRootRoutingFixture(t, runtime, "personal");
  const key = ownerRoutingIdentity();
  const peer = f.member("WORK-PEER", "work", key);
  const policy = f.record("owner/work", [peer]);
  let fetches = 0;
  f.cfg.bootstrapUrl = "https://owner-pins.invalid/api/bootstrap";
  f.cfg.fetchOwnerBuiltInFlocksFn = async () => {
    fetches++;
    await new Promise((resolve) => setImmediate(resolve));
    return { ok: true, githubUser: "owner", githubUserId: 1001, ownedFlocks: [policy] };
  };
  const request = (device = key, machineId = peer.machineId) => signedRequest({ key: device, machineId,
    action: "send_message", params: { flock: "owner", targetSession: "latest", message: "Cache check", dryRun: true },
    toMachine: f.cfg.machineId });
  const invalid = request();
  invalid.auth.signature = Buffer.alloc(64).toString("base64");
  await assert.rejects(() => runtime.handleRpcAction(f.cfg, invalid), /no pinned roster key/);
  const stale = request();
  stale.auth.sentAt = new Date(Date.now() - 600000).toISOString();
  await assert.rejects(() => runtime.handleRpcAction(f.cfg, stale), /no pinned roster key/);
  assert.equal(fetches, 0);
  const results = await Promise.all([runtime.handleRpcAction(f.cfg, request()), runtime.handleRpcAction(f.cfg, request())]);
  assert.ok(results.every((result) => result.status === "dry_run_verified"));
  assert.equal(fetches, 1);
  for (let index = 0; index < 8; index++) {
    await assert.rejects(() => runtime.handleRpcAction(f.cfg, request(ownerRoutingIdentity(), `UNKNOWN-${index}`)), /no pinned roster key/);
  }
  assert.equal(fetches, 4);
  const now = Date.now();
  t.mock.method(Date, "now", () => now + 61000);
  assert.equal((await runtime.handleRpcAction(f.cfg, request())).status, "dry_run_verified");
  assert.equal(fetches, 5);
});

test("Gate8a owner pin refresh keeps its single-flight result attached across a refresh-window rollover", async (t) => {
  const runtime = await import("../flock.mjs");
  const f = ownerRootRoutingFixture(t, runtime, "personal");
  const key = ownerRoutingIdentity();
  const peer = f.member("WORK-PEER", "work", key);
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  let fetches = 0;
  f.cfg.bootstrapUrl = "https://owner-pins.invalid/api/bootstrap";
  f.cfg.fetchOwnerBuiltInFlocksFn = async () => {
    fetches++;
    await pending;
    return { ok: true, githubUser: "owner", githubUserId: 1001,
      ownedFlocks: [f.record("owner/work", [peer])] };
  };
  const makeRequest = () => {
    const request = signedRequest({ key, machineId: peer.machineId, action: "send_message",
      params: { flock: "owner", fromMachine: peer.machineId, targetSession: "latest",
        message: "Window rollover", dryRun: true }, toMachine: f.cfg.machineId });
    delete request.auth.sentAt;
    delete request.auth.fromMachine;
    return request;
  };
  const first = runtime.handleRpcAction(f.cfg, makeRequest());
  const now = Date.now();
  t.mock.method(Date, "now", () => now + 16000);
  const second = runtime.handleRpcAction(f.cfg, makeRequest());
  assert.equal(fetches, 1);
  release();
  const results = await Promise.all([first, second]);
  assert.ok(results.every((result) => result.status === "dry_run_verified"));
  assert.equal((await runtime.handleRpcAction(f.cfg, makeRequest())).status, "dry_run_verified");
  assert.equal(fetches, 1, "The completed result must remain in the map rather than a detached entry");
});

test("Gate8a cross-scope owner pins use the existing HTTPS my-flocks endpoint and configured device identity without GitHub credentials", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-owner-pin-https-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const device = ownerRoutingIdentity();
  const remote = ownerRoutingIdentity();
  const storePath = path.join(root, "broker.json");
  const enroll = (key, machineId, scope) => enrollV3Device({ githubUser: "owner", githubUserId: 1001,
    deviceId: key.fingerprint, machineId, scope, publicKey: key.publicKey, keyFingerprint: key.fingerprint },
  { storePath, connectionString: "" });
  const enrollment = await enroll(device, "PERSONAL-RECEIVER", "personal");
  await enroll(remote, "WORK-SENDER", "work");
  const inputPath = path.join(root, "input.json");
  fs.writeFileSync(inputPath, JSON.stringify({ device, remote, enrollment }));
  const tls = createTlsFixture(root);
  const broker = createBootstrapServer({ v3StorePath: storePath, membersPath: path.join(root, "members.json"),
    apiGet: async () => { throw new Error("Owner pin resolution must not request GitHub credentials"); } });
  const requests = [];
  const server = https.createServer(tls, (req, res) => {
    requests.push({ path: req.url, device: req.headers["x-flock-device-id"], authorization: req.headers.authorization });
    broker.listeners("request")[0](req, res);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const origin = `https://127.0.0.1:${server.address().port}`;
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(home, "flock"), { recursive: true });
  const child = spawn(process.execPath, ["--input-type=module", "-e", `
    import fs from "node:fs";import path from "node:path";import assert from "node:assert/strict";
    import {applyV3EnrollmentResult,handleRpcAction,signRpcRequest,openFlockMembershipRegistry}
      from ${JSON.stringify(new URL("../flock.mjs", import.meta.url).href)};
    const data=JSON.parse(fs.readFileSync(${JSON.stringify(inputPath)}));
    const file=path.join(process.env.COPILOT_HOME,"flock","flocks.json");
    const cfg={githubUser:"owner",machineId:"PERSONAL-RECEIVER",scope:"personal",tokenLocalAuth:true,
      identity:data.device,bootstrapUrl:${JSON.stringify(origin + "/api/bootstrap")},flocksConfigPath:file};
    applyV3EnrollmentResult(cfg,{...data.enrollment,completeMembershipSnapshot:true,
      enrolledFlocks:data.enrollment.enrolledFlocks.filter(f=>f.flockId==="owner/personal")},file,{requireMemberProof:true});
    fs.writeFileSync(path.join(path.dirname(file),"cli-sessions.json"),JSON.stringify([
      {session_id:"fixture-session",title:"Fixture",session_type:"cli",updated_at:new Date().toISOString()}]));
    const before=fs.readFileSync(file), registry=openFlockMembershipRegistry(file), registryBefore=fs.readFileSync(registry.filename);
    for(let i=0;i<2;i++){
      const requestId="owner-pin-https-"+i,sentAt=new Date().toISOString();
      const params={flock:"owner",targetSession:"latest",message:"HTTPS owner pin check",dryRun:true};
      const auth=signRpcRequest({requestId,sentAt,fromMachine:"WORK-SENDER",toMachine:cfg.machineId,
        action:"send_message",params,identity:data.remote});
      const result=await handleRpcAction(cfg,{requestId,sentAt,auth,toMachine:cfg.machineId,action:"send_message",params});
      assert.equal(result.status,"dry_run_verified");
    }
    assert.deepEqual(fs.readFileSync(file),before);
    assert.deepEqual(fs.readFileSync(registry.filename),registryBefore);
    assert.deepEqual(registry.listFlockIds(),["owner/personal"]);
    assert.equal(fs.existsSync(path.join(path.dirname(file),"identity.json")),false,"Configured identity must be used without creating another key");
    console.log("HTTPS owner pins verified without membership persistence");
  `], { windowsHide: true, env: { ...process.env, COPILOT_HOME: home, COPILOT_CLI_PATH: "",
    HOME: root, USERPROFILE: root, APPDATA: path.join(root, "AppData"), LOCALAPPDATA: path.join(root, "LocalAppData"),
    GITHUB_TOKEN: "must-not-forward-github-canary", GH_TOKEN: "must-not-forward-github-canary",
    NODE_OPTIONS: "", NODE_PATH: "", NODE_EXTRA_CA_CERTS: tls.certPath, COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN: origin },
    stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill(); });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
  assert.equal(code, 0, `${stdout}\n${stderr}`);
  assert.match(stdout, /HTTPS owner pins verified/);
  assert.equal(requests.length, 1, "The second request must reuse the in-memory cache");
  assert.ok(requests[0].path.includes(`/my-flocks?deviceId=${device.fingerprint}`));
  assert.equal(requests[0].device, device.fingerprint);
  assert.equal(requests[0].authorization, undefined);
});

test("Gate8a owner-root verification rejects shared/retained/cross-owner/unpinned/conflicting and revoked scoped keys", async (t) => {
  const runtime = await import("../flock.mjs");
  for (const mode of ["shared", "retained", "cross-owner", "unpinned", "conflict", "tombstone", "revoked",
    "expired", "role", "scope", "foreign-user", "forged-key", "policy-expired", "tombstone-shadow"]) {
    await t.test(mode, async (t) => {
      const f = ownerRootRoutingFixture(t, runtime, "personal");
      const key = identity();
      const peer = f.member("CLAIMED-PC", "work", key);
      const policy = f.record(mode === "shared" ? "owner/team" : mode === "cross-owner" ? "other/work" : "owner/work",
        [peer], { sessionVisibility: mode === "shared" ? "explicit_opt_in_only" : "all" });
      if (mode === "role") policy.members[0].trustTier = "collaborator";
      if (mode === "scope") policy.members[0].scope = "personal";
      if (mode === "foreign-user") policy.members[0].githubUser = "alice";
      if (mode === "expired") policy.members[0].membershipExpiresAtMs = Date.now() - 1;
      if (mode === "policy-expired") policy.membershipExpiresAtMs = Date.now() - 1;
      if (mode !== "unpinned") f.add(policy);
      if (mode === "retained") f.registry.retainFlocks(["owner/work"]);
      if (mode === "tombstone" || mode === "tombstone-shadow") f.registry.recordRemovalTombstone("owner/work", peer);
      if (mode === "tombstone-shadow") f.add(f.record("owner/personal", [f.self, { ...peer, scope: "personal" }],
        { rosterEpoch: 13 }));
      if (mode === "conflict") f.add(f.record("owner/personal", [f.self, {
        ...peer, ...f.member(peer.machineId, "personal", identity()),
      }], { rosterEpoch: 13 }));
      if (mode === "revoked") {
        const stored = JSON.parse(fs.readFileSync(f.flocksPath));
        stored.flocks["owner/work"].revokedPrincipals = { [peer.peerId]: true };
        fs.writeFileSync(f.flocksPath, JSON.stringify(stored));
      }
      const request = signedRequest({ key: mode === "forged-key" ? identity() : key, machineId: peer.machineId, action: "send_message",
        params: { flock: "owner", targetSession: "latest", message: "Must not dispatch",
          fromGitHubUser: "owner", fromScope: "work", dryRun: true },
        toMachine: f.cfg.machineId });
      await assert.rejects(() => runtime.handleRpcAction(f.cfg, request),
        (error) => error.code === "UNPINNED_PEER_KEY" && error.statusCode === 403);
      assert.equal(f.registry.hasFlock("owner"), false);
    });
  }
});

function brokerPersistenceFixture(root, kind) {
  const directory = path.join(root, kind);
  fs.mkdirSync(directory);
  const filename = path.join(directory, "state.json");
  fs.writeFileSync(filename, '{"before":true}');
  if (kind === "members-leave") {
    const key = identity();
    const member = { githubUser: "owner", githubUserId: 1001, deviceId: key.fingerprint,
      peerId: `1001:${key.fingerprint}`, publicKey: key.publicKey, machineId: "TARGET" };
    const storePath = path.join(directory, "broker.json");
    fs.writeFileSync(storePath, JSON.stringify({ flocks: { "owner/team": {
      flockId: "owner/team", rosterEpoch: 7, members: { target: member }, revokedPrincipals: {},
    } } }));
    fs.writeFileSync(filename, JSON.stringify({ target: member, sibling: { machineId: "SIBLING", publicKey: "keep" } }));
    const request = signLeave({ flockId: "owner/team", deviceId: key.fingerprint, machineId: "TARGET" }, key.privateKey);
    return { directory, filename, storePath, requestId: request.requestId,
      write: () => leaveV3Device(request, { storePath, membersPath: filename,
        deleteSubscription: async () => ({ confirmed: true }), evict: async () => ({ evicted: true }) }),
      verify: (result) => {
        assert.equal(result.confirmed, true);
        assert.deepEqual(JSON.parse(fs.readFileSync(filename)), { sibling: { machineId: "SIBLING", publicKey: "keep" } });
        assert.equal(JSON.parse(fs.readFileSync(storePath)).flocks["owner/team"].leaveReceipts[request.requestId].confirmed, true);
      } };
  }
  const now = Date.now();
  return { directory, filename, write: () => kind === "v3"
    ? saveV3FlockStore({ flocks: { "owner/team": { rosterEpoch: 9 } },
      nonces: { keep: { issuedAtMs: now }, expired: { issuedAtMs: now - 7200000 } } }, filename)
    : saveOfflineQueueStore({ items: [{ requestId: "keep", expiresAtMs: now + 600000 },
      { requestId: "expired", expiresAtMs: now - 1000 }] }, filename),
  verify: () => {
    const stored = JSON.parse(fs.readFileSync(filename));
    if (kind === "v3") {
      assert.equal(stored.flocks["owner/team"].rosterEpoch, 9);
      assert.deepEqual(Object.keys(stored.nonces), ["keep"]);
      assert.ok(Number.isFinite(Date.parse(stored.updatedAt)));
    } else assert.deepEqual(stored.items.map((item) => item.requestId), ["keep"]);
  } };
}

test("broker V3, offline queue and signed leave writes retry transient replacement locks without unlinking existing state", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-broker-replace-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rename = fs.renameSync;
  const unlink = fs.unlinkSync;
  let target;
  let before;
  let code;
  let calls = 0;
  const delays = [];
  t.mock.method(Atomics, "wait", (_buffer, _index, _value, timeout) => { delays.push(timeout); return "timed-out"; });
  t.mock.method(fs, "unlinkSync", (filename) => {
    assert.notEqual(filename, target, "Atomic replacement must never unlink the destination");
    return unlink(filename);
  });
  t.mock.method(fs, "renameSync", (source, destination) => {
    if (destination !== target) return rename(source, destination);
    assert.deepEqual(fs.readFileSync(target), before);
    if (++calls <= 2) throw Object.assign(new Error("synthetic sharing violation"), { code });
    return rename(source, destination);
  });
  for (const kind of ["v3", "queue", "members-leave"]) for (code of ["EPERM", "EACCES", "EBUSY"]) {
    const f = brokerPersistenceFixture(root, kind);
    target = f.filename;
    before = fs.readFileSync(target);
    calls = 0;
    delays.length = 0;
    const result = await f.write();
    assert.equal(calls, 3, `${kind}/${code}`);
    assert.deepEqual(delays, [10, 20], `${kind}/${code}`);
    f.verify(result);
    assert.equal(fs.readdirSync(f.directory).some((name) => name.endsWith(".tmp")), false);
    target = null;
    fs.rmSync(f.directory, { recursive: true });
  }
});

test("broker replacement exhaustion and permanent failures preserve the destination, clean staged files and never confirm an unpersisted leave", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-broker-denied-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rename = fs.renameSync;
  let target;
  let failure;
  let calls = 0;
  const delays = [];
  t.mock.method(Atomics, "wait", (_buffer, _index, _value, timeout) => { delays.push(timeout); return "timed-out"; });
  t.mock.method(fs, "renameSync", (source, destination) => {
    if (destination !== target) return rename(source, destination);
    calls++;
    throw failure;
  });
  for (const kind of ["v3", "queue", "members-leave"]) for (const code of ["EPERM", "EACCES", "EBUSY", "EIO", "ENOSPC"]) {
    const f = brokerPersistenceFixture(root, kind);
    target = f.filename;
    const before = fs.readFileSync(target);
    failure = Object.assign(new Error("synthetic replacement failure"), { code });
    calls = 0;
    delays.length = 0;
    await assert.rejects(async () => f.write(), (error) => kind === "queue"
      ? error.code === "QUEUE_STORAGE_ERROR" && error.statusCode === 500
      : error === failure);
    const retryable = ["EPERM", "EACCES", "EBUSY"].includes(code);
    assert.equal(calls, retryable ? 9 : 1, `${kind}/${code}`);
    assert.deepEqual(delays, retryable ? [10, 20, 40, 80, 160, 200, 200, 200] : []);
    assert.deepEqual(fs.readFileSync(target), before);
    assert.equal(fs.readdirSync(f.directory).some((name) => name.endsWith(".tmp")), false);
    if (kind === "members-leave") {
      const state = JSON.parse(fs.readFileSync(f.storePath));
      assert.equal(state.flocks["owner/team"].leaveReceipts[f.requestId].confirmed, false);
      target = null;
      f.verify(await f.write());
    }
    target = null;
    fs.rmSync(f.directory, { recursive: true });
  }
});

test("broker replacement retries reject intervening writers instead of overwriting concurrent state", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-broker-replace-cas-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rename = fs.renameSync;
  const external = Buffer.from('{"external":"preserve"}');
  let target;
  let calls = 0;
  t.mock.method(Atomics, "wait", () => "timed-out");
  t.mock.method(fs, "renameSync", (source, destination) => {
    if (destination !== target) return rename(source, destination);
    calls++;
    fs.writeFileSync(target, external);
    throw Object.assign(new Error("synthetic sharing violation"), { code: "EPERM" });
  });
  for (const kind of ["v3", "queue", "members-leave"]) {
    const f = brokerPersistenceFixture(root, kind);
    target = f.filename;
    calls = 0;
    await assert.rejects(async () => f.write(), /Concurrent config change/);
    assert.equal(calls, 1, kind);
    assert.deepEqual(fs.readFileSync(target), external);
    assert.equal(fs.readdirSync(f.directory).some((name) => name.endsWith(".tmp")), false);
    target = null;
  }
  const preReadRoot = path.join(root, "pre-read-race");
  fs.mkdirSync(preReadRoot);
  const leave = brokerPersistenceFixture(preReadRoot, "members-leave");
  const read = fs.readFileSync;
  let observed = false;
  t.mock.method(fs, "readFileSync", (filename, ...args) => {
    const bytes = read(filename, ...args);
    if (filename === leave.filename && !observed) {
      observed = true;
      fs.writeFileSync(leave.filename, external);
    }
    return bytes;
  });
  await assert.rejects(leave.write(), /Concurrent config change/);
  assert.equal(observed, true);
  assert.deepEqual(read(leave.filename), external, "Leave must bind replacement to its pre-read member-registry bytes");
  assert.equal(JSON.parse(read(leave.storePath)).flocks["owner/team"].leaveReceipts[leave.requestId].confirmed, false);
  assert.equal(fs.readdirSync(leave.directory).some((name) => name.endsWith(".tmp")), false);
});

test("broker replacement retries reject parent link swaps and retain displaced staged evidence", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-broker-replace-link-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rename = fs.renameSync;
  let target;
  let directory;
  let retained;
  let outside;
  let calls = 0;
  let displacedTemporary;
  let setupError;
  t.mock.method(Atomics, "wait", () => "timed-out");
  t.mock.method(fs, "renameSync", (source, destination) => {
    if (destination !== target) return rename(source, destination);
    calls++;
    if (calls === 1) {
      try { renameFixtureDirectory(directory, retained, rename); }
      catch (error) { setupError = error; throw error; }
      displacedTemporary = path.join(outside, path.basename(source));
      fs.writeFileSync(displacedTemporary, "external evidence");
      fs.symlinkSync(outside, directory, process.platform === "win32" ? "junction" : "dir");
    }
    throw Object.assign(new Error("synthetic sharing violation"), { code: "EPERM" });
  });
  for (const kind of ["v3", "queue", "members-leave"]) {
    const f = brokerPersistenceFixture(root, kind);
    target = f.filename;
    directory = f.directory;
    retained = `${directory}-retained`;
    outside = `${directory}-outside`;
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, "state.json"), '{"external":"preserve"}');
    const before = fs.readFileSync(target);
    calls = 0;
    setupError = null;
    await assert.rejects(async () => f.write(), /link|junction|escape/);
    assert.ifError(setupError);
    assert.equal(calls, 1, kind);
    assert.equal(fs.readFileSync(displacedTemporary, "utf8"), "external evidence");
    assert.deepEqual(fs.readFileSync(path.join(retained, "state.json")), before);
    assert.equal(JSON.parse(fs.readFileSync(path.join(outside, "state.json"))).external, "preserve");
    assert.ok(fs.readdirSync(retained).some((name) => name.endsWith(".tmp")),
      "Unsafe-path cleanup must not delete displaced staged evidence");
    target = null;
  }
});

test("processed-offline persistence in both entrypoints retries sharing locks and preserves dirty-memory and pre-dispatch failure contracts", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-offline-replace-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rename = fs.renameSync;
  let target;
  let calls = 0;
  let scenario;
  let failure;
  const external = Buffer.from('{"processedIds":["external"]}');
  t.mock.method(Atomics, "wait", () => "timed-out");
  t.mock.method(fs, "renameSync", (source, destination) => {
    if (destination !== target) return rename(source, destination);
    calls++;
    if (scenario === "concurrent") fs.writeFileSync(target, external);
    if (scenario !== "transient" || calls <= 2) throw failure;
    return rename(source, destination);
  });
  for (const filename of ["flock.mjs", "bridge.mjs"]) {
    const runtime = await import(new URL(`../${filename}`, import.meta.url));
    for (const code of ["EPERM", "EACCES", "EBUSY", "EIO", "ENOSPC"]) {
      for (const mode of ["transient", "exhausted", "concurrent"]) {
        scenario = mode;
        target = path.join(root, `${filename}-${code}-${scenario}.json`);
        const before = Buffer.from('{"processedIds":["before"]}');
        fs.writeFileSync(target, before);
        calls = 0;
        failure = Object.assign(new Error("synthetic sharing failure"), { code });
        const input = { processedIds: ["next", "next"], inFlightIds: ["pending"], retainInMemoryOnFailure: false };
        if (scenario === "transient" && ["EPERM", "EACCES", "EBUSY"].includes(code)) {
          runtime.saveProcessedOfflineState(input, target);
          assert.equal(calls, 3);
          assert.deepEqual(runtime.loadProcessedOfflineState(target).processedIds, ["next"]);
        } else {
          assert.throws(() => runtime.saveProcessedOfflineState(input, target),
            (error) => error.code === "OFFLINE_STATE_STORAGE_ERROR" && error.statusCode === 500);
          const retryable = ["EPERM", "EACCES", "EBUSY"].includes(code);
          assert.equal(calls, scenario === "exhausted" && retryable ? 9 : 1);
          assert.deepEqual(fs.readFileSync(target), scenario === "concurrent" ? external : before);
          assert.equal(runtime.loadProcessedOfflineState(target).processedIds.includes("next"), false);
          scenario = "exhausted";
          assert.throws(() => runtime.saveProcessedOfflineState({ processedIds: ["after-dispatch"] }, target),
            (error) => error.code === "OFFLINE_STATE_STORAGE_ERROR");
          assert.ok(runtime.loadProcessedOfflineState(target).processedIds.includes("after-dispatch"));
        }
        assert.equal(fs.readdirSync(root).some((name) => name.endsWith(".tmp")), false);
      }
    }
  }
});

test("NEXUS personal reconciliation never turns account-owned work overviews into device enrollment or downgrades owner roles", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-nexus-roster-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const flocksPath = path.join(root, "flocks.json");
  const device = identity();
  const self = { peerId: `1001:${device.fingerprint}`, githubUser: "owner", githubUserId: 1001,
    deviceId: device.fingerprint, keyFingerprint: device.fingerprint, publicKey: device.publicKey,
    machineId: "NEXUS-V2", scope: "personal", trustTier: "owner" };
  const cfg = { githubUser: "owner", machineId: "NEXUS-V2", scope: "personal", identity: device, flocksConfigPath: flocksPath };
  const record = (flockId, allowedScopes, members, rosterEpoch = 12) => ({
    flockId, flockUuid: `uuid-${flockId}`, flockType: flockId === "owner" ? "owner_root"
      : /\/(?:personal|work)$/.test(flockId) ? "owner_scope" : "shared",
    ownerGitHubUser: "owner", ownerGitHubUserId: 1001, trustTier: "owner",
    allowedScopes, rosterEpoch, members,
  });
  const valid = [record("owner", ["personal", "work"], [self], 11),
    record("owner/personal", ["personal"], [self]), record("owner/personal-team", ["personal"], [self], 13)];
  const incompatible = ["owner/work", "owner/work-team", "owner/japan-stu", "owner/experimental"].map((id) =>
    record(id, ["work"], [{ ...self, peerId: "1001:work-device", deviceId: "work-device",
      machineId: "WORK-PC", scope: "work" }], 17));
  const notEnrolled = record("owner/other-personal", ["personal"], [{ ...self, deviceId: "another-device",
    peerId: "1001:another-device", machineId: "OTHER-PC" }], 18);
  const overview = [...valid, ...incompatible, notEnrolled];
  fs.writeFileSync(flocksPath, JSON.stringify({ ownerGitHubUser: "owner", scope: "personal",
    threadBindings: { approved: "owner/personal-team" }, flocks: Object.fromEntries(overview.map((entry) => [entry.flockId, {
      ...entry, sharedSessionIds: ["approved"], sharedSnapshots: { approved: { summarySnapshot: "keep" } },
      sessionVisibility: entry.flockType === "shared" ? "explicit_opt_in_only" : "all",
    }])) }));
  const registry = openFlockMembershipRegistry(flocksPath);
  registry.reconcileV3Broker({ enrolledFlocks: overview });
  registry.recordRemovalTombstone("owner/work-team", { peerId: "1001:removed-device", machineId: "REMOVED",
    githubUser: "owner", keyFingerprint: "removed-device", removedAtEpoch: 17, reason: "must-not-rewind" });
  const before = registry.read();
  const response = { ok: true, githubUser: "owner", githubUserId: 1001, deviceId: device.fingerprint,
    ownedFlocks: overview.map(({ trustTier, ...entry }) => entry.flockId === "owner/personal-team"
      ? { ...entry, members: entry.members.map((member) => ({ ...member, trustTier: "collaborator" })) } : entry),
    joinedFlocks: valid };
  await resolveLegacyFlockRoster(cfg, { fetchV3MyFlocks: async () => response, fetchLegacyMembers: async () => [] });
  const persisted = JSON.parse(fs.readFileSync(flocksPath, "utf8"));
  assert.deepEqual(Object.keys(persisted.flocks).sort(), valid.map((entry) => entry.flockId).sort());
  for (const entry of valid) {
    assert.equal(persisted.flocks[entry.flockId].trustTier, "owner");
    assert.equal(persisted.flocks[entry.flockId].rosterEpoch, entry.rosterEpoch);
    assert.equal(hasVerifiedOwnerAuthority(persisted.flocks[entry.flockId], {
      githubUser: "owner", githubUserId: 1001, deviceId: device.fingerprint, peerId: self.peerId,
    }), true);
  }
  assert.equal(persisted.threadBindings.approved, "owner/personal-team");
  assert.equal(persisted.flocks["owner/personal-team"].sharedSnapshots.approved.summarySnapshot, "keep");
  assert.deepEqual(registry.listFlockIds(), valid.map((entry) => entry.flockId).sort());
  const after = registry.read();
  for (const entry of [...incompatible, notEnrolled]) {
    assert.deepEqual(after.retainedFlocks[entry.flockId], { ...before.flocks[entry.flockId], presence: {},
      retainedAtMs: after.retainedFlocks[entry.flockId].retainedAtMs, retainedReason: "unenrolled_or_scope_incompatible" },
      "Pruning active enrollment must retain the complete registry floor, tombstones and live state");
  }
  registry.save(before);
  assert.deepEqual(registry.listFlockIds(), valid.map((entry) => entry.flockId).sort(),
    "A stale registry writer must not resurrect pruned enrollment");
  assert.throws(() => registry.reconcileV3BrokerFlock({ ...incompatible[1], rosterEpoch: 16 }),
    (error) => error.code === "ROSTER_ROLLBACK_REJECTED");
  const archived = registry.read();
  const archivedTeam = archived.retainedFlocks["owner/work-team"];
  registry.reconcileV3BrokerFlock(incompatible[1]);
  const restored = registry.read().flocks["owner/work-team"];
  assert.ok(restored.rosterRevision >= archivedTeam.rosterRevision);
  assert.deepEqual(restored.tombstones, archivedTeam.tombstones);
  assert.equal(registry.findActiveMember("owner/work-team", { machineId: "REMOVED" }), null);
  registry.save(archived);
  assert.equal(registry.hasFlock("owner/work-team"), true, "Stale inactive writers cannot undo verified restoration");
  const filename = registry.filename;
  const clean = fs.readFileSync(filename);
  const invalid = JSON.parse(clean);
  invalid.retainedFlocks = [];
  fs.writeFileSync(filename, JSON.stringify(invalid));
  assert.throws(() => registry.read(), (error) => error.code === "ROSTER_CORRUPT_STORE");
  fs.writeFileSync(filename, clean);
  const registryBeforeConcurrent = fs.readFileSync(filename);
  await assert.rejects(resolveLegacyFlockRoster(cfg, {
    fetchV3MyFlocks: async () => {
      const current = JSON.parse(fs.readFileSync(flocksPath));
      current.threadBindings["concurrent-share"] = "owner/personal-team";
      fs.writeFileSync(flocksPath, JSON.stringify(current));
      return response;
    }, fetchLegacyMembers: async () => [],
  }), (error) => error.code === "CONCURRENT_FLOCK_CONFIG_CHANGE");
  assert.equal(JSON.parse(fs.readFileSync(flocksPath)).threadBindings["concurrent-share"], "owner/personal-team");
  assert.deepEqual(fs.readFileSync(filename), registryBeforeConcurrent);
});

test("verified owner reconciliation heals stale revoked root flags without losing epoch floors or accepting revoked authority", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-nexus-owner-heal-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const flocksPath = path.join(root, "flocks.json");
  const device = identity();
  const member = { peerId: `1001:${device.fingerprint}`, githubUser: "owner", githubUserId: 1001,
    deviceId: device.fingerprint, publicKey: device.publicKey, keyFingerprint: device.fingerprint,
    machineId: "NEXUS-V2", scope: "personal", trustTier: "owner" };
  const record = { flockId: "owner", flockUuid: "uuid-root", flockType: "owner_root",
    ownerGitHubUser: "owner", ownerGitHubUserId: 1001, trustTier: "owner",
    rosterEpoch: 11, allowedScopes: ["personal", "work"], members: [member] };
  const auth = { ok: true, githubUser: "owner", githubUserId: 1001, deviceId: device.fingerprint,
    peerId: member.peerId, enrolledFlocks: [record], revokedFlockIds: ["owner"] };
  const cfg = { githubUser: "owner", machineId: "NEXUS-V2", scope: "personal", flocksConfigPath: flocksPath };
  fs.writeFileSync(flocksPath, JSON.stringify({ flocks: { owner: { ...record, revoked: true, membershipStatus: "active",
    members: [{ githubUser: "owner", machineId: "NEXUS-V2", scope: "personal", trustTier: "owner",
      peerId: `owner:${device.fingerprint}` }], sharedSessionIds: ["approved"], sharedSnapshots: { approved: { summarySnapshot: "keep" } } } } }));
  reconcileAuthoritativeFlockMemberships(cfg, auth, flocksPath);
  let healed = JSON.parse(fs.readFileSync(flocksPath, "utf8")).flocks.owner;
  assert.equal(healed.revoked, undefined);
  assert.equal(healed.membershipStatus, "active");
  assert.equal(healed.rosterEpoch, 11);
  assert.equal(healed.sharedSnapshots.approved.summarySnapshot, "keep");
  assert.equal(hasVerifiedOwnerAuthority(healed, auth), true);
  healed.revoked = true;
  fs.writeFileSync(flocksPath, JSON.stringify({ flocks: { owner: healed } }));
  await resolveLegacyFlockRoster({ ...cfg, identity: device }, {
    fetchV3MyFlocks: async () => ({ ...auth, ownedFlocks: [record], joinedFlocks: [record] }),
    fetchLegacyMembers: async () => [{ githubUser: "owner", machineId: "NEXUS-V2",
      scope: "personal", keyFingerprint: device.fingerprint }],
  });
  healed = JSON.parse(fs.readFileSync(flocksPath, "utf8")).flocks.owner;
  assert.equal(healed.revoked, undefined);
  assert.equal(hasVerifiedOwnerAuthority(healed, auth), true, "Sparse legacy registrations must not replace the proven self row");
  const before = fs.readFileSync(flocksPath);
  assert.throws(() => reconcileAuthoritativeFlockMemberships(cfg, { ...auth,
    enrolledFlocks: [{ ...record, rosterEpoch: 10 }] }, flocksPath), (error) => error.code === "STALE_ROSTER_EPOCH");
  assert.deepEqual(fs.readFileSync(flocksPath), before);
  assert.throws(() => reconcileAuthoritativeFlockMemberships(cfg, { ...auth,
    enrolledFlocks: [{ ...record, rosterEpoch: 12, revokedPrincipals: { [member.peerId]: true } }] }, flocksPath),
  (error) => error.code === "REVOKED_AUTHORITY");
  assert.deepEqual(fs.readFileSync(flocksPath), before);
});

test("broker built-in owner healing requires enrolled scope and never revokes the whole owner principal", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-owner-authority-heal-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const storePath = path.join(root, "broker.json");
  const device = identity();
  const request = { githubUser: "owner", githubUserId: 1001, deviceId: device.fingerprint,
    machineId: "NEXUS-V2", scope: "personal", publicKey: device.publicKey, keyFingerprint: device.fingerprint };
  await enrollV3Device(request, { storePath, connectionString: "" });
  let state = JSON.parse(fs.readFileSync(storePath, "utf8"));
  const rootFlock = state.flocks.owner;
  rootFlock.revokedPrincipals = { owner: "stale", "1001": "stale" };
  rootFlock.rosterEpoch = 11;
  state.flocks["owner/work"] = { ...structuredClone(state.flocks["owner/personal"]), flockId: "owner/work",
    flockUuid: "work-uuid", allowedScopes: ["work"] };
  fs.writeFileSync(storePath, JSON.stringify(state));
  const sync = () => syncV3DeviceMemberships({ githubUser: "owner", githubUserId: 1001,
    ...signV3MembershipSyncRequest({ deviceId: device.fingerprint, machineId: "NEXUS-V2" }, device),
    requireSignature: true }, { storePath, connectionString: "" });
  const healed = await sync();
  assert.equal(healed.completeMembershipSnapshot, true);
  assert.ok(healed.enrolledFlocks.some((entry) => entry.flockId === "owner" && entry.trustTier === "owner"));
  assert.equal(healed.enrolledFlocks.some((entry) => entry.flockId === "owner/work"), false);
  state = JSON.parse(fs.readFileSync(storePath, "utf8"));
  assert.equal(state.flocks.owner.revokedPrincipals.owner, undefined);
  assert.equal(state.flocks.owner.revokedPrincipals["1001"], undefined);
  assert.ok(state.flocks.owner.rosterEpoch >= 11);
  const previousMaintainer = process.env.PLATFORM_MAINTAINER_USER;
  try {
    process.env.PLATFORM_MAINTAINER_USER = "owner";
    await kickV3FlockMember({ callerGitHubUser: "owner", callerGitHubUserId: 1001,
      flockId: "owner", targetMachineId: "NEXUS-V2" }, { storePath, connectionString: "" });
    state = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assert.equal(state.flocks.owner.revokedPrincipals.owner, undefined);
    assert.equal(state.flocks.owner.revokedPrincipals["1001"], undefined);
    assert.ok(state.flocks.owner.revokedPrincipals[`1001:${device.fingerprint}`]);
    await enrollV3Device(request, { storePath, connectionString: "" });
    state = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assert.equal(state.flocks.owner.revokedPrincipals[`1001:${device.fingerprint}`], undefined);
    assert.ok((await sync()).enrolledFlocks.some((entry) => entry.flockId === "owner"));
  } finally {
    if (previousMaintainer === undefined) delete process.env.PLATFORM_MAINTAINER_USER;
    else process.env.PLATFORM_MAINTAINER_USER = previousMaintainer;
  }
});

test("retained signed snapshots preserve version and owner pins across stale writers and explicit restoration", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-retained-snapshot-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const registry = openFlockMembershipRegistry(path.join(root, "flocks.json"));
  const owner = identity();
  const sign = (epoch, revision, signer = owner) => createSignedRosterSnapshot({
    flockId: "owner/signed", ownerIdentity: { ed25519: signer }, epoch, revision, members: [],
  });
  const snapshot = sign(4, 8);
  registry.applySignedSnapshot(snapshot, { ownerPublicKey: owner.publicKey });
  const before = registry.read();
  const expectedHash = before.flocks["owner/signed"].rosterHash;
  registry.retainFlocks(["owner/signed"]);
  registry.save(before);
  assert.equal(registry.hasFlock("owner/signed"), false);
  assert.equal(registry.findActiveMember("owner/signed", { machineId: "ANY" }), null);
  assert.throws(() => registry.applySignedSnapshot(sign(3, 9), { ownerPublicKey: owner.publicKey }),
    (error) => error.code === "ROSTER_ROLLBACK_REJECTED");
  const imposter = identity();
  assert.throws(() => registry.applySignedSnapshot(sign(5, 1, imposter), { ownerPublicKey: imposter.publicKey }),
    (error) => error.code === "ROSTER_OWNER_MISMATCH");
  registry.applySignedSnapshot(snapshot, { ownerPublicKey: owner.publicKey });
  assert.equal(registry.hasFlock("owner/signed"), true);
  assert.equal(registry.read().flocks["owner/signed"].rosterHash, expectedHash);
});

test("only explicit complete snapshots with local device proof prune memberships; partial enroll and old broker responses stay additive", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-complete-snapshot-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "flocks.json");
  const key = identity();
  const member = { githubUser: "owner", githubUserId: 1001, deviceId: key.fingerprint,
    peerId: `1001:${key.fingerprint}`, publicKey: key.publicKey, keyFingerprint: key.fingerprint,
    machineId: "OWNER-PC", scope: "work", trustTier: "owner" };
  const owner = { flockId: "owner", flockUuid: "uuid-root", flockType: "owner_root", ownerGitHubUser: "owner",
    ownerGitHubUserId: 1001, allowedScopes: ["personal", "work"], rosterEpoch: 5, trustTier: "owner", members: [member] };
  const collaborator = { ...owner, flockId: "alice/team-one", flockUuid: "uuid-one", flockType: "shared",
    ownerGitHubUser: "alice", ownerGitHubUserId: 2002, trustTier: "collaborator",
    members: [{ ...member, trustTier: "collaborator" }] };
  const guest = { ...collaborator, flockId: "alice/team-two", flockUuid: "uuid-two", trustTier: "guest",
    membershipExpiresAtMs: Date.now() + 600000, members: [{ ...member, trustTier: "guest" }] };
  const cfg = { githubUser: "owner", machineId: "OWNER-PC", scope: "work", identity: key, flocksConfigPath: file };
  const response = (entries, marker) => ({ ok: true, githubUser: "owner", githubUserId: 1001, deviceId: key.fingerprint,
    peerId: member.peerId, enrolledFlocks: entries.map((entry) => ({ ...entry,
      endpoint: "https://fixture.service.signalr.net", clientToken: "fixture-token",
      tokenExpiresAt: new Date(Date.now() + 600000).toISOString() })),
    ...(marker === undefined ? {} : { completeMembershipSnapshot: marker }) });
  applyV3EnrollmentResult(cfg, response([owner, collaborator], false), file);
  applyV3EnrollmentResult(cfg, response([owner, guest], false), file);
  applyV3EnrollmentResult(cfg, response([owner]), file);
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(file)).flocks).filter((id) => !id.endsWith("/work")).sort(),
    ["alice/team-one", "alice/team-two", "owner"]);
  const registry = openFlockMembershipRegistry(file);
  assert.ok(registry.hasFlock(collaborator.flockId));
  assert.ok(registry.hasFlock(guest.flockId));
  assert.ok(loadFlockCredentialVault(file).credentials[collaborator.flockId]);
  const before = fs.readFileSync(file);
  assert.throws(() => reconcileAuthoritativeFlockMemberships(cfg, response([owner], true), file,
    { requireMemberProof: false }), (error) => error.code === "UNVERIFIED_AUTHORITY");
  assert.throws(() => reconcileAuthoritativeFlockMemberships(cfg,
    { ...response([owner], true), deviceId: "other-device", peerId: "1001:other-device" }, file),
  (error) => error.code === "UNVERIFIED_AUTHORITY");
  assert.deepEqual(fs.readFileSync(file), before);
  await syncFlockMemberships(cfg, { customPath: file, identityKeypair: key,
    callEndpoint: async (_cfg, endpoint) => endpoint === "/capabilities"
      ? { ok: true, capabilities: { rosterSync: true, tokenLocalDeviceAuth: true,
        deviceSignedOperations: true, scopedSignalRTransportTokens: true } }
      : response([owner], true) });
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(file)).flocks), ["owner"]);
  assert.deepEqual(registry.listFlockIds(), ["owner"]);
  assert.ok(registry.read().retainedFlocks[collaborator.flockId]);
  assert.ok(registry.read().retainedFlocks[guest.flockId]);
  assert.equal(loadFlockCredentialVault(file).credentials[collaborator.flockId], undefined);
  assert.equal(loadFlockCredentialVault(file).credentials[guest.flockId], undefined);
});

test("NEXUS actual list_flocks reconcile keeps signed sync authoritative over account-wide HTTPS overview", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-nexus-https-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  const device = identity();
  const work = identity();
  const storePath = path.join(root, "broker.json");
  const connectionString = "Endpoint=https://fixture.service.signalr.net;AccessKey=fixture-key;Version=1.0;";
  const request = (key, machineId, scope) => ({ githubUser: "owner", githubUserId: 1001,
    deviceId: key.fingerprint, machineId, scope, publicKey: key.publicKey, keyFingerprint: key.fingerprint });
  await enrollV3Device(request(device, "NEXUS-V2", "personal"), { storePath, connectionString });
  await enrollV3Device(request(work, "WORK-PC", "work"), { storePath, connectionString });
  for (const name of ["work-team", "japan-stu", "experimental"]) {
    await createV3FlockInvite({ callerGitHubUser: "owner", callerGitHubUserId: 1001,
      targetAddress: `owner/${name}`, invitedUser: "alice", invitedGitHubUserId: 2002, allowedScopes: ["work"] }, { storePath });
  }
  const overview = await listV3UserFlocks({ githubUser: "owner", githubUserId: 1001 }, { storePath });
  assert.equal(overview.completeMembershipSnapshot, false);
  const enrollment = await enrollV3Device(request(device, "NEXUS-V2", "personal"), { storePath, connectionString });
  assert.equal(enrollment.completeMembershipSnapshot, false);
  const inputPath = path.join(root, "input.json");
  fs.writeFileSync(inputPath, JSON.stringify({ device, overview, enrollment }));
  const tls = createTlsFixture(root);
  const broker = createBootstrapServer({ v3StorePath: storePath, membersPath: path.join(root, "members.json"),
    apiGet: async () => { throw Error("Unexpected GitHub credential request"); } });
  const paths = [];
  const server = https.createServer(tls, (req, res) => {
    paths.push(req.url);
    broker.listeners("request")[0](req, res);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const origin = `https://127.0.0.1:${server.address().port}`;
  const home = path.join(root, "isolated-home");
  fs.mkdirSync(path.join(home, "flock"), { recursive: true, mode: 0o700 });
  const moduleUrl = new URL("../flock.mjs", import.meta.url).href;
  const child = spawn(process.execPath, ["--input-type=module", "-e", `
import fs from "node:fs";import path from "node:path";import assert from "node:assert/strict";
import {applyV3EnrollmentResult,executeMcpTool,openFlockMembershipRegistry} from ${JSON.stringify(moduleUrl)};
const data=JSON.parse(fs.readFileSync(${JSON.stringify(inputPath)}));
const file=path.join(process.env.COPILOT_HOME,"flock","flocks.json");
fs.writeFileSync(path.join(path.dirname(file),"identity.json"),JSON.stringify(data.device));
const cfg={githubUser:"owner",machineId:"NEXUS-V2",scope:"personal",tokenLocalAuth:true,
 bootstrapUrl:${JSON.stringify(origin + "/api/bootstrap")},flocksConfigPath:file};
applyV3EnrollmentResult(cfg,data.enrollment,file);
const stored=JSON.parse(fs.readFileSync(file));
for(const entry of data.overview.ownedFlocks)if(entry.flockId!=="owner"&&entry.flockId!=="owner/personal")stored.flocks[entry.flockId]={...entry,trustTier:"collaborator"};
stored.flocks.owner.revoked=true;
fs.writeFileSync(file,JSON.stringify(stored));
openFlockMembershipRegistry(file).reconcileV3Broker({myFlocksResponse:data.overview});
const result=await executeMcpTool(cfg,"list_flocks",{reconcile:true,full:true});
const persisted=JSON.parse(fs.readFileSync(file));
assert.deepEqual(Object.keys(persisted.flocks).sort(),["owner","owner/personal"]);
assert.equal(persisted.flocks.owner.revoked,undefined);
assert.equal(persisted.flocks.owner.trustTier,"owner");
assert.deepEqual(openFlockMembershipRegistry(file).listFlockIds(),["owner","owner/personal"]);
assert.deepEqual(result.flocks.map(entry=>entry.flockId).sort(),["owner","owner/personal"]);
process.stdout.write(JSON.stringify({persistedIds:Object.keys(persisted.flocks),registryIds:openFlockMembershipRegistry(file).listFlockIds()}));
`], { windowsHide: true, env: { ...process.env, COPILOT_HOME: home, COPILOT_CLI_PATH: "",
    HOME: root, USERPROFILE: root, APPDATA: path.join(root, "AppData"), LOCALAPPDATA: path.join(root, "LocalAppData"),
    NODE_OPTIONS: "", NODE_PATH: "", NODE_EXTRA_CA_CERTS: tls.certPath, COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN: origin },
    stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill(); });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
  assert.equal(code, 0, `${stdout}\n${stderr}`);
  assert.deepEqual(JSON.parse(stdout).registryIds, ["owner", "owner/personal"]);
  assert.ok(paths.some((url) => url.includes(`/my-flocks?deviceId=${device.fingerprint}`)));
});

test("3.6 authoritative registry closes split-brain and pins peer keys by exact flock", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-roster-"));
  const flocksPath = path.join(root, "flocks.json");
  const alice = identity();
  const collision = identity();
  try {
    fs.writeFileSync(flocksPath, JSON.stringify({
      flocks: {
        "owner/team": {
          flockId: "owner/team",
          ownerGitHubUser: "owner",
          trustTier: "collaborator",
          rosterEpoch: 3,
          sessionVisibility: "explicit_opt_in_only",
          members: [],
        },
        "other/team": {
          flockId: "other/team",
          ownerGitHubUser: "other",
          trustTier: "collaborator",
          rosterEpoch: 9,
          sessionVisibility: "explicit_opt_in_only",
          members: [],
        },
      },
    }));
    const registry = openFlockMembershipRegistry(flocksPath);
    registry.reconcileV3BrokerFlock({
      flockId: "owner/team",
      ownerGitHubUser: "owner",
      rosterEpoch: 4,
      members: [{
        peerId: "2002:alice-device",
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: "alice-device",
        keyFingerprint: "alice-device",
        machineId: "JAPAN-STU",
        scope: "work",
        trustTier: "collaborator",
        publicKey: alice.publicKey,
      }],
    });
    registry.reconcileV3BrokerFlock({
      flockId: "other/team",
      ownerGitHubUser: "other",
      rosterEpoch: 9,
      members: [{
        peerId: "3003:collision-device",
        githubUser: "mallory",
        githubUserId: 3003,
        deviceId: "collision-device",
        keyFingerprint: "collision-device",
        machineId: "JAPAN-STU",
        scope: "work",
        trustTier: "collaborator",
        publicKey: collision.publicKey,
      }],
    });

    const params = { flock: "owner/team" };
    const request = signedRequest({
      key: alice,
      machineId: "JAPAN-STU",
      action: "ping",
      params,
    });
    const result = await handleRpcAction(
      { machineId: "LOCAL", githubUser: "owner", scope: "work", flocksConfigPath: flocksPath },
      { ...request, flocksConfigPath: flocksPath }
    );
    assert.equal(result.machineId, "LOCAL");
    assert.equal(registry.findActiveMember("owner/team", { machineId: "JAPAN-STU" }).githubUser, "alice");
    assert.equal(registry.findActiveMember("other/team", { machineId: "JAPAN-STU" }).githubUser, "mallory");

    const forged = signedRequest({
      key: collision,
      machineId: "JAPAN-STU",
      action: "ping",
      params,
    });
    await assert.rejects(
      () => handleRpcAction(
        { machineId: "LOCAL", githubUser: "owner", scope: "work", flocksConfigPath: flocksPath },
        { ...forged, flocksConfigPath: flocksPath }
      ),
      /public key mismatch|signature verification failed/i
    );

    registry.reconcileV3BrokerFlock({
      flockId: "owner/team",
      ownerGitHubUser: "owner",
      rosterEpoch: 5,
      members: [],
    });
    assert.equal(registry.findActiveMember("owner/team", { machineId: "JAPAN-STU" }), null);
    assert.throws(
      () => registry.reconcileV3BrokerFlock({
        flockId: "owner/team",
        ownerGitHubUser: "owner",
        rosterEpoch: 4,
        members: [],
      }),
      (error) => error.code === "ROSTER_ROLLBACK_REJECTED"
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 membership sync capability preflight is bounded and single-flight", async () => {
  const key = identity();
  const cfg = { machineId: "LOCAL", bootstrapUrl: "https://broker.invalid/api/bootstrap" };
  await assert.rejects(
    () => syncFlockMemberships(cfg, {
      identityKeypair: key,
      callEndpoint: async (_cfg, subPath) => subPath === "/capabilities"
        ? { ok: true, capabilities: { rosterSync: false, tokenLocalDeviceAuth: true, deviceSignedOperations: true } }
        : { ok: true },
    }),
    (error) => error.code === "BROKER_CAPABILITY_UNSUPPORTED" && error.stage === "broker_capability"
  );

  let capabilityCalls = 0;
  let syncCalls = 0;
  const callEndpoint = async (_cfg, subPath) => {
    if (subPath === "/capabilities") {
      capabilityCalls++;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return {
        ok: true,
        capabilities: {
          rosterSync: true,
          tokenLocalDeviceAuth: true,
          deviceSignedOperations: true,
          scopedSignalRTransportTokens: true,
        },
      };
    }
    syncCalls++;
    return { ok: false, code: "SYNTHETIC_SYNC_FAILURE", error: "synthetic sync failure" };
  };
  const attempts = await Promise.allSettled([
    syncFlockMemberships(cfg, { identityKeypair: key, callEndpoint }),
    syncFlockMemberships(cfg, { identityKeypair: key, callEndpoint }),
  ]);
  assert.equal(capabilityCalls, 1);
  assert.equal(syncCalls, 1);
  assert.ok(attempts.every((attempt) => attempt.status === "rejected"));
  assert.ok(attempts.every((attempt) => attempt.reason.code === "SYNTHETIC_SYNC_FAILURE"));
});

test("3.6 token-local REST refresh and sync stay bound to the actual shared flock", async () => {
  const calls = [];
  const cfg = {
    tokenLocalAuth: true,
    credentialFlockId: "owner/root",
    flockId: "owner/root",
    clientToken: "client",
    credentialExpiresAt: Date.now() + 60000,
    restTokens: { broadcast: null, users: {} },
  };
  await ensureTokenLocalTransportCredentials(cfg, {
    targetUserId: "REMOTE-PC",
    flockId: "owner/shared-team",
    refreshFn: async (_cfg, options) => {
      calls.push(["refresh", options.flockId]);
    },
    syncFn: async (_cfg, options) => {
      calls.push(["sync", options.flockId]);
      cfg.restTokens.users["REMOTE-PC"] = { token: "scoped" };
    },
  });

  assert.deepEqual(calls, [
    ["refresh", "owner/shared-team"],
    ["sync", "owner/shared-team"],
    ["refresh", "owner/shared-team"],
  ]);
});

test("3.6 credential vault rotation clears expired scoped tokens but retains refresh identity", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-vault-cleanup-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const flocksPath = path.join(root, "flocks.json");
  fs.writeFileSync(path.join(root, "flock-credentials.json"), JSON.stringify({
    type: "copilot-flock-token-local-credentials-v1",
    credentials: {
      "owner/team": {
        flockId: "owner/team",
        clientToken: "expired-client",
        bearerToken: "expired-bearer",
        restTokens: { broadcast: { token: "expired-broadcast" }, users: { PC: { token: "expired-user" } } },
        credentialExpiresAtMs: 1000,
        serverNonce: "retain-for-refresh",
      },
    },
  }));
  const cleaned = cleanupFlockCredentialVault(flocksPath, { now: 2000 });
  assert.equal(cleaned.changed, true);
  const entry = cleaned.vault.credentials["owner/team"];
  assert.equal(entry.clientToken, null);
  assert.deepEqual(entry.restTokens, { broadcast: null, users: {} });
  assert.equal(entry.serverNonce, "retain-for-refresh");
});

test("3.6 owner second workstation readiness uses positive assertions and shared-flock backfill", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-owner-backfill-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const storePath = path.join(root, "broker.json");
  const first = identity();
  const second = identity();
  await enrollV3Device({
    githubUser: "owner",
    githubUserId: 1001,
    deviceId: first.fingerprint,
    machineId: "OWNER-PC-1",
    scope: "work",
    publicKey: first.publicKey,
    keyFingerprint: first.fingerprint,
  }, { storePath, connectionString: "" });
  await createV3FlockInvite({
    callerGitHubUser: "owner",
    callerGitHubUserId: 1001,
    targetAddress: "owner/shared-team",
    invitedUser: "alice",
    invitedGitHubUserId: 2002,
    allowedScopes: ["work"],
  }, { storePath });
  const enrolled = await enrollV3Device({
    githubUser: "owner",
    githubUserId: 1001,
    deviceId: second.fingerprint,
    machineId: "OWNER-PC-2",
    scope: "work",
    publicKey: second.publicKey,
    keyFingerprint: second.fingerprint,
  }, { storePath, connectionString: "" });
  assert.ok(enrolled.enrolledFlocks.some((flock) => flock.flockId === "owner/shared-team"));
  const stored = JSON.parse(fs.readFileSync(storePath, "utf8"));
  const shared = stored.flocks["owner/shared-team"];
  assert.equal(Object.values(shared.members).some((member) => member.machineId === "OWNER-PC-2"), true);
  assert.equal(shared.sessionVisibility, undefined);

  for (const [memberKey, member] of Object.entries(shared.members)) {
    if (member.machineId === "OWNER-PC-2") delete shared.members[memberKey];
  }
  fs.writeFileSync(storePath, JSON.stringify(stored, null, 2));
  const synced = await syncV3DeviceMemberships({
    githubUser: "owner",
    githubUserId: 1001,
    deviceId: second.fingerprint,
    machineId: "OWNER-PC-2",
  }, { storePath, connectionString: "" });
  assert.ok(synced.enrolledFlocks.some((flock) => flock.flockId === "owner/shared-team"));
  const afterSync = JSON.parse(fs.readFileSync(storePath, "utf8"));
  assert.equal(
    Object.values(afterSync.flocks["owner/shared-team"].members)
      .some((member) => member.machineId === "OWNER-PC-2" && member.trustTier === "owner"),
    true
  );

  const ownerScope = enrolled.enrolledFlocks.find((flock) => flock.flockId === "owner/work");
  const readiness = await verifyEnrollmentReadiness(
    { machineId: "OWNER-PC-2", githubUser: "owner", scope: "work" },
    [ownerScope],
    {
      correlationId: "owner-second-pc",
      invokeRpc: async () => ({
        result: {
          enrollmentReadinessAck: {
            correlationId: "owner-second-pc",
            flockId: ownerScope.flockId,
            rosterEpoch: ownerScope.rosterEpoch,
          },
        },
      }),
    }
  );
  assert.equal(readiness.ready, true);
  assert.equal(readiness.policyAssertions.mode, "owner_positive_assertions");
});

test("3.6 first contact auto-syncs once on an unpinned explicit-flock peer and retries", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-first-contact-"));
  const flocksPath = path.join(root, "flocks.json");
  const newcomer = identity();
  try {
    fs.writeFileSync(flocksPath, JSON.stringify({
      flocks: {
        "owner/japan-team": {
          flockId: "owner/japan-team",
          ownerGitHubUser: "owner",
          trustTier: "collaborator",
          rosterEpoch: 3,
          sessionVisibility: "explicit_opt_in_only",
          members: [],
        },
      },
    }));
    let syncCalls = 0;
    const cfg = {
      machineId: "LOCAL",
      githubUser: "owner",
      scope: "work",
      flocksConfigPath: flocksPath,
      syncFlockMembershipsFn: async () => {
        syncCalls++;
        openFlockMembershipRegistry(flocksPath).reconcileV3BrokerFlock({
          flockId: "owner/japan-team",
          ownerGitHubUser: "owner",
          rosterEpoch: 4,
          members: [{
            peerId: "4004:japan-device",
            githubUser: "newcomer",
            githubUserId: 4004,
            deviceId: "japan-device",
            keyFingerprint: "japan-device",
            machineId: "JAPAN-STU",
            scope: "work",
            trustTier: "collaborator",
            publicKey: newcomer.publicKey,
          }],
        });
        return { ok: true, reconciledFlockIds: ["owner/japan-team"] };
      },
    };
    const request = signedRequest({
      key: newcomer,
      machineId: "JAPAN-STU",
      action: "ping",
      params: { flock: "owner/japan-team" },
    });
    const result = await handleRpcAction(cfg, { ...request, flocksConfigPath: flocksPath });
    assert.equal(result.machineId, "LOCAL");
    assert.equal(syncCalls, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 voucher reissue separates redemption lifetime, membership duration, replay, and expiry", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-voucher-"));
  const storePath = path.join(root, "broker.json");
  const invited = identity();
  try {
    const first = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "alice",
      invitedGitHubUserId: 2002,
      allowedScopes: ["work"],
      durationMinutes: 60,
      trustTier: "guest",
    }, { storePath });
    assert.equal(first.enrollmentJson.remainingRedemptionLifetimeSeconds, 86400);
    assert.equal(first.enrollmentJson.membershipDurationMinutes, 60);

    const replacement = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "alice",
      invitedGitHubUserId: 2002,
      allowedScopes: ["work"],
      trustTier: "collaborator",
      reissue: true,
    }, { storePath });
    assert.deepEqual(replacement.supersededVoucherIds, [first.voucherId]);
    assert.equal(replacement.enrollmentJson.remainingRedemptionLifetimeSeconds, 259200);

    const firstGuest = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/work/HOST-PC",
      invitedUser: "carol",
      invitedGitHubUserId: 4004,
      durationMinutes: 30,
    }, { storePath });
    const reissuedGuest = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/work/HOST-PC",
      invitedUser: "carol",
      invitedGitHubUserId: 4004,
      durationMinutes: 30,
      reissue: true,
    }, { storePath });
    assert.notEqual(firstGuest.flockId, reissuedGuest.flockId);
    assert.ok(reissuedGuest.supersededVoucherIds.includes(firstGuest.voucherId));
    const missingSecret = structuredClone(replacement.enrollmentJson);
    delete missingSecret.flocks[0].voucherSecret;
    await assert.rejects(
      () => enrollV3Device({
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: invited.fingerprint,
        machineId: "ALICE-PC",
        scope: "work",
        publicKey: invited.publicKey,
        keyFingerprint: invited.fingerprint,
        enrollmentJson: missingSecret,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_SECRET_REQUIRED"
    );

    await assert.rejects(
      () => enrollV3Device({
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: invited.fingerprint,
        machineId: "ALICE-PC",
        scope: "work",
        publicKey: invited.publicKey,
        keyFingerprint: invited.fingerprint,
        enrollmentJson: first.enrollmentJson,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_SUPERSEDED"
    );

    const enrolled = await enrollV3Device({
      githubUser: "alice",
      githubUserId: 2002,
      deviceId: invited.fingerprint,
      machineId: "ALICE-PC",
      scope: "work",
      publicKey: invited.publicKey,
      keyFingerprint: invited.fingerprint,
      enrollmentJson: replacement.enrollmentJson,
    }, { storePath, connectionString: "" });
    assert.ok(enrolled.enrolledFlocks.some((flock) => flock.flockId === "owner/team"));

    const replayKey = identity();
    await assert.rejects(
      () => enrollV3Device({
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: invited.fingerprint,
        machineId: "ALICE-PC",
        scope: "work",
        publicKey: replayKey.publicKey,
        keyFingerprint: invited.fingerprint,
        enrollmentJson: replacement.enrollmentJson,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_REPLAY"
    );

    const expired = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "bob",
      invitedGitHubUserId: 3003,
      voucherTtlSeconds: 60,
    }, { storePath });
    const state = JSON.parse(fs.readFileSync(storePath, "utf8"));
    state.flocks["owner/team"].vouchers[expired.voucherId].voucherExpiresAtMs = Date.now() - 1;
    fs.writeFileSync(storePath, JSON.stringify(state));
    const bob = identity();
    await assert.rejects(
      () => enrollV3Device({
        githubUser: "bob",
        githubUserId: 3003,
        deviceId: bob.fingerprint,
        machineId: "BOB-PC",
        scope: "work",
        publicKey: bob.publicKey,
        keyFingerprint: bob.fingerprint,
        enrollmentJson: expired.enrollmentJson,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_EXPIRED"
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 token-local enrollment rejects master SignalR AccessKey persistence", () => {
  assert.throws(
    () => applyV3EnrollmentResult(
      { tokenLocalAuth: true },
      {
        ok: true,
        connectionString: "Endpoint=https://example.invalid;AccessKey=secret;Version=1.0;",
        enrolledFlocks: [],
      }
    ),
    (error) => error.code === "MASTER_CREDENTIAL_EXPOSURE_REJECTED"
  );
});

test("3.6 broker advertises capabilities and never returns a master AccessKey to voucher enrollment", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-http-enroll-"));
  const storePath = path.join(root, "broker.json");
  const membersPath = path.join(root, "members.json");
  const invited = identity();
  const previousConnection = process.env.SIGNALR_CONNECTION_STRING;
  process.env.SIGNALR_CONNECTION_STRING =
    "Endpoint=https://example.service.signalr.net;AccessKey=master-secret;Version=1.0;";
  const server = createBootstrapServer({
    v3StorePath: storePath,
    v3PreviewStorePath: path.join(root, "preview.json"),
    membersPath,
  });
  try {
    const invite = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "alice",
      invitedGitHubUserId: 2002,
      allowedScopes: ["work"],
    }, { storePath });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    const capabilities = await fetch(`http://127.0.0.1:${port}/api/v3/capabilities`).then((res) => res.json());
    assert.equal(capabilities.capabilities.rosterSync, true);
    assert.equal(capabilities.capabilities.tokenLocalDeviceAuth, true);

    const body = signV3EnrollmentRequest({
      deviceId: invited.fingerprint,
      machineId: "ALICE-PC",
      scope: "work",
      publicKey: invited.publicKey,
      keyFingerprint: invited.fingerprint,
      enrollmentJson: invite.enrollmentJson,
      maintainerVisibilityAck: true,
    }, 2002, invited);
    const response = await fetch(`http://127.0.0.1:${port}/api/v3/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    assert.equal(response.status, 200);
    assert.equal(result.ok, true);
    assert.equal(result.connectionString, undefined);
    assert.doesNotMatch(JSON.stringify(result), /AccessKey=|master-secret/);
    const shared = result.enrolledFlocks.find((flock) => flock.flockId === "owner/team");
    assert.equal(shared.transportHub, "copilotbridge");
    assert.equal(
      decodeJwtPayload(shared.clientToken).aud,
      "https://example.service.signalr.net/client/?hub=copilotbridge"
    );
    assert.equal(
      decodeJwtPayload(shared.restTokens.broadcast.token).aud,
      "https://example.service.signalr.net/api/v1/hubs/copilotbridge"
    );
    assert.equal(
      decodeJwtPayload(shared.restTokens.users["ALICE-PC"].token).aud,
      "https://example.service.signalr.net/api/v1/hubs/copilotbridge/users/ALICE-PC"
    );
    const flocksPath = path.join(root, "flocks.json");
    const applied = applyV3EnrollmentResult(
      {
        tokenLocalAuth: true,
        githubUser: "alice",
        machineId: "ALICE-PC",
        scope: "work",
      },
      result,
      flocksPath
    );
    assert.ok(applied.enrolledFlocks.every((flock) => !flock.hubToken && !flock.serverNonce));
    const persistedPolicy = fs.readFileSync(flocksPath, "utf8");
    assert.doesNotMatch(persistedPolicy, /master-secret|hubToken|serverNonce/);
    const vault = JSON.parse(fs.readFileSync(path.join(root, "flock-credentials.json"), "utf8"));
    assert.ok(Object.values(vault.credentials).some((entry) => entry.clientToken));
    assert.ok(Object.values(vault.credentials).some((entry) => entry.restTokens?.broadcast?.token));
    assert.doesNotMatch(JSON.stringify(vault), /AccessKey=|master-secret/);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    if (previousConnection === undefined) delete process.env.SIGNALR_CONNECTION_STRING;
    else process.env.SIGNALR_CONNECTION_STRING = previousConnection;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 token-local config and MCP load from the vault without a connection string", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-config-vault-"));
  const flockHome = path.join(root, "flock");
  fs.mkdirSync(flockHome, { recursive: true });
  const expiresAt = new Date(Date.now() + 3600000).toISOString();
  fs.writeFileSync(path.join(flockHome, "config.json"), JSON.stringify({
    machineId: "TOKEN-LOCAL-PC",
    githubUser: "alice",
    scope: "work",
    tokenLocalAuth: true,
    bootstrapUrl: "https://bootstrap.example.invalid/api/bootstrap",
    connectionString:
      "Endpoint=https://wrong.service.signalr.net;AccessKey=must-not-load;Version=1.0;",
  }));
  fs.writeFileSync(path.join(flockHome, "flocks.json"), JSON.stringify({ flocks: {} }));
  fs.writeFileSync(path.join(flockHome, "flock-credentials.json"), JSON.stringify({
    type: "copilot-flock-token-local-credentials-v1",
    credentials: {
      "owner/team": {
        flockId: "owner/team",
        flockUuid: "team-uuid",
        endpoint: "https://example.service.signalr.net",
        hubName: "copilotbridge",
        clientToken: "header.payload.signature",
        restTokens: {
          broadcast: { token: "broadcast-token" },
          users: { REMOTE: { token: "remote-token" } },
        },
        tokenExpiresAt: expiresAt,
        credentialExpiresAtMs: Date.parse(expiresAt),
        serverNonce: "nonce",
        rosterEpoch: 4,
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: "device",
        machineId: "TOKEN-LOCAL-PC",
      },
    },
  }));
  try {
    const moduleUrl = pathToFileURL(path.resolve("flock.mjs")).href;
    const script = `
      const m = await import(${JSON.stringify(moduleUrl)});
      const cfg = m.loadConfig({ autoFetchAz: false });
      const self = await m.executeMcpTool(cfg, "mcp_self_info");
      process.stdout.write(JSON.stringify({
        machineId: cfg.machineId,
        connectionString: cfg.connectionString,
        accessKey: cfg.accessKey,
        endpoint: cfg.endpoint,
        hub: cfg.hub,
        clientToken: cfg.clientToken,
        restTarget: cfg.restTokens.users.REMOTE.token,
        mcpLoaded: Boolean(self && typeof self === "object")
      }));
    `;
    const output = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
      env: {
        ...process.env,
        COPILOT_HOME: root,
        SIGNALR_CONNECTION_STRING:
          "Endpoint=https://wrong-env.service.signalr.net;AccessKey=must-not-load-env;Version=1.0;",
        COPILOT_FLOCK_TOKEN_LOCAL: "1",
        COPILOT_FLOCK_SANDBOX: "",
        COPILOT_BRIDGE_SANDBOX: "",
      },
    }));
    assert.deepEqual(output, {
      machineId: "TOKEN-LOCAL-PC",
      connectionString: null,
      accessKey: null,
      endpoint: "https://example.service.signalr.net",
      hub: "copilotbridge",
      clientToken: "header.payload.signature",
      restTarget: "remote-token",
      mcpLoaded: true,
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 all v3 paths vault credentials and reconcile empty, revoked, and expired rosters", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-empty-rosters-"));
  const flocksPath = path.join(root, "flocks.json");
  const key = identity();
  const cfg = {
    githubUser: "alice",
    machineId: "ALICE-PC",
    scope: "work",
    flocksConfigPath: flocksPath,
  };
  const member = {
    peerId: `2002:${key.fingerprint}`,
    githubUser: "alice",
    githubUserId: 2002,
    deviceId: key.fingerprint,
    keyFingerprint: key.fingerprint,
    machineId: "ALICE-PC",
    scope: "work",
    trustTier: "collaborator",
    publicKey: key.publicKey,
  };
  const record = (flockId) => ({
    flockId,
    flockUuid: `${flockId}-uuid`,
    flockType: "shared",
    ownerGitHubUser: "owner",
    ownerGitHubUserId: 1001,
    trustTier: "collaborator",
    rosterEpoch: 1,
    members: [member],
    hubToken: "legacy-client-token",
    clientToken: "client-token",
    restTokens: { broadcast: { token: "rest-token" }, users: {} },
    serverNonce: "nonce",
    endpoint: "https://example.service.signalr.net",
    tokenExpiresAt: new Date(Date.now() + 3600000).toISOString(),
  });
  try {
    applyV3EnrollmentResult(cfg, {
      ok: true,
      githubUser: "alice",
      githubUserId: 2002,
      deviceId: key.fingerprint,
      machineId: "ALICE-PC",
      enrolledFlocks: [
        record("owner/empty"),
        record("owner/revoked"),
        record("owner/expired"),
      ],
    }, flocksPath);
    const rawPolicy = fs.readFileSync(flocksPath, "utf8");
    assert.doesNotMatch(rawPolicy, /client-token|rest-token|serverNonce|hubToken|restTokens/);
    const vault = loadFlockCredentialVault(flocksPath);
    assert.equal(vault.credentials["owner/empty"].clientToken, "client-token");

    applyV3EnrollmentResult(cfg, {
      ok: true,
      githubUser: "alice",
      githubUserId: 2002,
      deviceId: key.fingerprint,
      machineId: "ALICE-PC",
      enrolledFlocks: [{
        ...record("owner/empty"),
        rosterEpoch: 2,
        members: [],
        hubToken: null,
        clientToken: null,
        restTokens: null,
        serverNonce: null,
      }],
      revokedFlockIds: ["owner/revoked"],
      expiredFlockIds: ["owner/expired"],
      revokedFlockSummaries: [{
        ...record("owner/revoked"),
        rosterEpoch: 2,
        members: [],
        hubToken: null,
        clientToken: null,
        restTokens: null,
        serverNonce: null,
      }],
      expiredFlockSummaries: [{
        ...record("owner/expired"),
        rosterEpoch: 2,
        members: [],
        hubToken: null,
        clientToken: null,
        restTokens: null,
        serverNonce: null,
      }],
    }, flocksPath);

    const registry = openFlockMembershipRegistry(flocksPath);
    for (const flockId of ["owner/empty", "owner/revoked", "owner/expired"]) {
      assert.equal(registry.findActiveMember(flockId, { machineId: "ALICE-PC" }), null);
    }
    const policy = JSON.parse(fs.readFileSync(flocksPath, "utf8")).flocks;
    assert.equal(policy["owner/revoked"], undefined);
    assert.equal(policy["owner/expired"], undefined);
    assert.ok(registry.read().retainedFlocks["owner/revoked"]);
    assert.ok(registry.read().retainedFlocks["owner/expired"]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 unmocked HTTP broker converges owner and newcomer for immediate first contact", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-http-first-contact-"));
  const storePath = path.join(root, "broker.json");
  const ownerFlocksPath = path.join(root, "owner", "flocks.json");
  const newcomerFlocksPath = path.join(root, "newcomer", "flocks.json");
  const owner = identity();
  const newcomer = identity();
  const previousConnection = process.env.SIGNALR_CONNECTION_STRING;
  process.env.SIGNALR_CONNECTION_STRING =
    "Endpoint=https://example.service.signalr.net;AccessKey=master-secret;Version=1.0;";
  const principals = {
    ownerToken: { login: "owner", id: 1001 },
  };
  const server = createBootstrapServer({
    v3StorePath: storePath,
    v3PreviewStorePath: path.join(root, "preview.json"),
    membersPath: path.join(root, "members.json"),
    apiGet: async (apiPath, token) => {
      if (apiPath === "/user") {
        return { statusCode: principals[token] ? 200 : 401, body: principals[token] || {} };
      }
      if (apiPath === "/users/alice") {
        return { statusCode: 200, body: { login: "alice", id: 2002 } };
      }
      return {
        statusCode: 200,
        body: {
          full_name: "erjadi/copilot-flock",
          owner: { login: "erjadi" },
          private: false,
          permissions: { pull: true, push: true, admin: false },
        },
      };
    },
  });
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${server.address().port}/api/v3`;
    const ownerEnrollBody = signV3EnrollmentRequest({
      deviceId: owner.fingerprint,
      machineId: "OWNER-PC",
      scope: "work",
      publicKey: owner.publicKey,
      keyFingerprint: owner.fingerprint,
      maintainerVisibilityAck: true,
    }, 1001, owner);
    const ownerEnrollment = await postJson(
      `${base}/enroll`,
      ownerEnrollBody,
      { authorization: "Bearer ownerToken" }
    );
    assert.equal(ownerEnrollment.response.status, 200);
    assert.equal(ownerEnrollment.body.ok, true);

    const teamName = `japan-${crypto.randomBytes(4).toString("hex")}`;
    const inviteResult = await postJson(
      `${base}/flocks/invite`,
      {
        targetAddress: `owner/${teamName}`,
        invitedUser: "alice",
        invitedGitHubUserId: 2002,
        allowedScopes: ["work"],
      },
      { authorization: "Bearer ownerToken" }
    );
    assert.equal(inviteResult.response.status, 200);
    const invite = inviteResult.body.enrollmentJson;

    const newcomerEnrollBody = signV3EnrollmentRequest({
      deviceId: newcomer.fingerprint,
      machineId: "JAPAN-STU",
      scope: "work",
      publicKey: newcomer.publicKey,
      keyFingerprint: newcomer.fingerprint,
      enrollmentJson: invite,
      maintainerVisibilityAck: true,
    }, 2002, newcomer);
    const newcomerEnrollment = await postJson(`${base}/enroll`, newcomerEnrollBody);
    assert.equal(newcomerEnrollment.response.status, 200);
    assert.equal(newcomerEnrollment.body.ok, true);

    const ownerCfg = {
      githubUser: "owner",
      machineId: "OWNER-PC",
      scope: "work",
      flocksConfigPath: ownerFlocksPath,
      identity: owner,
    };
    const newcomerCfg = {
      tokenLocalAuth: true,
      githubUser: "alice",
      machineId: "JAPAN-STU",
      scope: "work",
      flocksConfigPath: newcomerFlocksPath,
    };
    applyV3EnrollmentResult(ownerCfg, ownerEnrollment.body, ownerFlocksPath);
    const newcomerApplied = applyV3EnrollmentResult(
      newcomerCfg,
      newcomerEnrollment.body,
      newcomerFlocksPath
    );
    const teamId = `owner/${teamName}`;
    const joined = newcomerApplied.enrolledFlocks.find((flock) => flock.flockId === teamId);
    assert.ok(joined.members.some((member) => member.machineId === "OWNER-PC"));
    await refreshTokenLocalTransportCredentials(newcomerCfg, {
      customPath: newcomerFlocksPath,
      identityKeypair: newcomer,
      callEndpoint: async (_cfg, subPath, options) => {
        assert.equal(subPath, "/token/refresh");
        const refreshed = (await postJson(`${base}${subPath}`, options.body)).body;
        assert.equal(refreshed.completeMembershipSnapshot, false);
        return refreshed;
      },
    });
    assert.ok(newcomerCfg.clientToken);
    assert.ok(newcomerCfg.restTokens.users["OWNER-PC"].token);

    ownerCfg.syncFlockMembershipsFn = async () => {
      const signed = signV3MembershipSyncRequest({
        deviceId: owner.fingerprint,
        machineId: "OWNER-PC",
      }, owner);
      const syncResponse = await postJson(`${base}/flocks/sync`, signed);
      assert.equal(syncResponse.response.status, 200);
      return applyV3EnrollmentResult(ownerCfg, syncResponse.body, ownerFlocksPath, { requireMemberProof: true });
    };
    const request = signedRequest({
      key: newcomer,
      machineId: "JAPAN-STU",
      action: "ping",
      params: { flock: teamId },
      toMachine: "OWNER-PC",
    });
    const result = await handleRpcAction(ownerCfg, {
      ...request,
      flocksConfigPath: ownerFlocksPath,
    });
    assert.equal(result.machineId, "OWNER-PC");
    assert.equal(
      openFlockMembershipRegistry(ownerFlocksPath)
        .findActiveMember(teamId, { machineId: "JAPAN-STU" })
        .githubUser,
      "alice"
    );
    const ownerPolicy = JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8")).flocks[teamId];
    assert.equal(ownerPolicy.trustTier, "owner");
    assert.equal(ownerPolicy.sessionVisibility, "explicit_opt_in_only");
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    if (previousConnection === undefined) delete process.env.SIGNALR_CONNECTION_STRING;
    else process.env.SIGNALR_CONNECTION_STRING = previousConnection;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 cross-user unscoped project and lock reads fail closed", async () => {
  const alice = identity();
  const cfg = { machineId: "LOCAL", githubUser: "owner", scope: "work" };
  for (const action of ["list_projects", "list_locks"]) {
    const request = signedRequest({ key: alice, machineId: "ALICE-PC", action });
    await assert.rejects(
      () => handleRpcAction(cfg, {
        ...request,
        registryMembers: [{
          machineId: "ALICE-PC",
          githubUser: "alice",
          scope: "work",
          publicKey: alice.publicKey,
        }],
      }),
      (error) => error.code === "UNAUTHORIZED_FLOCK" && error.statusCode === 403
    );
  }
});

test("3.6 enrollment readiness requires correlated bidirectional epoch agreement", async () => {
  const awaitingPeer = await verifyEnrollmentReadiness(
    { machineId: "LOCAL" },
    [{ flockId: "owner/team", rosterEpoch: 7, members: [{ machineId: "LOCAL" }] }],
    { correlationId: "corr-awaiting" }
  );
  assert.equal(awaitingPeer.status, "enrolled_awaiting_peer_online");
  assert.equal(awaitingPeer.ready, false);
  assert.equal(awaitingPeer.policyAssertions, null);

  const enrolledFlocks = [{
    flockId: "owner/team",
    flockType: "shared",
    trustTier: "collaborator",
    sessionVisibility: "explicit_opt_in_only",
    rosterEpoch: 7,
    members: [
      { machineId: "LOCAL", peerId: "1001:local", githubUser: "owner" },
      { machineId: "REMOTE", peerId: "2002:remote", githubUser: "alice" },
    ],
  }];
  const success = await verifyEnrollmentReadiness(
    { machineId: "LOCAL" },
    enrolledFlocks,
    {
      correlationId: "corr-success",
      invokeRpc: async () => ({
        result: {
          enrollmentReadinessAck: {
            correlationId: "corr-success",
            flockId: "owner/team",
            rosterEpoch: 7,
          },
        },
      }),
    }
  );
  assert.equal(success.ready, true);
  assert.equal(success.status, "verified_bidirectional");
  assert.equal(success.stages.at(-1).stage, "first_contact");
  assert.equal(success.stages.at(-1).ok, true);
  assert.deepEqual(
    {
      proven: success.policyAssertions.proven,
      unsharedThreadAccessDenied: success.policyAssertions.unsharedThreadAccessDenied,
      forbiddenMutationDenied: success.policyAssertions.forbiddenMutationDenied,
      fileMutationDenied: success.policyAssertions.fileMutationDenied,
    },
    {
      proven: true,
      unsharedThreadAccessDenied: true,
      forbiddenMutationDenied: true,
      fileMutationDenied: true,
    }
  );

  const mismatch = await verifyEnrollmentReadiness(
    { machineId: "LOCAL" },
    enrolledFlocks,
    {
      correlationId: "corr-fail",
      invokeRpc: async () => ({
        result: {
          enrollmentReadinessAck: {
            correlationId: "corr-fail",
            flockId: "owner/team",
            rosterEpoch: 6,
          },
        },
      }),
    }
  );
  assert.equal(mismatch.ready, false);
  assert.equal(mismatch.stages.at(-1).ok, false);
  assert.match(mismatch.error, /roster epoch/i);
  assert.equal(mismatch.policyAssertions, null);
});
