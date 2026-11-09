import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import vm from "node:vm";
import * as flock from "../flock.mjs";
import * as bridge from "../bridge.mjs";

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
  const request = (action = "acquire_lock", params = { resource: "synthetic-dummy-lock" }) =>
    api.createSignedRpcRequest({ ...cfg, machineId: "ORIGIN" }, sending, { toMachine: "VICTIM", action, params });
  return { cfg, receiving, sending, senderKey, receiverKey, attackerKey, request, callback, replies, rejected };
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
  const normal = source.indexOf(`export function ${name}(`);
  const start = normal >= 0 ? normal : source.indexOf(`export async function ${name}(`);
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
      ], 100);
      assert.equal(batch.length, 2);
      assert.ok(batch.every((entry) => entry.ok && entry.response.auth.v === 3));
      assert.equal(seen.length, 3);
      assert.equal(closed, 2);
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
