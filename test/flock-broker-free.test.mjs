import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { AzureTransport, azureEndpoints, validateTransport, sas } from "../flock-azure.mjs";
import { BrokerFreeRuntime } from "../flock-broker-free.mjs";
import { encryptEnvelope, ownerFingerprint, peerSubscription } from "../flock-protocol.mjs";
import { lifecyclePaths, atomicJson, uninstallFlock, recordInstalledArtifact } from "../flock-lifecycle.mjs";
import { pathToFileURL } from "node:url";

const endpoints = azureEndpoints("https://fixture.service.signalr.net", "https://fixture.servicebus.windows.net");
const credentials = {
  connectionString: "Endpoint=https://fixture.service.signalr.net;AccessKey=signalr-fixture",
  manageConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=manage-fixture",
  sendConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockSendRule;SharedAccessKey=send-fixture",
  listenConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockListenRule;SharedAccessKey=listen-fixture",
};
async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock34-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const subscribers = new Map();
  const sockets = new Set();
  const requests = [];
  let deny = false;
  let deniedRealtimeType = null;
  const fetchImpl = async (url, options) => {
    requests.push({ url, ...options });
    if (deny) return new Response("denied", { status: 403 });
    const parsed = new URL(url);
    const peer = parsed.pathname.match(/\/subscriptions\/(sub-[a-f0-9]{46})/)?.[1];
    if (options.method === "PUT" && peer && !parsed.pathname.includes("/messages/")) {
      assert.equal(options.body, '<entry xmlns="http://www.w3.org/2005/Atom"><content type="application/xml"><SubscriptionDescription xmlns="http://schemas.microsoft.com/netservices/2010/10/servicebus/connect" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"/></content></entry>');
      if (!subscribers.has(peer)) subscribers.set(peer, []);
      return new Response("", { status: 201 });
    }
    if (options.method === "DELETE" && peer && !parsed.pathname.includes("/messages/")) {
      subscribers.delete(peer);
      return new Response(null, { status: 204 });
    }
    if (parsed.hostname.endsWith(".signalr.net")) {
      assert.match(options.headers.Authorization, /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
      const { target, arguments: args } = JSON.parse(options.body);
      if (args[0].type === deniedRealtimeType) { deniedRealtimeType = null; return new Response("denied", { status: 403 }); }
      for (const socket of sockets) if (!socket.ws.closed) socket.callback(target, structuredClone(args));
      return new Response("", { status: 202 });
    }
    if (options.method === "POST" && parsed.pathname.endsWith("/messages") && !peer) {
      for (const queue of subscribers.values()) queue.push(JSON.parse(options.body));
      return new Response("", { status: 201 });
    }
    if (options.method === "POST" && parsed.pathname.endsWith("/messages/head")) {
      const queue = subscribers.get(peer);
      if (!queue?.length) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(queue[0]), { status: 201,
        headers: { Location: `${endpoints.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peer}/messages/lock` } });
    }
    if (options.method === "DELETE" && parsed.pathname.endsWith("/messages/lock")) {
      subscribers.get(peer)?.shift();
      return new Response(null, { status: 204 });
    }
    if (options.method === "PUT" && parsed.pathname.endsWith("/messages/lock")) return new Response(null, { status: 204 });
    throw new Error(`Unexpected synthetic transport operation: ${options.method} ${parsed.pathname}`);
  };
  const connect = async (cfg, { userId, onInvocation }) => {
    const claims = JSON.parse(Buffer.from(cfg.clientToken.split(".")[1], "base64url").toString());
    assert.equal(claims.nameid, userId);
    const socket = { ws: { closed: false }, callback: onInvocation, close() { this.ws.closed = true; sockets.delete(this); } };
    sockets.add(socket);
    return socket;
  };
  const effects = [];
  const logs = [];
  const options = { connect, log: (message) => logs.push(message),
    dispatch: async ({ action, payload, assertAuthorized }) => {
      assertAuthorized();
      effects.push(action);
      return { machineId: "OWNER", message: payload.params.message || "pong" };
    },
    transportFactory: (config, options) => new AzureTransport(config, { ...options, fetchImpl }) };
  const owner = new BrokerFreeRuntime(path.join(root, "owner"), options);
  const peer = new BrokerFreeRuntime(path.join(root, "peer"), options);
  await owner.initializeOwner({ flockId: "demo/team", machineId: "OWNER", scope: "personal", ...credentials });
  const code = await peer.joinRequest({ machineId: "PEER", scope: "personal", flockId: "demo/team" });
  const ticket = await owner.approve({ flockId: "demo/team", code, expectedEd25519Fingerprint: code.body.peerId,
    role: "guest", sessionIds: ["shared"], membershipExpiresAt: Date.now() + 3600000 });
  await peer.accept(ticket, ownerFingerprint(owner.record("demo/team").ownerPublicKey));
  return { root, owner, peer, ticket, code, options, subscribers, requests, effects, logs,
    deny: (value) => { deny = value; }, failRealtime: (type) => { deniedRealtimeType = type; } };
}
test("scoped Azure issuance has exact audiences, expiry, policy and target-only management", async (t) => {
  const f = await fixture(t);
  const record = f.peer.record("demo/team");
  validateTransport(record.transport, endpoints, record.localPeerId, record.cert.body.expiresAt);
  assert.equal(record.ownerSecrets, undefined);
  assert.ok(f.subscribers.has(peerSubscription(record.localPeerId)));
  assert.equal(record.transport.subscription.length, 50);
  assert.throws(() => peerSubscription("not-a-fingerprint"), /identity/);
  for (const field of ["signalrClientToken", "signalrRestToken"]) {
    const parts = record.transport[field].split(".");
    assert.equal(parts[2], crypto.createHmac("sha256", "signalr-fixture").update(parts.slice(0, 2).join(".")).digest("base64url"));
  }
  const token = new URLSearchParams(record.transport.serviceBusListenSas.slice(22));
  assert.equal(token.get("sr"), `${endpoints.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peerSubscription(record.localPeerId)}`);
  const encoded = encodeURIComponent(token.get("sr"));
  assert.equal(token.get("sig"), crypto.createHmac("sha256", "listen-fixture").update(`${encoded}\n${token.get("se")}`).digest("base64"));
  const mixed = new URLSearchParams(sas("https://FIXTURE.servicebus.windows.net/TOPIC/Subscriptions/sub-test",
    "FlockListenRule", "listen-fixture", record.transport.expiresAt).slice(22));
  assert.equal(mixed.get("sr"), "https://fixture.servicebus.windows.net/topic/subscriptions/sub-test");
  assert.equal(mixed.get("sig"), crypto.createHmac("sha256", "listen-fixture")
    .update(`${encodeURIComponent(mixed.get("sr"))}\n${mixed.get("se")}`).digest("base64"));
  const tampered = { ...record.transport, serviceBusListenSas: sas(`${endpoints.serviceBusEndpoint}/copilot-bridge-offline`,
    "FlockListenRule", "listen-fixture", record.transport.expiresAt) };
  assert.throws(() => validateTransport(tampered, endpoints, record.localPeerId, record.cert.body.expiresAt), /audience/);
  await assert.rejects(new AzureTransport(endpoints, { secrets: { listenKey: "listen-fixture" } }).subscription(record.localPeerId, "DELETE"), /Manage/);
  assert.throws(() => azureEndpoints("https://evil.example", endpoints.serviceBusEndpoint), /endpoints/);
});
test("subscription names bind the full peer identity and known namespace collisions reject before cloud effects", async (t) => {
  const f = await fixture(t);
  const code = await f.peer.joinRequest({ machineId: "ANOTHER-PEER", scope: "personal", flockId: "demo/team" });
  const colliding = code.body.peerId.slice(0, 44) + (code.body.peerId[44] === "a" ? "b" : "a") + code.body.peerId.slice(45);
  assert.notEqual(colliding, code.body.peerId);
  assert.notEqual(peerSubscription(colliding), peerSubscription(code.body.peerId), "Different full identities must not alias by fingerprint prefix");
  assert.equal(peerSubscription(code.body.peerId),
    `sub-${crypto.createHash("sha256").update("copilot-flock/3.4/subscription\n" + code.body.peerId).digest("hex").slice(0, 46)}`);
  const data = f.owner.read();
  data.flocks["demo/other"] = { ...structuredClone(data.flocks["demo/team"]), flockId: "demo/other", localPeerId: code.body.peerId };
  f.owner.save(data);
  const before = f.requests.length;
  await assert.rejects(f.owner.approve({ flockId: "demo/team", code, expectedEd25519Fingerprint: code.body.peerId,
    role: "guest", membershipExpiresAt: Date.now() + 3600000 }), /subscription collides/);
  assert.equal(f.requests.length, before);
  assert.ok(f.subscribers.has(peerSubscription(f.code.body.peerId)));
});
test("active two-device encrypted RPC, durable admission and guest role negatives", async (t) => {
  const f = await fixture(t);
  const daemon = await f.owner.start();
  t.after(() => daemon.close());
  const response = await f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "ping", timeoutMs: 1000 });
  assert.equal(response.result.message, "pong");
  assert.equal(response.fromMachine, "OWNER");
  const request = f.requests.find((item) => item.url.endsWith("/messages") && JSON.parse(item.body).envelope?.header.action === "ping");
  const message = JSON.parse(request.body);
  await f.owner.consume(f.owner.record("demo/team"), message);
  assert.deepEqual(f.effects, ["ping"]);
  for (const action of ["create_session", "self_update", "send_file_chunk"]) {
    await assert.rejects(f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action, timeoutMs: 100 }), /forbids/);
  }
  await assert.rejects(f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "send_message",
    params: { targetSession: "private", message: "do not dispatch" }, timeoutMs: 100 }), /forbids/);
});
test("owner-mediated signed leave rotates only retained peers and safely retries offline failures", async (t) => {
  const f = await fixture(t);
  const daemon = await f.owner.start();
  t.after(() => daemon.close());
  f.deny(true);
  const pending = await f.peer.leaveAll();
  assert.equal(pending[0].confirmed, false);
  assert.equal(f.peer.record("demo/team").departed, false);
  const operationId = f.peer.record("demo/team").leaveOperationId;
  f.deny(false);
  const results = await f.peer.leaveAll();
  assert.equal(results[0].confirmed, true);
  assert.equal(results[0].receipt.body.operationId, operationId);
  assert.equal(f.owner.record("demo/team").epoch, 2);
  assert.equal(f.subscribers.has(peerSubscription(f.code.body.peerId)), false);
  assert.equal(f.subscribers.has(peerSubscription(f.owner.record("demo/team").localPeerId)), true);
  assert.deepEqual(await f.peer.leaveAll(), []);
});
test("owner renewal preserves device and role; wrong pins, target changes and stale epochs fail", async (t) => {
  const f = await fixture(t);
  const before = f.peer.record("demo/team");
  const daemon = await f.owner.start();
  t.after(() => daemon.close());
  await f.peer.renewMembership("demo/team");
  const after = f.peer.record("demo/team");
  assert.equal(after.localPeerId, before.localPeerId);
  assert.equal(after.cert.body.role, "guest");
  await assert.rejects(f.peer.approve({ flockId: "demo/team", code: f.code }), /owner/);
  const other = new BrokerFreeRuntime(path.join(f.root, "other"), f.options);
  const code = await other.joinRequest({ machineId: "OTHER", scope: "work", flockId: "demo/team" });
  const ticket = await f.owner.approve({ flockId: "demo/team", code, expectedEd25519Fingerprint: code.body.peerId,
    role: "collaborator", membershipExpiresAt: Date.now() + 3600000 });
  await assert.rejects(other.accept(ticket, "wrong"), /pin/);
  await other.accept(ticket, ownerFingerprint(before.ownerPublicKey));
  await f.owner.removePeer({ flockId: "demo/team", peerId: f.code.body.peerId, operationId: "target-only" });
  assert.equal(f.subscribers.has(peerSubscription(code.body.peerId)), true);
  const old = encryptEnvelope({ state: before, identity: before.identity, cert: before.cert,
    action: "ping", targetPeerId: "*", payload: {} });
  await assert.rejects(f.owner.consume(f.owner.record("demo/team"), { type: "envelope", flockId: "demo/team", envelope: old }), /epoch/);
  await assert.rejects(f.owner.removePeer({ flockId: "demo/team", peerId: code.body.peerId, operationId: "target-only" }), /target changed/);
});
test("leave retries after targeted deletion and failed rotation publication without using the revoked epoch", async (t) => {
  const f = await fixture(t);
  const daemon = await f.owner.start();
  t.after(() => daemon.close());
  const peer = f.peer.record("demo/team");
  await f.peer.mutate(async (data) => {
    data.flocks["demo/team"].leaveOperationId = "durable-retry";
    f.peer.save(data);
  });
  f.failRealtime("rotation");
  await assert.rejects(f.owner.removePeer({ flockId: "demo/team", peerId: peer.localPeerId, operationId: "durable-retry" }), /HTTP 403/);
  assert.equal(f.owner.record("demo/team").minAcceptedEpoch, 2);
  assert.equal((await f.peer.leaveAll())[0].confirmed, true);
  assert.equal(f.owner.record("demo/team").epoch, 2);
});
test("multiple memberships use distinct peer subscriptions, explicit dispatch and exact target selection", async (t) => {
  const f = await fixture(t);
  await f.owner.initializeOwner({ flockId: "demo/second", machineId: "OWNER", scope: "personal", ...credentials });
  const code = await f.peer.joinRequest({ machineId: "PEER", scope: "personal", flockId: "demo/second" });
  assert.notEqual(code.body.peerId, f.code.body.peerId);
  const ticket = await f.owner.approve({ flockId: "demo/second", code, expectedEd25519Fingerprint: code.body.peerId,
    role: "guest", membershipExpiresAt: Date.now() + 3600000 });
  await f.peer.accept(ticket, ownerFingerprint(f.owner.record("demo/second").ownerPublicKey));
  assert.throws(() => f.peer.select(), /ambiguous/);
  await assert.rejects(f.owner.approve({ flockId: "demo/team", code, expectedEd25519Fingerprint: code.body.peerId,
    role: "guest", membershipExpiresAt: Date.now() + 3600000 }), /another flock/);
  await f.owner.removePeer({ flockId: "demo/team", peerId: f.code.body.peerId });
  assert.equal(f.subscribers.has(peerSubscription(code.body.peerId)), true);
  const duplicate = await f.peer.joinRequest({ machineId: "PEER", scope: "work", flockId: "demo/second" });
  await assert.rejects(f.owner.approve({ flockId: "demo/second", code: duplicate, expectedEd25519Fingerprint: duplicate.body.peerId,
    role: "guest", membershipExpiresAt: Date.now() + 3600000 }), /ambiguous/);
});
test("broker-free uninstall retains offline recovery, then leaves every flock and preserves conversations, twice", async (t) => {
  const f = await fixture(t);
  const home = path.join(f.root, "synthetic-home");
  const paths = lifecyclePaths({ home, copilotHome: path.join(home, ".copilot"), platform: "linux" });
  const root = paths.roots[0];
  fs.mkdirSync(root, { recursive: true });
  fs.copyFileSync(f.peer.filename, path.join(root, "broker-free.json"));
  fs.writeFileSync(path.join(root, "flock.mjs"), 'export const BRIDGE_VERSION = "test";\nexport async function runDaemon() {}');
  recordInstalledArtifact(root, path.join(root, "flock.mjs"), paths);
  atomicJson(path.join(root, "config.json"), { protocol: "broker-free-v34", machineId: "PEER", scope: "personal" });
  const preserved = path.join(paths.copilotHome, "session-state", "keep");
  fs.mkdirSync(preserved, { recursive: true });
  fs.writeFileSync(path.join(preserved, "events.jsonl"), "conversation evidence");
  const runtime = new BrokerFreeRuntime(root, f.options);
  const options = { paths, brokerFreeLeave: () => runtime.leaveAll(), findProcesses: async () => [],
    stopDaemon: async () => {}, removeTasks: async () => [], disable: async () => {},
    checkPersistence: async () => {} };
  f.deny(true);
  const pending = await uninstallFlock(options);
  assert.equal(pending.fullyRemoved, false);
  assert.ok(fs.existsSync(runtime.filename));
  f.deny(false);
  const daemon = await f.owner.start();
  t.after(() => daemon.close());
  const removed = await uninstallFlock(options);
  assert.equal(removed.fullyRemoved, true, JSON.stringify(removed));
  assert.equal(fs.readFileSync(path.join(preserved, "events.jsonl"), "utf8"), "conversation evidence");
  assert.equal((await uninstallFlock(options)).fullyRemoved, true);
});
test("active dispatcher exposes only approved snapshots and rechecks local sharing, without legacy credential fallback", async (t) => {
  const f = await fixture(t);
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = path.join(f.root, "dispatch-home");
  t.after(() => { if (previous === undefined) delete process.env.COPILOT_HOME; else process.env.COPILOT_HOME = previous; });
  const source = pathToFileURL(path.resolve("flock.mjs"));
  source.search = `fixture=${crypto.randomUUID()}`;
  const module = await import(source.href);
  const localRoot = path.join(process.env.COPILOT_HOME, "flock");
  fs.mkdirSync(localRoot, { recursive: true });
  atomicJson(path.join(localRoot, "config.json"), { protocol: "broker-free-v34", machineId: "OWNER", scope: "personal" });
  atomicJson(path.join(localRoot, "broker-free.json"), f.owner.read());
  const policies = { flocks: { "demo/team": { sharedSessionIds: ["shared"], sharedSnapshots: {
    shared: { title: "Approved thread", summarySnapshot: "public summary AccessKey=secret-fixture", sharedAt: new Date().toISOString() },
  } } } };
  atomicJson(path.join(localRoot, "flocks.json"), policies);
  const cfg = module.loadConfig();
  assert.equal(cfg.bootstrapUrl, null);
  assert.equal(cfg.connectionString, null);
  f.owner.dispatch = (request) => module.dispatchBrokerFreeRpc(cfg, request);
  const daemon = await f.owner.start();
  t.after(() => daemon.close());
  const response = await f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "get_transcript",
    params: { session: "shared" } });
  assert.match(response.result.messages[0].content, /\[redacted\]/);
  assert.doesNotMatch(JSON.stringify(response), /secret-fixture/);
  policies.threadBindings = { shared: "demo/other" };
  atomicJson(path.join(localRoot, "flocks.json"), policies);
  assert.equal((await f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "list_sessions" })).result.count, 0);
  await assert.rejects(f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "get_transcript",
    params: { session: "shared" } }), /not explicitly shared/);
  policies.threadBindings = {};
  atomicJson(path.join(localRoot, "flocks.json"), policies);
  const preview = await f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "send_message",
    params: { targetSession: "shared", message: "preview", dryRun: true } });
  assert.equal(preview.result.dispatchedToRuntime, false);
  atomicJson(path.join(localRoot, "cli-sessions.json"), [{ session_id: "shared", title: "Approved thread", session_type: "cli" }]);
  const run = path.join(process.env.COPILOT_HOME, "run");
  fs.mkdirSync(run);
  fs.writeFileSync(path.join(run, "ws.port"), "12345");
  fs.writeFileSync(path.join(run, "ws.token"), "synthetic");
  const methods = {};
  const frames = [];
  for (const name of ["connect", "sendText", "close"]) methods[name] = module.RawWebSocketClient.prototype[name];
  t.after(() => { for (const [name, method] of Object.entries(methods)) module.RawWebSocketClient.prototype[name] = method; });
  module.RawWebSocketClient.prototype.connect = async function () {
    policies.flocks["demo/team"].sharedSessionIds = [];
    atomicJson(path.join(localRoot, "flocks.json"), policies);
  };
  module.RawWebSocketClient.prototype.sendText = (frame) => frames.push(frame);
  module.RawWebSocketClient.prototype.close = function () { this.closed = true; };
  await assert.rejects(f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "send_message",
    params: { targetSession: "shared", message: "must not dispatch after revocation" } }), /not explicitly shared/);
  assert.equal(frames.length, 0, "Sharing must be rechecked immediately after the socket await, before sending a frame");
  policies.flocks["demo/team"].sharedSessionIds = [];
  atomicJson(path.join(localRoot, "flocks.json"), policies);
  await assert.rejects(f.peer.invoke({ flockId: "demo/team", toMachine: "OWNER", action: "get_transcript",
    params: { session: "shared" } }), /not explicitly shared/);
});
test("owner removal cleans targeted interrupted approvals without deleting retained peer subscriptions", async (t) => {
  const f = await fixture(t);
  const code = await f.peer.joinRequest({ machineId: "INTERRUPTED", scope: "personal", flockId: "demo/team" });
  f.deny(true);
  await assert.rejects(f.owner.approve({ flockId: "demo/team", code, expectedEd25519Fingerprint: code.body.peerId,
    role: "guest", membershipExpiresAt: Date.now() + 3600000 }), /HTTP 403/);
  assert.ok(f.owner.record("demo/team").pendingApprovals[code.body.peerId]);
  f.deny(false);
  assert.equal((await f.owner.leaveAll())[0].confirmed, true);
  assert.equal(f.subscribers.has(peerSubscription(f.code.body.peerId)), true);
  assert.ok(f.requests.some((request) => request.method === "DELETE" && request.url.includes(`${peerSubscription(code.body.peerId)}?`)));
});
test("a provably stale mutation lock is recoverable while a live lock is never stolen", async (t) => {
  const f = await fixture(t);
  const lock = path.join(f.owner.root, "broker-free-mutation.lock");
  atomicJson(lock, { type: "copilot-flock-mutation-lock-v1", identity: { pid: 2147483647, start: "stale" } });
  await f.owner.joinRequest({ machineId: "RECOVERED", scope: "work", flockId: "demo/other" });
  await f.owner.mutate(async () => {
    await assert.rejects(f.owner.mutate(async () => assert.fail("live lock stolen")), /in progress/);
  });
  assert.equal(fs.existsSync(lock), false);
});
