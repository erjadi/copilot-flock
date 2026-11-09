import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import net from "node:net";
import { fork, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { makeIdentity, isInsideDirectory } from "../trial.mjs";
import { Store, fingerprint, privateAddress, endpoint, LIMITS } from "../store.mjs";
import { PeerServer, request } from "../transport.mjs";
import { DesktopAdapter } from "../desktop.mjs";
import { installLoopbackEgressGuard } from "./egress-guard.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const parentEgress = installLoopbackEgressGuard();
test.after(() => assert.deepEqual(parentEgress.denied, [], "Parent test runtime attempted unexpected non-loopback egress"));
const sessionA = "11111111-1111-4111-8111-111111111111";
const sessionB = "22222222-2222-4222-8222-222222222222";
const identities = await Promise.all([makeIdentity(), makeIdentity(), makeIdentity()]);
const pins = identities.map((i) => fingerprint(i.cert));
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const cleanups = new WeakMap();
function cleanup(t, fn) {
  if (!cleanups.has(t)) {
    const stack = [];
    cleanups.set(t, stack);
    t.after(async () => {
      for (const release of stack.reverse()) await release();
    });
  }
  cleanups.get(t).push(fn);
}

async function port() {
  const socket = net.createServer();
  await new Promise((resolve) => socket.listen(0, "127.0.0.1", resolve));
  const p = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return p;
}
function temp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "copilot-lan-test-"));
  cleanup(t, () => fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  return dir;
}
async function child(dir) {
  const cp = fork(path.join(here, "peer-fixture.mjs"), [dir], { stdio: ["ignore", "pipe", "pipe", "ipc"] });
  let stderr = "";
  cp.stderr.on("data", (chunk) => { stderr += chunk; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Fixture startup timeout: ${stderr}`)), 10000);
    cp.once("exit", (code) => { clearTimeout(timer); reject(new Error(`Fixture exited ${code}: ${stderr}`)); });
    cp.on("message", (m) => { if (m.type === "ready") { clearTimeout(timer); resolve(); } });
  });
  let seq = 0;
  return {
    cp,
    call(command, fields = {}) {
      const id = ++seq;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { cp.off("message", onMessage); reject(new Error(`Fixture command timeout ${command}: ${stderr}`)); }, 10000);
        const onMessage = (m) => {
          if (m.id !== id) return;
          clearTimeout(timer); cp.off("message", onMessage);
          if (m.error) reject(new Error(m.error)); else resolve(m.result);
        };
        cp.on("message", onMessage); cp.send({ id, command, ...fields });
      });
    },
    async stop() {
      if (cp.exitCode !== null) return;
      const unexpectedEgress = await this.call("denied-egress");
      const exited = new Promise((resolve) => cp.once("exit", resolve));
      await this.call("stop");
      await exited;
      assert.deepEqual(unexpectedEgress, [], "Unexpected non-loopback egress attempt was blocked");
    },
  };
}
async function pair(t, configB = {}) {
  const root = temp(t);
  const dirs = [path.join(root, "a"), path.join(root, "b")];
  const ports = await Promise.all([port(), port()]);
  const urls = ports.map((p) => `wss://127.0.0.1:${p}/`);
  for (let i = 0; i < 2; i++) {
    const s = new Store(dirs[i]);
    s.approve({ cert: identities[1 - i].cert, endpoint: urls[1 - i] }, pins[1 - i], true);
    s.share(pins[1 - i], i ? sessionB : sessionA, { title: i ? "B shared" : "A shared",
      snapshot: "Approved plain-text conversation excerpt", message: true, transcript: true });
    if (i === 1 && configB.extraSession) s.share(pins[0], sessionA, { title: "B second shared", message: true });
    s.close();
    fs.writeFileSync(path.join(dirs[i], "fixture.json"), JSON.stringify({
      identity: identities[i], port: ports[i],
      sessions: i === 1 && configB.extraSession ? [sessionB, sessionA] : [i ? sessionB : sessionA],
      ...(i === 1 ? configB : {}),
    }));
  }
  const a = await child(dirs[0]);
  cleanup(t, () => a.stop());
  let b = await child(dirs[1]);
  cleanup(t, () => b.stop());
  return { a, get b() { return b; }, dirs, urls, async restartB() { b = await child(dirs[1]); } };
}
const toB = (options = {}) => ({ pin: pins[1], action: "message", session: sessionB, payload: "Hello existing session", ...options });
const toA = (options = {}) => ({ pin: pins[0], action: "message", session: sessionA, payload: "Reply from second peer", ...options });

test("two distinct processes: reciprocal pinned TLS, real adapter admission both ways, explicit shares only", async (t) => {
  const p = await pair(t);
  const before = fs.readFileSync(path.join(p.dirs[1], "fixture.json"));
  const status = await p.a.call("request", { options: toB({ action: "status", session: "", payload: "" }) });
  assert.equal(status.status, "DELIVERED");
  assert.equal(status.peer, pins[1]);
  const sessions = await p.a.call("request", { options: toB({ action: "sessions", session: "", payload: "" }) });
  assert.deepEqual(sessions.sessions.map((s) => s.session), [sessionB]);
  const transcript = await p.a.call("request", { options: toB({ action: "transcript", payload: "" }) });
  assert.equal(transcript.snapshot, "Approved plain-text conversation excerpt");
  assert.equal(transcript.source, "locally-approved-snapshot");
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.equal((await p.b.call("request", { options: toA() })).status, "DELIVERED");
  assert.equal((await p.a.call("request", { options: toB({ session: sessionA }) })).status, "DENIED");
  const frames = await p.b.call("frames");
  assert.equal(frames.length, 1);
  assert.equal(frames[0].type, "send_message");
  assert.equal(frames[0].session_id, sessionB);
  assert.equal(frames[0].delivery_mode, "immediate");
  assert.equal("mode" in frames[0], false);
  assert.equal("permission_mode" in frames[0], false);
  assert.equal("model" in frames[0], false);
  assert.match(frames[0].prompt, /Untrusted LAN peer/);
  assert.match(frames[0].prompt, new RegExp(pins[0]));
  assert.deepEqual(fs.readFileSync(path.join(p.dirs[1], "fixture.json")), before);
  const connections = [...await p.a.call("connections"), ...await p.b.call("connections")];
  assert.ok(connections.length >= 4);
  assert.ok(connections.every((c) => c.address === "127.0.0.1"));
});

test("concurrent replay, changed payload and per-session busy never redispatch", async (t) => {
  const p = await pair(t, { admitDelay: 250 });
  const exact = toB({ id: randomUUID(), expires: Date.now() + 10000 });
  const first = p.a.call("request", { options: exact });
  await pause(100);
  const replay = p.a.call("request", { options: exact });
  const changed = p.a.call("request", { options: { ...exact, payload: "changed" } });
  const busy = p.a.call("request", { options: toB() });
  const results = await Promise.all([first, replay, changed, busy]);
  assert.deepEqual(results.map((r) => r.status), ["DELIVERED", "UNKNOWN", "DENIED", "BUSY"]);
  assert.equal((await p.b.call("frames")).length, 1);
  assert.equal((await p.a.call("request", { options: exact })).status, "UNKNOWN");
});

test("revocation cancels work awaiting local handshake, closes connections, cannot restore old grants", async (t) => {
  const p = await pair(t, { holdHandshake: true });
  const pending = p.a.call("request", { options: toB() });
  assert.equal(await p.b.call("wait-handshake"), 1);
  await p.b.call("unshare", { pin: pins[0], session: sessionB });
  assert.equal((await pending).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 0);
  assert.equal((await p.a.call("request", { options: toB() })).status, "DENIED");
  await p.b.call("revoke", { pin: pins[0] });
  assert.notEqual((await p.a.call("request", { options: toB({ action: "status", session: "", payload: "" }) })).status, "DELIVERED");
  const s = new Store(p.dirs[1]);
  s.approve({ cert: identities[0].cert, endpoint: p.urls[0] }, pins[0], true);
  assert.equal(s.shares(pins[0]).length, 0); s.close();
});

test("ambiguous timeout and process crash retain durable claim through restart", async (t) => {
  const p = await pair(t, { neverAdmit: true });
  const exact = toB({ id: randomUUID(), expires: Date.now() + 60000, timeout: 200 });
  assert.equal((await p.a.call("request", { options: exact })).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 1);
  const exited = new Promise((resolve) => p.b.cp.once("exit", resolve));
  p.b.cp.kill();
  await exited;
  await p.restartB();
  assert.equal((await p.a.call("request", { options: exact })).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 0);
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(p.urls[1], { cert: identities[0].cert, key: identities[0].key,
      ca: identities[1].cert, checkServerIdentity: () => undefined, maxVersion: "TLSv1.2" });
    const timer = setTimeout(() => { ws.terminate(); reject(new Error("TLS 1.2 connection did not close")); }, 3000);
    ws.on("error", () => {});
    ws.on("open", () => { clearTimeout(timer); ws.terminate(); reject(new Error("TLS 1.2 was accepted")); });
    ws.on("close", () => { clearTimeout(timer); resolve(); });
  });
});

test("identity mismatch, one-sided approval and inactive peer do not admit", async (t) => {
  const p = await pair(t);
  const impostor = new Store(path.join(temp(t), "impostor"));
  cleanup(t, () => impostor.close());
  impostor.approve({ cert: identities[1].cert, endpoint: p.urls[1] }, pins[1], true);
  const result = await request({ store: impostor, identity: identities[2], ...toB(), allowLoopback: true });
  assert.notEqual(result.status, "DELIVERED");
  assert.equal((await p.b.call("frames")).length, 0);
  const mismatch = new Store(path.join(temp(t), "mismatch"));
  cleanup(t, () => mismatch.close());
  mismatch.approve({ cert: identities[2].cert, endpoint: p.urls[1] }, pins[2], true);
  assert.notEqual((await request({ store: mismatch, identity: identities[0],
    ...toB({ pin: pins[2] }), allowLoopback: true })).status, "DELIVERED");
  mismatch.revoke(pins[2]);
  assert.equal((await request({ store: mismatch, identity: identities[0],
    ...toB({ pin: pins[2] }), allowLoopback: true })).status, "DENIED");
});

test("dedup binding, capacity, expiry, independent pin and persistence fail closed", (t) => {
  const dir = temp(t);
  let s = new Store(dir, { capacity: 1 });
  const offer = { cert: identities[1].cert, endpoint: "wss://10.0.0.2:9443/" };
  assert.throws(() => s.approve(offer, pins[0]), /fingerprint/);
  s.approve(offer, pins[1]);
  assert.equal(s.shares(pins[1]).length, 0);
  const r = { action: "message", session: sessionB, payload: "hello", id: randomUUID(), expires: 200 };
  assert.equal(s.claim(pins[1], r, 100), "NEW");
  assert.equal(s.claim(pins[1], r, 101), "UNKNOWN");
  assert.equal(s.claim(pins[1], { ...r, session: sessionA }, 101), "DENIED");
  assert.equal(s.claim(pins[1], { ...r, action: "transcript" }, 101), "DENIED");
  assert.equal(s.claim(pins[1], { ...r, payload: "other" }, 101), "DENIED");
  assert.equal(s.claim(pins[1], { ...r, id: randomUUID() }, 101), "BUSY");
  s.close(); s = new Store(dir, { capacity: 1 });
  assert.equal(s.claim(pins[1], r, 199), "UNKNOWN");
  assert.equal(s.claim(pins[1], { ...r, expires: 400 }, 201), "NEW");
  s.close();
  assert.throws(() => s.claim(pins[1], r), /closed|open/i);
});

test("broken receiver storage denies requests without dispatch", async (t) => {
  const p = await pair(t);
  await p.b.call("break-store");
  assert.notEqual((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.equal((await p.b.call("frames")).length, 0);
});

test("bounded payload, private addresses, frame limit, no wildcard/DNS/cloud endpoints", async (t) => {
  assert.equal(privateAddress("0.0.0.0"), false);
  assert.equal(privateAddress("8.8.8.8"), false);
  assert.equal(privateAddress("10.0.0.2"), true);
  assert.equal(privateAddress("172.31.0.2"), true);
  assert.equal(privateAddress("192.168.1.2"), true);
  for (const value of ["wss://example.com:443/", "wss://0.0.0.0:9443/", "wss://127.0.0.1:9443/",
    "ws://10.0.0.2:9443/", "wss://10.0.0.2:9443/other", "wss://10.0.0.2:9443/?token=secret"]) {
    assert.throws(() => endpoint(value));
  }
  const p = await pair(t);
  const s = new Store(p.dirs[0]); cleanup(t, () => s.close());
  assert.throws(() => request({ store: s, identity: identities[0], ...toB({ payload: "a".repeat(LIMITS.text + 1) }), allowLoopback: true }));
  assert.throws(() => request({ store: s, identity: identities[0], ...toB({ expires: Date.now() - 1 }), allowLoopback: true }));
  assert.throws(() => request({ store: s, identity: identities[0], ...toB({ action: "shell" }), allowLoopback: true }));
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(p.urls[1], { cert: identities[0].cert, key: identities[0].key,
      ca: identities[1].cert, checkServerIdentity: () => undefined, minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
    const timer = setTimeout(() => { ws.terminate(); reject(new Error("Oversize connection did not close")); }, 3000);
    ws.on("error", () => {});
    ws.on("open", () => ws.send("x".repeat(LIMITS.frame + 1)));
    ws.on("close", () => { clearTimeout(timer); resolve(); });
  });
  assert.equal((await p.b.call("frames")).length, 0);
});

test("safe Desktop adapter denies unsupported headless/missing sessions without spawning", async (t) => {
  const dir = temp(t);
  const adapter = new DesktopAdapter(dir);
  const result = await adapter.send(sessionA, "hello", {
    signal: new AbortController().signal, authorize: () => true, id: randomUUID(), peer: pins[0],
  });
  assert.equal(result.status, "DENIED");
  assert.throws(() => adapter.events("..\\other"));
  assert.deepEqual(fs.readdirSync(dir), []);
});

test("source isolation: no full-Flock imports, cloud transports or privileged CLI fallback", () => {
  const root = path.join(here, "..");
  for (const name of ["trial.mjs", "store.mjs", "transport.mjs", "desktop.mjs"]) {
    const source = fs.readFileSync(path.join(root, name), "utf8");
    assert.doesNotMatch(source, /from\s+["'][^"']*(?:flock\.mjs|bridge\.mjs|bootstrap-server)/);
    assert.doesNotMatch(source, /--allow-all|--no-ask-user|connectionString|servicebus|azurewebsites|signalr\.net/i);
  }
  assert.match(fs.readFileSync(path.join(root, "trial.mjs"), "utf8"), /copilot-lan-trial/);
});

test("MCP initialization is distinct and invalid CLI configuration has no state side effects", (t) => {
  const root = path.join(here, "..");
  const dir = path.join(temp(t), "not-created");
  const run = spawnSync(process.execPath, [path.join(root, "trial.mjs"), "init", "--state", dir,
    "--host", "0.0.0.0", "--port", "9443"], { encoding: "utf8" });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /explicit private IPv4/);
  assert.equal(fs.existsSync(dir), false);
  const forbidden = spawnSync(process.execPath, [path.join(root, "trial.mjs"), "init",
    "--state", path.join(os.homedir(), ".copilot", "flock"), "--host", "10.0.0.2", "--port", "9443"], { encoding: "utf8" });
  assert.equal(forbidden.status, 1);
  assert.match(forbidden.stderr, /outside the full Copilot profile/);
});

test("CLI init protects isolated Windows state and emits working absolute MCP fragment without registration", (t) => {
  const root = path.join(here, "..");
  const dir = path.join(temp(t), "initialized");
  const init = spawnSync(process.execPath, [path.join(root, "trial.mjs"), "init", "--state", dir,
    "--host", "10.23.45.67", "--port", "9443"], { cwd: root, encoding: "utf8" });
  assert.equal(init.status, 0, init.stderr);
  const output = JSON.parse(init.stdout);
  assert.equal(output.status, "INITIALIZED");
  const offer = JSON.parse(fs.readFileSync(path.join(dir, "offer.json"), "utf8"));
  assert.equal(fingerprint(offer.cert), output.fingerprint);
  assert.equal(offer.endpoint, "wss://10.23.45.67:9443/");
  const fragment = JSON.parse(fs.readFileSync(path.join(dir, "mcp-fragment.json"), "utf8"));
  const server = fragment.mcpServers["copilot-lan-trial"];
  assert.equal(server.args[0], path.join(root, "trial.mjs"));
  assert.equal("copilot-flock" in fragment.mcpServers, false);
  const mcp = spawnSync(server.command, server.args, { encoding: "utf8", input:
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }) + "\n" +
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n" +
    JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: {
      name: "lan_peer_status", arguments: { peer: pins[1] },
    } }) + "\n",
  });
  assert.equal(mcp.status, 0, mcp.stderr);
  const responses = mcp.stdout.trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(responses[0].result.serverInfo.name, "copilot-lan-trial");
  assert.equal(responses[1].result.tools.length, 4);
  assert.deepEqual(responses[1].result.tools.map((tool) => tool.name),
    ["lan_peer_status", "lan_shared_sessions", "lan_approved_transcript", "lan_send_message"]);
  assert.equal(JSON.parse(responses[2].result.content[0].text).status, "DENIED");
  assert.equal(responses[2].result.isError, true);
  const again = spawnSync(server.command, [server.args[0], "init", "--state", dir,
    "--host", "10.23.45.67", "--port", "9443"], { encoding: "utf8" });
  assert.equal(again.status, 1);
  assert.match(again.stderr, /new, dedicated trial directory/);
  const peers = spawnSync(server.command, [server.args[0], "peers", "--state", dir], { encoding: "utf8" });
  assert.equal(peers.status, 0);
  assert.deepEqual(JSON.parse(peers.stdout), []);
});

test("default no shares, action-specific grants and bounded result disclosure", async (t) => {
  const p = await pair(t);
  await p.b.call("unshare", { pin: pins[0], session: sessionB });
  const listing = await p.a.call("request", { options: toB({ action: "sessions", session: "", payload: "" }) });
  assert.deepEqual(listing.sessions, []);
  assert.equal((await p.a.call("request", { options: toB() })).status, "DENIED");
  assert.equal((await p.a.call("request", { options: toB({ action: "transcript", payload: "" }) })).status, "DENIED");
  await p.b.call("share", { pin: pins[0], session: sessionB, share: {
    title: "Explicit read-only", snapshot: "a".repeat(LIMITS.snapshot), transcript: true, message: false,
  } });
  const transcript = await p.a.call("request", { options: toB({ action: "transcript", payload: "" }) });
  assert.equal(Buffer.byteLength(transcript.snapshot), LIMITS.snapshot);
  assert.equal((await p.a.call("request", { options: toB() })).status, "DENIED");
  assert.equal((await p.b.call("frames")).length, 0);
  const s = new Store(p.dirs[1]); cleanup(t, () => s.close());
  assert.throws(() => s.share(pins[0], sessionB, {
    title: "Too large", snapshot: "a".repeat(LIMITS.snapshot + 1), transcript: true,
  }), /Invalid local share/);
});

test("receiver capacity fails closed until expiry; expired in-flight requests cannot confirm delivery", async (t) => {
  const p = await pair(t, { capacity: 1, neverAdmit: true });
  const exact = toB({ expires: Date.now() + 300, timeout: 1000 });
  const pending = p.a.call("request", { options: exact });
  await pause(100);
  assert.equal((await p.a.call("request", { options: toB() })).status, "BUSY");
  assert.equal((await pending).status, "UNKNOWN");
  const ready = await p.a.call("request", { options: toB({ action: "status", session: "", payload: "" }) });
  assert.equal(ready.status, "DELIVERED");
  assert.equal((await p.b.call("frames")).length, 1);
});

test("revocation after dispatch withholds delivery disclosure; does not promise undo of admitted work", async (t) => {
  const p = await pair(t, { admitDelay: 400 });
  const pending = p.a.call("request", { options: toB() });
  assert.equal(await p.b.call("wait-frame"), 1);
  await p.b.call("revoke", { pin: pins[0] });
  assert.equal((await pending).status, "UNKNOWN");
});

test("certificate replacement requires local revoke and fresh pin; reapproval never restores grants", (t) => {
  const s = new Store(temp(t)); cleanup(t, () => s.close());
  const url = "wss://10.0.0.2:9443/";
  s.approve({ cert: identities[1].cert, endpoint: url }, pins[1]);
  s.share(pins[1], sessionB, { title: "original", message: true });
  assert.throws(() => s.approve({ cert: identities[2].cert, endpoint: url }, pins[2]), /Revoke the old certificate/);
  s.revoke(pins[1]);
  s.approve({ cert: identities[2].cert, endpoint: url }, pins[2]);
  assert.equal(s.shares(pins[2]).length, 0);
  assert.equal(s.peer(pins[1]), undefined);
  assert.throws(() => s.approve({ cert: identities[1].cert, endpoint: url }, pins[2]), /fingerprint/);
});

test("protected ancestry distinguishes dot-dot names, parents, siblings and Windows cross-drive paths", () => {
  const profile = path.resolve("profile", ".copilot");
  assert.equal(isInsideDirectory(profile, profile), true);
  assert.equal(isInsideDirectory(profile, path.join(profile, "..trial")), true);
  assert.equal(isInsideDirectory(profile, path.join(profile, "..trial", "nested")), true);
  assert.equal(isInsideDirectory(profile, path.dirname(profile)), false);
  assert.equal(isInsideDirectory(profile, path.join(path.dirname(profile), "..trial")), false);
  assert.equal(isInsideDirectory(profile, path.join(path.dirname(profile), ".copilot-other")), false);
  if (process.platform === "win32") {
    assert.equal(isInsideDirectory("C:\\Users\\tester\\.copilot", "D:\\trial"), false);
    assert.equal(isInsideDirectory("C:\\Users\\tester\\.copilot", "c:\\users\\tester\\.copilot\\..trial"), true);
  }
});

test("CLI blocks protected dot-dot children and canonicalized junction/symlink aliases without mutation", (t) => {
  const root = temp(t);
  const home = path.join(root, "fixture-home");
  const profile = path.join(home, ".copilot");
  fs.mkdirSync(profile, { recursive: true });
  fs.writeFileSync(path.join(profile, "sentinel"), "unchanged");
  const env = { ...process.env, USERPROFILE: home, HOME: home };
  const observedHome = spawnSync(process.execPath, ["-e", "console.log(require('node:os').homedir())"], { env, encoding: "utf8" });
  assert.equal(path.resolve(observedHome.stdout.trim()), home);
  const link = path.join(root, "outside-alias");
  fs.symlinkSync(profile, link, process.platform === "win32" ? "junction" : "dir");
  for (const state of [path.join(profile, "..trial"), path.join(profile, "..trial", "nested"),
    path.join(link, "..trial"), path.join(link, "regular-child")]) {
    const run = spawnSync(process.execPath, [path.join(here, "..", "trial.mjs"), "init",
      "--state", state, "--host", "10.23.45.67", "--port", "9443"], { env, encoding: "utf8" });
    assert.equal(run.status, 1, run.stderr);
    assert.match(run.stderr, /outside the full Copilot profile/);
    assert.equal(fs.existsSync(state), false);
  }
  assert.deepEqual(fs.readdirSync(profile), ["sentinel"]);
  assert.equal(fs.readFileSync(path.join(profile, "sentinel"), "utf8"), "unchanged");
});

test("receiver immediate post-adapter grant race returns UNKNOWN, not a false denial", async (t) => {
  const s = new Store(temp(t)); cleanup(t, () => s.close());
  s.approve({ cert: identities[0].cert, endpoint: "wss://127.0.0.1:9443/" }, pins[0], true);
  s.share(pins[0], sessionB, { title: "selected", message: true });
  let dispatches = 0;
  const server = new PeerServer({ store: s, identity: identities[1], host: "127.0.0.1", port: 0,
    allowLoopback: true, adapter: { async send() {
      dispatches++;
      s.unshare(pins[0], sessionB);
      return { status: "DELIVERED" };
    } },
  });
  cleanup(t, () => server.stop());
  const replies = [];
  await server.handle({ readyState: WebSocket.OPEN, send: (value) => replies.push(JSON.parse(value)) }, pins[0],
    Buffer.from(JSON.stringify({ id: randomUUID(), action: "message", session: sessionB,
      payload: "one admitted message", expires: Date.now() + 10000 })));
  assert.equal(dispatches, 1);
  assert.equal(replies.length, 1);
  assert.equal(replies[0].status, "UNKNOWN");
  assert.equal("admission" in replies[0], false);
});

test("receiver post-admission revocation reply retains UNKNOWN on the real TLS wire", async (t) => {
  const p = await pair(t, { unshareAfterAdmission: true });
  assert.equal((await p.a.call("request", { options: toB() })).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 1);
});

test("sender revision monitoring after send preserves UNKNOWN and never redispatches", async (t) => {
  const p = await pair(t, { neverAdmit: true });
  const pending = p.a.call("request", { options: toB() });
  assert.equal(await p.b.call("wait-frame"), 1);
  await p.a.call("revoke", { pin: pins[1] });
  assert.equal((await pending).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 1);
});

test("sender authorization loss on the reply path returns UNKNOWN after possible delivery", async (t) => {
  const root = temp(t);
  const a = new Store(path.join(root, "a")); cleanup(t, () => a.close());
  const b = new Store(path.join(root, "b")); cleanup(t, () => b.close());
  b.approve({ cert: identities[0].cert, endpoint: "wss://127.0.0.1:9443/" }, pins[0], true);
  b.share(pins[0], sessionB, { title: "selected", message: true });
  let dispatches = 0;
  const server = new PeerServer({ store: b, identity: identities[1], host: "127.0.0.1", port: 0,
    allowLoopback: true, adapter: { async send() {
      dispatches++;
      a.revoke(pins[1]);
      return { status: "DELIVERED" };
    } },
  });
  cleanup(t, () => server.stop());
  const url = await server.start();
  a.approve({ cert: identities[1].cert, endpoint: url }, pins[1], true);
  const result = await request({ store: a, identity: identities[0], ...toB(), allowLoopback: true });
  assert.equal(dispatches, 1);
  assert.equal(result.status, "UNKNOWN");
  assert.equal("admission" in result, false);
});

test("sender authorization loss before send is DENIED with no local admission", async (t) => {
  const p = await pair(t);
  const s = new Store(p.dirs[0]); cleanup(t, () => s.close());
  const originalPeer = s.peer(pins[1]);
  let reads = 0;
  s.peer = () => ++reads === 1 ? originalPeer : undefined;
  assert.equal((await request({ store: s, identity: identities[0], ...toB(), allowLoopback: true })).status, "DENIED");
  assert.equal((await p.b.call("frames")).length, 0);
});

test("Desktop error after sending a frame cannot prove non-delivery", async (t) => {
  const p = await pair(t, { errorAfterSend: true });
  assert.equal((await p.a.call("request", { options: toB() })).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 1);
});

test("fixture egress guard rejects cloud DNS/connect attempts and permits only loopback trial traffic", async (t) => {
  const p = await pair(t);
  const negative = await p.a.call("probe-egress");
  assert.deepEqual(negative, { code: "LAN_TEST_EGRESS", denied: 1 });
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.deepEqual(await p.a.call("denied-egress"), []);
  assert.deepEqual(await p.b.call("denied-egress"), []);
  assert.ok((await p.a.call("connections")).every((c) => c.address === "127.0.0.1"));
});

test("Desktop control files accept only their first line with LF or CRLF trailing metadata", async (t) => {
  for (const newline of ["\n", "\r\n"]) {
    const p = await pair(t, {
      portSuffix: `${newline}fixture-metadata=port${newline}ignored-trailing-line`,
      tokenSuffix: `${newline}fixture-metadata=token${newline}not-part-of-token`,
    });
    const result = await p.a.call("request", { options: toB() });
    assert.equal(result.status, "DELIVERED");
    assert.equal((await p.b.call("frames")).length, 1);
    assert.doesNotMatch(JSON.stringify(result), /fixture-only-not-a-desktop-token|fixture-metadata|not-part-of-token/);
  }
});

test("observed laptop layout: exactly two nonempty LF segments, numeric second line, no final newline", async (t) => {
  const p = await pair(t, { portSuffix: "\n123456", tokenSuffix: "\n789012" });
  const run = path.join(p.dirs[1], "desktop-fixture", "run");
  const portFile = fs.readFileSync(path.join(run, "ws.port"), "utf8");
  const tokenFile = fs.readFileSync(path.join(run, "ws.token"), "utf8");
  for (const file of [portFile, tokenFile]) {
    assert.equal(file.includes("\r"), false);
    assert.equal(file.endsWith("\n"), false);
    const segments = file.split("\n");
    assert.equal(segments.length, 2);
    assert.ok(segments.every((segment) => segment.length > 0));
    assert.match(segments[1], /^\d+$/);
  }
  assert.match(portFile.split("\n")[0], /^\d+$/);
  const result = await p.a.call("request", { options: toB() });
  assert.equal(result.status, "DELIVERED");
  assert.equal((await p.b.call("frames")).length, 1);
  assert.doesNotMatch(JSON.stringify(result), /fixture-only-not-a-desktop-token|123456|789012/);
});

test("invalid first control-file lines are denied without searching later lines or dispatching", async (t) => {
  for (const control of [
    { portFile: "not-a-port\n9443" },
    { portFile: "\r\n9443" },
    { portFile: "65536\n9443" },
    { tokenFile: "\nfixture-only-not-a-desktop-token" },
    { tokenFile: `${"x".repeat(4097)}\nfixture-only-not-a-desktop-token` },
  ]) {
    const p = await pair(t, control);
    const result = await p.a.call("request", { options: toB() });
    assert.equal(result.status, "DENIED");
    assert.equal((await p.b.call("frames")).length, 0);
    assert.doesNotMatch(JSON.stringify(result), /fixture-only-not-a-desktop-token/);
  }
});

test("observed Desktop admission schema succeeds without echoed request-ID fields", async (t) => {
  const p = await pair(t);
  const id = randomUUID();
  const payload = "Exact observed-schema acceptance message";
  const result = await p.a.call("request", { options: toB({ id, payload }) });
  assert.equal(result.status, "DELIVERED");
  assert.equal(result.admission, "confirmed");
  assert.equal(result.executed, false);
  const [frame] = await p.b.call("frames");
  const [event] = await p.b.call("admission-events");
  const nonce = frame.prompt.match(/ admission ([0-9a-f-]{36});/)[1];
  assert.notEqual(nonce, id);
  assert.equal(frame.prompt, `[Untrusted LAN peer ${pins[0]} request ${id} admission ${nonce}; keep this session's existing permissions]\n${payload}`);
  assert.equal(event.type, "user.message");
  assert.deepEqual(Object.keys(event).sort(), ["data", "id", "parentId", "timestamp", "type"]);
  assert.equal(event.data.content, frame.display_prompt);
  assert.ok(event.data.transformedContent.endsWith(`\n\n${frame.prompt}`));
  for (const object of [event, event.data]) {
    assert.equal("requestId" in object, false);
    assert.equal("request_id" in object, false);
  }
  for (const serverId of [event.id, event.data.messageId, event.data.interactionId]) {
    assert.notEqual(serverId, id);
  }
});

test("matching display text cannot substitute for exact request/peer envelope and transformed-content type", async (t) => {
  for (const admissionMode of ["wrong-request", "wrong-nonce", "wrong-content", "missing-transformed", "wrong-peer",
    "assistant", "legacy-id-only", "wrong-type-transformed", "quoted", "nested", "duplicate-date", "arbitrary-suffix"]) {
    const p = await pair(t, { admissionMode });
    const result = await p.a.call("request", { options: toB() });
    assert.equal(result.status, "UNKNOWN", admissionMode);
    assert.equal((await p.b.call("frames")).length, 1);
    assert.equal("admission" in result, false);
  }
});

test("receipt-only WebSocket acknowledgment without persisted user admission remains UNKNOWN", async (t) => {
  const p = await pair(t, { ackOnly: true });
  assert.equal((await p.a.call("request", { options: toB() })).status, "UNKNOWN");
  assert.deepEqual(await p.b.call("admission-events"), []);
});

test("sequential identical text with distinct request IDs waits for each own observed-schema admission", async (t) => {
  const p = await pair(t, { admissionModes: ["observed", "previous-then-current"] });
  const payload = "Identical message text";
  const firstId = randomUUID(), secondId = randomUUID();
  assert.equal((await p.a.call("request", { options: toB({ id: firstId, payload }) })).status, "DELIVERED");
  const pending = p.a.call("request", { options: toB({ id: secondId, payload }) });
  assert.equal(await Promise.race([pending.then(() => "finished"), pause(150).then(() => "waiting")]), "waiting");
  assert.equal((await pending).status, "DELIVERED");
  const events = await p.b.call("admission-events");
  assert.equal(events.length, 3);
  assert.equal(events[0].data.content, events[2].data.content);
  assert.ok(events[1].data.transformedContent.includes(`request ${firstId} admission `));
  assert.ok(events[2].data.transformedContent.includes(`request ${secondId} admission `));
  const frames = await p.b.call("frames");
  assert.notEqual(frames[0].prompt.match(/ admission ([0-9a-f-]{36});/)[1],
    frames[1].prompt.match(/ admission ([0-9a-f-]{36});/)[1]);
});

test("a newly appended replay of a previous identical-text admission cannot confirm a new request", async (t) => {
  const p = await pair(t, { admissionModes: ["observed", "previous-only"] });
  const payload = "Identical text with replayed prior event";
  assert.equal((await p.a.call("request", { options: toB({ id: randomUUID(), payload }) })).status, "DELIVERED");
  assert.equal((await p.a.call("request", { options: toB({ id: randomUUID(), payload }) })).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 2);
});

test("invalid adapter request and peer identifiers deny before any Desktop dispatch", async (t) => {
  const p = await pair(t);
  for (const fields of [
    { requestId: "not-a-uuid", peer: pins[0] },
    { requestId: randomUUID(), peer: "not-a-pin" },
    { requestId: randomUUID(), peer: pins[0].toUpperCase() },
    { requestId: randomUUID(), peer: `${pins[0]}\nforged-header` },
  ]) {
    assert.equal((await p.b.call("adapter-probe", fields)).status, "DENIED");
  }
  assert.deepEqual(await p.b.call("frames"), []);
});

test("direct and datetime-prefixed admission envelopes permit only supported system-block suffixes", async (t) => {
  for (const admissionMode of ["direct", "system-suffix"]) {
    const p = await pair(t, { admissionMode });
    assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  }
});

test("simultaneous identical text for two granted sessions uses distinct receiver nonces and own admissions", async (t) => {
  const p = await pair(t, { extraSession: true });
  const payload = "Same text at the same time";
  const ids = [randomUUID(), randomUUID()];
  const results = await Promise.all([
    p.a.call("request", { options: toB({ payload, id: ids[0] }) }),
    p.a.call("request", { options: toB({ payload, id: ids[1], session: sessionA }) }),
  ]);
  assert.deepEqual(results.map((r) => r.status), ["DELIVERED", "DELIVERED"]);
  const frames = await p.b.call("frames");
  assert.equal(frames.length, 2);
  assert.equal(frames[0].display_prompt, frames[1].display_prompt);
  assert.notEqual(frames[0].prompt.match(/ admission ([0-9a-f-]{36});/)[1],
    frames[1].prompt.match(/ admission ([0-9a-f-]{36});/)[1]);
  assert.deepEqual(new Set(frames.map((frame) => frame.request_id)), new Set(ids));
});

test("UTF-8 code point and CRLF JSON delimiter split across admission poll reads remain intact", async (t) => {
  const p = await pair(t, { admissionMode: "crlf-chunked" });
  const payload = "Multibyte admission: \u00e9 \u4f60\u597d \ud83d\ude80";
  assert.equal((await p.a.call("request", { options: toB({ payload }) })).status, "DELIVERED");
  const [event] = await p.b.call("admission-events");
  assert.equal(event.data.content, `[LAN peer ${pins[0]}] ${payload}`);
  assert.ok(event.data.transformedContent.includes("\r\n\r\n"));
});

test("local Desktop app-wide broadcast exceeds LAN frame bound without interrupting admission", async (t) => {
  const p = await pair(t, { admitDelay: 50 });
  assert.equal(LIMITS.frame, 32768);
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.deepEqual(await p.b.call("broadcasts"), [68626]);
  assert.equal((await p.b.call("admission-events")).length, 1);
});

test("large Desktop broadcast immediately after persisted admission cannot preempt confirmation", async (t) => {
  const p = await pair(t, { broadcastAfterAdmission: true, admitDelay: 50 });
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.deepEqual(await p.b.call("broadcasts"), [68626]);
});

test("pre-send Desktop authentication failure is OFFLINE with no dispatch", async (t) => {
  const p = await pair(t, { tokenFile: "different-valid-but-unauthorized-token" });
  assert.equal((await p.a.call("request", { options: toB() })).status, "OFFLINE");
  assert.deepEqual(await p.b.call("frames"), []);
});

test("timeout performs final admission scan even if regular poll ticks have not run", async (t) => {
  const p = await pair(t, { finalScanOnly: true, closeAfterSend: true, admitDelay: 50 });
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.equal((await p.b.call("frames")).length, 1);
});

test("Desktop graceful close after send still observes a delayed persisted admission", async (t) => {
  const p = await pair(t, { closeAfterSend: true, admitDelay: 50 });
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.equal((await p.b.call("frames")).length, 1);
});

test("Desktop abrupt disconnect after send still observes a delayed persisted admission", async (t) => {
  const p = await pair(t, { terminateAfterSend: true, admitDelay: 50 });
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.equal((await p.b.call("frames")).length, 1);
});

test("local broadcast above16MiB limit cannot cancel polling for already-sent admission", async (t) => {
  const p = await pair(t, { broadcastBytes: 16 * 1024 * 1024 + 1, admitDelay: 100 });
  assert.equal((await p.a.call("request", { options: toB() })).status, "DELIVERED");
  assert.deepEqual(await p.b.call("broadcasts"), [16 * 1024 * 1024 + 1]);
});

test("disconnected Desktop with no admission expires UNKNOWN without redispatch", async (t) => {
  const p = await pair(t, { closeAfterSend: true, neverAdmit: true });
  assert.equal((await p.a.call("request", { options: toB() })).status, "UNKNOWN");
  assert.equal((await p.b.call("frames")).length, 1);
  assert.deepEqual(await p.b.call("admission-events"), []);
});

test("authorization loss during post-disconnect polling remains UNKNOWN", async (t) => {
  const p = await pair(t, { terminateAfterSend: true, admitDelay: 400 });
  const pending = p.a.call("request", { options: toB() });
  assert.equal(await p.b.call("wait-frame"), 1);
  await p.b.call("unshare", { pin: pins[0], session: sessionB });
  assert.equal((await pending).status, "UNKNOWN");
});
