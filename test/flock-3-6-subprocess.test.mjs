import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import https from "node:https";
import crypto from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createBootstrapServer, enrollV3Device, createV3FlockInvite } from "../bootstrap-server.mjs";
import { SupportMailbox } from "../flock-support.mjs";
import { REQUIRED_RUNTIME_MODULES, computeRuntimeManifest, inspectProcess } from "../flock-lifecycle.mjs";
import { BRIDGE_VERSION, openFlockMembershipRegistry } from "../flock.mjs";
import { resolveOpenSsl, createTlsFixture as tlsFixture } from "./openssl.mjs";

const repo = path.resolve(".");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("Windows TLS fixture OpenSSL resolves PATH, Git-derived and standard locations without ambient OpenSSL", () => {
  const win = path.win32;
  const probe = (files, env) => resolveOpenSsl({ platform: "win32", env,
    isFile: (filename) => files.some((file) => win.normalize(file).toLowerCase() === win.normalize(filename).toLowerCase()) });
  assert.equal(probe(["X:\\tools\\openssl.exe", "Y:\\Git\\usr\\bin\\openssl.exe"],
    { PATH: "X:\\tools;Y:\\Git\\cmd" }), "X:\\tools\\openssl.exe");
  assert.equal(probe(["Y:\\Git\\cmd\\git.exe", "Y:\\Git\\usr\\bin\\openssl.exe"],
    { PATH: "Y:\\Git\\cmd" }), "Y:\\Git\\usr\\bin\\openssl.exe");
  assert.equal(probe(["C:\\Program Files\\Git\\usr\\bin\\openssl.exe"], { PATH: "" }),
    "C:\\Program Files\\Git\\usr\\bin\\openssl.exe");
  assert.equal(probe(["C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe"], { PATH: "" }),
    "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe");
  assert.equal(probe(["C:\\Program Files\\Git\\clangarm64\\bin\\openssl.exe"], { PATH: "" }),
    "C:\\Program Files\\Git\\clangarm64\\bin\\openssl.exe");
  assert.equal(probe(["X:\\Local\\Programs\\Git\\clangarm64\\bin\\openssl.exe"], { PATH: "", LOCALAPPDATA: "X:\\Local" }),
    "X:\\Local\\Programs\\Git\\clangarm64\\bin\\openssl.exe");
  assert.equal(probe(["C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe"], { PATH: "" }),
    "C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe");
  assert.throws(() => probe([], { PATH: "" }), /OpenSSL is required/);
});

function temp(t, cleanup = async () => {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-subprocess-"));
  t.after(async () => {
    try { await cleanup(); }
    finally { fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
  });
  return root;
}

test("no-OpenSSL TLS fixture creates a trusted localhost certificate with DNS and IP SANs using only Node", async (t) => {
  const root = temp(t);
  const tls = tlsFixture(root, { platform: "win32", env: { PATH: "" }, isFile: () => false,
    run: () => assert.fail("No external certificate command is available") });
  const certificate = new crypto.X509Certificate(tls.cert);
  assert.equal(certificate.subject, "CN=localhost");
  assert.equal(certificate.checkHost("localhost"), "localhost");
  assert.equal(certificate.checkIP("127.0.0.1"), "127.0.0.1");
  assert.equal(certificate.verify(certificate.publicKey), true);
  assert.equal(certificate.checkPrivateKey(crypto.createPrivateKey(tls.key)), true);
  const server = https.createServer(tls, (_req, res) => res.end("trusted"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const result = await new Promise((resolve, reject) => {
      https.get({ hostname: "127.0.0.1", port: server.address().port, ca: tls.cert, agent: false }, (res) => {
        let body = "";
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => resolve(body));
        res.on("error", reject);
      }).on("error", reject);
    });
    assert.equal(result, "trusted");
  } finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
});

test("subprocess fixture cleanup is registered before TLS setup failure and runs after resource teardown", async () => {
  const after = [];
  let tornDown = false;
  const root = temp({ after: (callback) => after.push(callback) }, async () => {
    assert.equal(fs.existsSync(root), true);
    tornDown = true;
  });
  try {
    assert.throws(() => tlsFixture(root, { platform: "win32", env: { PATH: "X:\\fixture" },
      isFile: () => true, run: () => { throw new Error("injected certificate setup failure"); } }), /injected certificate setup failure/);
  } finally { await after[0](); }
  assert.equal(tornDown, true);
  assert.equal(fs.existsSync(root), false);
});

function key(deviceId) {
  return { deviceId, ...crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  }) };
}

function childEnv(home, certPath) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (/^(COPILOT_|BRIDGE_|SIGNALR_|SERVICEBUS_|NODE_TEST_|GITHUB_TOKEN|GH_TOKEN|NODE_OPTIONS)/.test(name)) delete env[name];
  }
  return { ...env, COPILOT_HOME: home, COPILOT_CLI_PATH: "", HOME: path.dirname(home), USERPROFILE: path.dirname(home),
    APPDATA: path.join(home, "AppData"), NODE_EXTRA_CA_CERTS: certPath };
}

async function until(predicate, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const result = await predicate();
    if (result) return result;
    await sleep(100);
  }
  throw new Error("Subprocess condition timed out");
}

function stdioRpc(child) {
  let nextId = 0;
  let buffer = "";
  let stderr = "";
  const pending = new Map();
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let newline;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      if (!line.trim()) continue;
      const message = JSON.parse(line);
      pending.get(message.id)?.(message);
    }
  });
  return async (method, params = {}) => {
    const id = ++nextId;
    let timer;
    try {
      return await new Promise((resolve, reject) => {
        pending.set(id, resolve);
        timer = setTimeout(() => reject(new Error(`stdio RPC ${method} timed out: ${stderr}`)), 15000);
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      });
    } finally { clearTimeout(timer); pending.delete(id); }
  };
}

test("manual stop survives MCP host restarts and direct persistence launches without starting a daemon", async (t) => {
  const root = temp(t);
  const home = path.join(root, "home");
  const runtime = path.join(home, "flock");
  fs.mkdirSync(runtime, { recursive: true });
  fs.writeFileSync(path.join(runtime, "config.json"), JSON.stringify({
    machineId: "STOPPED-FIXTURE", scope: "personal", githubUser: "fixture",
    connectionString: "Endpoint=https://fixture.invalid;AccessKey=Zml4dHVyZQ==;Version=1.0;",
  }));
  const env = childEnv(home, "");
  const stopped = JSON.parse(execFileSync(process.execPath, [path.join(repo, "flock.mjs"), "stop-daemon"], {
    env, encoding: "utf8", windowsHide: true, timeout: 10000,
  }));
  assert.deepEqual(stopped, {
    stopped: false,
    status: "not_running",
    pid: null,
    reason: "no_daemon_pid",
    autostart: false,
  });
  for (let attempt = 0; attempt < 2; attempt++) {
    const child = spawn(process.execPath, [path.join(repo, "flock.mjs"), "mcp"], {
      env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
    });
    try {
      const rpc = stdioRpc(child);
      assert.equal((await rpc("initialize")).result.serverInfo.version, BRIDGE_VERSION);
      const result = await rpc("tools/call", { name: "list_remote_machines", arguments: {} });
      assert.equal(result.result.isError, true);
      assert.match(result.result.content[0].text, /explicitly stopped/);
      assert.equal(fs.existsSync(path.join(runtime, "daemon.pid")), false);
    } finally {
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill();
      await exited;
    }
  }
  assert.throws(() => execFileSync(process.execPath, [path.join(repo, "flock.mjs"), "daemon"], {
    env, encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"], timeout: 10000,
  }), (error) => /explicitly stopped/.test(String(error.stderr)));
  assert.equal(fs.existsSync(path.join(runtime, "daemon.pid")), false);
});

test("unconfigured and missing-vault MCP subprocesses initialize and submit support without credential helpers or transport authority", async (t) => {
  const root = temp(t);
  const tls = tlsFixture(root);
  const mailbox = new SupportMailbox(path.join(root, "support"));
  const bootstrap = createBootstrapServer({
    v3StorePath: path.join(root, "v3.json"), membersPath: path.join(root, "members.json"),
    supportRoot: mailbox.root, apiGet: async () => { throw new Error("Unexpected GitHub request"); },
  });
  const server = https.createServer(tls, bootstrap.listeners("request")[0]);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const origin = `https://127.0.0.1:${server.address().port}`;
  const previousSignalR = process.env.SIGNALR_CONNECTION_STRING;
  process.env.SIGNALR_CONNECTION_STRING = `Endpoint=${origin};AccessKey=fixture-only-key;Version=1.0;`;
  t.after(() => {
    if (previousSignalR === undefined) delete process.env.SIGNALR_CONNECTION_STRING;
    else process.env.SIGNALR_CONNECTION_STRING = previousSignalR;
  });
  const owner = key("owner-device");
  await enrollV3Device({
    githubUser: "owner", githubUserId: 1001, deviceId: owner.deviceId, machineId: "OWNER",
    scope: "work", publicKey: owner.publicKey, keyFingerprint: owner.deviceId,
  }, { storePath: path.join(root, "v3.json") });
  for (const missingVault of [false, true]) {
    const home = path.join(root, `home-${missingVault}`);
    fs.mkdirSync(path.join(home, "flock"), { recursive: true });
    if (missingVault) fs.writeFileSync(path.join(home, "flock", "config.json"), JSON.stringify({
      tokenLocalAuth: true, machineId: "NEWCOMER", scope: "work", bootstrapUrl: origin,
    }));
    const noHelpers = path.join(home, "helpers");
    fs.mkdirSync(noHelpers);
    for (const name of ["gh", "az", "git"]) {
      fs.writeFileSync(path.join(noHelpers, `${name}.cmd`), "@echo off\r\necho forbidden-helper>>\"%COPILOT_HOME%\\helper-used\"\r\nexit /b 99\r\n");
      fs.writeFileSync(path.join(noHelpers, name), '#!/bin/sh\necho forbidden-helper >> "$COPILOT_HOME/helper-used"\nexit 99\n', { mode: 0o700 });
    }
    const env = childEnv(home, tls.certPath);
    env.PATH = `${noHelpers}${path.delimiter}${env.PATH}`;
    const child = spawn(process.execPath, [path.join(repo, "flock.mjs"), "mcp"], { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    try {
      const rpc = stdioRpc(child);
      assert.equal((await rpc("initialize")).result.serverInfo.name, "copilot-flock");
      assert.ok((await rpc("tools/list")).result.tools.some((tool) => tool.name === "submit_support_report"));
      const call = (name, args = {}) => rpc("tools/call", { name, arguments: args });
      const publicKey = JSON.parse((await call("create_support_device_key")).result.content[0].text).publicKey;
      const ticket = mailbox.issue({ maintainerIdentity: key("owner"), flockId: "owner/work", supportPublicKey: publicKey });
      const report = await call("submit_support_report", { ticket, bootstrap_url: origin, text: "Enrollment is unavailable.", diagnostics: { stage: "startup" } });
      assert.notEqual(report.result.isError, true, report.result.content[0].text);
      assert.equal(JSON.parse(report.result.content[0].text).untrustedData.identity, "ticket_holder");
      const rejected = await call("list_remote_sessions", { to_machine: "REMOTE" });
      assert.equal(rejected.result.isError, true);
      assert.match(rejected.result.content[0].text, missingVault ? /TOKEN_LOCAL_CREDENTIALS_UNAVAILABLE/ : /UNCONFIGURED_TRANSPORT/);
      const status = await call("flock_status", { passive: true });
      assert.notEqual(status.result.isError, true);
      assert.equal(fs.existsSync(path.join(home, "helper-used")), false);
      assert.equal(fs.existsSync(path.join(home, "flock", "daemon.pid")), false);
      assert.equal(fs.existsSync(path.join(home, "flock", ".data", "support-quarantine", "mailbox")), false);
      const invite = await createV3FlockInvite({
        callerGitHubUser: "owner", callerGitHubUserId: 1001, targetAddress: "owner/team",
        invitedUser: `newcomer-${missingVault}`, invitedGitHubUserId: missingVault ? 2003 : 2002,
        allowedScopes: ["work"], tokenLocalVoucherAuth: true, bootstrapUrl: origin,
      }, { storePath: path.join(root, "v3.json") });
      const enrollment = { ...invite.enrollmentJson, bootstrapUrl: origin, tokenLocalVoucherAuth: true };
      const enrolled = await call("enroll_from_invite_json", { enrollment_json: enrollment });
      assert.notEqual(enrolled.result.isError, true, enrolled.result.content[0].text);
      const afterEnrollment = await call("list_flock_members", { flock: "owner/team" });
      assert.notEqual(afterEnrollment.result.isError, true, afterEnrollment.result.content[0].text);
      assert.ok(JSON.parse(afterEnrollment.result.content[0].text).members.length >= 1);
      await until(() => fs.existsSync(path.join(home, "flock", "daemon.pid")), 20000);
      assert.ok(Number(fs.readFileSync(path.join(home, "flock", "daemon.pid"), "utf8")) > 0,
        "Successful enrollment in non-passive MCP starts the daemon");
      assert.equal(fs.existsSync(path.join(home, "helper-used")), false);
    } finally {
      child.kill();
      await new Promise((resolve) => child.exitCode !== null || child.signalCode !== null ? resolve() : child.once("exit", resolve));
      const pidPath = path.join(home, "flock", "daemon.pid");
      if (fs.existsSync(pidPath)) {
        const pid = Number(fs.readFileSync(pidPath, "utf8"));
        const live = inspectProcess(pid);
        const pinPath = path.join(home, "flock", "daemon-identity.json");
        const pin = fs.existsSync(pinPath) ? JSON.parse(fs.readFileSync(pinPath, "utf8")) : null;
        if (pin?.pid === pid && pin.start === live?.start && pin.executable === live?.executable &&
            (pin.script === path.join(repo, "flock.mjs") || pin.script?.startsWith(home + path.sep))) {
          try { process.kill(pid); } catch {}
        }
      }
    }
  }
});

function frame(text) {
  const bytes = Buffer.from(text);
  const header = Buffer.alloc(bytes.length < 126 ? 2 : 4);
  header[0] = 0x81;
  if (bytes.length < 126) header[1] = bytes.length;
  else { header[1] = 126; header.writeUInt16BE(bytes.length, 2); }
  return Buffer.concat([header, bytes]);
}

test("real daemon connection failures persist only credential-free WebSocket diagnostics in log and state", async (t) => {
  let child;
  let service;
  const root = temp(t, async () => {
    if (child) {
      child.kill();
      await new Promise((resolve) => child.exitCode !== null || child.signalCode !== null ? resolve() : child.once("exit", resolve));
    }
    if (service?.listening) {
      service.closeAllConnections();
      await new Promise((resolve) => service.close(resolve));
    }
  });
  const home = path.join(root, "home");
  const runtime = path.join(home, "flock");
  fs.mkdirSync(runtime, { recursive: true });
  for (const filename of REQUIRED_RUNTIME_MODULES) fs.copyFileSync(path.join(repo, filename), path.join(runtime, filename));
  fs.writeFileSync(path.join(runtime, "runtime-manifest.json"),
    JSON.stringify(computeRuntimeManifest(runtime, { version: BRIDGE_VERSION })));
  const tls = tlsFixture(root);
  const canaries = ["WS_LOCAL_CANARY", "WS_SIGNATURE_CANARY", "WS_SIG_CANARY"];
  const capturedTokens = [];
  service = https.createServer(tls, (_req, res) => { res.writeHead(404); res.end(); });
  service.on("upgrade", (req, socket) => {
    socket.on("error", () => {});
    capturedTokens.push(new URL(req.url, "https://localhost").searchParams.get("access_token"));
    socket.end(`HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nwss://fixture.invalid/?token=${canaries[0]}&signature=${canaries[1]}&sig=${canaries[2]}`);
  });
  await new Promise((resolve) => service.listen(0, "127.0.0.1", resolve));
  fs.writeFileSync(path.join(runtime, "config.json"), JSON.stringify({
    machineId: "DIAGNOSTIC-PC", githubUser: "owner", scope: "work", bootstrapUrl: null,
    connectionString: `Endpoint=https://127.0.0.1:${service.address().port};AccessKey=fixture-only-key;Version=1.0;`,
    specs: { cpu: { model: "fixture" } },
  }));
  child = spawn(process.execPath, [path.join(runtime, "flock.mjs"), "daemon"], {
    env: childEnv(home, tls.certPath), stdio: "ignore", windowsHide: true,
  });
  const state = await until(() => {
    try {
      const current = JSON.parse(fs.readFileSync(path.join(runtime, "state.json"), "utf8"));
      return current.status === "error" && current;
    } catch { return false; }
  }, 45000);
  assert.ok(capturedTokens[0]);
  assert.match(state.lastError, /WebSocket upgrade failed/);
  assert.doesNotMatch(state.lastError, /[?#]/);
  const persisted = fs.readFileSync(path.join(runtime, "daemon.log"), "utf8") +
    fs.readFileSync(path.join(runtime, "state.json"), "utf8");
  for (const token of [...canaries, ...capturedTokens]) assert.equal(persisted.includes(token), false);
});

test("resident daemon self_update flushes its RPC response before real activator replaces its PID and records terminal verification", { timeout: 240000 }, async (t) => {
  let mcp;
  let daemon;
  let service;
  let runtime;
  const sockets = new Set();
  const root = temp(t, async () => {
    const candidates = new Set(daemon ? [daemon.pid] : []);
    try { candidates.add(Number(fs.readFileSync(path.join(runtime, "daemon.pid"), "utf8"))); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    for (const pid of candidates) {
      const identity = inspectProcess(pid);
      if (identity?.command?.includes(runtime) || identity?.argv?.some((arg) => arg.includes(runtime))) {
        try { process.kill(pid); } catch {}
      }
    }
    if (mcp) {
      mcp.kill();
      await new Promise((resolve) => mcp.exitCode !== null || mcp.signalCode !== null ? resolve() : mcp.once("exit", resolve));
    }
    for (const socket of sockets) socket.destroy();
    if (service?.listening) {
      service.closeAllConnections();
      await new Promise((resolve) => service.close(resolve));
    }
    if (mcp) await sleep(500);
    try {
      const journal = JSON.parse(fs.readFileSync(path.join(runtime, "update-activation.json"), "utf8"));
      if (journal.rollbackSource && path.dirname(journal.rollbackSource) === os.tmpdir() &&
          path.basename(journal.rollbackSource).startsWith(`flock-update-rollback-${journal.updateId}-`)) {
        fs.rmSync(journal.rollbackSource, { recursive: true, force: true });
      }
    } catch (error) { if (error.code !== "ENOENT") throw error; }
  });
  const home = path.join(root, "home");
  runtime = path.join(home, "flock");
  const source = path.join(root, "copilot-flock");
  fs.mkdirSync(runtime, { recursive: true });
  fs.mkdirSync(source, { recursive: true });
  for (const filename of REQUIRED_RUNTIME_MODULES) {
    fs.copyFileSync(path.join(repo, filename), path.join(runtime, filename));
    fs.copyFileSync(path.join(repo, filename), path.join(source, filename));
  }
  const manifest = computeRuntimeManifest(runtime, { version: BRIDGE_VERSION });
  for (const dir of [runtime, source]) fs.writeFileSync(path.join(dir, "runtime-manifest.json"), JSON.stringify(manifest));
  fs.appendFileSync(path.join(source, "flock.mjs"), "\n// subprocess update generation\n");
  fs.appendFileSync(path.join(source, "bridge.mjs"), "\n// subprocess update generation\n");
  const candidate = computeRuntimeManifest(source, { version: BRIDGE_VERSION });
  fs.writeFileSync(path.join(source, "runtime-manifest.json"), JSON.stringify(candidate));
  const git = (args, cwd = source) => execFileSync("git", ["-C", cwd, ...args], { stdio: "ignore", windowsHide: true });
  git(["init", "-b", "main"]);
  git(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "add", "."]);
  git(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "candidate"]);
  const bare = path.join(root, "origin.git");
  execFileSync("git", ["clone", "--bare", source, bare], { stdio: "ignore", windowsHide: true });
  git(["remote", "add", "origin", bare]);
  const tls = tlsFixture(root);
  const clients = new Map();
  const responses = [];
  let oldDaemonAliveAtReply = false;
  service = https.createServer(tls, (req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      const message = JSON.parse(body);
      if (message.target === "bridgeRpcResponse") {
        responses.push(message.arguments[0]);
        if (message.arguments[0].result?.status === "activating") {
          try { process.kill(daemon.pid, 0); oldDaemonAliveAtReply = true; } catch {}
        }
      }
      const user = decodeURIComponent(new URL(req.url, "https://localhost").pathname.split("/users/")[1] || "");
      const selected = user ? [clients.get(user)] : [...clients.values()];
      for (const socket of selected.filter(Boolean)) socket.write(frame(`${JSON.stringify({ type: 1, ...message })}\x1e`));
      res.writeHead(202); res.end();
    });
    service.keepAliveTimeout = 120000;
  });
  service.on("upgrade", (req, socket) => {
    const accept = crypto.createHash("sha1").update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    const jwt = new URL(req.url, "https://localhost").searchParams.get("access_token");
    const user = JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString()).sub;
    sockets.add(socket);
    let buffer = Buffer.alloc(0);
    let handshaken = false;
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        let length = buffer[1] & 127;
        let offset = 2;
        if (length === 126) { if (buffer.length < 4) return; length = buffer.readUInt16BE(2); offset = 4; }
        if (length === 127) return socket.destroy();
        const masked = Boolean(buffer[1] & 128);
        if (buffer.length < offset + (masked ? 4 : 0) + length) return;
        const opcode = buffer[0] & 15;
        buffer = buffer.subarray(offset + (masked ? 4 : 0) + length);
        if (opcode === 8) { socket.end(Buffer.from([0x88, 0])); return; }
        if (!handshaken) {
          handshaken = true;
          socket.write(frame("{}\x1e"), () => clients.set(user, socket));
        }
      }
    });
    socket.on("close", () => { sockets.delete(socket); if (clients.get(user) === socket) clients.delete(user); });
    socket.on("error", () => {});
  });
  await new Promise((resolve) => service.listen(0, "127.0.0.1", resolve));
  const endpoint = `https://127.0.0.1:${service.address().port}`;
  const owner = key("owner-device");
  const caller = key("caller-device");
  const config = {
    machineId: "TARGET", githubUser: "owner", scope: "work",
    connectionString: `Endpoint=${endpoint};AccessKey=fixture-only-key;Version=1.0;`, bootstrapUrl: null,
    specs: { cpu: { model: "fixture" } }, preferWscriptVbs: false,
  };
  fs.writeFileSync(path.join(runtime, "config.json"), JSON.stringify(config));
  const fingerprint = crypto.createHash("sha256").update(owner.publicKey).digest("hex").slice(0, 32);
  fs.writeFileSync(path.join(runtime, "identity.json"), JSON.stringify({ ...owner, fingerprint }));
  fs.writeFileSync(path.join(runtime, "cli-sessions.json"), JSON.stringify([
    { session_id: crypto.randomUUID(), title: "Fixture session", session_type: "chat", updated_at: new Date().toISOString() },
  ]));
  const flock = {
      flockId: "owner/work", ownerGitHubUser: "owner", trustTier: "owner", sessionVisibility: "all",
      rosterEpoch: 1,
      members: [["CALLER", caller], ["TARGET", owner]].map(([machineId, identity]) => ({
        machineId, githubUser: "owner", githubUserId: 1001, scope: "work", publicKey: identity.publicKey,
        keyFingerprint: crypto.createHash("sha256").update(identity.publicKey).digest("hex").slice(0, 32),
        deviceId: identity.deviceId, peerId: `1001:${identity.deviceId}`, trustTier: "owner",
      })),
  };
  fs.writeFileSync(path.join(runtime, "flocks.json"), JSON.stringify({
    ownerGitHubUser: "owner", flocks: { "owner/work": flock, owner: { ...flock, flockId: "owner" } },
  }));
  openFlockMembershipRegistry(path.join(runtime, "flocks.json")).reconcileV3BrokerFlock(flock);
  openFlockMembershipRegistry(path.join(runtime, "flocks.json")).reconcileV3BrokerFlock({ ...flock, flockId: "owner" });
  const env = childEnv(home, tls.certPath);
  mcp = spawn(process.execPath, [path.join(runtime, "flock.mjs"), "mcp"], { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const mcpRpc = stdioRpc(mcp);
  assert.equal((await mcpRpc("initialize")).result.serverInfo.name, "copilot-flock");
  await until(() => fs.existsSync(path.join(runtime, "daemon.pid")));
  daemon = { pid: Number(fs.readFileSync(path.join(runtime, "daemon.pid"), "utf8")) };
  await until(() => clients.get("TARGET"), 30000);
  const requestId = crypto.randomUUID();
  const params = { flock: "owner/work", operationId: requestId, correlationId: "subprocess-correlation" };
  const callerHome = path.join(root, "caller");
  fs.mkdirSync(path.join(callerHome, "flock"), { recursive: true });
  fs.writeFileSync(path.join(callerHome, "flock", "config.json"), JSON.stringify({ ...config, machineId: "CALLER" }));
  fs.writeFileSync(path.join(callerHome, "flock", "identity.json"), JSON.stringify({
    ...caller, fingerprint: crypto.createHash("sha256").update(caller.publicKey).digest("hex").slice(0, 32),
  }));
  fs.copyFileSync(path.join(runtime, "flocks.json"), path.join(callerHome, "flock", "flocks.json"));
  const callerProcess = spawn(process.execPath, ["--input-type=module", "-e", `
    import {loadConfig, invokeRemoteRpc} from ${JSON.stringify(pathToFileURL(path.join(runtime, "flock.mjs")).href)};
    try {
      const result = await invokeRemoteRpc(loadConfig({passive:true,autoFetchAz:false}), {
        toMachine:"TARGET", action:"self_update", params:${JSON.stringify(params)}, timeoutMs:90000
      });
      process.stdout.write(JSON.stringify(result), () => process.exit(0));
    } catch (error) { console.error(error.message); process.exit(1); }
  `], { env: childEnv(callerHome, tls.certPath), stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let stdout = "";
  let stderr = "";
  callerProcess.stdout.on("data", (chunk) => { stdout += chunk; });
  callerProcess.stderr.on("data", (chunk) => { stderr += chunk; });
  const exitCode = await new Promise((resolve) => callerProcess.once("exit", resolve));
  assert.equal(exitCode, 0, `${stderr}\n${fs.readFileSync(path.join(runtime, "daemon.log"), "utf8")}\n${
    fs.existsSync(path.join(runtime, "runtime-state.json")) ? fs.readFileSync(path.join(runtime, "runtime-state.json"), "utf8") : "No update state"
  }`);
  const response = JSON.parse(stdout);
  assert.ok(responses.some((entry) => entry.requestId === response.requestId));
  assert.equal(response.result.updateId, requestId);
  assert.equal(oldDaemonAliveAtReply, true);
  assert.equal(response.error, undefined, response.error);
  assert.equal(response.result.status, "activating");
  assert.equal(response.result.targetDigest, candidate.manifestDigest);
  assert.equal(response.result.previousPid, daemon.pid);
  assert.equal(response.result.updateId, requestId);
  const terminal = await until(() => {
    try {
      const state = JSON.parse(fs.readFileSync(path.join(runtime, "runtime-state.json"), "utf8"));
      return state.update?.updateId === requestId && ["verified", "rolled_back", "failed"].includes(state.update.phase) && state;
    } catch { return false; }
  }, 180000);
  const newPid = Number(fs.readFileSync(path.join(runtime, "daemon.pid"), "utf8"));
  t.diagnostic(`Unmocked activation terminal phase: ${terminal.update.phase}; ${terminal.update.error || "self-test verified"}`);
  assert.equal(terminal.update.phase, "verified", terminal.update.error);
  assert.equal(execFileSync("git", ["-C", source, "remote", "get-url", "origin"], {
    encoding: "utf8", windowsHide: true,
  }).trim(), bare, "Unattended update must not rewrite the configured repository origin");
  assert.notEqual(newPid, daemon.pid, `Activator must replace the original resident PID: ${JSON.stringify(terminal.update)}`);
  assert.ok(inspectProcess(newPid));
  if (terminal.update.phase === "verified") {
    assert.equal(terminal.update.manifestDigest, candidate.manifestDigest);
    assert.equal(JSON.parse(fs.readFileSync(path.join(runtime, "update-verification.json"), "utf8")).selfTest, true);
  } else {
    assert.ok(terminal.update.error);
    assert.ok(terminal.update.code);
  }
});
