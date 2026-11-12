import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import http from "node:http";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { pathToFileURL, fileURLToPath } from "node:url";

import {
  BRIDGE_VERSION,
  refreshLiveSpecs,
  matchesSelectorList,
  filterBroadcastTargets,
  readTranscriptMessagesFromTailSync,
  readTranscriptMessagesFromTailAsync,
  getLocalSessionTranscript,
  getLocalSessionTranscriptAsync,
  createIncrementalEventReader,
  isMatchingDispatchedUserEvent,
  injectLocalSessionMessage,
  handleRpcAction,
  computeMessageDedupKey,
  recentDeliveryCache,
  resolveCliMessage,
  formatClarificationRequestMessage,
  buildCrossSessionEnvelope,
  signV3EnrollmentRequest,
  ensureMachineIdentityKeypair,
  signRpcRequest,
  verifyRpcSignature,
  resolveVerifiedSenderIdentity,
  assertSafeTransferFilePath,
  waitForSessionReply,
  acquireLocalResourceLock,
  releaseLocalResourceLock,
  listLocalResourceLocks,
  verifyVoteBallotSignature,
  drainAndProcessOfflineQueue,
  loadProcessedOfflineState,
  saveProcessedOfflineState,
  getOfflineReplaySummary,
  reconcileOfflineReplayState,
  formatErrorDetail,
  writeConfigFileSecure,
  normalizeScope,
  parseFlockAddress,
  signV3RpcEnvelope,
  verifyV3RpcEnvelope,
  loadLocalFlocksConfig,
  shareThreadWithFlock,
  unshareThreadFromFlock,
  listSharedThreadsForMachine,
  enforceFlockPolicyAndWalls,
  validatePinnedBootstrapOrigin,
  recordSandboxManifestResource,
  teardownLocalSandbox,
  executeMcpTool,
  resolveLegacyFlockRoster,
  resolveBrokerFreeFlockRoster,
} from "../flock.mjs";

import {
  verifyGitHubRepoAccess,
  createBootstrapServer,
  saveMemberRegistration,
  enqueueOfflineStoreItem,
  drainOfflineStoreItems,
  ackOfflineStoreItems,
  normalizeV3Scope,
  enrollV3Device,
  refreshV3FlockToken,
  createV3FlockInvite,
  kickV3FlockMember,
  listV3UserFlocks,
} from "../bootstrap-server.mjs";

import { AzureTransport, azureEndpoints } from "../flock-azure.mjs";
import { BrokerFreeRuntime } from "../flock-broker-free.mjs";
import { ownerFingerprint } from "../flock-protocol.mjs";

test("reply and clarification shell examples strip unsafe remote identifiers", () => {
  const text = buildCrossSessionEnvelope({
    cfg: { installedScriptPath: "C:\\demo\\flock.mjs", host: "example.invalid", hub: "demo" },
    fromMachine: 'DEMO";$(danger)&|`\\\n-HOST',
    fromSessionId: 'session";$(danger)&|`\\\n:1',
    targetSessionId: 'recipient";$(danger)&|`\\\n.2',
    fromScope: "personal",
    message: "Synthetic test",
  });
  const commands = text.split("\n").filter((line) => line.startsWith("node "));
  assert.equal(commands.length, 2);
  for (const command of commands) {
    assert.match(command, /--to-machine "DEMOdanger-HOST" --to-session "sessiondanger:1" --from-session "recipientdanger\.2"/);
    for (const [, value] of command.matchAll(/--(?:to-machine|to-session|from-session) "([^"]*)"/g)) {
      assert.match(value, /^[A-Za-z0-9._:-]+$/);
    }
  }
});

test("public distribution has Apache licensing, loopback viewer defaults and synthetic demo traffic", () => {
  if (process.env.BRIDGE_FAST_VOTE_TEST === "1" && !fs.existsSync(new URL("../package.json", import.meta.url))) return;
  for (const file of ["../package.json", "../viewer/package.json"]) {
    const manifest = JSON.parse(fs.readFileSync(new URL(file, import.meta.url), "utf8"));
    assert.equal(manifest.license, "Apache-2.0");
    assert.equal(manifest.version, BRIDGE_VERSION);
  }
  const viewerLock = JSON.parse(fs.readFileSync(new URL("../viewer/package-lock.json", import.meta.url), "utf8"));
  assert.equal(viewerLock.version, BRIDGE_VERSION);
  assert.equal(viewerLock.packages[""].version, BRIDGE_VERSION);
  const license = fs.readFileSync(new URL("../LICENSE", import.meta.url), "utf8");
  assert.match(license, /Apache License\s+Version 2\.0, January 2004/);
  const viewer = fs.readFileSync(new URL("../viewer/viewer-server.mjs", import.meta.url), "utf8");
  assert.match(viewer, /const HOST = process\.env\.VIEWER_HOST \|\| "127\.0\.0\.1";/);
  assert.match(viewer, /return "127\.0\.0\.1";/);
  const traffic = JSON.parse(fs.readFileSync(new URL("../viewer/seed-traffic.json", import.meta.url), "utf8"));
  const machines = new Set(["MAIN-WORKSTATION", "3D-STUDIO-PC", "MINI-SERVER-PC", "LINUX-GPU-HOST", "LINUX-CONSOLE", "CLOUD-DEV-VM", "ARM64-LAPTOP"]);
  assert.ok(traffic.length >= 12 && traffic.length <= 16);
  assert.equal(new Set(traffic.map((event) => event.id)).size, traffic.length);
  for (const event of traffic) {
    assert.ok(machines.has(event.fromMachine) && machines.has(event.toMachine));
    assert.match(event.text, /^Synthetic demo(?: result)?: /);
    assert.ok(Number.isFinite(Date.parse(event.timestamp)));
  }
});

test("managed ARM template deploys Serverless SignalR and Standard Service Bus without secret outputs", () => {
  if (process.env.BRIDGE_FAST_VOTE_TEST === "1" && !fs.existsSync(new URL("../package.json", import.meta.url))) return;
  const template = JSON.parse(fs.readFileSync(new URL("../infra/azuredeploy.json", import.meta.url), "utf8"));
  assert.equal(template.$schema, "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#");
  assert.equal(template.parameters.location.defaultValue, "[resourceGroup().location]");
  assert.equal(template.parameters.signalrSku.defaultValue, "Free_F1");
  assert.deepEqual(template.parameters.signalrSku.allowedValues, ["Free_F1", "Standard_S1"]);
  assert.deepEqual(template.parameters.serviceBusSku.allowedValues, ["Standard"]);
  const signalr = template.resources.find((resource) => resource.type === "Microsoft.SignalRService/signalR");
  const serviceBus = template.resources.find((resource) => resource.type === "Microsoft.ServiceBus/namespaces");
  const topic = template.resources.find((resource) => resource.type === "Microsoft.ServiceBus/namespaces/topics");
  assert.ok(signalr && serviceBus && topic);
  assert.equal(signalr.apiVersion, "2023-02-01");
  assert.equal(signalr.sku.capacity, 1);
  assert.deepEqual(signalr.properties.features, [{ flag: "ServiceMode", value: "Serverless" }]);
  assert.deepEqual(signalr.properties.cors.allowedOrigins, ["*"]);
  assert.equal(serviceBus.apiVersion, "2022-10-01-preview");
  assert.equal(serviceBus.sku.name, "[parameters('serviceBusSku')]");
  assert.ok(topic.dependsOn.includes("[resourceId('Microsoft.ServiceBus/namespaces', variables('serviceBusNamespaceName'))]"));
  assert.equal(template.parameters.serviceBusTopicName.defaultValue, "copilot-bridge-offline");
  assert.ok(template.outputs.bootstrapUrl && template.outputs.webAppName);
  assert.doesNotMatch(JSON.stringify(template.outputs), /listKeys|ConnectionString|AccessKey/i);
});

test("bootstrap rejects public read access and requires authenticated owner, write access or explicit allowlisting", async () => {
  const previousAllowlist = process.env.ALLOWED_GITHUB_USERS;
  const previousMaintainer = process.env.PLATFORM_MAINTAINER_USER;
  const fullName = process.env.ALLOWED_GITHUB_REPO || process.env.ALLOWED_REPO || "erjadi/copilot-flock";
  const repository = {
    full_name: fullName,
    owner: { login: "demo-owner" },
    private: false,
    permissions: { pull: true, push: false, admin: false },
  };
  async function verify(repo = repository, user = { statusCode: 200, body: { login: "unrelated-user", id: 123 } }, repoStatus = 200) {
    const calls = [];
    const result = await verifyGitHubRepoAccess("synthetic-token", async (apiPath, token) => {
      assert.equal(token, "synthetic-token");
      calls.push(apiPath);
      return apiPath === "/user" ? user : { statusCode: repoStatus, body: repo };
    });
    assert.deepEqual(calls.sort(), [`/repos/${fullName.toLowerCase()}`, "/user"].sort());
    return result;
  }
  try {
    delete process.env.ALLOWED_GITHUB_USERS;
    process.env.PLATFORM_MAINTAINER_USER = "deployment-maintainer";
    assert.deepEqual(await verify(), {
      ok: false, statusCode: 403, reason: "Repository collaborator/write access required",
    });
    assert.equal((await verify({ ...repository, private: true })).statusCode, 403);
    assert.equal((await verify(repository, { statusCode: 200, body: { login: "DEMO-OWNER" } })).ok, true);
    for (const permission of ["push", "admin", "maintain"]) {
      const writable = { ...repository, permissions: { ...repository.permissions, [permission]: true } };
      assert.equal((await verify(writable)).ok, true);
      assert.equal((await verify(writable, { statusCode: 401, body: { login: "unrelated-user" } })).statusCode, 403);
      assert.equal((await verify(writable, { statusCode: 200, body: {} })).statusCode, 403);
    }
    assert.equal((await verify({ ...repository, full_name: "demo-owner/unrelated-repository" })).statusCode, 403);
    const maintainer = { statusCode: 200, body: { login: "DEPLOYMENT-MAINTAINER", id: 456 } };
    assert.equal((await verify(repository, maintainer)).ok, true);
    assert.equal((await verify({}, maintainer, 404)).ok, true);
    assert.equal((await verify({}, { statusCode: 401, body: maintainer.body }, 404)).statusCode, 403);
    process.env.PLATFORM_MAINTAINER_USER = "  unrelated-USER  ";
    assert.equal((await verify({}, undefined, 404)).ok, true);
    process.env.PLATFORM_MAINTAINER_USER = "deployment-maintainer";
    assert.equal((await verify({}, undefined, 404)).ok, false);
    process.env.ALLOWED_GITHUB_USERS = " first-user, UNRELATED-USER , last-user ";
    assert.equal((await verify()).ok, true);
    assert.equal((await verify({}, undefined, 404)).ok, true);
    assert.equal((await verify(repository, { statusCode: 401, body: { login: "unrelated-user" } })).statusCode, 403);
    assert.equal((await verify(repository, { statusCode: 200, body: { login: "another-user" } })).statusCode, 403);
  } finally {
    if (previousAllowlist === undefined) delete process.env.ALLOWED_GITHUB_USERS;
    else process.env.ALLOWED_GITHUB_USERS = previousAllowlist;
    if (previousMaintainer === undefined) delete process.env.PLATFORM_MAINTAINER_USER;
    else process.env.PLATFORM_MAINTAINER_USER = previousMaintainer;
  }
});

test("broker HTTP routes admit signed invited devices without repo write access and preserve privileged boundaries", async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "broker-invite-test-"));
  const storePath = path.join(tempRoot, "v3-flocks.json");
  const previousAllowlist = process.env.ALLOWED_GITHUB_USERS;
  const previousMaintainer = process.env.PLATFORM_MAINTAINER_USER;
  const fullName = process.env.ALLOWED_GITHUB_REPO || process.env.ALLOWED_REPO || "erjadi/copilot-flock";
  const keys = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const principals = {
    guest: { login: "invited-user", id: 2002 },
    other: { login: "other-user", id: 3003 },
    maintainer: { login: "deployment-maintainer", id: 1001 },
  };
  const server = createBootstrapServer({
    v3StorePath: storePath,
    v3PreviewStorePath: storePath,
    apiGet: async (apiPath, token) => apiPath === "/user"
      ? { statusCode: principals[token] ? 200 : 401, body: principals[token] || {} }
      : { statusCode: 200, body: { full_name: fullName, owner: { login: "source-owner" }, private: false, permissions: { pull: true, push: false, admin: false } } },
  });
  try {
    delete process.env.ALLOWED_GITHUB_USERS;
    process.env.PLATFORM_MAINTAINER_USER = "deployment-maintainer";
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    async function request(endpoint, token = "guest", body = null) {
      return await new Promise((resolve, reject) => {
        const payload = body === null ? null : JSON.stringify(body);
        const req = http.request({
          hostname: "127.0.0.1", port: server.address().port, path: endpoint,
          method: payload === null ? "GET" : "POST",
          headers: { Authorization: `Bearer ${token}`, ...(payload === null ? {} : { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }) },
        }, (res) => {
          let text = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => { text += chunk; });
          res.on("end", () => {
            try { resolve({ status: res.statusCode, body: JSON.parse(text) }); }
            catch (err) { reject(err); }
          });
          res.on("error", reject);
        });
        req.on("error", reject);
        req.setTimeout(5000, () => req.destroy(new Error("Test broker request timed out")));
        req.end(payload);
      });
    }
    const invite = await createV3FlockInvite({
      callerGitHubUser: "deployment-maintainer", callerGitHubUserId: 1001,
      targetAddress: "deployment-maintainer/studio-team", invitedUser: "invited-user",
      invitedGitHubUserId: 2002, durationMinutes: 10, maxDevices: 2,
    }, { storePath });
    const body = {
      deviceId: "demo-device", machineId: "ARM64-LAPTOP", scope: "work",
      publicKey: keys.publicKey, keyFingerprint: "demo-device",
      enrollmentJson: invite.enrollmentJson, maintainerVisibilityAck: true,
      githubUser: "deployment-maintainer", githubUserId: 1001,
    };
    const signed = signV3EnrollmentRequest(body, 2002, keys);
    assert.throws(() => signV3EnrollmentRequest(body, 0, keys), /numeric GitHub user ID/);
    assert.equal((await request("/api/v3/enroll", "guest", body)).status, 401);
    assert.equal((await request("/api/v3/enroll", "guest", { ...signed, enrollmentJson: null })).status, 403);
    assert.equal((await request("/api/v3/enroll", "guest", { ...signed, machineId: "MODIFIED-PC" })).status, 401);
    assert.equal((await request("/api/v3/enroll", "guest", { ...signed, signature: "AAAA" })).status, 401);
    assert.equal((await request("/api/v3/enroll", "guest", signV3EnrollmentRequest({ ...body, timestamp: new Date(Date.now() - 600000).toISOString() }, 2002, keys))).status, 401);
    assert.equal((await request("/api/v3/enroll", "other", signV3EnrollmentRequest(body, 3003, keys))).status, 403);
    assert.equal((await request("/api/v3/enroll", "guest", signV3EnrollmentRequest({ ...body, scope: "personal" }, 2002, keys))).status, 403);
    assert.equal((await request("/api/v3/preview/enroll", "guest", { ...signed, sandboxPrincipalOverride: { githubUser: "deployment-maintainer", githubUserId: 1001 } })).status, 403);
    assert.equal((await request("/api/v3/enroll", "invalid", signed)).status, 403);
    const enrollment = await request("/api/v3/enroll", "guest", signed);
    assert.equal(enrollment.status, 200, enrollment.body.error);
    assert.equal(enrollment.body.githubUser, "invited-user");
    const joined = enrollment.body.enrolledFlocks.find((flock) => flock.flockId === invite.flockId);
    assert.equal(joined.trustTier, "guest");
    assert.ok(Date.parse(joined.membershipExpiresAt) > Date.now());
    const myFlocks = await request("/api/v3/my-flocks");
    assert.equal(myFlocks.status, 200);
    assert.equal(myFlocks.body.githubUser, "invited-user");
    assert.ok(myFlocks.body.joinedFlocks.some((flock) => flock.flockId === invite.flockId));
    assert.equal((await request("/api/v3/my-flocks?githubUser=deployment-maintainer")).status, 403);
    for (const endpoint of ["/api/bootstrap", "/api/register", "/api/members", "/api/queue/status"]) {
      assert.equal((await request(endpoint)).status, 403, endpoint);
    }
    for (const endpoint of ["/api/queue/enqueue", "/api/queue/drain", "/api/queue/ack", "/api/v3/flocks/create", "/api/v3/flocks/invite", "/api/v3/flocks/kick"]) {
      assert.equal((await request(endpoint, "guest", {})).status, 403, endpoint);
    }
    const ownerEnrollment = await request("/api/v3/enroll", "maintainer", { ...body, enrollmentJson: null });
    assert.equal(ownerEnrollment.status, 200, ownerEnrollment.body.error);
    const ownerInvites = [];
    for (const target of ["deployment-maintainer", "deployment-maintainer/work"]) {
      const selfInvite = await request("/api/v3/flocks/invite", "maintainer", {
        targetAddress: target, invitedUser: "deployment-maintainer", allowedScopes: ["work"],
      });
      assert.equal(selfInvite.status, 200, selfInvite.body.error);
      ownerInvites.push(...selfInvite.body.enrollmentJson.flocks);
    }
    for (const flocks of [ownerInvites, [...ownerInvites].reverse()]) {
      const selfEnrollment = await request("/api/v3/enroll", "maintainer", {
        ...body, githubUser: "spoofed-label", githubUserId: 9999,
        enrollmentJson: { flocks, invitedUser: "spoofed-label", trustTier: "guest" },
      });
      assert.equal(selfEnrollment.status, 200, selfEnrollment.body.error);
      assert.equal(selfEnrollment.body.githubUser, "deployment-maintainer");
      assert.equal(selfEnrollment.body.githubUserId, 1001);
      assert.equal(selfEnrollment.body.enrolledFlocks.length, 2);
      assert.deepEqual(selfEnrollment.body.enrolledFlocks.map((flock) => flock.trustTier), ["owner", "owner"]);
    }
    for (const [trustTier, durationMinutes] of [["collaborator", null], ["guest", 10]]) {
      const scopedInvite = await request("/api/v3/flocks/invite", "maintainer", {
        targetAddress: "deployment-maintainer/work", invitedUser: "invited-user",
        allowedScopes: ["work"], trustTier, durationMinutes,
      });
      assert.equal(scopedInvite.status, 200, scopedInvite.body.error);
      const spoofedOwner = await request("/api/v3/enroll", "guest", signV3EnrollmentRequest({
        ...body, enrollmentJson: {
          ...scopedInvite.body.enrollmentJson,
          invitedUser: "deployment-maintainer", trustTier: "owner",
        },
      }, 2002, keys));
      assert.equal(spoofedOwner.status, 200, spoofedOwner.body.error);
      assert.equal(spoofedOwner.body.githubUser, "invited-user");
      assert.equal(spoofedOwner.body.enrolledFlocks.find((flock) =>
        flock.flockId === "deployment-maintainer/work").trustTier, trustTier);
    }
    const store = JSON.parse(fs.readFileSync(storePath, "utf8"));
    const voucher = store.flocks[invite.flockId].vouchers[invite.enrollmentJson.flocks[0].voucherId];
    voucher.membershipExpiresAtMs = Date.now() - 1;
    fs.writeFileSync(storePath, JSON.stringify(store));
    assert.equal((await request("/api/v3/enroll", "guest", signed)).status, 403);
    voucher.membershipExpiresAtMs = null;
    voucher.voucherExpiresAtMs = Date.now() - 1;
    fs.writeFileSync(storePath, JSON.stringify(store));
    assert.equal((await request("/api/v3/enroll", "guest", signed)).status, 403);
  } finally {
    if (previousAllowlist === undefined) delete process.env.ALLOWED_GITHUB_USERS;
    else process.env.ALLOWED_GITHUB_USERS = previousAllowlist;
    if (previousMaintainer === undefined) delete process.env.PLATFORM_MAINTAINER_USER;
    else process.env.PLATFORM_MAINTAINER_USER = previousMaintainer;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

/**
 * Minimal RFC 6455 WebSocket server for testing `injectLocalSessionMessage`
 * without touching the live Copilot Desktop instance.
 */
function startMockCopilotWsServer(onFrameReceived) {
  const sockets = new Set();
  let activeUpgradedCount = 0;

  const server = net.createServer((socket) => {
    sockets.add(socket);
    let upgraded = false;
    let buf = Buffer.alloc(0);

    socket.on("close", () => {
      sockets.delete(socket);
      if (upgraded) activeUpgradedCount--;
    });
    socket.on("error", () => {});

    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!upgraded) {
        const idx = buf.indexOf("\r\n\r\n");
        if (idx === -1) return;
        const header = buf.subarray(0, idx).toString("utf8");
        const keyMatch = header.match(/Sec-WebSocket-Key:\s*([^\r\n]+)/i);
        const accept = crypto
          .createHash("sha1")
          .update((keyMatch ? keyMatch[1].trim() : "") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
          .digest("base64");
        socket.write(
          [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            `Sec-WebSocket-Accept: ${accept}`,
            "\r\n",
          ].join("\r\n")
        );
        upgraded = true;
        activeUpgradedCount++;
        buf = buf.subarray(idx + 4);
      }

      while (buf.length >= 2) {
        const b0 = buf[0];
        const b1 = buf[1];
        const opcode = b0 & 0x0f;
        const masked = (b1 & 0x80) !== 0;
        let len = b1 & 0x7f;
        let offset = 2;
        if (len === 126) {
          if (buf.length < 4) return;
          len = buf.readUInt16BE(2);
          offset = 4;
        } else if (len === 127) {
          if (buf.length < 10) return;
          len = Number(buf.readBigUInt64BE(2));
          offset = 10;
        }
        const maskLen = masked ? 4 : 0;
        if (buf.length < offset + maskLen + len) return;
        let payload = Buffer.from(buf.subarray(offset + maskLen, offset + maskLen + len));
        if (masked) {
          const mask = buf.subarray(offset, offset + 4);
          for (let i = 0; i < payload.length; i++) {
            payload[i] ^= mask[i % 4];
          }
        }
        buf = buf.subarray(offset + maskLen + len);

        if (opcode === 0x08) {
          socket.end();
          return;
        }
        if (opcode === 0x01) {
          const text = payload.toString("utf8");
          let parsed;
          try {
            parsed = JSON.parse(text);
          } catch {
            continue;
          }
          onFrameReceived(parsed, {
            sendJson(obj) {
              const body = Buffer.from(JSON.stringify(obj), "utf8");
              let hdr;
              if (body.length < 126) {
                hdr = Buffer.from([0x81, body.length]);
              } else {
                hdr = Buffer.alloc(4);
                hdr[0] = 0x81;
                hdr[1] = 126;
                hdr.writeUInt16BE(body.length, 2);
              }
              socket.write(Buffer.concat([hdr, body]));
            },
            socket,
          });
        }
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        getActiveCount: () => activeUpgradedCount,
        close: () =>
          new Promise((res) => {
            for (const s of sockets) {
              try {
                s.destroy();
              } catch {}
            }
            server.close(() => res());
          }),
      });
    });
  });
}

function setupTempCopilotEnv() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bridge-test-"));
  fs.mkdirSync(path.join(tempRoot, "run"), { recursive: true });
  fs.mkdirSync(path.join(tempRoot, "session-state"), { recursive: true });
  fs.mkdirSync(path.join(tempRoot, "signalr-bridge"), { recursive: true });
  fs.mkdirSync(path.join(tempRoot, "flock"), { recursive: true });

  const sqliteMod =
    typeof process.getBuiltinModule === "function"
      ? process.getBuiltinModule("node:sqlite")
      : null;
  const dbPath = path.join(tempRoot, "data.db");
  const cliSessionsPath = path.join(tempRoot, "flock", "cli-sessions.json");

  if (sqliteMod?.DatabaseSync) {
    const db = new sqliteMod.DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE projects (
        id TEXT PRIMARY KEY,
        name TEXT,
        container_kind TEXT,
        main_repo_path TEXT,
        default_branch TEXT,
        github_owner TEXT,
        github_repo TEXT,
        last_opened_at TEXT,
        created_at TEXT
      );
      CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        title TEXT,
        session_type TEXT,
        mode TEXT,
        model TEXT,
        is_running INTEGER,
        provisional INTEGER,
        archived_at TEXT,
        updated_at TEXT,
        created_at TEXT
      );
      CREATE TABLE workspaces (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        project_id TEXT,
        name TEXT,
        branch TEXT,
        source_path TEXT,
        archived_at TEXT
      );
    `);
    db.close();
  }

  return {
    tempRoot,
    dbPath,
    insertSession({
      id,
      title = "Synthetic Session",
      isRunning = 1,
      updatedAt = "2026-11-06T19:00:00.000Z",
    }) {
      if (sqliteMod?.DatabaseSync) {
        const d = new sqliteMod.DatabaseSync(dbPath);
        d.prepare(
          `INSERT OR REPLACE INTO sessions (id, title, session_type, mode, model, is_running, provisional, archived_at, updated_at, created_at)
           VALUES (?, ?, 'general_chat', 'autopilot', 'gemini-4-argon', ?, 0, NULL, ?, ?)`
        ).run(id, title, isRunning, updatedAt, updatedAt);
        d.close();
      } else {
        let existing = [];
        try {
          if (fs.existsSync(cliSessionsPath)) {
            existing = JSON.parse(fs.readFileSync(cliSessionsPath, "utf8")) || [];
          }
        } catch {}
        existing = existing.filter((s) => s.session_id !== id);
        existing.push({
          session_id: id,
          title,
          session_type: "general_chat",
          mode: "autopilot",
          model: "gemini-4-argon",
          is_running: Boolean(isRunning),
          updated_at: updatedAt,
        });
        fs.writeFileSync(cliSessionsPath, JSON.stringify(existing, null, 2), "utf8");
      }
      const sessionDir = path.join(tempRoot, "session-state", id);
      fs.mkdirSync(sessionDir, { recursive: true });
      return path.join(sessionDir, "events.jsonl");
    },
    writeWsConfig(port, token = "test-ws-token") {
      fs.writeFileSync(path.join(tempRoot, "run", "ws.port"), String(port), "utf8");
      fs.writeFileSync(path.join(tempRoot, "run", "ws.token"), token, "utf8");
    },
    cleanup() {
      try {
        fs.rmSync(tempRoot, { recursive: true, force: true });
      } catch {}
    },
  };
}

test("parseTranscriptEventLine and reverse chunked tail reader preserve exact semantics across small chunks, UTF-8 boundaries, and oversized lines", async () => {
  const env = setupTempCopilotEnv();
  try {
    const sessionId = "11111111-2222-3333-4444-555555555555";
    const eventsPath = env.insertSession({ id: sessionId, title: "Chunk Boundary Test" });

    const rawEvents = [
      JSON.stringify({
        type: "session.start",
        id: "ev-0",
        timestamp: "2026-11-06T18:00:00.000Z",
        data: { sessionId },
      }),
      JSON.stringify({
        type: "user.message",
        id: "msg-1",
        timestamp: "2026-11-06T18:00:01.000Z",
        data: {
          messageId: "m-1",
          turnId: "0",
          content: "First user turn with multi-byte UTF-8: äöü ß 🚀 日本語",
        },
      }),
      JSON.stringify({
        type: "assistant.message",
        id: "msg-2",
        timestamp: "2026-11-06T18:00:02.000Z",
        data: {
          messageId: "m-2",
          turnId: "0",
          content: "",
          toolRequests: [{ name: "view" }, { toolName: "grep" }],
        },
      }),
      // Oversized non-message single line (> 64 KB) to exercise oversized-line skipping
      JSON.stringify({
        type: "tool.execution_complete",
        id: "tool-big",
        timestamp: "2026-11-06T18:00:03.000Z",
        data: {
          output: "X".repeat(90 * 1024) + ' mentions "user.message" inside tool output',
        },
      }),
      JSON.stringify({
        type: "user.message",
        id: "msg-empty-ignored",
        timestamp: "2026-11-06T18:00:03.500Z",
        data: { content: "   " },
      }),
      JSON.stringify({
        type: "user.message",
        id: "msg-3",
        timestamp: "2026-11-06T18:00:04.000Z",
        data: {
          messageId: "m-3",
          turnId: "1",
          transformedContent: "Fallback transformedContent prompt 🧠",
        },
      }),
      JSON.stringify({
        type: "assistant.message",
        id: "msg-4",
        timestamp: "2026-11-06T18:00:05.000Z",
        data: {
          messageId: "m-4",
          turnId: "1",
          content: "Final assistant answer ✅",
          toolRequests: [],
        },
      }),
    ];

    fs.writeFileSync(eventsPath, rawEvents.join("\r\n") + "\r\n", "utf8");

    // Test with a tiny 73-byte chunkSize and 32 KB maxLineBytes to force chunk splits inside UTF-8 and oversized line discard
    const syncAll = readTranscriptMessagesFromTailSync(eventsPath, 10, {
      chunkSize: 73,
      maxLineBytes: 32 * 1024,
    });
    const asyncAll = await readTranscriptMessagesFromTailAsync(eventsPath, 10, {
      chunkSize: 73,
      maxLineBytes: 32 * 1024,
    });

    assert.equal(syncAll.length, 4);
    assert.deepEqual(asyncAll, syncAll);
    assert.equal(syncAll[0].role, "user");
    assert.equal(syncAll[0].messageId, "m-1");
    assert.equal(syncAll[0].content, "First user turn with multi-byte UTF-8: äöü ß 🚀 日本語");
    assert.equal(syncAll[1].role, "assistant");
    assert.deepEqual(syncAll[1].toolCalls, ["view", "grep"]);
    assert.equal(syncAll[2].role, "user");
    assert.equal(syncAll[2].content, "Fallback transformedContent prompt 🧠");
    assert.equal(syncAll[3].role, "assistant");
    assert.equal(syncAll[3].content, "Final assistant answer ✅");
    assert.equal(syncAll[3].toolCalls, undefined);

    // Limit = 2 returns only the last 2 messages in chronological order
    const lastTwo = await readTranscriptMessagesFromTailAsync(eventsPath, 2, { chunkSize: 73 });
    assert.deepEqual(
      lastTwo.map((m) => m.messageId),
      ["m-3", "m-4"]
    );
  } finally {
    env.cleanup();
  }
});

test(
  "synthetic >512 MiB (>0x1fffffe8 V8 string limit) events.jsonl: get_transcript, non-wait send_message, wait send_message, and concurrent RPCs succeed rapidly without blocking event loop",
  { skip: process.env.BRIDGE_FAST_VOTE_TEST === "1" },
  async () => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = env.tempRoot;

  let wsServer = null;
  try {
    assert.equal(BRIDGE_VERSION, "3.4.1");

    const hugeSessionId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const eventsPath = env.insertSession({
      id: hugeSessionId,
      title: "Synthetic Huge 540MB Session",
    });

    // Build a synthetic >537 MB (540 MiB = 566,231,040 bytes > 0x1fffffe8 = 536,870,888 chars) events.jsonl
    const fd = fs.openSync(eventsPath, "w");
    try {
      const fillerLine =
        JSON.stringify({
          type: "tool.execution_complete",
          id: "filler",
          timestamp: "2026-11-06T18:10:00.000Z",
          data: { result: "A".repeat(65400) },
        }) + "\n";
      const batchBuf = Buffer.from(fillerLine.repeat(64), "utf8"); // ~4.19 MB per write
      const targetPaddingBytes = 540 * 1024 * 1024;
      let written = 0;
      while (written < targetPaddingBytes) {
        fs.writeSync(fd, batchBuf);
        written += batchBuf.length;
      }

      // Append 12 synthetic transcript messages at the tail of the 540 MiB log
      const tailLines = [];
      for (let i = 1; i <= 6; i++) {
        tailLines.push(
          JSON.stringify({
            type: "user.message",
            id: `u-${i}`,
            timestamp: `2026-11-06T18:40:0${i}.000Z`,
            data: {
              messageId: `u-msg-${i}`,
              turnId: String(i),
              content: `Synthetic user question #${i}`,
            },
          })
        );
        // Put 1.5 MB of tool output between turns 5 and 6 to verify multi-chunk tail traversal
        if (i === 5) {
          for (let k = 0; k < 24; k++) {
            tailLines.push(fillerLine.trimEnd());
          }
        }
        tailLines.push(
          JSON.stringify({
            type: "assistant.message",
            id: `a-${i}`,
            timestamp: `2026-11-06T18:40:1${i}.000Z`,
            data: {
              messageId: `a-msg-${i}`,
              turnId: String(i),
              content: `Synthetic assistant response #${i}`,
            },
          })
        );
      }
      fs.writeSync(fd, Buffer.from(tailLines.join("\n") + "\n", "utf8"));
    } finally {
      fs.closeSync(fd);
    }

    const fileSize = fs.statSync(eventsPath).size;
    assert.ok(
      fileSize > 0x1fffffe8,
      `Expected synthetic events.jsonl (${fileSize} bytes) to exceed V8 string limit 0x1fffffe8 (${0x1fffffe8})`
    );

    // 1. Confirm that legacy fs.readFileSync(eventsPath, "utf8") throws ERR_STRING_TOO_LONG on this file
    assert.throws(
      () => fs.readFileSync(eventsPath, "utf8"),
      /Cannot create a string longer than 0x1fffffe8 characters/
    );

    // 2. Verify synchronous and async getLocalSessionTranscript complete in < 50ms with exact semantics
    const tSync0 = performance.now();
    const syncTranscript = getLocalSessionTranscript(hugeSessionId, 6);
    const syncElapsedMs = performance.now() - tSync0;

    assert.equal(syncTranscript.messages.length, 6);
    assert.deepEqual(
      syncTranscript.messages.map((m) => m.messageId),
      ["u-msg-4", "a-msg-4", "u-msg-5", "a-msg-5", "u-msg-6", "a-msg-6"]
    );
    assert.ok(
      syncElapsedMs < 500,
      `Expected bounded sync transcript read < 500ms on 540 MiB log, took ${syncElapsedMs.toFixed(2)}ms`
    );

    // 3. Start mock Copilot Desktop WebSocket server to test simultaneous get_transcript + ping + list_sessions + send_message
    const cfg = {
      machineId: "TEST-MACHINE",
      scope: "private",
      hub: "copilotbridge",
      host: "your-signalr.service.signalr.net",
      endpoint: "https://your-signalr.service.signalr.net",
      installedScriptPath: path.join(env.tempRoot, "signalr-bridge", "bridge.mjs"),
    };

    wsServer = await startMockCopilotWsServer((frame) => {
      if (frame.type === "send_message") {
        // First append an UNRELATED user.message after 15ms to verify it cannot falsely ack our request
        setTimeout(() => {
          const unrelated = {
            type: "user.message",
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            data: {
              messageId: crypto.randomUUID(),
              content: "Unrelated local user prompt from another window",
            },
          };
          fs.appendFileSync(eventsPath, JSON.stringify(unrelated) + "\n", "utf8");
        }, 15);

        // Then append the actual matching user.message after 45ms
        setTimeout(() => {
          const matchedUser = {
            type: "user.message",
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            data: {
              messageId: crypto.randomUUID(),
              turnId: frame.request_id,
              content: frame.display_prompt,
              transformedContent: frame.prompt,
            },
          };
          fs.appendFileSync(eventsPath, JSON.stringify(matchedUser) + "\n", "utf8");
        }, 45);

        // And append the assistant reply after 80ms (for wait_for_reply tests)
        setTimeout(() => {
          const replyEv = {
            type: "assistant.message",
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            data: {
              messageId: "reply-on-540mb-log",
              turnId: frame.request_id,
              content: `Ack for ${frame.request_id}`,
              toolRequests: [],
            },
          };
          fs.appendFileSync(eventsPath, JSON.stringify(replyEv) + "\n", "utf8");
        }, 80);
      }
    });
    env.writeWsConfig(wsServer.port);

    // 4. Run concurrent get_transcript, ping, list_sessions, non-wait send_message, and wait send_message against the 540 MiB session
    let maxTimerLagMs = 0;
    let lastTick = performance.now();
    const lagInterval = setInterval(() => {
      const now = performance.now();
      const lag = now - lastTick - 10;
      if (lag > maxTimerLagMs) maxTimerLagMs = lag;
      lastTick = now;
    }, 10);

    const tConcurrent0 = performance.now();
    const [transcriptRes, pingRes, listRes, nonWaitSendRes, waitSendRes] = await Promise.all([
      handleRpcAction(cfg, {
        requestId: "req-transcript-1",
        action: "get_transcript",
        params: { session: hugeSessionId, limit: 8 },
      }),
      handleRpcAction(cfg, {
        requestId: "req-ping-1",
        action: "ping",
        params: {},
      }),
      handleRpcAction(cfg, {
        requestId: "req-list-1",
        action: "list_sessions",
        params: { limit: 10 },
      }),
      handleRpcAction(cfg, {
        requestId: "req-send-nonwait",
        fromMachine: "PEER-PC",
        action: "send_message",
        params: {
          targetSession: hugeSessionId,
          message: "Non-wait message on 540 MiB log",
          fromMachine: "PEER-PC",
          fromScope: "private",
          fromSessionId: "peer-session-1",
          fromSessionName: "Peer Session 1",
          waitForReply: false,
        },
      }),
      handleRpcAction(cfg, {
        requestId: "req-send-wait",
        fromMachine: "PEER-PC",
        action: "send_message",
        params: {
          targetSession: hugeSessionId,
          message: "Wait message on 540 MiB log",
          fromMachine: "PEER-PC",
          fromScope: "private",
          fromSessionId: "peer-session-2",
          fromSessionName: "Peer Session 2",
          waitForReply: true,
          waitTimeoutMs: 5000,
        },
      }),
    ]);
    const totalConcurrentMs = performance.now() - tConcurrent0;
    clearInterval(lagInterval);

    assert.equal(transcriptRes.messages.length, 8);
    assert.equal(pingRes.machineId, "TEST-MACHINE");
    assert.equal(listRes.count, 1);

    assert.equal(nonWaitSendRes.status, "delivered");
    assert.equal(nonWaitSendRes.dispatchedToRuntime, true);

    assert.equal(waitSendRes.status, "delivered");
    assert.equal(waitSendRes.dispatchedToRuntime, true);
    assert.equal(waitSendRes.reply?.completed, true);
    assert.equal(waitSendRes.reply?.content, `Ack for ${waitSendRes.requestId}`);

    assert.ok(
      totalConcurrentMs < 1500,
      `Expected all concurrent RPCs on 540 MiB log to finish in < 1500ms, took ${totalConcurrentMs.toFixed(2)}ms`
    );
    assert.ok(
      maxTimerLagMs < 500,
      `Expected event-loop timer lag < 500ms during concurrent 540 MiB operations, got ${maxTimerLagMs.toFixed(2)}ms`
    );
  } finally {
    if (wsServer) await wsServer.close();
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    env.cleanup();
  }
});

test("injectLocalSessionMessage rejects unrelated user.message events, never reports false dispatchedToRuntime as delivered, and closes WebSocket on timeout or error", async () => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = env.tempRoot;

  let wsServer = null;
  try {
    const sessionId = "99999999-8888-4777-8666-555555555555";
    const eventsPath = env.insertSession({ id: sessionId, title: "Dispatch Timeout Test" });
    fs.writeFileSync(
      eventsPath,
      JSON.stringify({
        type: "user.message",
        id: "old-1",
        data: { content: "Baseline user message before send" },
      }) + "\n",
      "utf8"
    );

    let mode = "unrelated-only";
    wsServer = await startMockCopilotWsServer((frame, client) => {
      if (mode === "unrelated-only") {
        // Append only an unrelated user.message and a tool output mentioning "user.message"
        setTimeout(() => {
          fs.appendFileSync(
            eventsPath,
            JSON.stringify({
              type: "tool.execution_complete",
              id: "t-1",
              data: { output: 'Found string "user.message" in log' },
            }) +
              "\n" +
              JSON.stringify({
                type: "user.message",
                id: "u-other",
                data: { content: "Completely different user message from another caller" },
              }) +
              "\n",
            "utf8"
          );
        }, 20);
      } else if (mode === "ws-error") {
        setTimeout(() => {
          client.sendJson({
            type: "error",
            request_id: frame.request_id,
            message: "Simulated desktop dispatch failure",
          });
        }, 20);
      }
    });
    env.writeWsConfig(wsServer.port);

    const cfg = {
      machineId: "TEST-MACHINE",
      scope: "private",
      hub: "copilotbridge",
      host: "your-signalr.service.signalr.net",
      endpoint: "https://your-signalr.service.signalr.net",
      installedScriptPath: path.join(env.tempRoot, "signalr-bridge", "bridge.mjs"),
    };

    // 1. Unrelated user.message must NOT acknowledge our request; dispatch timeout must throw and close WS
    await assert.rejects(
      () =>
        injectLocalSessionMessage({
          cfg,
          targetSession: sessionId,
          message: "Expected target message that never gets written",
          fromMachine: "PEER-PC",
          fromScope: "private",
          fromSessionId: "s-1",
          fromSessionName: "Sender 1",
          dispatchTimeoutMs: 220,
          dispatchPollIntervalMs: 25,
        }),
      /Timed out after 220ms waiting for Copilot Desktop runtime to acknowledge dispatch/
    );

    // Wait briefly for close handshake to finish and verify WebSocket was closed
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(wsServer.getActiveCount(), 0, "WebSocket must be closed after dispatch timeout");

    // 2. WebSocket error frame must fail fast and close WS
    mode = "ws-error";
    await assert.rejects(
      () =>
        injectLocalSessionMessage({
          cfg,
          targetSession: sessionId,
          message: "Message triggering ws error",
          fromMachine: "PEER-PC",
          fromScope: "private",
          fromSessionId: "s-2",
          fromSessionName: "Sender 2",
          dispatchTimeoutMs: 2000,
          dispatchPollIntervalMs: 25,
        }),
      /Copilot Desktop WebSocket error: Simulated desktop dispatch failure/
    );

    await new Promise((r) => setTimeout(r, 150));
    assert.equal(wsServer.getActiveCount(), 0, "WebSocket must be closed after WS error frame");
  } finally {
    if (wsServer) await wsServer.close();
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    env.cleanup();
  }
});

test("filterBroadcastTargets supports selective broadcast by wildcard machines, githubUser, scope, GPU, RAM, disk, and repo", () => {
  const sampleMachines = [
    {
      machineId: "ARM64-LAPTOP",
      scope: "work",
      githubUser: "erjadi",
      specs: {
        memory: { totalGb: 32, freeGb: 12 },
        gpus: [{ name: "Intel Iris Xe Graphics", vramGb: 1 }],
        disks: [{ mount: "C:", totalGb: 950, freeGb: 240 }],
      },
      recentSessions: [{ title: "Coordinator", repo: "erjadi/copilot-signalr-bridge" }],
    },
    {
      machineId: "MAIN-WORKSTATION",
      scope: "private",
      githubUser: "erjadi",
      specs: {
        memory: { totalGb: 64, freeGb: 40 },
        gpus: [{ name: "NVIDIA GeForce RTX 4090", vramGb: 24 }],
        disks: [{ mount: "C:", totalGb: 2000, freeGb: 850 }],
      },
      recentSessions: [{ title: "Stage event routing", repo: "erjadi/service-api" }],
    },
    {
      machineId: "3D-STUDIO-PC",
      scope: "private",
      githubUser: "erjadi",
      specs: {
        memory: { totalGb: 64, freeGb: 38 },
        gpus: [{ name: "NVIDIA GeForce RTX 4090", vramGb: 24 }],
        disks: [{ mount: "C:", totalGb: 1000, freeGb: 120 }],
      },
      recentSessions: [{ title: "Prompt tuning", repo: "example/material-lab" }],
    },
    {
      machineId: "GUEST-MACBOOK",
      scope: "private",
      githubUser: "guestdev",
      specs: {
        memory: { totalGb: 16, freeGb: 6 },
        gpus: [],
        disks: [{ mount: "/", totalGb: 512, freeGb: 45 }],
      },
      recentSessions: [{ title: "Guest thread", repo: "guestdev/demo" }],
    },
  ];

  assert.equal(matchesSelectorList("MAIN-WORKSTATION", "*-WORKSTATION,*-PC"), true);
  assert.equal(matchesSelectorList("ARM64-LAPTOP", "*-WORKSTATION,*-PC"), false);

  // Filter by wildcard machine + exclude
  const desktopsOnly = filterBroadcastTargets(sampleMachines, {
    localMachineId: "ARM64-LAPTOP",
    machines: "*-WORKSTATION,*-PC",
    exclude: "3D-STUDIO-PC",
  });
  assert.deepEqual(desktopsOnly.map((m) => m.machineId), ["MAIN-WORKSTATION"]);

  // Filter by GitHub handle
  const erjadiRemote = filterBroadcastTargets(sampleMachines, {
    localMachineId: "ARM64-LAPTOP",
    githubUser: "erjadi",
  });
  assert.deepEqual(erjadiRemote.map((m) => m.machineId), ["MAIN-WORKSTATION", "3D-STUDIO-PC"]);

  // Filter by GPU + minFreeDiskGb
  const rtxHighDisk = filterBroadcastTargets(sampleMachines, {
    localMachineId: "ARM64-LAPTOP",
    gpu: "RTX 4090",
    minRamGb: 64,
    minFreeDiskGb: 500,
  });
  assert.deepEqual(rtxHighDisk.map((m) => m.machineId), ["MAIN-WORKSTATION"]);

  // Filter by repo
  const serviceApiNodes = filterBroadcastTargets(sampleMachines, {
    localMachineId: "ARM64-LAPTOP",
    hasRepo: "service-api",
  });
  assert.deepEqual(serviceApiNodes.map((m) => m.machineId), ["MAIN-WORKSTATION"]);
});

test("refreshLiveSpecs and ping include githubUser and live hardware specs", async () => {
  const specs = refreshLiveSpecs(null);
  assert.ok(specs.cpu && specs.cpu.logicalCores >= 1);
  assert.ok(specs.memory && specs.memory.totalGb > 0);
  assert.ok(Array.isArray(specs.disks) && specs.disks.length >= 1);

  const pingRes = await handleRpcAction(
    {
      machineId: "TEST-NODE",
      scope: "private",
      githubUser: "erjadi",
      specs,
    },
    { action: "ping", params: {} }
  );
  assert.equal(pingRes.version, BRIDGE_VERSION);
  assert.equal(pingRes.githubUser, "erjadi");
  assert.ok(pingRes.specs && pingRes.specs.memory.totalGb > 0);
});

test("v1.8.0: daemon deduplication, chunked SHA-256 file transfer, and --message-file CLI parsing", async () => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = env.tempRoot;

  try {
    // 1. Test --message-file resolution
    const msgFile = path.join(env.tempRoot, "sample-msg.txt");
    fs.writeFileSync(msgFile, "Multi-line message with (parentheses) and *markdown*\nLine 2", "utf8");
    const parsedMsg = resolveCliMessage({ "message-file": msgFile }, []);
    assert.equal(parsedMsg, "Multi-line message with (parentheses) and *markdown*\nLine 2");

    // 2. Test chunked file transfer (send_file_chunk + pull_file_chunk) with SHA-256 verification
    const cfg = { machineId: "TEST-NODE", scope: "private", githubUser: "erjadi" };
    const payload = Buffer.from("Hello SignalR chunked binary transfer! 🚀".repeat(200), "utf8");
    const expectedSha256 = crypto.createHash("sha256").update(payload).digest("hex");
    const half = Math.floor(payload.length / 2);

    const chunk0 = await handleRpcAction(cfg, {
      action: "send_file_chunk",
      params: {
        remotePath: "test-artifact.bin",
        chunkIndex: 0,
        totalChunks: 2,
        dataBase64: payload.subarray(0, half).toString("base64"),
      },
    });
    assert.equal(chunk0.status, "chunk_written");

    const chunk1 = await handleRpcAction(cfg, {
      action: "send_file_chunk",
      params: {
        remotePath: "test-artifact.bin",
        chunkIndex: 1,
        totalChunks: 2,
        dataBase64: payload.subarray(half).toString("base64"),
        expectedSha256,
      },
    });
    assert.equal(chunk1.status, "completed");
    assert.equal(chunk1.sha256, expectedSha256);

    const pulled = await handleRpcAction(cfg, {
      action: "pull_file_chunk",
      params: {
        remotePath: chunk1.remotePath,
        offset: 0,
        length: 262144,
      },
    });
    assert.equal(pulled.eof, true);
    assert.equal(pulled.sha256, expectedSha256);
    assert.deepEqual(Buffer.from(pulled.dataBase64, "base64"), payload);

    // 3. Test deduplication key stability
    const k1 = computeMessageDedupKey({
      fromMachine: "PC-A",
      fromSessionId: "s-1",
      targetSession: "latest",
      message: "Hello",
      nowMs: 100000,
    });
    const k2 = computeMessageDedupKey({
      fromMachine: "pc-a",
      fromSessionId: "S-1",
      targetSession: "LATEST",
      message: "Hello",
      nowMs: 104000,
    });
    assert.equal(k1, k2);

    // 4. Test formatClarificationRequestMessage and CLARIFICATION_INSTRUCTION in envelope
    const clarifyMsg = formatClarificationRequestMessage({
      askingMachine: "MAIN-WORKSTATION",
      askingSessionId: "00000000-0000-4000-8000-000000000011",
      question: "Which UE 5.8 scene should we benchmark?",
      context: "Found both Scene 04 and Scene 09 in active worktrees.",
      options: ["Scene 04 (Kitchen)", "Scene 09 (Living Room)"],
    });
    assert.ok(clarifyMsg.includes("[CLARIFICATION REQUEST from @MAIN-WORKSTATION"));
    assert.ok(clarifyMsg.includes("1. Scene 04 (Kitchen)"));
    assert.ok(clarifyMsg.includes("2. Scene 09 (Living Room)"));

    const envText = buildCrossSessionEnvelope({
      cfg: {
        installedScriptPath: "C:\\Users\\demo-user\\.copilot\\signalr-bridge\\bridge.mjs",
        host: "your-signalr.service.signalr.net",
        hub: "copilotbridge",
      },
      fromMachine: "ARM64-LAPTOP",
      fromScope: "work",
      fromGitHubUser: "erjadi",
      fromSessionId: "00000000-0000-4000-8000-000000000012",
      fromSessionName: "Coordinator",
      targetSessionId: "00000000-0000-4000-8000-000000000011",
      message: "Run the benchmark",
    });
    assert.ok(envText.includes("CLARIFICATION_INSTRUCTION:"));
    assert.ok(envText.includes("ask_remote_originator_clarification"));

    // 5. Test Ed25519 anti-spoofing signature verification & registry header binding
    const aliceKey = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const bobKey = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const registryMembers = [
      {
        machineId: "ALICE-PC",
        githubUser: "alice",
        scope: "work",
        publicKey: aliceKey.publicKey,
      },
      {
        machineId: "ERJADI-PC",
        githubUser: "erjadi",
        scope: "private",
        publicKey: bobKey.publicKey,
      },
    ];

    const sentAt = new Date().toISOString();
    const signedAuth = signRpcRequest({
      requestId: "req-sec-1",
      sentAt,
      fromMachine: "ALICE-PC",
      toMachine: "MAIN-WORKSTATION",
      action: "send_message",
      params: {
        // Alice tries to spoof fromGitHubUser="erjadi" and fromScope="private" in params!
        fromGitHubUser: "erjadi",
        fromScope: "private",
        message: "What is your status?",
      },
      identity: {
        publicKey: aliceKey.publicKey,
        privateKey: aliceKey.privateKey,
        fingerprint: "alice-fp",
      },
    });

    const resolvedSender = resolveVerifiedSenderIdentity(
      { machineId: "MAIN-WORKSTATION", githubUser: "erjadi", scope: "private" },
      {
        requestId: "req-sec-1",
        sentAt,
        fromMachine: "ALICE-PC",
        toMachine: "MAIN-WORKSTATION",
        action: "send_message",
        params: {
          fromGitHubUser: "erjadi",
          fromScope: "private",
          message: "What is your status?",
        },
        auth: signedAuth,
        registryMembers,
      }
    );

    // Registry-bound identity overwrites spoofed params!
    assert.equal(resolvedSender.senderVerified, true);
    assert.equal(resolvedSender.fromMachine, "ALICE-PC");
    assert.equal(resolvedSender.fromGitHubUser, "alice");
    assert.equal(resolvedSender.fromScope, "work");
    assert.equal(resolvedSender.isCrossUser, true);
    assert.equal(resolvedSender.trustLevel, "cross_user_informational_only");

    // Forged signature or wrong key claiming ERJADI-PC must be rejected
    assert.throws(
      () =>
        resolveVerifiedSenderIdentity(
          { machineId: "MAIN-WORKSTATION", githubUser: "erjadi", scope: "private" },
          {
            requestId: "req-forged",
            sentAt,
            fromMachine: "ERJADI-PC",
            toMachine: "MAIN-WORKSTATION",
            action: "send_message",
            params: { message: "Spoofed" },
            auth: { ...signedAuth, fromMachine: "ERJADI-PC" },
            registryMembers,
          }
        ),
      /public key mismatch|signature verification failed/i
    );

    // 6. Test cross-user informational-only policy blocks config/file/state-changing RPCs
    for (const blockedAction of ["self_update", "send_file_chunk", "pull_file_chunk", "create_session"]) {
      await assert.rejects(
        () =>
          handleRpcAction(
            { machineId: "MAIN-WORKSTATION", githubUser: "erjadi", scope: "private" },
            {
              requestId: `req-block-${blockedAction}`,
              fromMachine: "ALICE-PC",
              action: blockedAction,
              params: { fromGitHubUser: "alice", remotePath: "test.txt" },
              registryMembers,
            }
          ),
        /Cross-user security policy violation/
      );
    }

    // Protected paths (.git, config.json, Startup, ..) are always blocked even for same-user
    assert.throws(() => assertSafeTransferFilePath("../secret.txt"), /path traversal/i);
    assert.throws(() => assertSafeTransferFilePath("C:\\repo\\.git\\config"), /protected config/i);
    assert.throws(
      () => assertSafeTransferFilePath("/home/erjadi/.copilot/signalr-bridge/config.json"),
      /protected config/i
    );

    // 7. Test v2.1.0 waitForSessionReply fallback to task_complete summary when assistant.message.content is empty (even after earlier progress commentary)
    const tcEventsPath = path.join(env.tempRoot, "tc-events.jsonl");
    fs.writeFileSync(
      tcEventsPath,
      [
        JSON.stringify({
          type: "user.message",
          id: crypto.randomUUID(),
          data: { turnId: "0", content: "Status check" },
        }),
        JSON.stringify({
          type: "assistant.message",
          id: crypto.randomUUID(),
          data: {
            turnId: "0",
            content: "Working on it...",
            toolRequests: [{ name: "powershell", arguments: { command: "hostname" } }],
          },
        }),
        JSON.stringify({
          type: "assistant.message",
          id: crypto.randomUUID(),
          data: {
            turnId: "0",
            content: "",
            toolRequests: [
              {
                name: "task_complete",
                arguments: { summary: "Summary extracted from task_complete toolRequest!" },
              },
            ],
          },
        }),
      ].join("\n") + "\n",
      "utf8"
    );
    const tcReply = await waitForSessionReply(tcEventsPath, 0, 2000, 25, "0");
    assert.equal(tcReply.completed, true);
    assert.equal(tcReply.content, "Summary extracted from task_complete toolRequest!");

    // 7b. Lengthy intermediate progress (>200 chars) must NEVER override a shorter terminal task_complete summary
    const tcLongProgressPath = path.join(env.tempRoot, "tc-long-progress.jsonl");
    fs.writeFileSync(
      tcLongProgressPath,
      [
        JSON.stringify({
          type: "user.message",
          id: crypto.randomUUID(),
          data: { turnId: "0", content: "Deploy service" },
        }),
        JSON.stringify({
          type: "assistant.message",
          id: crypto.randomUUID(),
          data: {
            turnId: "0",
            content:
              "I will now inspect the repository structure, validate the environment variables, check disk space, and run the deployment script across the target cluster nodes...",
            toolRequests: [{ name: "powershell", arguments: { command: "df -h" } }],
          },
        }),
        JSON.stringify({
          type: "assistant.message",
          id: crypto.randomUUID(),
          data: {
            turnId: "0",
            content: "",
            toolRequests: [
              {
                name: "task_complete",
                arguments: { summary: "Deployment failed. Do not proceed." },
              },
            ],
          },
        }),
      ].join("\n") + "\n",
      "utf8"
    );
    const tcFailureReply = await waitForSessionReply(tcLongProgressPath, 0, 2000, 25, "0");
    assert.equal(tcFailureReply.completed, true);
    assert.equal(tcFailureReply.content, "Deployment failed. Do not proceed.");

    // 8. Test v2.1.0 daemon resource locks (acquire, collision, renew, release)
    const lockCfg = { machineId: "TEST-LOCK-NODE" };
    const l1 = acquireLocalResourceLock(lockCfg, {
      resource: "RTX-GPU",
      ownerMachine: "3D-STUDIO-PC",
      ownerSessionId: "s-1",
      ttlSeconds: 120,
      reason: "UE 5.8 render",
    });
    assert.equal(l1.acquired, true);

    const lCollision = acquireLocalResourceLock(lockCfg, {
      resource: "rtx-gpu",
      ownerMachine: "3D-STUDIO-PC",
      ownerSessionId: "s-2",
      ttlSeconds: 60,
    });
    assert.equal(lCollision.acquired, false);
    assert.equal(lCollision.holder.ownerMachine, "3D-STUDIO-PC");

    // Another caller on the SAME machine omitting ownerSessionId must NOT steal s-1's lock
    const lSameMachineNoSession = acquireLocalResourceLock(lockCfg, {
      resource: "rtx-gpu",
      ownerMachine: "3D-STUDIO-PC",
      ownerSessionId: null,
      ttlSeconds: 60,
    });
    assert.equal(lSameMachineNoSession.acquired, false);

    // Another caller on the SAME machine omitting ownerSessionId and leaseId must NOT release s-1's lock
    assert.throws(
      () =>
        releaseLocalResourceLock(lockCfg, {
          resource: "RTX-GPU",
          ownerMachine: "3D-STUDIO-PC",
          ownerSessionId: null,
        }),
      /without matching leaseId\/session/i
    );

    const listed = listLocalResourceLocks(lockCfg);
    assert.equal(listed.count, 1);

    const released = releaseLocalResourceLock(lockCfg, {
      resource: "RTX-GPU",
      ownerMachine: "3D-STUDIO-PC",
      ownerSessionId: "s-1",
    });
    assert.equal(released.released, true);
    assert.equal(listLocalResourceLocks(lockCfg).count, 0);

    // 9. Test offline-queued message replay with >6 minute age succeeds when maxSkewMs matches TTL
    const tenMinAgoIso = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const delayedAuth = signRpcRequest({
      requestId: "req-delayed-10m",
      sentAt: tenMinAgoIso,
      fromMachine: "ALICE-PC",
      toMachine: "MAIN-WORKSTATION",
      action: "send_message",
      params: { message: "Queued while laptop was asleep" },
      identity: {
        publicKey: aliceKey.publicKey,
        privateKey: aliceKey.privateKey,
        fingerprint: "alice-fp",
      },
    });
    const delayedVerified = resolveVerifiedSenderIdentity(
      { machineId: "MAIN-WORKSTATION", githubUser: "erjadi", scope: "private" },
      {
        requestId: "req-delayed-10m",
        sentAt: tenMinAgoIso,
        fromMachine: "ALICE-PC",
        toMachine: "MAIN-WORKSTATION",
        action: "send_message",
        params: { message: "Queued while laptop was asleep" },
        auth: delayedAuth,
        maxSkewMs: 86400 * 1000,
        registryMembers,
      }
    );
    assert.equal(delayedVerified.senderVerified, true);

    // 10. Test concurrent offline queue enqueue + peekOnly drain + selective ack
    const testQueuePath = path.join(env.tempRoot, "offline-queue-test.json");
    const slowPublish = async (_entry, delayMs) => {
      await new Promise((r) => setTimeout(r, delayMs));
      return { published: true };
    };
    const [enq1, enq2] = await Promise.all([
      enqueueOfflineStoreItem({
        toMachine: "ARM64-LAPTOP",
        rpcPayload: { requestId: "q-req-1", fromMachine: "MAIN-WORKSTATION", action: "send_message" },
        githubUser: "erjadi",
        queuePath: testQueuePath,
        publishFn: (e) => slowPublish(e, 45),
      }),
      enqueueOfflineStoreItem({
        toMachine: "ARM64-LAPTOP",
        rpcPayload: { requestId: "q-req-2", fromMachine: "MINI-SERVER-PC", action: "send_message" },
        githubUser: "erjadi",
        queuePath: testQueuePath,
        publishFn: (e) => slowPublish(e, 10),
      }),
    ]);
    assert.equal(enq1.status, "queued");
    assert.equal(enq2.status, "queued");

    const peeked = await drainOfflineStoreItems({
      targetMachine: "ARM64-LAPTOP",
      peekOnly: true,
      queuePath: testQueuePath,
    });
    assert.equal(peeked.drainedCount, 2);

    const acked = await ackOfflineStoreItems({
      requestIds: ["q-req-1"],
      queuePath: testQueuePath,
    });
    assert.equal(acked.ackedCount, 1);
    assert.equal(acked.remainingCount, 1);

    // 11. Test failed write/rename propagates storage error (500) instead of silently reporting ok:true
    const invalidQueuePath = path.join(testQueuePath, "nested-under-file", "queue.json");
    await assert.rejects(
      () =>
        enqueueOfflineStoreItem({
          toMachine: "ARM64-LAPTOP",
          rpcPayload: { requestId: "q-req-fail", fromMachine: "MAIN-WORKSTATION", action: "send_message" },
          githubUser: "erjadi",
          queuePath: invalidQueuePath,
          publishFn: async () => ({ published: false }),
        }),
      (err) => err.code === "QUEUE_STORAGE_ERROR" && err.statusCode === 500
    );

    // 12. Test v2.2.0 verifyVoteBallotSignature over full 40-char commit SHA
    const fullCommit = "1234567890abcdef1234567890abcdef12345678";
    const votePayload = `vote|ALICE-PC|v2.2.0-rc|${fullCommit}|ACCEPT`;
    const voteSig = crypto
      .sign(null, Buffer.from(votePayload, "utf8"), aliceKey.privateKey)
      .toString("base64");
    const validBallot = {
      machineId: "ALICE-PC",
      branch: "v2.2.0-rc",
      candidateCommit: fullCommit,
      candidateSha: fullCommit.slice(0, 7),
      vote: "ACCEPT",
      votePayload,
      voteSignature: voteSig,
    };
    assert.equal(verifyVoteBallotSignature(validBallot, aliceKey.publicKey), true);
    assert.equal(verifyVoteBallotSignature(validBallot, bobKey.publicKey), false);
    assert.equal(
      verifyVoteBallotSignature({ ...validBallot, candidateCommit: "aaaa567890abcdef1234567890abcdef12345678" }, aliceKey.publicKey),
      false
    );

    // 13. Test v2.2.0 idempotent drainAndProcessOfflineQueue across failed ACK + restart
    const offlineStatePath = path.join(env.tempRoot, "processed-offline-test.json");
    let handleCalls = 0;
    let ackCalls = 0;
    let ackShouldSucceed = false;
    const mockQueuedMessages = [
      {
        requestId: "offline-idem-1",
        fromMachine: "MAIN-WORKSTATION",
        toMachine: "ARM64-LAPTOP",
        ttlSeconds: 86400,
        rpcPayload: {
          requestId: "offline-idem-1",
          fromMachine: "MAIN-WORKSTATION",
          action: "ping",
          params: {},
        },
      },
    ];

    // First drain: handleFn succeeds, ackFn fails (returns { ok: false })
    const run1Count = await drainAndProcessOfflineQueue(
      { machineId: "ARM64-LAPTOP" },
      {
        statePath: offlineStatePath,
        drainFn: async () => ({ ok: true, messages: mockQueuedMessages }),
        ackFn: async () => {
          ackCalls++;
          return { ok: ackShouldSucceed };
        },
        handleFn: async () => {
          handleCalls++;
          return { ok: true };
        },
      }
    );
    assert.equal(run1Count, 1);
    assert.equal(handleCalls, 1);
    assert.deepEqual(loadProcessedOfflineState(offlineStatePath).pendingAckIds, ["offline-idem-1"]);

    // Second drain (same unacked message still in queue): must NOT re-execute handleFn, and must clear pendingAckIds once ACK succeeds
    ackShouldSucceed = true;
    const run2Count = await drainAndProcessOfflineQueue(
      { machineId: "ARM64-LAPTOP" },
      {
        statePath: offlineStatePath,
        drainFn: async () => ({ ok: true, messages: mockQueuedMessages }),
        ackFn: async () => {
          ackCalls++;
          return { ok: ackShouldSucceed };
        },
        handleFn: async () => {
          handleCalls++;
          return { ok: true };
        },
      }
    );
    assert.equal(run2Count, 0);
    assert.equal(handleCalls, 1, "Idempotent replay must not execute handleFn a second time");
    assert.deepEqual(loadProcessedOfflineState(offlineStatePath).pendingAckIds, []);

    // 14. Test saveProcessedOfflineState / drainAndProcessOfflineQueue fail-closed pre-dispatch durability AND cross-process crash/interruption recovery
    const badStatePath = path.join(testQueuePath, "not-a-dir", "processed.json");
    assert.throws(
      () =>
        saveProcessedOfflineState(
          { processedIds: ["x-1"], pendingAckIds: ["x-1"] },
          badStatePath
        ),
      (err) => err.code === "OFFLINE_STATE_STORAGE_ERROR" && err.statusCode === 500
    );

    const badDrainStatePath = path.join(testQueuePath, "not-a-dir-2", "processed.json");
    let badHandleCalls = 0;
    await assert.rejects(
      () =>
        drainAndProcessOfflineQueue(
          { machineId: "ARM64-LAPTOP" },
          {
            statePath: badDrainStatePath,
            drainFn: async () => ({
              ok: true,
              messages: [
                {
                  requestId: "offline-disk-fail-1",
                  rpcPayload: { requestId: "offline-disk-fail-1", action: "ping" },
                },
              ],
            }),
            ackFn: async () => ({ ok: false }),
            handleFn: async () => {
              badHandleCalls++;
              return { ok: true };
            },
          }
        ),
      (err) => err.code === "OFFLINE_STATE_STORAGE_ERROR" && err.statusCode === 500
    );
    assert.equal(
      badHandleCalls,
      0,
      "Pre-dispatch durability failure must fail closed BEFORE handleFn executes"
    );

    // 14a. Storage-failure -> storage-recovery -> retry regression:
    // If pre-dispatch persistence fails (0 executions), fixing storage and retrying on the same statePath must execute once (1 execution, 1 ACK) and NOT mark the request ambiguous!
    const recoverableBlockerPath = path.join(env.tempRoot, "recoverable-parent-blocker");
    fs.writeFileSync(recoverableBlockerPath, "file-blocking-mkdir", "utf8");
    const recoverableStatePath = path.join(recoverableBlockerPath, "processed.json");
    let recovExecutions = 0;
    let recovAcks = 0;
    await assert.rejects(
      () =>
        drainAndProcessOfflineQueue(
          { machineId: "ARM64-LAPTOP" },
          {
            statePath: recoverableStatePath,
            drainFn: async () => ({
              ok: true,
              messages: [
                {
                  requestId: "offline-recover-retry-1",
                  rpcPayload: { requestId: "offline-recover-retry-1", action: "ping" },
                },
              ],
            }),
            ackFn: async () => {
              recovAcks++;
              return { ok: true };
            },
            handleFn: async () => {
              recovExecutions++;
              return { ok: true };
            },
          }
        ),
      (err) => err.code === "OFFLINE_STATE_STORAGE_ERROR" && err.statusCode === 500
    );
    assert.equal(recovExecutions, 0);
    assert.equal(recovAcks, 0);

    // Recover storage by removing the blocking file so mkdirSync succeeds on retry
    fs.unlinkSync(recoverableBlockerPath);
    const recovCount = await drainAndProcessOfflineQueue(
      { machineId: "ARM64-LAPTOP" },
      {
        statePath: recoverableStatePath,
        drainFn: async () => ({
          ok: true,
          messages: [
            {
              requestId: "offline-recover-retry-1",
              rpcPayload: { requestId: "offline-recover-retry-1", action: "ping" },
            },
          ],
        }),
        ackFn: async () => {
          recovAcks++;
          return { ok: true };
        },
        handleFn: async () => {
          recovExecutions++;
          return { ok: true };
        },
      }
    );
    assert.equal(recovCount, 1);
    assert.equal(recovExecutions, 1, "Retry after storage recovery must execute handleFn once");
    assert.equal(recovAcks, 1, "Retry after storage recovery must ACK once after execution");
    const postRecovState = loadProcessedOfflineState(recoverableStatePath);
    assert.deepEqual(postRecovState.processedIds, ["offline-recover-retry-1"]);
    assert.deepEqual(postRecovState.ambiguousIds, []);

    // 14b. Cross-process regression: Process 1 establishes pre-dispatch claim, executes side-effect, and crashes before post-dispatch completion save.
    // Process 2 (separate OS process) must detect inFlightIds, skip handleFn (never executing a 2nd time), and quarantine into ambiguousIds.
    const bridgeModuleUrl = pathToFileURL(
      path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "bridge.mjs")
    ).href;
    const crossProcStatePath = path.join(env.tempRoot, "cross-proc-offline-state.json");
    const crossProcCounterPath = path.join(env.tempRoot, "cross-proc-counter.txt");
    fs.writeFileSync(crossProcCounterPath, "", "utf8");

    const workerScriptPath = path.join(env.tempRoot, "cross-proc-worker.mjs");
    fs.writeFileSync(
      workerScriptPath,
      `import fs from "node:fs";
import { drainAndProcessOfflineQueue, loadProcessedOfflineState } from ${JSON.stringify(bridgeModuleUrl)};
const [mode, statePath, counterPath] = process.argv.slice(2);
await drainAndProcessOfflineQueue(
  { machineId: "ARM64-LAPTOP" },
  {
    statePath,
    drainFn: async () => ({
      ok: true,
      messages: [
        {
          requestId: "offline-cross-proc-1",
          rpcPayload: { requestId: "offline-cross-proc-1", action: "ping" },
        },
      ],
    }),
    ackFn: async () => ({ ok: mode === "recover" }),
    handleFn: async () => {
      fs.appendFileSync(counterPath, "executed\\n", "utf8");
      if (mode === "crash-mid-execution") {
        // Simulate abrupt process termination after side-effect but before post-dispatch save/ACK
        process.exit(0);
      }
      return { ok: true };
    },
  }
);
if (mode === "recover") {
  const st = loadProcessedOfflineState(statePath);
  process.stdout.write(JSON.stringify(st));
}
`,
      "utf8"
    );

    execFileSync(
      process.execPath,
      [workerScriptPath, "crash-mid-execution", crossProcStatePath, crossProcCounterPath],
      { stdio: "pipe" }
    );
    const afterCrashExecutions = fs
      .readFileSync(crossProcCounterPath, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean).length;
    assert.equal(afterCrashExecutions, 1);
    assert.deepEqual(loadProcessedOfflineState(crossProcStatePath).inFlightIds, [
      "offline-cross-proc-1",
    ]);

    const recoverOut = execFileSync(
      process.execPath,
      [workerScriptPath, "recover", crossProcStatePath, crossProcCounterPath],
      { encoding: "utf8", stdio: "pipe" }
    );
    const afterRecoverExecutions = fs
      .readFileSync(crossProcCounterPath, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean).length;
    assert.equal(
      afterRecoverExecutions,
      1,
      "Second OS process must NOT re-execute handleFn after interrupted/ambiguous prior execution"
    );
    const recoveredState = JSON.parse(recoverOut);
    assert.deepEqual(recoveredState.inFlightIds, []);
    assert.deepEqual(recoveredState.ambiguousIds, ["offline-cross-proc-1"]);
    assert.deepEqual(recoveredState.pendingAckIds, []);

    // 15. Test getOfflineReplaySummary, two-process reconcileOfflineReplayState (no daemon cache resurrection), formatErrorDetail, and writeConfigFileSecure
    const summaryBefore = getOfflineReplaySummary(crossProcStatePath);
    assert.equal(summaryBefore.ambiguousCount, 1);
    assert.deepEqual(summaryBefore.ambiguousIds, ["offline-cross-proc-1"]);

    // Run reconciliation in a separate OS process (simulating `node bridge.mjs queue --reconcile-ambiguous` while daemon has crossProcStatePath cached in memory)
    const reconcileWorkerPath = path.join(env.tempRoot, "reconcile-worker.mjs");
    fs.writeFileSync(
      reconcileWorkerPath,
      `import { reconcileOfflineReplayState } from ${JSON.stringify(bridgeModuleUrl)};
const [statePath] = process.argv.slice(2);
const res = reconcileOfflineReplayState(
  { clearAmbiguousIds: ["offline-cross-proc-1"], promoteToProcessed: true },
  statePath
);
process.stdout.write(JSON.stringify(res));
`,
      "utf8"
    );
    const reconciledJson = execFileSync(
      process.execPath,
      [reconcileWorkerPath, crossProcStatePath],
      { encoding: "utf8", stdio: "pipe" }
    );
    const reconciled = JSON.parse(reconciledJson);
    assert.equal(reconciled.reconciledCount, 1);
    assert.deepEqual(reconciled.remainingAmbiguousIds, []);

    // Verify the current process (which previously cached `ambiguousIds: ["offline-cross-proc-1"]` in `inMemoryOfflineStateByPath`)
    // reads the updated disk state and does NOT resurrect the cleared ambiguous ID!
    const summaryAfter = getOfflineReplaySummary(crossProcStatePath);
    assert.equal(
      summaryAfter.ambiguousCount,
      0,
      "Daemon in-memory cache must not resurrect ambiguousIds cleared on disk by another process"
    );
    assert.deepEqual(summaryAfter.ambiguousIds, []);
    assert.ok(loadProcessedOfflineState(crossProcStatePath).processedIds.includes("offline-cross-proc-1"));

    const blankErr = new Error("");
    blankErr.code = "ECONNRESET";
    assert.equal(formatErrorDetail(blankErr), "Error [ECONNRESET]");
    assert.ok(formatErrorDetail(new Error("")).length > 0);

    const testSecConfigPath = path.join(env.tempRoot, "secure-config.json");
    writeConfigFileSecure({ machineId: "TEST-SEC", scope: "personal" }, testSecConfigPath);
    assert.equal(JSON.parse(fs.readFileSync(testSecConfigPath, "utf8")).scope, "personal");
    if (process.platform !== "win32") {
      assert.equal(fs.statSync(testSecConfigPath).mode & 0o077, 0);
    }
  } finally {
    recentDeliveryCache.clear();
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    env.cleanup();
  }
});

test("v3.0.0 multi-flock platform: universal <owner>/<flock>[/<machineId>] addressing, role-bound collaborator/guest walls, time-bound guest pass expiry, multi-device vouchers, and sandbox manifest teardown", async () => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = env.tempRoot;

  try {
    // 1. Scope normalization ("private" -> "personal", "work" -> "work", no "private" output)
    assert.equal(normalizeScope("private"), "personal");
    assert.equal(normalizeScope("personal"), "personal");
    assert.equal(normalizeScope("work"), "work");
    assert.equal(normalizeV3Scope("private"), "personal");
    assert.equal(normalizeV3Scope("work"), "work");

    // 2. Universal <owner>/<flock>[/<machineId>] address parser
    const addrRoot = parseFlockAddress("erjadi");
    assert.equal(addrRoot.owner, "erjadi");
    assert.equal(addrRoot.flockId, "erjadi");
    assert.equal(addrRoot.isOwnerRoot, true);

    const addrPersonal = parseFlockAddress("erjadi/personal");
    assert.equal(addrPersonal.flockId, "erjadi/personal");
    assert.equal(addrPersonal.isBuiltInScope, true);
    assert.equal(addrPersonal.machineId, null);

    const addrLegacyPrivate = parseFlockAddress("erjadi/private/MAIN-WORKSTATION");
    assert.equal(addrLegacyPrivate.flockId, "erjadi/personal");
    assert.equal(addrLegacyPrivate.machineId, "MAIN-WORKSTATION");
    assert.equal(addrLegacyPrivate.canonicalPath, "erjadi/personal/MAIN-WORKSTATION");

    const addrTeamPc = parseFlockAddress("erjadi/studio-team/CLOUD-DEV-VM");
    assert.equal(addrTeamPc.flockId, "erjadi/studio-team");
    assert.equal(addrTeamPc.machineId, "CLOUD-DEV-VM");
    assert.equal(addrTeamPc.isBuiltInScope, false);

    assert.throws(() => parseFlockAddress("../bad"), /Invalid/);
    assert.throws(() => parseFlockAddress("a/b/c/d"), /Expected <owner>/);

    // 3. v3 Ed25519 request & response envelopes (cross-flock replay rejection + stale rosterEpoch rejection)
    const keyA = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const reqEnv = signV3RpcEnvelope({
      kind: "req",
      flockUuid: "uuid-flock-1",
      rosterEpoch: 3,
      requestId: "v3-req-1",
      fromPeerId: "1001:dev-a",
      toPeerId: "1001:dev-b",
      actionOrStatus: "ping",
      payload: { includeSessions: true },
      identity: { publicKey: keyA.publicKey, privateKey: keyA.privateKey, fingerprint: "dev-a" },
    });
    assert.equal(
      verifyV3RpcEnvelope({
        envelope: reqEnv,
        expectedFlockUuid: "uuid-flock-1",
        minRosterEpoch: 3,
        requestId: "v3-req-1",
        actionOrStatus: "ping",
        payload: { includeSessions: true },
      }).valid,
      true
    );
    // Cross-flock replay must fail
    const crossFlockCheck = verifyV3RpcEnvelope({
      envelope: reqEnv,
      expectedFlockUuid: "uuid-flock-2",
      minRosterEpoch: 1,
      requestId: "v3-req-1",
      actionOrStatus: "ping",
      payload: { includeSessions: true },
    });
    assert.equal(crossFlockCheck.valid, false);
    assert.equal(crossFlockCheck.reason, "cross_flock_signature_mismatch");

    // Stale rosterEpoch after kick must fail
    const staleEpochCheck = verifyV3RpcEnvelope({
      envelope: reqEnv,
      expectedFlockUuid: "uuid-flock-1",
      minRosterEpoch: 4,
      requestId: "v3-req-1",
      actionOrStatus: "ping",
      payload: { includeSessions: true },
    });
    assert.equal(staleEpochCheck.valid, false);
    assert.equal(staleEpochCheck.reason, "stale_roster_epoch");

    // 4. Bootstrap v3 store: built-in flocks, cross-scope owner awareness, multi-device vouchers, lost-response refresh grace window, time-bound expiry, and kick
    const v3StorePath = path.join(env.tempRoot, "v3-test-flocks.json");
    const testConnStr = "Endpoint=https://your-signalr.service.signalr.net;AccessKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;Version=1.0;";

    // Enroll Eric's work laptop (`ARM64-LAPTOP`)
    const laptopEnroll = await enrollV3Device(
      {
        githubUser: "erjadi",
        githubUserId: 1001,
        deviceId: "fp-laptop",
        machineId: "ARM64-LAPTOP",
        scope: "work",
        publicKey: keyA.publicKey,
        keyFingerprint: "fp-laptop",
      },
      { storePath: v3StorePath, connectionString: testConnStr }
    );
    assert.equal(laptopEnroll.ok, true);
    assert.deepEqual(
      laptopEnroll.enrolledFlocks.map((f) => f.flockId),
      ["erjadi", "erjadi/work"]
    );
    assert.ok(laptopEnroll.enrolledFlocks[0].hubToken);

    // Enroll Eric's personal home PC (`MAIN-WORKSTATION`) AFTER the work laptop was bootstrapped
    const desktopEnroll = await enrollV3Device(
      {
        githubUser: "erjadi",
        githubUserId: 1001,
        deviceId: "fp-desktop",
        machineId: "MAIN-WORKSTATION",
        scope: "personal",
        publicKey: keyA.publicKey,
        keyFingerprint: "fp-desktop",
      },
      { storePath: v3StorePath, connectionString: testConnStr }
    );
    assert.deepEqual(
      desktopEnroll.enrolledFlocks.map((f) => f.flockId),
      ["erjadi", "erjadi/personal"]
    );

    // Work laptop queries listV3UserFlocks (`GET /api/v3/my-flocks`) and sees `erjadi/personal` even though it is not a member of `erjadi/personal`!
    const myFlocksOnLaptop = await listV3UserFlocks(
      { githubUser: "erjadi", githubUserId: 1001, deviceId: "fp-laptop" },
      { storePath: v3StorePath }
    );
    assert.ok(myFlocksOnLaptop.ownedFlocks.some((f) => f.flockId === "erjadi/personal"));
    assert.equal(
      myFlocksOnLaptop.joinedFlocks.some((f) => f.flockId === "erjadi/personal"),
      false
    );

    // Create invite for colleague @alice to `erjadi/studio-team` with maxDevices: 2
    const inviteRes = await createV3FlockInvite(
      {
        callerGitHubUser: "erjadi",
        callerGitHubUserId: 1001,
        targetAddress: "erjadi/studio-team",
        invitedUser: "alice",
        invitedGitHubUserId: 2002,
        maxDevices: 2,
      },
      { storePath: v3StorePath }
    );
    assert.equal(inviteRes.ok, true);
    assert.equal(inviteRes.flockId, "erjadi/studio-team");
    assert.ok(inviteRes.pasteablePrompt.includes("erjadi/studio-team"));

    const aliceKey1 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    // Wrong GitHub principal (@bob) trying to redeem @alice's voucher must fail with 403
    await assert.rejects(
      () =>
        enrollV3Device(
          {
            githubUser: "bob",
            githubUserId: 3003,
            deviceId: "fp-bob",
            machineId: "BOB-PC",
            scope: "work",
            publicKey: aliceKey1.publicKey,
            enrollmentJson: inviteRes.enrollmentJson,
          },
          { storePath: v3StorePath, connectionString: testConnStr }
        ),
      /different GitHub principal/
    );

    // Alice's personal home PC trying to join work-only `erjadi/studio-team` must fail with 403
    await assert.rejects(
      () =>
        enrollV3Device(
          {
            githubUser: "alice",
            githubUserId: 2002,
            deviceId: "fp-alice-home",
            machineId: "ALICE-HOME",
            scope: "personal",
            publicKey: aliceKey1.publicKey,
            enrollmentJson: inviteRes.enrollmentJson,
          },
          { storePath: v3StorePath, connectionString: testConnStr }
        ),
      /not permitted in flock/
    );

    // Alice redeems on work laptop 1 + idempotent retry on laptop 1 + work VM 2 -> succeeds
    const aliceEnroll1 = await enrollV3Device(
      {
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: "fp-alice-1",
        machineId: "ALICE-LAPTOP",
        scope: "work",
        publicKey: aliceKey1.publicKey,
        enrollmentJson: inviteRes.enrollmentJson,
      },
      { storePath: v3StorePath, connectionString: testConnStr }
    );
    const teamJoined = aliceEnroll1.enrolledFlocks.find((f) => f.flockId === "erjadi/studio-team");
    assert.ok(teamJoined);
    assert.equal(teamJoined.trustTier, "collaborator");

    // Test challenge-bound token refresh + 30s grace window on lost HTTP response (repeating same serverNonce within 30s succeeds idempotently!)
    const refreshTs = new Date().toISOString();
    const refreshPayload = `refresh|v3|${teamJoined.flockUuid}|2002|fp-alice-1|${teamJoined.rosterEpoch}|${teamJoined.serverNonce}|${refreshTs}`;
    const refreshSig = crypto
      .sign(null, Buffer.from(refreshPayload, "utf8"), aliceKey1.privateKey)
      .toString("base64");
    const ref1 = await refreshV3FlockToken(
      {
        flockUuid: teamJoined.flockUuid,
        githubUserId: 2002,
        deviceId: "fp-alice-1",
        rosterEpoch: teamJoined.rosterEpoch,
        serverNonce: teamJoined.serverNonce,
        timestamp: refreshTs,
        signature: refreshSig,
      },
      { storePath: v3StorePath, connectionString: testConnStr }
    );
    assert.equal(ref1.ok, true);
    const ref2Retry = await refreshV3FlockToken(
      {
        flockUuid: teamJoined.flockUuid,
        githubUserId: 2002,
        deviceId: "fp-alice-1",
        rosterEpoch: teamJoined.rosterEpoch,
        serverNonce: teamJoined.serverNonce,
        timestamp: refreshTs,
        signature: refreshSig,
      },
      { storePath: v3StorePath, connectionString: testConnStr }
    );
    assert.equal(ref2Retry.ok, true);
    assert.equal(ref2Retry.serverNonce, ref1.serverNonce);

    // Kick @alice from `erjadi/studio-team` -> increments rosterEpoch and blocks subsequent refresh/re-join
    const kickRes = await kickV3FlockMember(
      {
        callerGitHubUser: "erjadi",
        callerGitHubUserId: 1001,
        flockId: "erjadi/studio-team",
        targetUser: "alice",
      },
      { storePath: v3StorePath, connectionString: testConnStr }
    );
    assert.equal(kickRes.kickedCount, 1);
    await assert.rejects(
      () =>
        refreshV3FlockToken(
          {
            flockUuid: teamJoined.flockUuid,
            githubUserId: 2002,
            deviceId: "fp-alice-1",
            rosterEpoch: kickRes.rosterEpoch,
            serverNonce: ref1.serverNonce,
            timestamp: refreshTs,
            signature: refreshSig,
          },
          { storePath: v3StorePath, connectionString: testConnStr }
        ),
      /not an active member|revoked/
    );

    // 5. Role-bound Collaborator & Guest Anti-Leakage Walls (even when same-owner @erjadi tests a collaborator flock!)
    const testFlocksCfgPath = path.join(env.tempRoot, "local-flocks.json");
    const hostCfg = { machineId: "CLOUD-DEV-VM", githubUser: "erjadi", scope: "work" };
    shareThreadWithFlock(
      hostCfg,
      {
        flockId: "erjadi/studio-team",
        sessionId: "shared-sess-1",
        title: "service-api debugging",
        summarySnapshot: "Approved summary: service-api uses Entra DefaultAzureCredential.",
      },
      testFlocksCfgPath
    );
    assert.equal(listSharedThreadsForMachine(hostCfg, testFlocksCfgPath).sharedCount, 1);

    const loadedFlocks = loadLocalFlocksConfig(hostCfg, testFlocksCfgPath);
    const teamPolicy = loadedFlocks.flocks["erjadi/studio-team"];

    // Unshared session request in collaborator flock must throw 403 SESSION_NOT_SHARED
    await assert.rejects(
      () =>
        handleRpcAction(hostCfg, {
          action: "get_transcript",
          flockPolicy: teamPolicy,
          params: { session: "private-unshared-sess" },
        }),
      (err) => err.code === "SESSION_NOT_SHARED" && err.statusCode === 403
    );

    // Mutating RPC (`self_update`) in collaborator flock must throw 403 FLOCK_MUTATION_FORBIDDEN even for same-owner
    await assert.rejects(
      () =>
        handleRpcAction(hostCfg, {
          action: "self_update",
          flockPolicy: teamPolicy,
          params: {},
        }),
      (err) => err.code === "FLOCK_MUTATION_FORBIDDEN" && err.statusCode === 403
    );

    // Shared session returns the clean approved snapshot deterministically
    const sharedTranscript = await handleRpcAction(hostCfg, {
      action: "get_transcript",
      flockPolicy: teamPolicy,
      params: { session: "shared-sess-1" },
    });
    assert.equal(
      sharedTranscript.messages[0].content,
      "Approved summary: service-api uses Entra DefaultAzureCredential."
    );

    // One-sentence unshare immediately revokes access
    unshareThreadFromFlock(
      hostCfg,
      { flockId: "erjadi/studio-team", sessionId: "shared-sess-1" },
      testFlocksCfgPath
    );
    const updatedPolicy = loadLocalFlocksConfig(hostCfg, testFlocksCfgPath).flocks["erjadi/studio-team"];
    await assert.rejects(
      () =>
        handleRpcAction(hostCfg, {
          action: "get_transcript",
          flockPolicy: updatedPolicy,
          params: { session: "shared-sess-1" },
        }),
      (err) => err.code === "SESSION_NOT_SHARED" && err.statusCode === 403
    );

    // Single-PC guest pass (`erjadi/work/CLOUD-DEV-VM`) must be rejected by sibling machine `ARM64-LAPTOP`
    assert.throws(
      () =>
        enforceFlockPolicyAndWalls(
          { machineId: "ARM64-LAPTOP", githubUser: "erjadi", scope: "work" },
          {
            flockId: "erjadi/guest-alice-1",
            trustTier: "guest",
            targetMachineId: "CLOUD-DEV-VM",
          },
          { action: "ping" }
        ),
      (err) => err.code === "GUEST_TARGET_MISMATCH" && err.statusCode === 403
    );

    // Expired time-bound guest pass must fail closed locally (`MEMBERSHIP_EXPIRED`)
    assert.throws(
      () =>
        enforceFlockPolicyAndWalls(
          hostCfg,
          {
            flockId: "erjadi/guest-alice-1",
            trustTier: "guest",
            membershipExpiresAtMs: Date.now() - 1000,
          },
          { action: "ping" }
        ),
      (err) => err.code === "MEMBERSHIP_EXPIRED" && err.statusCode === 403
    );

    // 6. Untrusted Enrollment JSON bootstrapUrl rejection
    assert.throws(
      () => validatePinnedBootstrapOrigin("https://evil-attacker.example.com/api/v3"),
      (err) => err.code === "UNTRUSTED_BOOTSTRAP_ORIGIN"
    );
    assert.equal(
      validatePinnedBootstrapOrigin("https://your-flock-bootstrap.azurewebsites.net/api/v3"),
      "https://your-flock-bootstrap.azurewebsites.net"
    );

    // 7. Manifest-driven sandbox teardown (verifies PID identity before killing and removes signalr-bridge-v3)
    const testSandboxDir = path.join(env.tempRoot, "signalr-bridge-v3");
    const testManifestPath = path.join(testSandboxDir, "sandbox-manifest.json");
    recordSandboxManifestResource(
      { daemonPid: 999999, daemonStartTime: new Date().toISOString() },
      testManifestPath
    );
    const tdRes = teardownLocalSandbox({
      sandboxDir: testSandboxDir,
      verifyProcessFn: () => false, // Simulate tampered/recycled PID that is NOT a sandbox daemon
    });
    assert.equal(tdRes.ok, true);
    assert.ok(tdRes.actions.includes("skipped_unverified_pid:999999"));
    assert.equal(fs.existsSync(testSandboxDir), false);

    // 8. v3.3.0 Bundled Skills, Bootstrap Documentation & SVG Assets Verification (in full repo checkout)
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    if (fs.existsSync(path.join(repoRoot, "package.json"))) {
      for (const relPath of [
        "AGENTS.md",
        "README.md",
        "docs/BOOTSTRAP_NEW_FLOCK_BYO_AZURE.md",
        "docs/JOINING_AND_SHARING_GUIDE.md",
        "skills/flock-topology/SKILL.md",
        "skills/copilot-flock/SKILL.md",
        "docs/assets/flock-topology-light.svg",
        "docs/assets/flock-topology-dark.svg",
        "docs/assets/flock-onboarding-paths.svg",
        "docs/assets/flock-security-hard-walls.svg",
        "docs/assets/flock-two-coordinator-flow.svg",
      ]) {
        const fullPath = path.join(repoRoot, relPath);
        assert.equal(fs.existsSync(fullPath), true, `Missing required v3.3.0 asset/doc: ${relPath}`);
        assert.ok(fs.statSync(fullPath).size > 200, `Asset/doc too small: ${relPath}`);
      }
    }
  } finally {
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    env.cleanup();
  }
});

test("legacy flock_status and list_flocks surface offline shared-flock collaborators and owner-root machines while keeping membership distinct from live presence", async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-status-legacy-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const storePath = path.join(tempRoot, "v3-flocks.json");
  const membersPath = path.join(tempRoot, "members.json");
  const localFlocksPath = path.join(tempRoot, "local-flocks.json");
  const testConnStr = "Endpoint=https://test-flock.service.signalr.net;AccessKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;Version=1.0;";

  const genKey = () =>
    crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
  const ownerKey1 = genKey();
  const ownerKey2 = genKey();
  const reneKey = genKey();

  // 1. Owner @erjadi enrolls DESKTOP-2R3PAUG (personal) and CLOUD-DEV-VM (work)
  await enrollV3Device(
    {
      githubUser: "erjadi",
      githubUserId: 1001,
      deviceId: "fp-owner-main",
      machineId: "DESKTOP-2R3PAUG",
      scope: "personal",
      publicKey: ownerKey1.publicKey,
      keyFingerprint: "fp-owner-main",
    },
    { storePath, connectionString: testConnStr }
  );
  await enrollV3Device(
    {
      githubUser: "erjadi",
      githubUserId: 1001,
      deviceId: "fp-owner-cloud",
      machineId: "CLOUD-DEV-VM",
      scope: "work",
      publicKey: ownerKey2.publicKey,
      keyFingerprint: "fp-owner-cloud",
    },
    { storePath, connectionString: testConnStr }
  );

  // Also register an offline legacy owner-root machine DESKTOP-UE3B1TD in /api/members
  saveMemberRegistration(
    {
      machineId: "DESKTOP-UE3B1TD",
      githubUser: "erjadi",
      githubName: "Eric",
      scope: "personal",
      version: BRIDGE_VERSION,
      specs: { cpu: { model: "Ryzen 9" }, memory: { totalGb: 64 } },
    },
    membersPath
  );

  // 2. Owner creates shared flock erjadi/experimental (initially epoch 1/2 before collaborator joins)
  const expInvite = await createV3FlockInvite(
    {
      callerGitHubUser: "erjadi",
      callerGitHubUserId: 1001,
      targetAddress: "erjadi/experimental",
      invitedUser: "renepajta",
      invitedGitHubUserId: 2002,
      allowedScopes: ["work"],
    },
    { storePath }
  );
  // Seed owner's local flocks.json at stale epoch 2 BEFORE @renepajta enrolls DESKTOP-PSCVM1T
  writeConfigFileSecure(
    {
      ownerGitHubUser: "erjadi",
      scope: "personal",
      flocks: {
        "erjadi/experimental": {
          flockId: "erjadi/experimental",
          flockUuid: expInvite.flockUuid,
          hubName: "v3_flock_exp",
          ownerGitHubUser: "erjadi",
          flockType: "shared",
          trustTier: "collaborator",
          sessionVisibility: "explicit_opt_in_only",
          shareSpecs: "summary",
          sharedSessionIds: ["sess-exp-1"],
          sharedSnapshots: {
            "sess-exp-1": {
              sessionId: "sess-exp-1",
              title: "Experimental feature",
              mode: "approved-snapshot",
              summarySnapshot: "Approved summary",
              sharedAt: "2026-11-10T00:00:00.000Z",
            },
          },
          rosterEpoch: 2,
          members: [
            {
              peerId: "1001:fp-owner-cloud",
              githubUser: "erjadi",
              machineId: "CLOUD-DEV-VM",
              scope: "work",
              trustTier: "collaborator",
            },
          ],
        },
      },
    },
    localFlocksPath
  );

  // 3. Collaborator @renepajta enrolls DESKTOP-PSCVM1T, and broker epoch advances to 5 while DESKTOP-PSCVM1T is offline
  await enrollV3Device(
    {
      githubUser: "renepajta",
      githubUserId: 2002,
      deviceId: "fp-rene-pc",
      machineId: "DESKTOP-PSCVM1T",
      scope: "work",
      publicKey: reneKey.publicKey,
      keyFingerprint: "fp-rene-pc",
      enrollmentJson: expInvite.enrollmentJson,
    },
    { storePath, connectionString: testConnStr }
  );
  const rawStore = JSON.parse(fs.readFileSync(storePath, "utf8"));
  rawStore.flocks["erjadi/experimental"].rosterEpoch = 5;
  fs.writeFileSync(storePath, JSON.stringify(rawStore, null, 2), "utf8");

  const cfg = {
    machineId: "DESKTOP-2R3PAUG",
    githubUser: "erjadi",
    scope: "personal",
    hub: "copilotbridge",
    endpoint: "https://test-flock.service.signalr.net",
    bootstrapUrl: "https://your-flock-bootstrap.azurewebsites.net/api/bootstrap",
    flocksConfigPath: localFlocksPath,
  };
  const deps = {
    skipSpecsRefresh: true,
    ensureDaemon: async () => ({ running: true, pid: 4242 }),
    discoverOnlineMachines: async () => [
      // ONLY DESKTOP-2R3PAUG is online on SignalR; CLOUD-DEV-VM, DESKTOP-UE3B1TD, and DESKTOP-PSCVM1T are all offline
      { machineId: "DESKTOP-2R3PAUG", githubUser: "erjadi", scope: "personal", version: BRIDGE_VERSION },
    ],
    fetchV3MyFlocks: async () => listV3UserFlocks({ githubUser: "erjadi", githubUserId: 1001 }, { storePath }),
    fetchLegacyMembers: async () => ({
      attempted: true,
      ok: true,
      status: "ok",
      statusCode: 200,
      fetchedAt: new Date().toISOString(),
      error: null,
      members: Object.values(JSON.parse(fs.readFileSync(membersPath, "utf8"))),
    }),
  };

  const statusOut = await executeMcpTool(cfg, "flock_status", {}, deps);
  assert.equal(statusOut.onlineMachines.length, 1);
  assert.equal(statusOut.onlineMachines[0].machineId, "DESKTOP-2R3PAUG");

  // Known authenticated members include online self + offline owner-root + offline collaborator at epoch 5
  const byMachine = new Map(statusOut.knownMembers.map((m) => [m.machineId, m]));
  assert.equal(byMachine.get("DESKTOP-2R3PAUG")?.online, true);
  assert.equal(byMachine.get("DESKTOP-2R3PAUG")?.presence, "online");
  assert.equal(byMachine.get("DESKTOP-2R3PAUG")?.heartbeatObserved, true);

  const rene = byMachine.get("DESKTOP-PSCVM1T");
  assert.ok(rene, "Offline collaborator DESKTOP-PSCVM1T must be surfaced in knownMembers");
  assert.equal(rene.githubUser, "renepajta");
  assert.equal(rene.online, false);
  assert.equal(rene.presence, "offline");
  assert.equal(rene.heartbeatObserved, false);
  assert.equal(rene.membershipAuthenticated, true);
  assert.equal(rene.membershipStatus, "active");
  assert.equal(rene.removed, false);
  assert.deepEqual(rene.flocks, ["erjadi/experimental"]);
  assert.equal(rene.rosterEpoch, 5);

  const ue3 = byMachine.get("DESKTOP-UE3B1TD");
  assert.ok(ue3, "Offline owner-root member DESKTOP-UE3B1TD from /api/members must be surfaced");
  assert.equal(ue3.online, false);
  assert.equal(ue3.removed, false);
  assert.ok(ue3.flocks.includes("erjadi"));
  assert.ok(ue3.flocks.includes("erjadi/personal"));

  const offlineIds = statusOut.offlineMembers.map((m) => m.machineId).sort();
  assert.deepEqual(offlineIds, ["CLOUD-DEV-VM", "DESKTOP-PSCVM1T", "DESKTOP-UE3B1TD"]);

  // Roster metadata explicitly reports source, freshness, and complete refresh
  assert.equal(statusOut.roster.source, "broker_live");
  assert.equal(statusOut.roster.freshness.stale, false);
  assert.equal(statusOut.roster.freshness.rosterEpoch, 5);
  assert.equal(statusOut.roster.freshness.epochsByFlock["erjadi/experimental"], 5);
  assert.ok(Number.isFinite(Date.parse(statusOut.roster.freshness.fetchedAt)));
  assert.equal(statusOut.roster.refresh.status, "ok");
  assert.equal(statusOut.roster.refresh.complete, true);
  assert.equal(statusOut.roster.refresh.incomplete, false);
  assert.equal(statusOut.roster.refresh.failed, false);

  // Local flocks.json was reconciled to epoch 5 while preserving sharing walls and approved snapshots
  const updatedDiskFlocks = JSON.parse(fs.readFileSync(localFlocksPath, "utf8"));
  assert.equal(updatedDiskFlocks.flocks["erjadi/experimental"].rosterEpoch, 5);
  assert.equal(updatedDiskFlocks.flocks["erjadi/experimental"].sessionVisibility, "explicit_opt_in_only");
  assert.equal(updatedDiskFlocks.flocks["erjadi/experimental"].shareSpecs, "summary");
  assert.deepEqual(updatedDiskFlocks.flocks["erjadi/experimental"].sharedSessionIds, ["sess-exp-1"]);

  // list_flocks also surfaces epoch 5 and knownMembers without probing SignalR unless requested
  const listOut = await executeMcpTool(cfg, "list_flocks", {}, deps);
  assert.equal(listOut.roster.livePresenceProbed, false);
  assert.equal(listOut.roster.freshness.epochsByFlock["erjadi/experimental"], 5);
  const reneFromList = listOut.knownMembers.find((m) => m.machineId === "DESKTOP-PSCVM1T");
  assert.ok(reneFromList);
  assert.equal(reneFromList.presence, "unprobed");
  assert.equal(reneFromList.online, null);
  assert.equal(reneFromList.removed, false);
});

test("legacy flock_status and list_flocks prevent cross-flock metadata disclosure, prevent stale-member resurrection, and report partial or failed refresh states", async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-status-walls-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const storePath = path.join(tempRoot, "v3-flocks.json");
  const membersPath = path.join(tempRoot, "members.json");
  const ownerFlocksPath = path.join(tempRoot, "owner-flocks.json");
  const bobFlocksPath = path.join(tempRoot, "bob-flocks.json");
  const reneFlocksPath = path.join(tempRoot, "rene-flocks.json");
  const testConnStr = "Endpoint=https://test-flock.service.signalr.net;AccessKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;Version=1.0;";

  const genKey = () =>
    crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

  // Enroll owner machines (including OLD-OWNER-LAPTOP which will be kicked)
  await enrollV3Device(
    { githubUser: "erjadi", githubUserId: 1001, deviceId: "fp-main", machineId: "DESKTOP-2R3PAUG", scope: "personal", publicKey: genKey().publicKey },
    { storePath, connectionString: testConnStr }
  );
  await enrollV3Device(
    { githubUser: "erjadi", githubUserId: 1001, deviceId: "fp-cloud", machineId: "CLOUD-DEV-VM", scope: "work", publicKey: genKey().publicKey, specs: { gpus: [{ name: "Private H100", vramGb: 80 }] } },
    { storePath, connectionString: testConnStr }
  );
  await enrollV3Device(
    { githubUser: "erjadi", githubUserId: 1001, deviceId: "fp-old", machineId: "OLD-OWNER-LAPTOP", scope: "work", publicKey: genKey().publicKey },
    { storePath, connectionString: testConnStr }
  );

  // Create two separate shared flocks: erjadi/experimental (@renepajta + @bob) and erjadi/secret-project (@alice)
  const expInviteRene = await createV3FlockInvite(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, targetAddress: "erjadi/experimental", invitedUser: "renepajta", invitedGitHubUserId: 2002, allowedScopes: ["work"] },
    { storePath }
  );
  const expInviteBob = await createV3FlockInvite(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, targetAddress: "erjadi/experimental", invitedUser: "bob", invitedGitHubUserId: 3003, allowedScopes: ["work"] },
    { storePath }
  );
  const secretInviteAlice = await createV3FlockInvite(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, targetAddress: "erjadi/secret-project", invitedUser: "alice", invitedGitHubUserId: 4004, allowedScopes: ["work"] },
    { storePath }
  );
  // Owner joins CLOUD-DEV-VM to both shared flocks
  const expInviteOwner = await createV3FlockInvite(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, targetAddress: "erjadi/experimental", invitedUser: "erjadi", invitedGitHubUserId: 1001, allowedScopes: ["work"] },
    { storePath }
  );
  const secretInviteOwner = await createV3FlockInvite(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, targetAddress: "erjadi/secret-project", invitedUser: "erjadi", invitedGitHubUserId: 1001, allowedScopes: ["work"] },
    { storePath }
  );
  await enrollV3Device(
    {
      githubUser: "erjadi",
      githubUserId: 1001,
      deviceId: "fp-cloud",
      machineId: "CLOUD-DEV-VM",
      scope: "work",
      publicKey: genKey().publicKey,
      enrollmentJson: {
        flocks: [...expInviteOwner.enrollmentJson.flocks, ...secretInviteOwner.enrollmentJson.flocks],
      },
    },
    { storePath, connectionString: testConnStr }
  );

  await enrollV3Device(
    { githubUser: "renepajta", githubUserId: 2002, deviceId: "fp-rene", machineId: "DESKTOP-PSCVM1T", scope: "work", publicKey: genKey().publicKey, enrollmentJson: expInviteRene.enrollmentJson },
    { storePath, connectionString: testConnStr }
  );
  await enrollV3Device(
    { githubUser: "bob", githubUserId: 3003, deviceId: "fp-bob", machineId: "BOB-PC", scope: "work", publicKey: genKey().publicKey, enrollmentJson: expInviteBob.enrollmentJson },
    { storePath, connectionString: testConnStr }
  );
  await enrollV3Device(
    { githubUser: "alice", githubUserId: 4004, deviceId: "fp-alice", machineId: "ALICE-PC", scope: "work", publicKey: genKey().publicKey, enrollmentJson: secretInviteAlice.enrollmentJson },
    { storePath, connectionString: testConnStr }
  );

  // Seed /api/members with OLD-OWNER-LAPTOP, BOB-PC, and DESKTOP-2R3PAUG (so stale /api/members has kicked peers!)
  for (const reg of [
    { machineId: "DESKTOP-2R3PAUG", githubUser: "erjadi", scope: "personal" },
    { machineId: "OLD-OWNER-LAPTOP", githubUser: "erjadi", scope: "work" },
    { machineId: "BOB-PC", githubUser: "bob", scope: "work" },
  ]) {
    saveMemberRegistration(reg, membersPath);
  }

  // Seed stale local flocks.json on owner (containing BOB-PC + an already-expired guest EXPIRED-GUEST-PC) and on @bob
  writeConfigFileSecure(
    {
      ownerGitHubUser: "erjadi",
      scope: "work",
      flocks: {
        "erjadi/experimental": {
          flockId: "erjadi/experimental",
          ownerGitHubUser: "erjadi",
          flockType: "shared",
          trustTier: "collaborator",
          rosterEpoch: 3,
          rosterFetchedAt: "2026-11-10T00:00:00.000Z",
          members: [
            { peerId: "1001:fp-cloud", githubUser: "erjadi", machineId: "CLOUD-DEV-VM", scope: "work", trustTier: "collaborator" },
            { peerId: "3003:fp-bob", githubUser: "bob", machineId: "BOB-PC", scope: "work", trustTier: "collaborator" },
            {
              peerId: "9999:fp-expired",
              githubUser: "tempguest",
              machineId: "EXPIRED-GUEST-PC",
              scope: "work",
              trustTier: "guest",
              membershipExpiresAt: new Date(Date.now() - 60000).toISOString(),
            },
          ],
        },
      },
    },
    ownerFlocksPath
  );
  writeConfigFileSecure(
    {
      ownerGitHubUser: "bob",
      scope: "work",
      flocks: {
        "erjadi/experimental": {
          flockId: "erjadi/experimental",
          ownerGitHubUser: "erjadi",
          flockType: "shared",
          trustTier: "collaborator",
          rosterEpoch: 3,
          members: [
            { peerId: "1001:fp-cloud", githubUser: "erjadi", machineId: "CLOUD-DEV-VM", scope: "work", trustTier: "collaborator" },
            { peerId: "3003:fp-bob", githubUser: "bob", machineId: "BOB-PC", scope: "work", trustTier: "collaborator" },
          ],
        },
      },
    },
    bobFlocksPath
  );

  // Kick @bob from erjadi/experimental AND kick OLD-OWNER-LAPTOP from erjadi + erjadi/work
  await kickV3FlockMember(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, flockId: "erjadi/experimental", targetUser: "bob" },
    { storePath, connectionString: testConnStr }
  );
  await kickV3FlockMember(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, flockId: "erjadi", targetMachineId: "OLD-OWNER-LAPTOP" },
    { storePath, connectionString: testConnStr }
  );
  await kickV3FlockMember(
    { callerGitHubUser: "erjadi", callerGitHubUserId: 1001, flockId: "erjadi/work", targetMachineId: "OLD-OWNER-LAPTOP" },
    { storePath, connectionString: testConnStr }
  );

  const ownerCfg = {
    machineId: "CLOUD-DEV-VM",
    githubUser: "erjadi",
    scope: "work",
    hub: "copilotbridge",
    endpoint: "https://test-flock.service.signalr.net",
    bootstrapUrl: "https://your-flock-bootstrap.azurewebsites.net/api/bootstrap",
    flocksConfigPath: ownerFlocksPath,
  };
  const readLegacyMembers = async () => ({
    attempted: true,
    ok: true,
    status: "ok",
    statusCode: 200,
    fetchedAt: new Date().toISOString(),
    error: null,
    members: Object.values(JSON.parse(fs.readFileSync(membersPath, "utf8"))),
  });

  // 1. Owner status: BOB-PC, EXPIRED-GUEST-PC, and OLD-OWNER-LAPTOP are NEVER resurrected from stale flocks.json or /api/members
  const ownerStatus = await executeMcpTool(ownerCfg, "flock_status", {}, {
    skipSpecsRefresh: true,
    ensureDaemon: async () => ({ running: true, pid: 1111 }),
    discoverOnlineMachines: async () => [{ machineId: "CLOUD-DEV-VM", githubUser: "erjadi", scope: "work" }],
    fetchV3MyFlocks: async () => listV3UserFlocks({ githubUser: "erjadi", githubUserId: 1001 }, { storePath }),
    fetchLegacyMembers: readLegacyMembers,
  });
  const ownerKnownIds = new Set(ownerStatus.knownMembers.map((m) => m.machineId));
  assert.equal(ownerKnownIds.has("DESKTOP-PSCVM1T"), true);
  assert.equal(ownerKnownIds.has("BOB-PC"), false, "Kicked collaborator BOB-PC must not be resurrected");
  assert.equal(ownerKnownIds.has("EXPIRED-GUEST-PC"), false, "Expired guest must not be resurrected");
  assert.equal(ownerKnownIds.has("OLD-OWNER-LAPTOP"), false, "Kicked owner device must not be resurrected from /api/members");

  // 2. Scoped query (--flock erjadi/experimental or boundFlockId) discloses ZERO metadata from erjadi/personal or erjadi/secret-project
  const scopedStatus = await executeMcpTool(
    { ...ownerCfg, boundFlockId: "erjadi/experimental" },
    "flock_status",
    {},
    {
      skipSpecsRefresh: true,
      ensureDaemon: async () => ({ running: true, pid: 1111 }),
      discoverOnlineMachines: async () => [
        { machineId: "CLOUD-DEV-VM", githubUser: "erjadi", scope: "work" },
        { machineId: "DESKTOP-2R3PAUG", githubUser: "erjadi", scope: "personal" },
        { machineId: "ALICE-PC", githubUser: "alice", scope: "work" },
      ],
      fetchV3MyFlocks: async () => listV3UserFlocks({ githubUser: "erjadi", githubUserId: 1001 }, { storePath }),
      fetchLegacyMembers: readLegacyMembers,
    }
  );
  assert.deepEqual(scopedStatus.flocks.map((f) => f.flockId), ["erjadi/experimental"]);
  assert.deepEqual(
    scopedStatus.knownMembers.map((m) => m.machineId).sort(),
    ["CLOUD-DEV-VM", "DESKTOP-PSCVM1T"]
  );
  assert.deepEqual(scopedStatus.onlineMachines.map((m) => m.machineId), ["CLOUD-DEV-VM"]);
  // CLOUD-DEV-VM in scoped erjadi/experimental response must NOT leak its membership in erjadi/secret-project or full private specs
  const scopedCloud = scopedStatus.knownMembers.find((m) => m.machineId === "CLOUD-DEV-VM");
  assert.deepEqual(scopedCloud.flocks, ["erjadi/experimental"]);
  assert.equal(scopedCloud.specs, undefined);
  await assert.rejects(
    executeMcpTool(ownerCfg, "flock_status", { flock: "other/unauthorized" }, {
      skipSpecsRefresh: true,
      ensureDaemon: async () => ({ running: true, pid: 1111 }),
      discoverOnlineMachines: async () => [],
      fetchV3MyFlocks: async () => listV3UserFlocks({ githubUser: "erjadi", githubUserId: 1001 }, { storePath }),
      fetchLegacyMembers: readLegacyMembers,
    }),
    /Not an authorized member/
  );

  // 3. Collaborator @renepajta: /api/members 403 produces explicit partial refresh without leaking owner's other flocks/machines
  const reneCfg = {
    machineId: "DESKTOP-PSCVM1T",
    githubUser: "renepajta",
    scope: "work",
    hub: "copilotbridge",
    endpoint: "https://test-flock.service.signalr.net",
    bootstrapUrl: "https://your-flock-bootstrap.azurewebsites.net/api/bootstrap",
    flocksConfigPath: reneFlocksPath,
  };
  const reneStatus = await executeMcpTool(reneCfg, "flock_status", {}, {
    skipSpecsRefresh: true,
    ensureDaemon: async () => ({ running: true, pid: 2222 }),
    discoverOnlineMachines: async () => [
      { machineId: "DESKTOP-PSCVM1T", githubUser: "renepajta", scope: "work" },
      { machineId: "DESKTOP-2R3PAUG", githubUser: "erjadi", scope: "personal" }, // unrelated owner PC on shared legacy hub
    ],
    fetchV3MyFlocks: async () => listV3UserFlocks({ githubUser: "renepajta", githubUserId: 2002 }, { storePath }),
    fetchLegacyMembers: async () => ({
      attempted: true,
      ok: false,
      status: "unauthorized",
      statusCode: 403,
      fetchedAt: null,
      error: "Access denied: repository collaborator/write access required",
      members: [],
    }),
  });
  assert.equal(reneStatus.roster.source, "broker_partial");
  assert.equal(reneStatus.roster.sources.bootstrapMembers.status, "unauthorized");
  assert.equal(reneStatus.roster.refresh.status, "partial");
  assert.equal(reneStatus.roster.refresh.incomplete, true);
  assert.equal(reneStatus.roster.refresh.failed, false);
  assert.deepEqual(
    reneStatus.knownMembers.map((m) => m.machineId).sort(),
    ["CLOUD-DEV-VM", "DESKTOP-PSCVM1T"]
  );
  assert.deepEqual(reneStatus.onlineMachines.map((m) => m.machineId), ["DESKTOP-PSCVM1T"]);
  assert.equal(JSON.stringify(reneStatus).includes("secret-project"), false);
  assert.equal(JSON.stringify(reneStatus).includes("ALICE-PC"), false);
  assert.equal(JSON.stringify(reneStatus).includes("DESKTOP-2R3PAUG"), false);

  // Even if @renepajta somehow received /api/members entries for @erjadi, cross-user /api/members entries are NOT disclosed
  const reneWithMembers = await executeMcpTool(reneCfg, "list_flocks", {}, {
    fetchV3MyFlocks: async () => listV3UserFlocks({ githubUser: "renepajta", githubUserId: 2002 }, { storePath }),
    fetchLegacyMembers: readLegacyMembers,
  });
  assert.equal(reneWithMembers.knownMembers.some((m) => m.machineId === "DESKTOP-2R3PAUG"), false);

  // 4. Kicked @bob querying status with stale erjadi/experimental in local flocks.json must NOT resurrect erjadi/experimental
  const bobStatus = await executeMcpTool(
    {
      machineId: "BOB-PC",
      githubUser: "bob",
      scope: "work",
      hub: "copilotbridge",
      endpoint: "https://test-flock.service.signalr.net",
      bootstrapUrl: "https://your-flock-bootstrap.azurewebsites.net/api/bootstrap",
      flocksConfigPath: bobFlocksPath,
    },
    "flock_status",
    {},
    {
      skipSpecsRefresh: true,
      ensureDaemon: async () => ({ running: true, pid: 3333 }),
      discoverOnlineMachines: async () => [{ machineId: "BOB-PC", githubUser: "bob", scope: "work" }],
      fetchV3MyFlocks: async () => listV3UserFlocks({ githubUser: "bob", githubUserId: 3003 }, { storePath }),
      fetchLegacyMembers: async () => ({ attempted: true, ok: false, status: "unauthorized", statusCode: 403, error: "Forbidden", members: [] }),
    }
  );
  assert.equal(bobStatus.flocks.some((f) => f.flockId === "erjadi/experimental"), false);
  assert.equal(bobStatus.knownMembers.some((m) => m.machineId === "CLOUD-DEV-VM"), false);

  // 5. Epoch rollback rejection + full broker failure fallback to non-expired local cache
  const rollbackOut = await executeMcpTool(ownerCfg, "list_flocks", { flock: "erjadi/experimental" }, {
    fetchV3MyFlocks: async () => ({
      ok: true,
      githubUser: "erjadi",
      ownedFlocks: [
        {
          flockId: "erjadi/experimental",
          ownerGitHubUser: "erjadi",
          flockType: "shared",
          rosterEpoch: 1, // rolled back below cached epoch in ownerFlocksPath!
          members: [{ peerId: "3003:fp-bob", githubUser: "bob", machineId: "BOB-PC", scope: "work", trustTier: "collaborator" }],
        },
      ],
      joinedFlocks: [],
    }),
    fetchLegacyMembers: readLegacyMembers,
  });
  assert.equal(rollbackOut.roster.refresh.incomplete, true);
  assert.ok(rollbackOut.roster.refresh.warnings.some((w) => /rollback/i.test(w)));
  assert.equal(rollbackOut.knownMembers.some((m) => m.machineId === "BOB-PC"), false);

  const failedOut = await executeMcpTool(ownerCfg, "flock_status", { flock: "erjadi/experimental" }, {
    skipSpecsRefresh: true,
    ensureDaemon: async () => ({ running: true, pid: 1111 }),
    discoverOnlineMachines: async () => [],
    fetchV3MyFlocks: async () => ({ ok: false, error: "connect ECONNREFUSED" }),
    fetchLegacyMembers: async () => ({ attempted: true, ok: false, status: "failed", statusCode: null, error: "connect ECONNREFUSED", members: [] }),
  });
  assert.equal(failedOut.roster.source, "local_cache");
  assert.equal(failedOut.roster.freshness.stale, true);
  assert.equal(failedOut.roster.refresh.status, "failed");
  assert.equal(failedOut.roster.refresh.failed, true);
  assert.equal(failedOut.roster.refresh.incomplete, true);
  assert.ok(failedOut.roster.refresh.errors.length >= 1);
  // Offline cached members remain active (missing heartbeats != removal), while expired guest stays excluded
  assert.deepEqual(
    failedOut.offlineMembers.map((m) => m.machineId).sort(),
    ["CLOUD-DEV-VM", "DESKTOP-PSCVM1T"]
  );
  assert.ok(failedOut.offlineMembers.every((m) => m.removed === false && m.presence === "offline"));
});

test("broker-free flock_status and list_flocks surface offline collaborators across post-join enrollments without cross-flock disclosure, resurrection, or legacy fallback", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-status-bf34-"));
  const prevGhToken = process.env.GH_TOKEN;
  process.env.GH_TOKEN = "ghp_poison_legacy_token_must_never_be_used";
  t.after(() => {
    if (prevGhToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = prevGhToken;
    fs.rmSync(root, { recursive: true, force: true });
  });

  const endpoints = azureEndpoints("https://fixture.service.signalr.net", "https://fixture.servicebus.windows.net");
  const credentials = {
    connectionString: "Endpoint=https://fixture.service.signalr.net;AccessKey=signalr-fixture",
    manageConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=manage-fixture",
    sendConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockSendRule;SharedAccessKey=send-fixture",
    listenConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockListenRule;SharedAccessKey=listen-fixture",
  };

  let nowMs = Date.now();
  const clock = () => nowMs;
  const subscribers = new Map();
  const sockets = new Set();
  let blockRealtimeDelivery = false;

  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    assert.ok(
      parsed.hostname.endsWith(".signalr.net") || parsed.hostname.endsWith(".servicebus.windows.net"),
      `Unexpected non-Azure request in broker-free mode: ${url}`
    );
    const peer = parsed.pathname.match(/\/subscriptions\/(sub-[a-f0-9]{46})/)?.[1];
    if (options.method === "PUT" && peer && !parsed.pathname.includes("/messages/")) {
      if (!subscribers.has(peer)) subscribers.set(peer, []);
      return new Response("", { status: 201 });
    }
    if (options.method === "DELETE" && peer && !parsed.pathname.includes("/messages/")) {
      subscribers.delete(peer);
      return new Response(null, { status: 204 });
    }
    if (parsed.hostname.endsWith(".signalr.net")) {
      const { target, arguments: args } = JSON.parse(options.body);
      if (!blockRealtimeDelivery) {
        for (const socket of sockets) if (!socket.ws.closed) socket.callback(target, structuredClone(args));
      }
      return new Response("", { status: 202 });
    }
    if (options.method === "POST" && parsed.pathname.endsWith("/messages") && !peer) {
      for (const queue of subscribers.values()) queue.push(JSON.parse(options.body));
      return new Response("", { status: 201 });
    }
    if (options.method === "POST" && parsed.pathname.endsWith("/messages/head")) {
      const queue = subscribers.get(peer);
      if (!queue?.length) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(queue[0]), {
        status: 201,
        headers: { Location: `${endpoints.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peer}/messages/lock` },
      });
    }
    if (options.method === "DELETE" && parsed.pathname.endsWith("/messages/lock")) {
      subscribers.get(peer)?.shift();
      return new Response(null, { status: 204 });
    }
    if (options.method === "PUT" && parsed.pathname.endsWith("/messages/lock")) {
      return new Response(null, { status: 204 });
    }
    throw new Error(`Unexpected transport call: ${options.method} ${parsed.pathname}`);
  };

  const connect = async (_cfg, { onInvocation }) => {
    const socket = {
      ws: { closed: false },
      callback: onInvocation,
      close() {
        this.ws.closed = true;
        sockets.delete(this);
      },
    };
    sockets.add(socket);
    return socket;
  };

  const logs = [];
  const mkRuntime = (subDir) =>
    new BrokerFreeRuntime(path.join(root, subDir), {
      clock,
      connect,
      log: (msg) => logs.push(msg),
      dispatch: async ({ action, assertAuthorized }) => {
        assertAuthorized();
        if (action === "ping") return { machineId: subDir.toUpperCase(), scope: "work", version: BRIDGE_VERSION };
        throw new Error(`Unhandled test action ${action}`);
      },
      transportFactory: (config, opts) => new AzureTransport(config, { ...opts, fetchImpl }),
    });

  const owner = mkRuntime("owner");
  const peerA = mkRuntime("peer-a");
  const peerOffline = mkRuntime("peer-offline");
  const peerGuest = mkRuntime("peer-guest");
  const peerSecond = mkRuntime("peer-second");

  await owner.initializeOwner({ flockId: "demo/team", machineId: "OWNER-PC", scope: "work", ...credentials });
  await owner.initializeOwner({ flockId: "demo/second", machineId: "OWNER-PC", scope: "personal", ...credentials });
  const ownerPinTeam = ownerFingerprint(owner.record("demo/team").ownerPublicKey);
  const ownerPinSecond = ownerFingerprint(owner.record("demo/second").ownerPublicKey);

  // 1. PEER-A joins demo/team BEFORE DESKTOP-PSCVM1T enrolls
  const codeA = await peerA.joinRequest({ machineId: "PEER-A", scope: "work", flockId: "demo/team" });
  const ticketA = await owner.approve({
    flockId: "demo/team",
    code: codeA,
    expectedEd25519Fingerprint: codeA.body.peerId,
    role: "collaborator",
    sessionIds: ["priv-session-a"],
    membershipExpiresAt: nowMs + 7 * 86400000,
  });
  await peerA.accept(ticketA, ownerPinTeam);

  // 2. DESKTOP-PSCVM1T joins demo/team AFTER PEER-A (and stays offline — never starts daemon)
  const codeOff = await peerOffline.joinRequest({ machineId: "DESKTOP-PSCVM1T", scope: "work", flockId: "demo/team" });
  const ticketOff = await owner.approve({
    flockId: "demo/team",
    code: codeOff,
    expectedEd25519Fingerprint: codeOff.body.peerId,
    role: "collaborator",
    sessionIds: ["priv-session-off"],
    membershipExpiresAt: nowMs + 7 * 86400000,
  });
  await peerOffline.accept(ticketOff, ownerPinTeam);

  // Guest joins demo/team, and SECOND-PC joins demo/second
  const codeGuest = await peerGuest.joinRequest({ machineId: "GUEST-PC", scope: "work", flockId: "demo/team" });
  const ticketGuest = await owner.approve({
    flockId: "demo/team",
    code: codeGuest,
    expectedEd25519Fingerprint: codeGuest.body.peerId,
    role: "guest",
    sessionIds: ["guest-sess"],
    membershipExpiresAt: nowMs + 7 * 86400000,
  });
  await peerGuest.accept(ticketGuest, ownerPinTeam);

  const codeSec = await peerSecond.joinRequest({ machineId: "SECOND-PC", scope: "personal", flockId: "demo/second" });
  const ticketSec = await owner.approve({
    flockId: "demo/second",
    code: codeSec,
    expectedEd25519Fingerprint: codeSec.body.peerId,
    role: "collaborator",
    membershipExpiresAt: nowMs + 7 * 86400000,
  });
  await peerSecond.accept(ticketSec, ownerPinSecond);

  let ownerDaemon = await owner.start();
  t.after(async () => { if (ownerDaemon) await ownerDaemon.close(); });

  const forbidLegacyFallback = {
    skipSpecsRefresh: true,
    ensureDaemon: async () => ({ running: true, pid: 7777 }),
    fetchV3MyFlocks: async () => assert.fail("Legacy /my-flocks must never be called in broker-free mode"),
    fetchLegacyMembers: async () => assert.fail("Legacy /api/members must never be called in broker-free mode"),
  };

  // Multi-flock owner without explicit --flock must reject ambiguous flock_status
  const ownerBfCfg = {
    protocol: "broker-free-v34",
    machineId: "OWNER-PC",
    scope: "work",
    bootstrapUrl: "https://poison-legacy.invalid/api/bootstrap", // must be ignored in broker-free mode
  };
  await assert.rejects(
    executeMcpTool(ownerBfCfg, "flock_status", {}, {
      ...forbidLegacyFallback,
      brokerFreeRuntimeFactory: () => owner,
      discoverOnlineMachines: async () => [{ machineId: "OWNER-PC", scope: "work" }],
    }),
    /ambiguous/
  );

  // Owner scoped to demo/team sees offline DESKTOP-PSCVM1T without disclosing demo/second or SECOND-PC
  const ownerTeamStatus = await executeMcpTool(ownerBfCfg, "flock_status", { flock: "demo/team" }, {
    ...forbidLegacyFallback,
    brokerFreeRuntimeFactory: () => owner,
    discoverOnlineMachines: async () => [
      { machineId: "OWNER-PC", scope: "work" },
      { machineId: "PEER-A", scope: "work" },
    ],
  });
  assert.equal(ownerTeamStatus.protocol, "broker-free-v34");
  assert.equal(ownerTeamStatus.roster.source, "broker_free_owner_authority");
  assert.equal(ownerTeamStatus.roster.refresh.complete, true);
  assert.deepEqual(ownerTeamStatus.onlineMachines.map((m) => m.machineId).sort(), ["OWNER-PC", "PEER-A"]);
  assert.deepEqual(ownerTeamStatus.offlineMembers.map((m) => m.machineId).sort(), ["DESKTOP-PSCVM1T", "GUEST-PC"]);
  assert.equal(JSON.stringify(ownerTeamStatus).includes("demo/second"), false);
  assert.equal(JSON.stringify(ownerTeamStatus).includes("SECOND-PC"), false);

  // PEER-A (whose local roster predated DESKTOP-PSCVM1T!) syncs owner-signed roster-snapshot over encrypted RPC
  const peerACfg = {
    protocol: "broker-free-v34",
    machineId: "PEER-A",
    scope: "work",
    bootstrapUrl: "https://poison-legacy.invalid/api/bootstrap",
  };
  const peerAStatus = await executeMcpTool(peerACfg, "flock_status", { flock: "demo/team" }, {
    ...forbidLegacyFallback,
    brokerFreeRuntimeFactory: () => peerA,
    discoverOnlineMachines: async () => [
      { machineId: "OWNER-PC", scope: "work" },
      { machineId: "PEER-A", scope: "work" },
    ],
  });
  assert.equal(peerAStatus.roster.source, "broker_free_owner_synced");
  assert.equal(peerAStatus.roster.refresh.status, "ok");
  assert.equal(peerAStatus.roster.refresh.complete, true);
  assert.ok(peerAStatus.offlineMembers.some((m) => m.machineId === "DESKTOP-PSCVM1T" && m.removed === false));
  // Private sessionIds from other peers' MemberCerts must NEVER be leaked in roster snapshots
  assert.equal(JSON.stringify(peerAStatus).includes("priv-session-off"), false);
  assert.equal(JSON.stringify(peerAStatus).includes("guest-sess"), false);

  // Guest role cannot enumerate sibling collaborators via list_roster
  await assert.rejects(
    peerGuest.invoke({ flockId: "demo/team", toMachine: "OWNER-PC", action: "list_roster", timeoutMs: 500 }),
    /forbids/
  );
  const guestStatus = await executeMcpTool(
    { protocol: "broker-free-v34", machineId: "GUEST-PC", scope: "work" },
    "flock_status",
    { flock: "demo/team" },
    {
      ...forbidLegacyFallback,
      brokerFreeRuntimeFactory: () => peerGuest,
      discoverOnlineMachines: async () => [{ machineId: "GUEST-PC", scope: "work" }],
    }
  );
  assert.equal(guestStatus.roster.refresh.status, "local_only");
  assert.deepEqual(guestStatus.knownMembers.map((m) => m.machineId).sort(), ["GUEST-PC", "OWNER-PC"]);

  // Simulate owner temporarily unreachable BEFORE rotation: PEER-A uses its verified epoch-1 cached snapshot with explicit incomplete/failed refresh
  blockRealtimeDelivery = true;
  const peerACachedWhileOwnerUnreachable = await executeMcpTool(peerACfg, "flock_status", { flock: "demo/team" }, {
    ...forbidLegacyFallback,
    rosterTimeoutMs: 200,
    brokerFreeRuntimeFactory: () => peerA,
    discoverOnlineMachines: async () => [{ machineId: "PEER-A", scope: "work" }],
  });
  assert.equal(peerACachedWhileOwnerUnreachable.roster.source, "broker_free_cached_snapshot");
  assert.equal(peerACachedWhileOwnerUnreachable.roster.freshness.stale, true);
  assert.equal(peerACachedWhileOwnerUnreachable.roster.refresh.incomplete, true);
  assert.equal(peerACachedWhileOwnerUnreachable.roster.refresh.failed, true);
  assert.ok(peerACachedWhileOwnerUnreachable.offlineMembers.some((m) => m.machineId === "DESKTOP-PSCVM1T" && m.removed === false));

  // Owner removes DESKTOP-PSCVM1T -> epoch advances to 2; neither owner nor PEER-A may resurrect DESKTOP-PSCVM1T!
  await owner.removePeer({ flockId: "demo/team", peerId: codeOff.body.peerId });
  // Deliver rotation to PEER-A from its queue while realtime owner RPC remains unreachable, testing offline epoch-2 anti-resurrection!
  await peerA.transport(peerA.record("demo/team")).drain(
    peerA.record("demo/team").transport,
    (msg) => peerA.consume(peerA.record("demo/team"), msg)
  );
  assert.equal(peerA.record("demo/team").epoch, 2);

  const peerAOfflineAfterRotation = await executeMcpTool(peerACfg, "flock_status", { flock: "demo/team" }, {
    ...forbidLegacyFallback,
    rosterTimeoutMs: 200,
    brokerFreeRuntimeFactory: () => peerA,
    discoverOnlineMachines: async () => [{ machineId: "PEER-A", scope: "work" }],
  });
  assert.equal(peerAOfflineAfterRotation.roster.source, "broker_free_local_certs");
  assert.equal(peerAOfflineAfterRotation.roster.refresh.incomplete, true);
  assert.equal(
    peerAOfflineAfterRotation.knownMembers.some((m) => m.machineId === "DESKTOP-PSCVM1T"),
    false,
    "Epoch-1 cached snapshot must not resurrect removed peer after epoch-2 rotation"
  );

  // Restore realtime connectivity and verify PEER-A syncs epoch-2 snapshot cleanly without DESKTOP-PSCVM1T
  blockRealtimeDelivery = false;
  const peerASyncedEpoch2 = await executeMcpTool(peerACfg, "list_flocks", { flock: "demo/team" }, {
    ...forbidLegacyFallback,
    brokerFreeRuntimeFactory: () => peerA,
  });
  assert.equal(peerASyncedEpoch2.roster.source, "broker_free_owner_synced");
  assert.equal(peerASyncedEpoch2.roster.freshness.rosterEpoch, 2);
  assert.equal(peerASyncedEpoch2.knownMembers.some((m) => m.machineId === "DESKTOP-PSCVM1T"), false);
  assert.equal(peerASyncedEpoch2.knownMembers.some((m) => m.machineId === "PEER-A"), true);

  // Advance clock monotonically +30 hours: retained PEER-A's 24h short cert expired while asleep, 7-day membership still active -> offline, NOT removed!
  await ownerDaemon.close();
  ownerDaemon = null;
  nowMs += 30 * 3600 * 1000;
  await owner.renewOwn("demo/team");
  const ownerAfter30h = await executeMcpTool(ownerBfCfg, "flock_status", { flock: "demo/team" }, {
    ...forbidLegacyFallback,
    brokerFreeRuntimeFactory: () => owner,
    discoverOnlineMachines: async () => [{ machineId: "OWNER-PC", scope: "work" }],
  });
  const asleepCollab = ownerAfter30h.offlineMembers.find((m) => m.machineId === "PEER-A");
  assert.ok(asleepCollab, "Asleep collaborator with active 7-day membership must remain in offlineMembers after 24h short-cert window");
  assert.equal(asleepCollab.credentialExpired, true);
  assert.equal(asleepCollab.membershipStatus, "active_credential_expired");
  assert.equal(asleepCollab.removed, false);
  assert.equal(ownerAfter30h.knownMembers.some((m) => m.machineId === "DESKTOP-PSCVM1T"), false);
});
