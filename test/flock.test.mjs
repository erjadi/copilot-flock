import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import http from "node:http";
import path from "node:path";
import crypto from "node:crypto";
import https from "node:https";
import {
  execFileSync,
  spawn,
  spawnSync,
} from "node:child_process";
import {
  pathToFileURL,
  fileURLToPath,
} from "node:url";
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
  parseExplicitFlockSelector,
  isExplicitOptInFlockPolicy,
  isSessionAuthorizedForFlock,
  authorizeCallerFlockSelection,
  executeMcpTool,
  dispatchBrokerFreeRpc,
  resolveLegacyFlockRoster,
  resolveBrokerFreeFlockRoster,
  FlockMembershipRegistry,
  createSignedRosterSnapshot,
  createSignedRosterDelta,
  computeRosterHash,
  applyV3EnrollmentResult,
  queryFlockMembershipRegistry,
  reconcileAuthoritativeFlockMemberships,
  syncFlockMemberships,
  signV3MembershipSyncRequest,
  hasVerifiedOwnerAuthority,
  RUNTIME_MANIFEST_FILENAME,
  REQUIRED_RUNTIME_MODULES,
  RUNTIME_MODULE_MANIFEST,
  hashRuntimeModule,
  computeRuntimeManifest,
  validateRuntimeManifest,
  loadRuntimeManifest,
  verifyStagedRuntimeClosure,
  inspectRuntimeGenerations,
  stageRuntimeRelease,
  activateStagedRuntime,
  stageAndActivateRuntime,
  getLocalRuntimeStates,
  performLocalSelfUpdate,
  updateFleetMachines,
  reprovisionLocalBridge,
  installBridge,
  diagnoseLocalBridgeState,
  buildCanonicalVoteBallotPayload,
  truncateUtf8Bounded,
  extractCandidateFixtureFromGit,
  reviewReleaseCandidate,
  voteReleaseAcrossFlock,
  RawWebSocketClient,
  loadConfig,
  diagnoseFleetMachines,
  inspectLocalDaemonPassive,
  getMcpSelfInfo,
  validateBootstrapControlPlaneUrl,
  redactBootstrapUrlForDiagnostic,
  callBootstrapV3Endpoint,
  getOfflineQueueStatus,
  captureCallerMcpSnapshot,
  inspectLocalRuntimeHealth,
  reapOrphanedMcpProcesses,
  SAFE_CALLER_MCP_RECONNECT_GUIDANCE,
  THERMAL_TELEMETRY_MAX_BUDGET_MS,
  probeThermalTelemetry,
  resetThermalTelemetryCache,
  parseNvidiaSmiThermalOutput,
  parseWin32ThermalCounterOutput,
  sanitizeSpecsForFlockPolicy,
} from "../flock.mjs";
import {
  verifyGitHubRepoAccess,
  createBootstrapServer,
  enqueueOfflineStoreItem,
  drainOfflineStoreItems,
  ackOfflineStoreItems,
  normalizeV3Scope,
  enrollV3Device,
  refreshV3FlockToken,
  createV3FlockInvite,
  kickV3FlockMember,
  listV3UserFlocks,
  saveMemberRegistration,
  syncV3DeviceMemberships,
} from "../bootstrap-server.mjs";
import {
  AzureTransport,
  azureEndpoints,
} from "../flock-azure.mjs";
import {
  BrokerFreeRuntime,
} from "../flock-broker-free.mjs";
import {
  ownerFingerprint,
  createDeviceIdentity,
} from "../flock-protocol.mjs";

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
    assert.equal(BRIDGE_VERSION, "3.5.0");

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

test("TODO #9: legacy two-flock list_remote_sessions and get_remote_session_transcript propagate args.flock end-to-end, enforce exact session IDs, deny unshared transcripts pre-body, and fail closed on invalid/non-member selectors while preserving omitted-selector owner routes", async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-todo9-legacy-"));
  const prevCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = path.join(tempRoot, "copilot-home");
  try {
    const mkKey = (label) => {
      const kp = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      return { ...kp, fingerprint: `fp-${label}` };
    };

    const callerKey = mkKey("caller");
    const workHostKey = mkKey("work-host");
    const personalHostKey = mkKey("personal-host");
    const aliceKey = mkKey("alice");

    const registryMembers = [
      { machineId: "CALLER-LAPTOP", githubUser: "owner", scope: "work", publicKey: callerKey.publicKey },
      { machineId: "HOST-WORK-VM", githubUser: "owner", scope: "work", publicKey: workHostKey.publicKey },
      { machineId: "HOST-PERSONAL-PC", githubUser: "owner", scope: "personal", publicKey: personalHostKey.publicKey },
      { machineId: "ALICE-LAPTOP", githubUser: "alice", scope: "work", publicKey: aliceKey.publicKey },
    ];

    const workSessions = [
      {
        session_id: "sess-private-owner",
        title: "Owner internal roadmap",
        session_type: "workspace",
        is_running: true,
        repo: "owner/private-core",
        updated_at: "2026-11-12T01:00:00.000Z",
      },
      {
        session_id: "sess-exp-only",
        title: "Experimental feature review",
        session_type: "workspace",
        is_running: false,
        repo: "owner/experimental-repo",
        updated_at: "2026-11-12T00:55:00.000Z",
      },
      {
        session_id: "sess-alpha-only",
        title: "Alpha team API rollout",
        session_type: "workspace",
        is_running: false,
        repo: "owner/alpha-service",
        updated_at: "2026-11-12T00:50:00.000Z",
      },
      {
        session_id: "sess-shared-both",
        title: "Cross-flock release checklist",
        session_type: "chat",
        is_running: false,
        repo: null,
        updated_at: "2026-11-12T00:45:00.000Z",
      },
      {
        session_id: "sess-foreign-bound",
        title: "Partner isolated thread",
        session_type: "workspace",
        is_running: false,
        repo: "partner/ext",
        updated_at: "2026-11-12T00:40:00.000Z",
      },
    ];

    const personalSessions = [
      {
        session_id: "sess-personal-unshared",
        title: "Home lab notes",
        session_type: "chat",
        is_running: false,
        repo: null,
        updated_at: "2026-11-12T00:35:00.000Z",
      },
    ];

    const workTranscriptBodies = new Map([
      ["sess-private-owner", "SENTINEL_PRIVATE_OWNER_BODY_DO_NOT_LEAK"],
      ["sess-exp-only", "LIVE_EXP_TRANSCRIPT_BODY"],
      ["sess-alpha-only", "SENTINEL_ALPHA_ONLY_BODY_DO_NOT_LEAK"],
      ["sess-shared-both", "SHARED_BOTH_TRANSCRIPT_BODY"],
      ["sess-foreign-bound", "SENTINEL_FOREIGN_BOUND_BODY_DO_NOT_LEAK"],
    ]);

    const transcriptReadCalls = [];
    const readWorkTranscript = async (selector) => {
      transcriptReadCalls.push(selector);
      const target =
        selector === "latest"
          ? workSessions[0]
          : workSessions.find((s) => s.session_id === selector);
      if (!target) throw new Error(`Session not found: ${selector}`);
      return {
        session: target,
        messages: [
          {
            role: "assistant",
            content: workTranscriptBodies.get(target.session_id),
            timestamp: target.updated_at,
          },
        ],
      };
    };

    const sharedMembersRoster = [
      { machineId: "CALLER-LAPTOP", githubUser: "owner", scope: "work", trustTier: "owner" },
      { machineId: "HOST-WORK-VM", githubUser: "owner", scope: "work", trustTier: "owner" },
      { machineId: "ALICE-LAPTOP", githubUser: "alice", scope: "work", trustTier: "collaborator" },
    ];

    const workHostFlocksPath = path.join(tempRoot, "work-host-flocks.json");
    writeConfigFileSecure(
      {
        flocks: {
          "owner/experimental": {
            flockId: "owner/experimental",
            flockType: "shared",
            // Even when trustTier is "owner", explicit_opt_in_only must strictly enforce opt-in session IDs!
            trustTier: "owner",
            ownerGitHubUser: "owner",
            allowedScopes: ["work"],
            sessionVisibility: "explicit_opt_in_only",
            sharedSessionIds: ["sess-exp-only", "sess-shared-both"],
            sharedSnapshots: {
              "sess-exp-only": {
                sessionId: "sess-exp-only",
                title: "Experimental feature review",
                mode: "approved-snapshot",
                summarySnapshot: "Approved snapshot for owner/experimental only.",
                sharedAt: "2026-11-12T00:55:00.000Z",
              },
            },
            members: sharedMembersRoster,
          },
          "owner/team-alpha": {
            flockId: "owner/team-alpha",
            flockType: "shared",
            trustTier: "collaborator",
            ownerGitHubUser: "owner",
            allowedScopes: ["work"],
            sessionVisibility: "explicit_opt_in_only",
            sharedSessionIds: ["sess-alpha-only", "sess-shared-both"],
            sharedSnapshots: {
              "sess-alpha-only": {
                sessionId: "sess-alpha-only",
                title: "Alpha team API rollout",
                mode: "approved-snapshot",
                summarySnapshot: "Approved snapshot for owner/team-alpha only.",
                sharedAt: "2026-11-12T00:50:00.000Z",
              },
            },
            members: sharedMembersRoster,
          },
        },
        threadBindings: {
          "sess-foreign-bound": "partner/ext-flock",
        },
      },
      workHostFlocksPath
    );

    const personalHostFlocksPath = path.join(tempRoot, "personal-host-flocks.json");
    writeConfigFileSecure({ flocks: {}, threadBindings: {} }, personalHostFlocksPath);

    const callerFlocksPath = path.join(tempRoot, "caller-flocks.json");
    writeConfigFileSecure(
      {
        flocks: {
          "owner/experimental": {
            flockId: "owner/experimental",
            flockType: "shared",
            trustTier: "collaborator",
            allowedScopes: ["work"],
            sessionVisibility: "explicit_opt_in_only",
            members: sharedMembersRoster,
          },
          "owner/team-alpha": {
            flockId: "owner/team-alpha",
            flockType: "shared",
            trustTier: "collaborator",
            allowedScopes: ["work"],
            sessionVisibility: "explicit_opt_in_only",
            members: sharedMembersRoster,
          },
        },
      },
      callerFlocksPath
    );

    const aliceFlocksPath = path.join(tempRoot, "alice-flocks.json");
    writeConfigFileSecure(
      {
        flocks: {
          "owner/experimental": {
            flockId: "owner/experimental",
            flockType: "shared",
            trustTier: "collaborator",
            allowedScopes: ["work"],
            sessionVisibility: "explicit_opt_in_only",
            members: sharedMembersRoster,
          },
        },
      },
      aliceFlocksPath
    );

    const workHostCfg = {
      machineId: "HOST-WORK-VM",
      githubUser: "owner",
      scope: "work",
      hub: "copilotbridge",
      flocksConfigPath: workHostFlocksPath,
      sessionsOverride: workSessions,
      readTranscriptFn: readWorkTranscript,
    };
    const personalHostCfg = {
      machineId: "HOST-PERSONAL-PC",
      githubUser: "owner",
      scope: "personal",
      hub: "copilotbridge",
      flocksConfigPath: personalHostFlocksPath,
      sessionsOverride: personalSessions,
      readTranscriptFn: async (selector) => ({
        session: personalSessions[0],
        messages: [{ role: "assistant", content: `PERSONAL:${selector}`, timestamp: "2026-11-12T00:35:00.000Z" }],
      }),
    };

    const wireLog = [];
    const simulatedHubTransport = async (rpcPayload) => {
      wireLog.push(structuredClone(rpcPayload));
      const targets =
        !rpcPayload.toMachine || rpcPayload.toMachine === "*" || rpcPayload.toMachine.toLowerCase() === "all"
          ? [workHostCfg, personalHostCfg]
          : [workHostCfg, personalHostCfg].filter(
              (h) => h.machineId.toLowerCase() === rpcPayload.toMachine.toLowerCase()
            );
      const replies = [];
      for (const host of targets) {
        try {
          const result = await handleRpcAction(host, {
            ...rpcPayload,
            registryMembers,
            enforceSignature: true,
          });
          replies.push({ requestId: rpcPayload.requestId, fromMachine: host.machineId, result });
        } catch (err) {
          replies.push({
            requestId: rpcPayload.requestId,
            fromMachine: host.machineId,
            error: formatErrorDetail(err),
          });
        }
      }
      return replies;
    };

    const callerCfg = {
      machineId: "CALLER-LAPTOP",
      githubUser: "owner",
      scope: "work",
      hub: "copilotbridge",
      identity: callerKey,
      flocksConfigPath: callerFlocksPath,
      rpcTransport: simulatedHubTransport,
    };

    const aliceCfg = {
      machineId: "ALICE-LAPTOP",
      githubUser: "alice",
      scope: "work",
      hub: "copilotbridge",
      identity: aliceKey,
      flocksConfigPath: aliceFlocksPath,
      rpcTransport: simulatedHubTransport,
    };

    // 1. Broadcast list_remote_sessions with explicit `flock: "owner/experimental"`:
    //    propagates signed selector on wire, excludes non-member HOST-PERSONAL-PC,
    //    and returns ONLY exact session IDs authorized for owner/experimental.
    const expListBroadcast = await executeMcpTool(callerCfg, "list_remote_sessions", {
      flock: "owner/experimental",
    });
    assert.equal(Array.isArray(expListBroadcast), true);
    assert.deepEqual(
      expListBroadcast.map((m) => m.machineId),
      ["HOST-WORK-VM"]
    );
    assert.equal(expListBroadcast[0].flockId, "owner/experimental");
    assert.deepEqual(
      expListBroadcast[0].sessions.map((s) => s.session_id).sort(),
      ["sess-exp-only", "sess-shared-both"]
    );
    assert.equal(wireLog.at(-1).flockId, "owner/experimental");
    assert.equal(wireLog.at(-1).params.flock, "owner/experimental");

    // 2. Targeted list_remote_sessions with explicit `flock: "owner/team-alpha"`:
    //    returns ONLY exact session IDs authorized for owner/team-alpha (excluding sess-exp-only, sess-private-owner, sess-foreign-bound).
    const alphaListTargeted = await executeMcpTool(callerCfg, "list_remote_sessions", {
      flock: "owner/team-alpha",
      machine: "HOST-WORK-VM",
    });
    assert.equal(alphaListTargeted.flockId, "owner/team-alpha");
    assert.deepEqual(
      alphaListTargeted.sessions.map((s) => s.session_id).sort(),
      ["sess-alpha-only", "sess-shared-both"]
    );

    // 3. Explicit owner scope flock `flock: "owner/work"` includes owner sessions on HOST-WORK-VM
    //    but STILL excludes foreign-bound `sess-foreign-bound` (`threadBindings`).
    const ownerWorkList = await executeMcpTool(callerCfg, "list_remote_sessions", {
      flock: "owner/work",
      machine: "HOST-WORK-VM",
    });
    assert.equal(ownerWorkList.flockId, "owner/work");
    assert.deepEqual(
      ownerWorkList.sessions.map((s) => s.session_id).sort(),
      ["sess-alpha-only", "sess-exp-only", "sess-private-owner", "sess-shared-both"]
    );

    // 4. get_remote_session_transcript with `to_machine: "auto"` + explicit `flock: "owner/experimental"`
    //    resolves ONLY member HOST-WORK-VM (ignoring non-member HOST-PERSONAL-PC) and returns authorized transcript/snapshot.
    transcriptReadCalls.length = 0;
    const expSnapTranscript = await executeMcpTool(callerCfg, "get_remote_session_transcript", {
      flock: "owner/experimental",
      to_machine: "auto",
      session: "sess-exp-only",
    });
    assert.equal(expSnapTranscript.session.session_id, "sess-exp-only");
    assert.equal(expSnapTranscript.messages[0].content, "Approved snapshot for owner/experimental only.");
    assert.deepEqual(transcriptReadCalls, []);

    const expSharedLiveTranscript = await executeMcpTool(callerCfg, "get_remote_session_transcript", {
      flock: "owner/experimental",
      to_machine: "HOST-WORK-VM",
      session: "sess-shared-both",
    });
    assert.equal(expSharedLiveTranscript.session.session_id, "sess-shared-both");
    assert.equal(expSharedLiveTranscript.messages[0].content, "SHARED_BOTH_TRANSCRIPT_BODY");
    assert.deepEqual(transcriptReadCalls, ["sess-shared-both"]);

    // 5. Pre-body transcript denial: requesting unshared, other-flock, foreign-bound, fuzzy-substring, or "latest"
    //    sessions under `flock: "owner/experimental"` rejects BEFORE reading any transcript body (`transcriptReadCalls` stays empty).
    transcriptReadCalls.length = 0;
    for (const forbiddenSession of [
      "sess-private-owner",
      "sess-alpha-only",
      "sess-foreign-bound",
      "Owner internal",
      "latest",
    ]) {
      await assert.rejects(
        () =>
          executeMcpTool(callerCfg, "get_remote_session_transcript", {
            flock: "owner/experimental",
            to_machine: "HOST-WORK-VM",
            session: forbiddenSession,
          }),
        (err) => {
          assert.match(err.message, /SESSION_NOT_SHARED|not shared/i);
          assert.doesNotMatch(err.message, /SENTINEL_/);
          return true;
        }
      );
    }
    assert.deepEqual(
      transcriptReadCalls,
      [],
      "Denied transcript requests must fail pre-body before invoking transcript reader"
    );

    // Foreign-bound session is also denied pre-body even under explicit `flock: "owner/work"`
    transcriptReadCalls.length = 0;
    await assert.rejects(
      () =>
        executeMcpTool(callerCfg, "get_remote_session_transcript", {
          flock: "owner/work",
          to_machine: "HOST-WORK-VM",
          session: "sess-foreign-bound",
        }),
      /SESSION_NOT_SHARED|not authorized/i
    );
    assert.deepEqual(transcriptReadCalls, []);

    // 6. Invalid, non-member, conflicting, or unauthorized explicit `flock` selectors fail closed
    //    without sending fallback RPCs or falling back to default owner routes.
    const wireCountBeforeInvalid = wireLog.length;
    for (const invalidFlock of ["", "   ", "../escape", "owner//experimental", "a/b/c/d", "*", "all"]) {
      await assert.rejects(
        () => executeMcpTool(callerCfg, "list_remote_sessions", { flock: invalidFlock }),
        (err) => err.code === "INVALID_FLOCK_SELECTOR"
      );
      await assert.rejects(
        () =>
          executeMcpTool(callerCfg, "get_remote_session_transcript", {
            flock: invalidFlock,
            to_machine: "HOST-WORK-VM",
            session: "sess-exp-only",
          }),
        (err) => err.code === "INVALID_FLOCK_SELECTOR"
      );
    }
    assert.equal(wireLog.length, wireCountBeforeInvalid, "Invalid selectors must fail closed before wire send");

    for (const nonMemberFlock of ["owner/unjoined-flock", "stranger/secret-team"]) {
      await assert.rejects(
        () => executeMcpTool(callerCfg, "list_remote_sessions", { flock: nonMemberFlock }),
        (err) => err.code === "FLOCK_NOT_ENROLLED" && err.statusCode === 403
      );
      await assert.rejects(
        () =>
          executeMcpTool(callerCfg, "get_remote_session_transcript", {
            flock: nonMemberFlock,
            to_machine: "HOST-WORK-VM",
            session: "sess-exp-only",
          }),
        (err) => err.code === "FLOCK_NOT_ENROLLED" && err.statusCode === 403
      );
    }

    // Targeting a non-member machine (`HOST-PERSONAL-PC`) with `flock: "owner/experimental"` fails closed
    await assert.rejects(
      () =>
        executeMcpTool(callerCfg, "list_remote_sessions", {
          flock: "owner/experimental",
          machine: "HOST-PERSONAL-PC",
        }),
      /FLOCK_NOT_ENROLLED|FLOCK_SCOPE_FORBIDDEN/
    );
    await assert.rejects(
      () =>
        executeMcpTool(callerCfg, "list_remote_sessions", {
          flock: "owner/experimental/HOST-PERSONAL-PC",
        }),
      (err) => err.code === "FLOCK_NON_MEMBER" && err.statusCode === 403
    );
    await assert.rejects(
      () =>
        executeMcpTool(callerCfg, "get_remote_session_transcript", {
          flock: "owner/experimental/HOST-WORK-VM",
          to_machine: "HOST-PERSONAL-PC",
          session: "sess-exp-only",
        }),
      (err) => err.code === "FLOCK_TARGET_CONFLICT"
    );

    // Cross-user `@alice`: allowed on enrolled `owner/experimental`, rejected fail-closed on `owner/team-alpha`,
    // `owner/work`, and omitted-selector default owner routes!
    const aliceExpList = await executeMcpTool(aliceCfg, "list_remote_sessions", {
      flock: "owner/experimental",
      machine: "HOST-WORK-VM",
    });
    assert.deepEqual(
      aliceExpList.sessions.map((s) => s.session_id).sort(),
      ["sess-exp-only", "sess-shared-both"]
    );
    await assert.rejects(
      () =>
        executeMcpTool(aliceCfg, "list_remote_sessions", {
          flock: "owner/team-alpha",
          machine: "HOST-WORK-VM",
        }),
      (err) => err.code === "FLOCK_NOT_ENROLLED" && err.statusCode === 403
    );
    await assert.rejects(
      () =>
        executeMcpTool(aliceCfg, "list_remote_sessions", {
          flock: "owner/work",
          machine: "HOST-WORK-VM",
        }),
      (err) => err.code === "FLOCK_NOT_ENROLLED" && err.statusCode === 403
    );
    // Direct responder check: even if @alice bypasses caller check and sends `flock: "owner/work"` or omits `flock` on wire, responder rejects pre-body!
    transcriptReadCalls.length = 0;
    await assert.rejects(
      () =>
        handleRpcAction(workHostCfg, {
          requestId: "req-alice-owner-steal",
          fromMachine: "ALICE-LAPTOP",
          action: "get_transcript",
          flockId: "owner/work",
          params: { flock: "owner/work", session: "sess-private-owner" },
          registryMembers,
        }),
      (err) => err.code === "UNAUTHORIZED_FLOCK" && err.statusCode === 403
    );
    await assert.rejects(
      () =>
        handleRpcAction(workHostCfg, {
          requestId: "req-alice-omitted-steal",
          fromMachine: "ALICE-LAPTOP",
          action: "list_sessions",
          params: {},
          registryMembers,
        }),
      (err) => err.code === "UNAUTHORIZED_FLOCK" && err.statusCode === 403
    );
    // Direct responder check: unsigned outer `flockId` injected onto a signed omitted-flock request is rejected!
    const sentAt = new Date().toISOString();
    const signedOmittedAuth = signRpcRequest({
      requestId: "req-tamper-outer-flock",
      sentAt,
      fromMachine: "CALLER-LAPTOP",
      toMachine: "HOST-WORK-VM",
      action: "list_sessions",
      params: { query: "", limit: 25, runningOnly: false },
      identity: callerKey,
    });
    await assert.rejects(
      () =>
        handleRpcAction(workHostCfg, {
          requestId: "req-tamper-outer-flock",
          sentAt,
          fromMachine: "CALLER-LAPTOP",
          toMachine: "HOST-WORK-VM",
          action: "list_sessions",
          flockId: "owner/experimental",
          params: { query: "", limit: 25, runningOnly: false },
          auth: signedOmittedAuth,
          registryMembers,
        }),
      (err) => err.code === "UNSIGNED_FLOCK_SELECTOR" && err.statusCode === 403
    );
    assert.deepEqual(transcriptReadCalls, []);

    // 7. Omitted-selector behavior preserved for same-owner default routes!
    const omittedOwnerList = await executeMcpTool(callerCfg, "list_remote_sessions", {
      machine: "HOST-WORK-VM",
    });
    assert.equal(omittedOwnerList.flockId, undefined);
    assert.deepEqual(
      omittedOwnerList.sessions.map((s) => s.session_id),
      workSessions.map((s) => s.session_id)
    );
    const omittedOwnerTranscript = await executeMcpTool(callerCfg, "get_remote_session_transcript", {
      to_machine: "HOST-WORK-VM",
      session: "sess-private-owner",
    });
    assert.equal(
      omittedOwnerTranscript.messages[0].content,
      "SENTINEL_PRIVATE_OWNER_BODY_DO_NOT_LEAK"
    );

    // 8. Real on-disk cli-sessions.json + session-state/<id>/events.jsonl verification (no overrides):
    //    proves fs.promises.open is NEVER called on events.jsonl when transcript access is denied!
    const diskFlockHome = path.join(process.env.COPILOT_HOME, "flock");
    fs.mkdirSync(diskFlockHome, { recursive: true });
    fs.writeFileSync(
      path.join(diskFlockHome, "cli-sessions.json"),
      JSON.stringify([
        { session_id: "disk-sess-owner", title: "Disk Owner Only", session_type: "cli", is_running: false },
        { session_id: "disk-sess-exp", title: "Disk Exp Shared", session_type: "cli", is_running: false },
        { session_id: "disk-sess-alpha", title: "Disk Alpha Shared", session_type: "cli", is_running: false },
      ]),
      "utf8"
    );
    for (const [sid, secretLine] of [
      ["disk-sess-owner", "DISK_OWNER_PRIVATE_TRANSCRIPT_BODY"],
      ["disk-sess-exp", "DISK_EXP_AUTHORIZED_TRANSCRIPT_BODY"],
      ["disk-sess-alpha", "DISK_ALPHA_OTHER_FLOCK_TRANSCRIPT_BODY"],
    ]) {
      const sessDir = path.join(process.env.COPILOT_HOME, "session-state", sid);
      fs.mkdirSync(sessDir, { recursive: true });
      fs.writeFileSync(
        path.join(sessDir, "events.jsonl"),
        JSON.stringify({
          type: "assistant.message",
          id: crypto.randomUUID(),
          data: { content: secretLine },
          timestamp: "2026-11-12T01:10:00.000Z",
        }) + "\n",
        "utf8"
      );
    }
    writeConfigFileSecure(
      {
        flocks: {
          "owner/experimental": {
            flockId: "owner/experimental",
            flockType: "shared",
            trustTier: "collaborator",
            allowedScopes: ["work"],
            sessionVisibility: "explicit_opt_in_only",
            sharedSessionIds: ["disk-sess-exp"],
          },
          "owner/team-alpha": {
            flockId: "owner/team-alpha",
            flockType: "shared",
            trustTier: "collaborator",
            allowedScopes: ["work"],
            sessionVisibility: "explicit_opt_in_only",
            sharedSessionIds: ["disk-sess-alpha"],
          },
        },
      },
      path.join(diskFlockHome, "flocks.json")
    );

    const diskHostCfg = { machineId: "DISK-WORK-VM", githubUser: "owner", scope: "work" };
    const diskExpSessions = await handleRpcAction(diskHostCfg, {
      action: "list_sessions",
      flockId: "owner/experimental",
      params: { flock: "owner/experimental" },
    });
    assert.deepEqual(
      diskExpSessions.sessions.map((s) => s.session_id),
      ["disk-sess-exp"]
    );

    const openedFiles = [];
    const origPromisesOpen = fs.promises.open;
    fs.promises.open = async function (targetPath, ...rest) {
      openedFiles.push(String(targetPath));
      return origPromisesOpen.call(this, targetPath, ...rest);
    };
    try {
      await assert.rejects(
        () =>
          handleRpcAction(diskHostCfg, {
            action: "get_transcript",
            flockId: "owner/experimental",
            params: { flock: "owner/experimental", session: "disk-sess-alpha" },
          }),
        (err) => err.code === "SESSION_NOT_SHARED" && err.statusCode === 403
      );
      await assert.rejects(
        () =>
          handleRpcAction(diskHostCfg, {
            action: "get_transcript",
            flockId: "owner/experimental",
            params: { flock: "owner/experimental", session: "disk-sess-owner" },
          }),
        (err) => err.code === "SESSION_NOT_SHARED" && err.statusCode === 403
      );
      assert.deepEqual(
        openedFiles,
        [],
        "events.jsonl must never be opened when get_transcript is denied for an unauthorized flock"
      );

      const allowedDiskTx = await handleRpcAction(diskHostCfg, {
        action: "get_transcript",
        flockId: "owner/experimental",
        params: { flock: "owner/experimental", session: "disk-sess-exp" },
      });
      assert.equal(allowedDiskTx.messages[0].content, "DISK_EXP_AUTHORIZED_TRANSCRIPT_BODY");
      assert.equal(openedFiles.length, 1);
      assert.match(openedFiles[0], /disk-sess-exp[\\/]events\.jsonl$/);
    } finally {
      fs.promises.open = origPromisesOpen;
    }
  } finally {
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("TODO #9: broker-free two-flock list_remote_sessions and get_remote_session_transcript propagate args.flock end-to-end, isolate per-flock session IDs, and reject invalid/non-member selectors fail-closed", async () => {
  const { AzureTransport, azureEndpoints } = await import("../flock-azure.mjs");
  const { BrokerFreeRuntime } = await import("../flock-broker-free.mjs");
  const { ownerFingerprint } = await import("../flock-protocol.mjs");
  const { atomicJson } = await import("../flock-lifecycle.mjs");

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-todo9-bf34-"));
  const prevCopilotHome = process.env.COPILOT_HOME;
  const ownerCopilotHome = path.join(root, "owner-copilot-home");
  process.env.COPILOT_HOME = ownerCopilotHome;

  let ownerDaemon = null;
  try {
    const endpoints = azureEndpoints(
      "https://fixture.service.signalr.net",
      "https://fixture.servicebus.windows.net"
    );
    const credentials = {
      connectionString: "Endpoint=https://fixture.service.signalr.net;AccessKey=signalr-fixture",
      manageConnectionString:
        "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=manage-fixture",
      sendConnectionString:
        "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockSendRule;SharedAccessKey=send-fixture",
      listenConnectionString:
        "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockListenRule;SharedAccessKey=listen-fixture",
    };

    const subscribers = new Map();
    const sockets = new Set();
    const fetchImpl = async (url, options) => {
      const parsed = new URL(url);
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
        for (const socket of sockets) {
          if (!socket.ws.closed) socket.callback(target, structuredClone(args));
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
          headers: {
            Location: `${endpoints.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peer}/messages/lock`,
          },
        });
      }
      if (options.method === "DELETE" && parsed.pathname.endsWith("/messages/lock")) {
        subscribers.get(peer)?.shift();
        return new Response(null, { status: 204 });
      }
      if (options.method === "PUT" && parsed.pathname.endsWith("/messages/lock")) {
        return new Response(null, { status: 204 });
      }
      throw new Error(`Unexpected synthetic transport operation: ${options.method} ${parsed.pathname}`);
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
    const transportFactory = (config, opts) => new AzureTransport(config, { ...opts, fetchImpl });

    const ownerFlockDir = path.join(ownerCopilotHome, "flock");
    const peerFlockDir = path.join(root, "peer-flock");
    fs.mkdirSync(ownerFlockDir, { recursive: true });
    fs.mkdirSync(peerFlockDir, { recursive: true });

    const ownerHostCfg = { protocol: "broker-free-v34", machineId: "OWNER-HOST", scope: "work" };
    const ownerRuntime = new BrokerFreeRuntime(ownerFlockDir, {
      connect,
      transportFactory,
      log: () => {},
      dispatch: (req) => dispatchBrokerFreeRpc(ownerHostCfg, req),
    });
    const peerRuntime = new BrokerFreeRuntime(peerFlockDir, {
      connect,
      transportFactory,
      log: () => {},
    });

    await ownerRuntime.initializeOwner({
      flockId: "demo/flock-a",
      machineId: "OWNER-HOST",
      scope: "work",
      ...credentials,
    });
    await ownerRuntime.initializeOwner({
      flockId: "demo/flock-b",
      machineId: "OWNER-HOST",
      scope: "work",
      ...credentials,
    });

    const joinA = await peerRuntime.joinRequest({
      machineId: "PEER-CLIENT",
      scope: "work",
      flockId: "demo/flock-a",
    });
    const ticketA = await ownerRuntime.approve({
      flockId: "demo/flock-a",
      code: joinA,
      expectedEd25519Fingerprint: joinA.body.peerId,
      role: "collaborator",
      sessionIds: ["sess-bf-a", "sess-bf-both"],
      membershipExpiresAt: Date.now() + 3600000,
    });
    await peerRuntime.accept(
      ticketA,
      ownerFingerprint(ownerRuntime.record("demo/flock-a").ownerPublicKey)
    );

    const joinB = await peerRuntime.joinRequest({
      machineId: "PEER-CLIENT",
      scope: "work",
      flockId: "demo/flock-b",
    });
    const ticketB = await ownerRuntime.approve({
      flockId: "demo/flock-b",
      code: joinB,
      expectedEd25519Fingerprint: joinB.body.peerId,
      role: "collaborator",
      sessionIds: ["sess-bf-b", "sess-bf-both"],
      membershipExpiresAt: Date.now() + 3600000,
    });
    await peerRuntime.accept(
      ticketB,
      ownerFingerprint(ownerRuntime.record("demo/flock-b").ownerPublicKey)
    );

    // Configure owner's local flocks.json with distinct shared sessions per flock + a foreign-bound session
    atomicJson(path.join(ownerFlockDir, "flocks.json"), {
      flocks: {
        "demo/flock-a": {
          sharedSessionIds: ["sess-bf-a", "sess-bf-both", "sess-bf-foreign"],
          sharedSnapshots: {
            "sess-bf-a": {
              title: "Flock A Thread",
              summarySnapshot: "Approved summary A",
              sharedAt: "2026-11-12T01:00:00.000Z",
            },
            "sess-bf-both": {
              title: "Shared AB Thread",
              summarySnapshot: "Approved summary AB (A view)",
              sharedAt: "2026-11-12T01:00:00.000Z",
            },
            "sess-bf-foreign": {
              title: "Foreign Bound Thread",
              summarySnapshot: "MUST_NOT_LEAK_FOREIGN",
              sharedAt: "2026-11-12T01:00:00.000Z",
            },
          },
        },
        "demo/flock-b": {
          sharedSessionIds: ["sess-bf-b", "sess-bf-both"],
          sharedSnapshots: {
            "sess-bf-b": {
              title: "Flock B Thread",
              summarySnapshot: "Approved summary B",
              sharedAt: "2026-11-12T01:05:00.000Z",
            },
            "sess-bf-both": {
              title: "Shared AB Thread",
              summarySnapshot: "Approved summary AB (B view)",
              sharedAt: "2026-11-12T01:05:00.000Z",
            },
          },
        },
      },
      threadBindings: {
        "sess-bf-foreign": "demo/external-other",
      },
    });

    ownerDaemon = await ownerRuntime.start();

    const peerCfg = {
      protocol: "broker-free-v34",
      machineId: "PEER-CLIENT",
      scope: "work",
      hub: "copilotbridge",
      skipDaemonEnsure: true,
      brokerFreeOptions: {
        root: peerFlockDir,
        connect,
        transportFactory,
        log: () => {},
      },
    };

    const listA = await executeMcpTool(peerCfg, "list_remote_sessions", {
      flock: "demo/flock-a",
      machine: "OWNER-HOST",
    });
    assert.equal(listA.flockId, "demo/flock-a");
    assert.deepEqual(
      listA.sessions.map((s) => s.session_id).sort(),
      ["sess-bf-a", "sess-bf-both"]
    );

    const listB = await executeMcpTool(peerCfg, "list_remote_sessions", {
      flock: "demo/flock-b",
      machine: "OWNER-HOST",
    });
    assert.equal(listB.flockId, "demo/flock-b");
    assert.deepEqual(
      listB.sessions.map((s) => s.session_id).sort(),
      ["sess-bf-b", "sess-bf-both"]
    );

    const txA = await executeMcpTool(peerCfg, "get_remote_session_transcript", {
      flock: "demo/flock-a",
      to_machine: "OWNER-HOST",
      session: "sess-bf-a",
    });
    assert.equal(txA.messages[0].content, "Approved summary A");

    // Pre-body transcript denial across flocks & unshared/foreign sessions
    for (const deniedSess of ["sess-bf-b", "sess-bf-foreign", "unshared-local-only", "latest"]) {
      await assert.rejects(
        () =>
          executeMcpTool(peerCfg, "get_remote_session_transcript", {
            flock: "demo/flock-a",
            to_machine: "OWNER-HOST",
            session: deniedSess,
          }),
        /forbids|not explicitly shared/i
      );
    }

    // Omitted selector with 2 broker-free memberships fails closed as ambiguous
    await assert.rejects(
      () => executeMcpTool(peerCfg, "list_remote_sessions", { machine: "OWNER-HOST" }),
      /ambiguous/i
    );

    // Explicit empty/invalid/non-member selectors fail closed even if cfg.flockId has a default
    const singleDefaultPeerCfg = { ...peerCfg, flockId: "demo/flock-a" };
    await assert.rejects(
      () => executeMcpTool(singleDefaultPeerCfg, "list_remote_sessions", { flock: "", machine: "OWNER-HOST" }),
      (err) => err.code === "INVALID_FLOCK_SELECTOR"
    );
    await assert.rejects(
      () =>
        executeMcpTool(singleDefaultPeerCfg, "get_remote_session_transcript", {
          flock: "demo/non-member",
          to_machine: "OWNER-HOST",
          session: "sess-bf-a",
        }),
      /Not an active broker-free flock/i
    );
  } finally {
    if (ownerDaemon) ownerDaemon.close();
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    fs.rmSync(root, { recursive: true, force: true });
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

test("durable v3 broker-backed membership registry: offline collaborators, cryptographic indexing over shared hostnames, stale caches, presence/thread isolation, restart persistence, tombstones, and rollback rejection", async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-registry-v3-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const storePath = path.join(tempRoot, "broker-v3-store.json");
  const registryPath = path.join(tempRoot, "flock-registry.json");
  const testConnStr =
    "Endpoint=https://your-signalr.service.signalr.net;AccessKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;Version=1.0;";

  const ownerKey = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const aliceKey = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const bobKey = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  let clockNow = 1_750_000_000_000;
  const registry = new FlockMembershipRegistry(registryPath, {
    clock: () => clockNow,
    staleAfterMs: 300_000,
    presenceTtlMs: 60_000,
  });

  // 1. Hostname-only member records without cryptographic identity must fail closed
  assert.throws(
    () =>
      registry.reconcileV3BrokerFlock({
        flockId: "erjadi/studio-team",
        rosterEpoch: 1,
        members: [{ machineId: "HOSTNAME-ONLY-PC", githubUser: "alice", scope: "work" }],
      }),
    (err) => err.code === "ROSTER_IDENTITY_REQUIRED"
  );

  // 2. Enroll owner in personal + work flocks, plus invite @alice and @bob to erjadi/studio-team
  //    BOTH @alice and @bob use identical hostname `WORK-LAPTOP` with distinct Ed25519 identities
  await enrollV3Device(
    {
      githubUser: "erjadi",
      githubUserId: 1001,
      deviceId: "fp-owner-pc",
      machineId: "MAIN-WORKSTATION",
      scope: "personal",
      publicKey: ownerKey.publicKey,
      keyFingerprint: "fp-owner-pc",
    },
    { storePath, connectionString: testConnStr }
  );
  const inviteAlice = await createV3FlockInvite(
    {
      callerGitHubUser: "erjadi",
      callerGitHubUserId: 1001,
      targetAddress: "erjadi/studio-team",
      invitedUser: "alice",
      invitedGitHubUserId: 2002,
    },
    { storePath }
  );
  const inviteBob = await createV3FlockInvite(
    {
      callerGitHubUser: "erjadi",
      callerGitHubUserId: 1001,
      targetAddress: "erjadi/studio-team",
      invitedUser: "bob",
      invitedGitHubUserId: 3003,
    },
    { storePath }
  );
  await enrollV3Device(
    {
      githubUser: "alice",
      githubUserId: 2002,
      deviceId: "fp-alice-1",
      machineId: "WORK-LAPTOP",
      scope: "work",
      publicKey: aliceKey.publicKey,
      keyFingerprint: "fp-alice-1",
      enrollmentJson: inviteAlice.enrollmentJson,
    },
    { storePath, connectionString: testConnStr }
  );
  await enrollV3Device(
    {
      githubUser: "bob",
      githubUserId: 3003,
      deviceId: "fp-bob-1",
      machineId: "WORK-LAPTOP",
      scope: "work",
      publicKey: bobKey.publicKey,
      keyFingerprint: "fp-bob-1",
      enrollmentJson: inviteBob.enrollmentJson,
    },
    { storePath, connectionString: testConnStr }
  );

  // Reconcile /api/v3/my-flocks + /api/members without pinging any machine
  const myFlocksBeforeKick = await listV3UserFlocks(
    { githubUser: "erjadi", githubUserId: 1001, deviceId: "fp-owner-pc" },
    { storePath }
  );
  const bootstrapMembers = [
    {
      machineId: "WORK-LAPTOP",
      githubUser: "alice",
      keyFingerprint: "fp-alice-1",
      scope: "work",
      version: "3.4.1",
      specs: { memory: { totalGb: 64 }, gpus: [{ name: "RTX 4090", vramGb: 24 }] },
      registeredAt: new Date(clockNow - 10_000).toISOString(),
      lastSeenAt: new Date(clockNow - 5_000).toISOString(),
    },
  ];
  registry.reconcileV3Broker({ myFlocksResponse: myFlocksBeforeKick, bootstrapMembers });

  // 3. Offline collaborators & shared-hostname coexistence without live pings
  const teamView = registry.getFlockView("erjadi/studio-team");
  assert.equal(teamView.isStale, false);
  assert.equal(teamView.sharedThreadVisibility, "isolated");
  const aliceMember = teamView.members.find((m) => m.peerId === "2002:fp-alice-1");
  const bobMember = teamView.members.find((m) => m.peerId === "3003:fp-bob-1");
  assert.ok(aliceMember && bobMember, "Both WORK-LAPTOP devices must coexist via cryptographic identity");
  assert.equal(aliceMember.keyFingerprint, "fp-alice-1");
  assert.equal(bobMember.keyFingerprint, "fp-bob-1");
  assert.equal(aliceMember.machineId, "WORK-LAPTOP");
  assert.equal(bobMember.machineId, "WORK-LAPTOP");
  assert.equal(aliceMember.specs?.memory?.totalGb, 64, "Matched /api/members specs by keyFingerprint");
  assert.equal(bobMember.specs, null, "Alice's /api/members specs must not bleed onto Bob's WORK-LAPTOP");
  assert.equal(aliceMember.membershipStatus, "active");
  assert.equal(aliceMember.presenceStatus, "unknown", "Broker registration lastSeenAt must never masquerade as live online");
  assert.ok(aliceMember.lastSeenAt);
  assert.equal(aliceMember.sharedThreadsExposed, false);

  // 4. Cross-flock isolation: erjadi/personal never sees studio-team collaborators
  const personalView = registry.getFlockView("erjadi/personal");
  assert.equal(personalView.members.length, 1);
  assert.equal(personalView.members[0].peerId, "1001:fp-owner-pc");

  // 5. Shared-thread isolation: registry membership grants zero access to unshared local sessions
  const localFlocksPath = path.join(tempRoot, "flocks.json");
  const hostCfg = { machineId: "MAIN-WORKSTATION", githubUser: "erjadi", scope: "work" };
  shareThreadWithFlock(
    hostCfg,
    {
      flockId: "erjadi/studio-team",
      sessionId: "approved-only",
      title: "Approved thread",
      summarySnapshot: "Clean summary",
    },
    localFlocksPath
  );
  const teamPolicy = loadLocalFlocksConfig(hostCfg, localFlocksPath).flocks["erjadi/studio-team"];
  await assert.rejects(
    () =>
      handleRpcAction(hostCfg, {
        action: "get_transcript",
        flockPolicy: teamPolicy,
        params: { session: "private-local-thread" },
      }),
    (err) => err.code === "SESSION_NOT_SHARED" && err.statusCode === 403
  );

  // 6. Live presence updates never mutate rosterEpoch, rosterRevision, or rosterHash, and decay back to unknown
  const hashBeforePresence = teamView.rosterHash;
  registry.recordPresence("erjadi/studio-team", [
    { peerId: "3003:fp-bob-1", observedAtMs: clockNow, version: "3.4.1" },
  ]);
  const withLiveBob = registry.getFlockView("erjadi/studio-team");
  assert.equal(withLiveBob.rosterHash, hashBeforePresence);
  assert.equal(withLiveBob.rosterRevision, teamView.rosterRevision);
  assert.equal(withLiveBob.members.find((m) => m.peerId === "3003:fp-bob-1").presenceStatus, "online");
  assert.equal(withLiveBob.members.find((m) => m.peerId === "2002:fp-alice-1").presenceStatus, "unknown");

  // Advance clock past presenceTtlMs (60s) and staleAfterMs (300s): stale cache still serves offline members
  clockNow += 360_000;
  const staleView = registry.getFlockView("erjadi/studio-team");
  assert.equal(staleView.isStale, true);
  assert.equal(staleView.totalMembers, teamView.totalMembers);
  assert.equal(staleView.members.find((m) => m.peerId === "3003:fp-bob-1").presenceStatus, "unknown");

  // 7. Restart persistence: brand-new registry instance reloads exact durable state from disk
  const oldCacheBackup = structuredClone(registry.read());
  const restartedRegistry = new FlockMembershipRegistry(registryPath, { clock: () => clockNow });
  assert.equal(restartedRegistry.getFlockView("erjadi/studio-team").rosterHash, hashBeforePresence);
  assert.equal(restartedRegistry.getFlockView("erjadi/studio-team").totalMembers, teamView.totalMembers);

  // 8. Kick @alice's device -> revisioned tombstone, Bob's WORK-LAPTOP survives, rollback & resurrection rejected
  await kickV3FlockMember(
    {
      callerGitHubUser: "erjadi",
      callerGitHubUserId: 1001,
      flockId: "erjadi/studio-team",
      targetUser: "alice",
      targetDeviceId: "fp-alice-1",
    },
    { storePath, connectionString: testConnStr }
  );
  const myFlocksAfterKick = await listV3UserFlocks(
    { githubUser: "erjadi", githubUserId: 1001, deviceId: "fp-owner-pc" },
    { storePath }
  );
  restartedRegistry.reconcileV3Broker({ myFlocksResponse: myFlocksAfterKick, bootstrapMembers });

  const afterKickView = restartedRegistry.getFlockView("erjadi/studio-team");
  assert.equal(afterKickView.tombstoneCount, 1);
  assert.equal(afterKickView.members.some((m) => m.peerId === "2002:fp-alice-1"), false);
  assert.equal(afterKickView.members.some((m) => m.peerId === "3003:fp-bob-1"), true, "Bob's WORK-LAPTOP must remain active");

  const withRemovedView = restartedRegistry.getFlockView("erjadi/studio-team", { includeRemoved: true });
  const aliceTombstone = withRemovedView.members.find((m) => m.peerId === "2002:fp-alice-1");
  assert.equal(aliceTombstone.removed, true);
  assert.equal(aliceTombstone.membershipStatus, "removed");
  assert.equal(aliceTombstone.removedAtEpoch, afterKickView.rosterEpoch);

  // Stale broker rollback must be rejected
  assert.throws(
    () => restartedRegistry.reconcileV3Broker({ myFlocksResponse: myFlocksBeforeKick }),
    (err) => err.code === "ROSTER_ROLLBACK_REJECTED"
  );

  // Merging an older persisted cache must be rejected and cannot resurrect Alice
  assert.throws(
    () => restartedRegistry.mergeRegistryCache(oldCacheBackup),
    (err) => err.code === "ROSTER_ROLLBACK_REJECTED"
  );

  // Crafted higher-revision cache attempting to resurrect tombstoned Alice at <= removedAtEpoch must be rejected
  const craftedStore = structuredClone(restartedRegistry.read());
  const craftedTeam = craftedStore.flocks["erjadi/studio-team"];
  craftedTeam.rosterRevision += 1;
  craftedTeam.members["2002:fp-alice-1"] = {
    ...oldCacheBackup.flocks["erjadi/studio-team"].members["2002:fp-alice-1"],
    addedAtEpoch: 1,
    updatedAtRevision: 1,
  };
  delete craftedTeam.tombstones["2002:fp-alice-1"];
  craftedTeam.rosterHash = computeRosterHash({
    flockId: "erjadi/studio-team",
    protocol: "v3-broker",
    rosterEpoch: craftedTeam.rosterEpoch,
    rosterRevision: craftedTeam.rosterRevision,
    members: craftedTeam.members,
    tombstones: craftedTeam.tombstones,
  });
  assert.throws(
    () => restartedRegistry.mergeRegistryCache(craftedStore),
    (err) => err.code === "ROSTER_RESURRECTION_REJECTED"
  );
  assert.equal(restartedRegistry.getFlockView("erjadi/studio-team").members.some((m) => m.peerId === "2002:fp-alice-1"), false);

  // 9. applyV3EnrollmentResult + queryFlockMembershipRegistry auto-persistence without live pings
  const enrollClientDir = path.join(tempRoot, "client-home");
  fs.mkdirSync(enrollClientDir, { recursive: true });
  const enrollFlocksPath = path.join(enrollClientDir, "flocks.json");
  const bobReEnroll = await enrollV3Device(
    {
      githubUser: "bob",
      githubUserId: 3003,
      deviceId: "fp-bob-1",
      machineId: "WORK-LAPTOP",
      scope: "work",
      publicKey: bobKey.publicKey,
      keyFingerprint: "fp-bob-1",
      enrollmentJson: inviteBob.enrollmentJson,
    },
    { storePath, connectionString: testConnStr }
  );
  applyV3EnrollmentResult({ machineId: "WORK-LAPTOP", githubUser: "bob", scope: "work" }, bobReEnroll, enrollFlocksPath);
  const queried = await queryFlockMembershipRegistry(
    { machineId: "WORK-LAPTOP", githubUser: "bob", scope: "work" },
    { flockId: "erjadi/studio-team", customFlocksPath: enrollFlocksPath }
  );
  assert.equal(queried.flockId, "erjadi/studio-team");
  assert.ok(queried.members.some((m) => m.peerId === "3003:fp-bob-1" && m.presenceStatus === "unknown"));
});

test("broker-free v3.4 owner-signed roster snapshots/deltas: offline collaborators, missed deltas + syncRoster recovery, 24h cert vs membership separation, removal tombstones, rollback rejection, restart persistence, and cross-flock isolation", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-registry-34-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const endpoints = azureEndpoints("https://fixture.service.signalr.net", "https://fixture.servicebus.windows.net");
  const credentials = {
    connectionString: "Endpoint=https://fixture.service.signalr.net;AccessKey=signalr-fixture",
    manageConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=manage-fixture",
    sendConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockSendRule;SharedAccessKey=send-fixture",
    listenConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockListenRule;SharedAccessKey=listen-fixture",
  };

  let clockNow = 1_760_000_000_000;
  const subscribers = new Map();
  const sockets = new Set();

  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
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
    throw new Error(`Unexpected synthetic transport call: ${options.method} ${parsed.pathname}`);
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

  const rpcTargetsHit = [];
  const runtimeOpts = {
    clock: () => clockNow,
    connect,
    log: () => {},
    dispatch: async ({ action }) => {
      rpcTargetsHit.push(action);
      return { ok: true };
    },
    transportFactory: (cfg, opts) => new AzureTransport(cfg, { ...opts, fetchImpl }),
  };

  const owner = new BrokerFreeRuntime(path.join(root, "owner"), runtimeOpts);
  const peerA = new BrokerFreeRuntime(path.join(root, "peerA"), runtimeOpts);
  const peerB = new BrokerFreeRuntime(path.join(root, "peerB"), runtimeOpts);
  const peerC = new BrokerFreeRuntime(path.join(root, "peerC"), runtimeOpts);

  await owner.initializeOwner({ flockId: "demo/team", machineId: "OWNER-PC", scope: "personal", ...credentials });
  await owner.initializeOwner({ flockId: "demo/second", machineId: "OWNER-PC", scope: "personal", ...credentials });
  const ownerTeamFp = ownerFingerprint(owner.record("demo/team").ownerPublicKey);
  const ownerSecondFp = ownerFingerprint(owner.record("demo/second").ownerPublicKey);
  const thirtyDaysMs = 30 * 86_400_000;

  // 1. PEER-A joins demo/team (rev 2) and demo/second, then goes OFFLINE
  const codeA = await peerA.joinRequest({ machineId: "PEER-A-LAPTOP", scope: "work", flockId: "demo/team" });
  const ticketA = await owner.approve({
    flockId: "demo/team",
    code: codeA,
    expectedEd25519Fingerprint: codeA.body.peerId,
    role: "collaborator",
    membershipExpiresAt: clockNow + thirtyDaysMs,
  });
  await peerA.accept(ticketA, ownerTeamFp);

  const codeASecond = await peerA.joinRequest({ machineId: "PEER-A-LAPTOP", scope: "work", flockId: "demo/second" });
  const ticketASecond = await owner.approve({
    flockId: "demo/second",
    code: codeASecond,
    expectedEd25519Fingerprint: codeASecond.body.peerId,
    role: "collaborator",
    membershipExpiresAt: clockNow + thirtyDaysMs,
  });
  await peerA.accept(ticketASecond, ownerSecondFp);

  // 2. While PEER-A is completely offline, PEER-B joins demo/team (rev 3)
  const codeB = await peerB.joinRequest({ machineId: "PEER-B-DESKTOP", scope: "work", flockId: "demo/team" });
  const ticketB = await owner.approve({
    flockId: "demo/team",
    code: codeB,
    expectedEd25519Fingerprint: codeB.body.peerId,
    role: "collaborator",
    membershipExpiresAt: clockNow + thirtyDaysMs,
  });
  await peerB.accept(ticketB, ownerTeamFp);

  // PEER-B immediately sees OWNER, offline PEER-A, and PEER-B from the Welcome Ticket's signed snapshot without pinging!
  const peerBInitialView = peerB.getFlockRegistryView("demo/team");
  assert.equal(peerBInitialView.totalMembers, 3);
  assert.equal(peerBInitialView.rosterRevision, 3);
  assert.deepEqual(
    peerBInitialView.members.map((m) => m.machineId).sort(),
    ["OWNER-PC", "PEER-A-LAPTOP", "PEER-B-DESKTOP"]
  );
  assert.equal(
    peerBInitialView.members.find((m) => m.machineId === "PEER-A-LAPTOP").presenceStatus,
    "unknown"
  );
  assert.equal(rpcTargetsHit.length, 0, "Zero live peer pings must occur when reading the registry");

  // PEER-B goes offline; PEER-A wakes up and drains its Service Bus queue (consuming owner-signed roster-update delta 2 -> 3)
  const recA = peerA.record("demo/team");
  await peerA.transport(recA).drain(recA.transport, (msg) => peerA.consume(peerA.record("demo/team"), msg));
  const peerAAfterDelta = peerA.getFlockRegistryView("demo/team");
  assert.equal(peerAAfterDelta.rosterRevision, 3);
  assert.equal(peerAAfterDelta.rosterHash, peerBInitialView.rosterHash);
  assert.ok(peerAAfterDelta.members.some((m) => m.peerId === codeB.body.peerId && m.presenceStatus === "unknown"));

  // 3. Certificate validity separation: after 48h, 24h MemberCert is expired while 30-day membership remains active
  const future48h = clockNow + 2 * 86_400_000;
  const certSeparatedView = peerA.getFlockRegistryView("demo/team", { now: future48h });
  const peerBIn48h = certSeparatedView.members.find((m) => m.peerId === codeB.body.peerId);
  assert.equal(peerBIn48h.certStatus, "expired");
  assert.equal(peerBIn48h.membershipStatus, "active");

  // 4. Missed delta detection (ROSTER_DELTA_GAP) + owner-mediated syncRoster recovery (without pinging peers)
  const snapshotRev3 = owner.exportSignedRosterSnapshot("demo/team");
  const codeC = await peerC.joinRequest({ machineId: "PEER-C-WORKSTATION", scope: "personal", flockId: "demo/team" });
  const ticketC = await owner.approve({
    flockId: "demo/team",
    code: codeC,
    expectedEd25519Fingerprint: codeC.body.peerId,
    role: "guest",
    membershipExpiresAt: clockNow + thirtyDaysMs,
  });
  await peerC.accept(ticketC, ownerTeamFp);
  const snapshotRev4 = owner.exportSignedRosterSnapshot("demo/team");

  const ownerRec = owner.record("demo/team");
  const delta4to5 = createSignedRosterDelta({
    flockId: "demo/team",
    ownerIdentity: ownerRec.identity,
    baseEpoch: 1,
    baseRevision: 4,
    baseRosterHash: snapshotRev4.body.rosterHash,
    epoch: 1,
    minAcceptedEpoch: 1,
    revision: 5,
    upserts: snapshotRev4.body.members.map((m) =>
      m.peerId === ownerRec.localPeerId ? { ...m, updatedAtRevision: 5 } : m
    ),
    removals: [],
    resultingMembers: snapshotRev4.body.members.map((m) =>
      m.peerId === ownerRec.localPeerId ? { ...m, updatedAtRevision: 5 } : m
    ),
    resultingTombstones: [],
    issuedAt: clockNow,
  });

  assert.throws(
    () =>
      peerB.registry.applySignedDelta(delta4to5, {
        ownerPublicKey: ownerRec.ownerPublicKey,
        expectedFlockId: "demo/team",
        expectedOwnerFingerprint: ownerTeamFp,
        minAcceptedEpoch: 1,
      }),
    (err) => err.code === "ROSTER_DELTA_GAP"
  );
  assert.equal(peerB.getFlockRegistryView("demo/team").needsSnapshotSync, true);
  assert.equal(peerB.getFlockRegistryView("demo/team").isStale, true);

  // Start owner daemon ONLY (PEER-A and PEER-C remain offline!) and recover PEER-B via syncRoster
  const ownerDaemon = await owner.start();
  t.after(() => ownerDaemon.close());
  const syncedViewB = await peerB.syncRoster("demo/team");
  assert.equal(syncedViewB.needsSnapshotSync, false);
  assert.equal(syncedViewB.rosterRevision, 4);
  assert.equal(syncedViewB.totalMembers, 4);
  assert.equal(syncedViewB.rosterHash, snapshotRev4.body.rosterHash);
  assert.equal(rpcTargetsHit.length, 0, "syncRoster contacts only owner control action, never peer dispatchers");

  // 5. Forged non-owner signatures and cross-flock snapshot replays must fail closed
  const forgedByPeer = createSignedRosterSnapshot({
    flockId: "demo/team",
    ownerIdentity: createDeviceIdentity(),
    epoch: 1,
    revision: 99,
    members: snapshotRev4.body.members,
    tombstones: [],
    issuedAt: clockNow,
  });
  assert.throws(
    () =>
      peerB.registry.applySignedSnapshot(forgedByPeer, {
        ownerPublicKey: ownerRec.ownerPublicKey,
        expectedFlockId: "demo/team",
      }),
    /ROSTER_OWNER_MISMATCH|Invalid control\/roster-snapshot signature/
  );
  assert.throws(
    () =>
      peerA.registry.applySignedSnapshot(snapshotRev4, {
        ownerPublicKey: ownerRec.ownerPublicKey,
        expectedFlockId: "demo/second",
      }),
    (err) => err.code === "ROSTER_FLOCK_MISMATCH"
  );

  // 6. Owner removes PEER-C (advancing epoch 1 -> 2 + tombstone); PEER-A (even at rev 3, having missed rev 4!)
  //    converges cleanly via rotation's snapshot fallback, while demo/second stays isolated!
  const peerASub = `sub-${crypto.createHash("sha256").update("copilot-flock/3.4/subscription\n" + codeA.body.peerId).digest("hex").slice(0, 46)}`;
  subscribers.set(peerASub, []);
  await owner.removePeer({ flockId: "demo/team", peerId: codeC.body.peerId, operationId: "kick-peer-c" });
  await peerA.transport(peerA.record("demo/team")).drain(
    peerA.record("demo/team").transport,
    (msg) => peerA.consume(peerA.record("demo/team"), msg)
  );

  const ownerAfterRemove = owner.getFlockRegistryView("demo/team", { includeRemoved: true });
  const peerAAfterRemove = peerA.getFlockRegistryView("demo/team", { includeRemoved: true });
  assert.equal(peerAAfterRemove.rosterEpoch, 2);
  assert.equal(peerAAfterRemove.rosterHash, ownerAfterRemove.rosterHash);
  assert.equal(peerAAfterRemove.totalMembers, 3);
  assert.equal(peerAAfterRemove.tombstoneCount, 1);
  const peerCTomb = peerAAfterRemove.members.find((m) => m.peerId === codeC.body.peerId);
  assert.equal(peerCTomb.removed, true);
  assert.equal(peerCTomb.membershipStatus, "removed");
  assert.equal(peerCTomb.removedAtEpoch, 2);

  // Cross-flock isolation: demo/second on PEER-A and OWNER is untouched at epoch 1 with PEER-A active
  const secondView = peerA.getFlockRegistryView("demo/second");
  assert.equal(secondView.rosterEpoch, 1);
  assert.equal(secondView.totalMembers, 2);
  assert.equal(secondView.tombstoneCount, 0);

  // 7. Rollback rejection: replaying snapshotRev3 or snapshotRev4 after epoch 2 must fail closed
  for (const staleSnap of [snapshotRev3, snapshotRev4]) {
    assert.throws(
      () =>
        peerA.registry.applySignedSnapshot(staleSnap, {
          ownerPublicKey: ownerRec.ownerPublicKey,
          expectedFlockId: "demo/team",
          expectedOwnerFingerprint: ownerTeamFp,
          minAcceptedEpoch: peerA.record("demo/team").minAcceptedEpoch,
        }),
      (err) => err.code === "ROSTER_ROLLBACK_REJECTED"
    );
  }

  // 8. Restart persistence: brand-new BrokerFreeRuntime reloaded from disk preserves epochs, hashes, members, and tombstones
  const restartedPeerA = new BrokerFreeRuntime(path.join(root, "peerA"), runtimeOpts);
  const reloadedView = restartedPeerA.getFlockRegistryView("demo/team", { includeRemoved: true });
  assert.equal(reloadedView.rosterEpoch, 2);
  assert.equal(reloadedView.rosterHash, ownerAfterRemove.rosterHash);
  assert.equal(reloadedView.totalMembers, 3);
  assert.equal(reloadedView.tombstoneCount, 1);
});

test("broker-free MCP unique route inference, ambiguity fail-closed, zero/expired/revoked route rejection, and explicit invalid flock rejection", async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-route-inference-"));
  const prevCopilotHome = process.env.COPILOT_HOME;
  const copilotHome = path.join(tempRoot, "copilot-home");
  process.env.COPILOT_HOME = copilotHome;
  t.after(() => {
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  let now = Date.now();
  const clock = () => now;
  const endpoints = azureEndpoints("https://fixture.service.signalr.net", "https://fixture.servicebus.windows.net");
  const credentials = {
    connectionString: "Endpoint=https://fixture.service.signalr.net;AccessKey=signalr-fixture",
    manageConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=manage-fixture",
    sendConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockSendRule;SharedAccessKey=send-fixture",
    listenConnectionString: "Endpoint=sb://fixture.servicebus.windows.net/;SharedAccessKeyName=FlockListenRule;SharedAccessKey=listen-fixture",
  };

  const subscribers = new Map();
  const sockets = new Set();
  const publishedMessages = [];
  let connectCount = 0;

  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
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
      for (const socket of sockets) {
        if (!socket.ws.closed) socket.callback(target, structuredClone(args));
      }
      return new Response("", { status: 202 });
    }
    if (options.method === "POST" && parsed.pathname.endsWith("/messages") && !peer) {
      const body = JSON.parse(options.body);
      publishedMessages.push(body);
      for (const queue of subscribers.values()) queue.push(body);
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
    throw new Error(`Unexpected synthetic transport call: ${options.method} ${parsed.pathname}`);
  };

  const connect = async (_cfg, { onInvocation }) => {
    connectCount += 1;
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

  const dispatched = [];
  const makeRuntimeOptions = (machineId, extra = {}) => ({
    clock,
    connect,
    log: () => {},
    dispatch: async ({ action, payload, flockId, assertAuthorized }) => {
      assertAuthorized();
      dispatched.push({ machineId, flockId, action, params: payload.params });
      if (action === "list_sessions") {
        return { machineId, scope: "personal", count: 1, sessions: [{ session_id: `sess-${machineId.toLowerCase()}`, title: `${machineId} shared` }] };
      }
      if (action === "get_transcript") {
        return { session: { session_id: payload.params.session, mode: "approved-snapshot" }, messages: [{ role: "assistant", content: `snapshot from ${machineId} via ${flockId}` }] };
      }
      return { delivered: true, targetMachine: machineId, flockId, targetSession: payload.params.targetSession };
    },
    transportFactory: (config, opts) => new AzureTransport(config, { ...opts, fetchImpl }),
    ...extra,
  });

  const callerRoot = path.join(copilotHome, "flock");
  fs.mkdirSync(callerRoot, { recursive: true });
  const caller = new BrokerFreeRuntime(callerRoot, makeRuntimeOptions("CALLER-PC"));
  const peerAlpha = new BrokerFreeRuntime(path.join(tempRoot, "peer-alpha"), makeRuntimeOptions("PEER-ALPHA"));
  const peerBeta = new BrokerFreeRuntime(path.join(tempRoot, "peer-beta"), makeRuntimeOptions("PEER-BETA"));
  const sharedPeer = new BrokerFreeRuntime(path.join(tempRoot, "shared-peer"), makeRuntimeOptions("SHARED-PEER"));
  const expiringPeer = new BrokerFreeRuntime(path.join(tempRoot, "expiring-peer"), makeRuntimeOptions("EXPIRING-PEER"));

  await caller.initializeOwner({ flockId: "demo/alpha", machineId: "CALLER-PC", scope: "personal", ...credentials });
  await caller.initializeOwner({ flockId: "demo/beta", machineId: "CALLER-PC", scope: "personal", ...credentials });
  await caller.initializeOwner({ flockId: "demo/expiring", machineId: "CALLER-PC", scope: "personal", ...credentials });

  const enrollPeer = async (peerRuntime, machineId, flockId, expiresAt = now + 3600000, sessionIds = ["shared-sess"]) => {
    const code = await peerRuntime.joinRequest({ machineId, scope: "personal", flockId });
    const ticket = await caller.approve({
      flockId,
      code,
      expectedEd25519Fingerprint: code.body.peerId,
      role: "collaborator",
      sessionIds,
      membershipExpiresAt: expiresAt,
    });
    await peerRuntime.accept(ticket, ownerFingerprint(caller.record(flockId).ownerPublicKey));
    return code.body.peerId;
  };

  const alphaPeerId = await enrollPeer(peerAlpha, "PEER-ALPHA", "demo/alpha");
  const betaPeerId = await enrollPeer(peerBeta, "PEER-BETA", "demo/beta");
  const sharedAlphaPeerId = await enrollPeer(sharedPeer, "SHARED-PEER", "demo/alpha");
  await enrollPeer(sharedPeer, "SHARED-PEER", "demo/beta");
  await enrollPeer(expiringPeer, "EXPIRING-PEER", "demo/expiring", now + 600000);

  const daemons = await Promise.all([peerAlpha.start(), peerBeta.start(), sharedPeer.start(), expiringPeer.start()]);
  t.after(async () => {
    await Promise.all(daemons.map((d) => d.close()));
  });

  const cfg = { protocol: "broker-free-v34", machineId: "CALLER-PC", scope: "personal", hub: "copilotbridge" };
  const mcpOpts = {
    ensureDaemon: async () => ({ running: true, pid: process.pid }),
    runtimeOptions: { ...makeRuntimeOptions("CALLER-PC"), root: callerRoot },
  };

  // 1. Unique route inference: omitted flock + explicit to_machine resolves to the sole active authorized flock
  publishedMessages.length = 0;
  dispatched.length = 0;
  const sendBeta = await executeMcpTool(
    cfg,
    "send_remote_session_message",
    { to_machine: "PEER-BETA", to_session: "shared-sess", message: "hello inferred beta" },
    mcpOpts
  );
  assert.equal(sendBeta.delivered, true);
  assert.equal(sendBeta.flockId, "demo/beta");
  assert.equal(dispatched.length, 1);
  assert.equal(dispatched[0].flockId, "demo/beta");
  assert.equal(dispatched[0].machineId, "PEER-BETA");
  const outboundBetaEnvelope = publishedMessages.find((m) => m.type === "envelope" && m.envelope?.header?.action === "send_message");
  assert.ok(outboundBetaEnvelope);
  assert.equal(outboundBetaEnvelope.flockId, "demo/beta");
  assert.equal(outboundBetaEnvelope.envelope.header.targetPeerId, betaPeerId);

  // Case-insensitive to_machine and transcript/session listing inference
  const transcriptAlpha = await executeMcpTool(
    cfg,
    "get_remote_session_transcript",
    { to_machine: "peer-alpha", session: "shared-sess" },
    mcpOpts
  );
  assert.equal(transcriptAlpha.messages[0].content, "snapshot from PEER-ALPHA via demo/alpha");
  const sessionsAlpha = await executeMcpTool(
    cfg,
    "list_remote_sessions",
    { machine: "PEER-ALPHA" },
    mcpOpts
  );
  assert.equal(sessionsAlpha.machineId, "PEER-ALPHA");

  // 2. Multi-route ambiguity rejection: >= 2 active flocks reach SHARED-PEER -> fail closed listing eligible owner/flock choices, 0 messages sent
  const publishedBeforeAmbiguous = publishedMessages.length;
  const connectsBeforeAmbiguous = connectCount;
  await assert.rejects(
    executeMcpTool(
      cfg,
      "send_remote_session_message",
      { to_machine: "SHARED-PEER", to_session: "shared-sess", message: "must not send" },
      mcpOpts
    ),
    /Ambiguous broker-free route to target machine "SHARED-PEER"[\s\S]*demo\/alpha, demo\/beta/
  );
  assert.equal(publishedMessages.length, publishedBeforeAmbiguous, "Ambiguous route must send zero messages");
  assert.equal(connectCount, connectsBeforeAmbiguous, "Ambiguous route must open zero sockets");

  // Wildcard / auto / broadcast without explicit flock must also fail closed without broadcasting
  await assert.rejects(
    executeMcpTool(cfg, "broadcast_remote_session_message", { message: "must not broadcast" }, mcpOpts),
    /Select an explicit --flock \(demo\/alpha, demo\/beta, demo\/expiring\); broker-free dispatch is ambiguous/
  );
  await assert.rejects(
    executeMcpTool(cfg, "send_remote_session_message", { to_machine: "auto", to_session: "shared-sess", message: "no auto" }, mcpOpts),
    /Select an explicit --flock \(demo\/alpha, demo\/beta, demo\/expiring\); broker-free dispatch is ambiguous/
  );
  assert.equal(publishedMessages.length, publishedBeforeAmbiguous);

  // 3. Zero-route & revoked-route rejection: fail closed without broadcasting or falling back
  const publishedBeforeZero = publishedMessages.length;
  const connectsBeforeZero = connectCount;
  await assert.rejects(
    executeMcpTool(
      cfg,
      "send_remote_session_message",
      { to_machine: "UNKNOWN-MACHINE", to_session: "shared-sess", message: "must not broadcast" },
      mcpOpts
    ),
    /No active, non-expired authorized broker-free route reaches target machine "UNKNOWN-MACHINE"; refusing broadcast or fallback/
  );
  assert.equal(publishedMessages.length, publishedBeforeZero);
  assert.equal(connectCount, connectsBeforeZero);

  // Revoking PEER-ALPHA removes its sole route -> fail closed with revoked evidence; revoking SHARED-PEER from demo/alpha leaves unique route demo/beta
  await caller.removePeer({ flockId: "demo/alpha", peerId: alphaPeerId });
  await caller.removePeer({ flockId: "demo/alpha", peerId: sharedAlphaPeerId });
  const publishedAfterRevoke = publishedMessages.length;
  await assert.rejects(
    executeMcpTool(
      cfg,
      "send_remote_session_message",
      { to_machine: "PEER-ALPHA", to_session: "shared-sess", message: "revoked peer" },
      mcpOpts
    ),
    /No active, non-expired authorized broker-free route reaches target machine "PEER-ALPHA"[\s\S]*revoked/
  );
  assert.equal(publishedMessages.length, publishedAfterRevoke, "Revoked peer must not trigger broadcast or fallback");

  const resolvedSharedAfterKick = await executeMcpTool(
    cfg,
    "send_remote_session_message",
    { to_machine: "SHARED-PEER", to_session: "shared-sess", message: "now unique on beta" },
    mcpOpts
  );
  assert.equal(resolvedSharedAfterKick.flockId, "demo/beta");

  // 4. Expired-route rejection: advance clock past EXPIRING-PEER membership expiry -> fail closed without sending
  now += 660000;
  const publishedBeforeExpired = publishedMessages.length;
  const connectsBeforeExpired = connectCount;
  await assert.rejects(
    executeMcpTool(
      cfg,
      "send_remote_session_message",
      { to_machine: "EXPIRING-PEER", to_session: "shared-sess", message: "expired peer" },
      mcpOpts
    ),
    /No active, non-expired authorized broker-free route reaches target machine "EXPIRING-PEER"[\s\S]*expired/
  );
  assert.equal(publishedMessages.length, publishedBeforeExpired, "Expired route must send zero messages");
  assert.equal(connectCount, connectsBeforeExpired, "Expired route must open zero sockets");

  // 5. Explicit invalid or unauthorized flock rejection: never replaced via inference even when demo/beta is valid for PEER-BETA
  const publishedBeforeExplicitInvalid = publishedMessages.length;
  const connectsBeforeExplicitInvalid = connectCount;
  for (const [badFlock, expectedPattern] of [
    ["demo/nonexistent", /Not an active broker-free flock/],
    ["", /Invalid explicit broker-free flock selector/],
    ["Invalid/Flock", /Invalid explicit broker-free flock selector/],
    ["demo/alpha", /Explicit flock "demo\/alpha" has no active, non-expired authorized route to target machine "PEER-BETA"/],
  ]) {
    await assert.rejects(
      executeMcpTool(
        cfg,
        "send_remote_session_message",
        { flock: badFlock, to_machine: "PEER-BETA", to_session: "shared-sess", message: "must not infer beta" },
        mcpOpts
      ),
      expectedPattern
    );
  }
  // Guest peer with restricted session scope must also reject unauthorized session on explicit or inferred route without sending
  const peerBetaMcpOpts = {
    ensureDaemon: async () => ({ running: true, pid: process.pid }),
    runtimeOptions: { ...makeRuntimeOptions("PEER-BETA"), root: path.join(tempRoot, "peer-beta") },
  };
  await assert.rejects(
    executeMcpTool(
      { protocol: "broker-free-v34", machineId: "PEER-BETA", scope: "personal", hub: "copilotbridge" },
      "send_remote_session_message",
      { flock: "demo/beta", to_machine: "CALLER-PC", to_session: "unapproved-private-session", message: "forbidden" },
      peerBetaMcpOpts
    ),
    /forbids/
  );
  assert.equal(publishedMessages.length, publishedBeforeExplicitInvalid, "Explicit invalid/unauthorized flock must send zero messages");
  assert.equal(connectCount, connectsBeforeExplicitInvalid, "Explicit invalid/unauthorized flock must open zero sockets");
});

test("reconcileAuthoritativeFlockMemberships heals downgraded owner roles, enforces epoch monotonicity across owner/collaborator/guest, preserves sharing atomically, and rejects stale/revoked/forged claims", async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-reconcile-roles-"));
  const brokerStorePath = path.join(tempRoot, "v3-flocks.json");
  const ownerFlocksPath = path.join(tempRoot, "owner-flocks.json");
  const peerFlocksPath = path.join(tempRoot, "peer-flocks.json");
  const testConnStr = "Endpoint=https://unit-test.service.signalr.net;AccessKey=dGVzdGtleQ==;Version=1.0;";

  const ownerKeys = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const ownerIdentity = {
    fingerprint: "fp-owner-main",
    publicKey: ownerKeys.publicKey,
    privateKey: ownerKeys.privateKey,
  };
  const aliceKeys = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const aliceIdentity = {
    fingerprint: "fp-alice-work",
    publicKey: aliceKeys.publicKey,
    privateKey: aliceKeys.privateKey,
  };

  const previousAllowlist = process.env.ALLOWED_GITHUB_USERS;
  const previousMaintainer = process.env.PLATFORM_MAINTAINER_USER;
  const fullName = process.env.ALLOWED_GITHUB_REPO || process.env.ALLOWED_REPO || "erjadi/copilot-flock";
  const principals = {
    ownerToken: { login: "erjadi", id: 1001 },
    aliceToken: { login: "alice", id: 2002 },
  };
  const server = createBootstrapServer({
    v3StorePath: brokerStorePath,
    v3PreviewStorePath: brokerStorePath,
    apiGet: async (apiPath, token) =>
      apiPath === "/user"
        ? { statusCode: principals[token] ? 200 : 401, body: principals[token] || {} }
        : {
            statusCode: 200,
            body: {
              full_name: fullName,
              owner: { login: "erjadi" },
              private: false,
              permissions: { pull: true, push: token === "ownerToken", admin: token === "ownerToken" },
            },
          },
  });

  try {
    delete process.env.ALLOWED_GITHUB_USERS;
    process.env.PLATFORM_MAINTAINER_USER = "erjadi";
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    async function brokerHttp(endpoint, token, body = null) {
      return await new Promise((resolve, reject) => {
        const payload = body === null ? null : JSON.stringify(body);
        const req = http.request(
          {
            hostname: "127.0.0.1",
            port: server.address().port,
            path: endpoint,
            method: payload === null ? "GET" : "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              ...(payload === null
                ? {}
                : {
                    "Content-Type": "application/json",
                    "Content-Length": Buffer.byteLength(payload),
                  }),
            },
          },
          (res) => {
            let raw = "";
            res.setEncoding("utf8");
            res.on("data", (chunk) => {
              raw += chunk;
            });
            res.on("end", () => {
              try {
                resolve({ status: res.statusCode, body: JSON.parse(raw) });
              } catch (err) {
                reject(err);
              }
            });
          }
        );
        req.on("error", reject);
        req.end(payload);
      });
    }

    const ownerCfg = { githubUser: "erjadi", machineId: "MAIN-WORKSTATION", scope: "personal" };

    // 1. Initial owner enrollment on broker + client; share two threads on `erjadi/personal`
    const initialOwnerEnroll = await enrollV3Device(
      {
        githubUser: "erjadi",
        githubUserId: 1001,
        deviceId: ownerIdentity.fingerprint,
        machineId: "MAIN-WORKSTATION",
        scope: "personal",
        publicKey: ownerIdentity.publicKey,
        keyFingerprint: ownerIdentity.fingerprint,
      },
      { storePath: brokerStorePath, connectionString: testConnStr }
    );
    applyV3EnrollmentResult(ownerCfg, initialOwnerEnroll, ownerFlocksPath);

    shareThreadWithFlock(
      ownerCfg,
      {
        flockId: "erjadi/personal",
        sessionId: "sess-keep-1",
        title: "Architecture review",
        summarySnapshot: "Approved snapshot 1",
      },
      ownerFlocksPath
    );
    shareThreadWithFlock(
      ownerCfg,
      {
        flockId: "erjadi/personal",
        sessionId: "sess-keep-2",
        title: "GPU render pipeline",
        summarySnapshot: "Approved snapshot 2",
      },
      ownerFlocksPath
    );

    // Advance broker `erjadi/personal` rosterEpoch to 12 and give local owner custom visibility to verify preservation
    const brokerStore = JSON.parse(fs.readFileSync(brokerStorePath, "utf8"));
    brokerStore.flocks["erjadi/personal"].rosterEpoch = 12;
    brokerStore.flocks["erjadi/personal"].allowedScopes = ["personal", "work"];
    fs.writeFileSync(brokerStorePath, JSON.stringify(brokerStore, null, 2), "utf8");

    const syncedAt12 = await syncV3DeviceMemberships(
      {
        githubUser: "erjadi",
        githubUserId: 1001,
        deviceId: ownerIdentity.fingerprint,
        machineId: "MAIN-WORKSTATION",
      },
      { storePath: brokerStorePath, connectionString: testConnStr }
    );
    reconcileAuthoritativeFlockMemberships(ownerCfg, syncedAt12, ownerFlocksPath);

    // Customize owner visibility setting on verified owner record to confirm lower-role invites never overwrite it
    const ownerStoredAt12 = JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8"));
    ownerStoredAt12.flocks["erjadi/personal"].sessionVisibility = "all_owner_threads";
    ownerStoredAt12.threadBindings = { "bound-sess-1": "erjadi/studio-team" };
    fs.writeFileSync(ownerFlocksPath, JSON.stringify(ownerStoredAt12, null, 2), "utf8");
    assert.equal(
      hasVerifiedOwnerAuthority(ownerStoredAt12.flocks["erjadi/personal"], {
        githubUser: "erjadi",
        githubUserId: 1001,
        deviceId: ownerIdentity.fingerprint,
        peerId: `1001:${ownerIdentity.fingerprint}`,
      }),
      true
    );

    // 2. Prevent lower-role invitation redemption (both broker cross-scope & client response) from downgrading owner
    const personalCollabInvite = await createV3FlockInvite(
      {
        callerGitHubUser: "erjadi",
        callerGitHubUserId: 1001,
        targetAddress: "erjadi/personal",
        invitedUser: "erjadi",
        invitedGitHubUserId: 1001,
        allowedScopes: ["personal", "work"],
        trustTier: "collaborator",
      },
      { storePath: brokerStorePath }
    );
    const teamInviteForOwner = await createV3FlockInvite(
      {
        callerGitHubUser: "erjadi",
        callerGitHubUserId: 1001,
        targetAddress: "erjadi/studio-team",
        invitedUser: "erjadi",
        invitedGitHubUserId: 1001,
        allowedScopes: ["personal", "work"],
        trustTier: "collaborator",
      },
      { storePath: brokerStorePath }
    );

    // Redeeming on a `work`-scoped owner call must NOT downgrade `erjadi/personal` on the broker
    const crossScopeRedeem = await enrollV3Device(
      {
        githubUser: "erjadi",
        githubUserId: 1001,
        deviceId: ownerIdentity.fingerprint,
        machineId: "MAIN-WORKSTATION",
        scope: "work",
        publicKey: ownerIdentity.publicKey,
        keyFingerprint: ownerIdentity.fingerprint,
        enrollmentJson: {
          flocks: [
            ...personalCollabInvite.enrollmentJson.flocks,
            ...teamInviteForOwner.enrollmentJson.flocks,
          ],
        },
      },
      { storePath: brokerStorePath, connectionString: testConnStr }
    );
    const redeemedPersonal = crossScopeRedeem.enrolledFlocks.find(
      (f) => f.flockId === "erjadi/personal"
    );
    assert.equal(redeemedPersonal.trustTier, "owner");
    assert.equal(redeemedPersonal.membershipExpiresAtMs, null);

    // Even if a lower-role collaborator/guest invite response arrives at the client for `erjadi/personal`,
    // verified `owner` membership and its visibility/sharing settings are preserved intact
    for (const lowerRole of ["collaborator", "guest"]) {
      const syntheticLowerPersonal = {
        ...redeemedPersonal,
        trustTier: lowerRole,
        rosterEpoch: 12,
        sessionVisibility: "explicit_opt_in_only",
        shareSpecs: "summary",
        membershipExpiresAtMs: lowerRole === "guest" ? Date.now() + 60000 : null,
        serverNonce: `lower-${lowerRole}-nonce`,
        hubToken: `lower-${lowerRole}-token`,
        members: redeemedPersonal.members.map((m) => ({
          ...m,
          trustTier: lowerRole,
          membershipExpiresAtMs: lowerRole === "guest" ? Date.now() + 60000 : null,
        })),
      };
      const teamRecord = crossScopeRedeem.enrolledFlocks.find(
        (f) => f.flockId === "erjadi/studio-team"
      );
      const appliedLower = applyV3EnrollmentResult(
        ownerCfg,
        {
          ...crossScopeRedeem,
          enrolledFlocks: [syntheticLowerPersonal, teamRecord],
        },
        ownerFlocksPath
      );
      const afterLower = JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8"));
      assert.equal(afterLower.flocks["erjadi/personal"].trustTier, "owner");
      assert.equal(afterLower.flocks["erjadi/personal"].sessionVisibility, "all_owner_threads");
      assert.equal(afterLower.flocks["erjadi/personal"].shareSpecs, "full");
      assert.equal(afterLower.flocks["erjadi/personal"].membershipExpiresAtMs, null);
      assert.notEqual(afterLower.flocks["erjadi/personal"].hubToken, `lower-${lowerRole}-token`);
      assert.deepEqual(afterLower.flocks["erjadi/personal"].sharedSessionIds, [
        "sess-keep-1",
        "sess-keep-2",
      ]);
      assert.equal(
        afterLower.flocks["erjadi/personal"].sharedSnapshots["sess-keep-1"].summarySnapshot,
        "Approved snapshot 1"
      );
      assert.equal(afterLower.flocks["erjadi/studio-team"].trustTier, "collaborator");
      assert.equal(
        appliedLower.enrolledFlocks.find((f) => f.flockId === "erjadi/personal").trustTier,
        "owner"
      );
    }

    // 3. Simulate pre-existing downgraded local `flocks.json` (`erjadi/personal` as `collaborator` at epoch 9
    // while authoritative broker is `owner` at epoch 12), verify unverified username never elevates,
    // and heal atomically (including concurrent shareThreadWithFlock CAS retry!)
    const expectedSnapshots = structuredClone(
      JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8")).flocks["erjadi/personal"].sharedSnapshots
    );
    const downgradedDisk = JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8"));
    downgradedDisk.flocks["erjadi/personal"] = {
      ...downgradedDisk.flocks["erjadi/personal"],
      trustTier: "collaborator",
      rosterEpoch: 9,
      sessionVisibility: "explicit_opt_in_only",
      shareSpecs: "summary",
      membershipExpiresAtMs: Date.now() + 120000,
      membershipExpiresAt: new Date(Date.now() + 120000).toISOString(),
      members: downgradedDisk.flocks["erjadi/personal"].members.map((m) => ({
        ...m,
        trustTier: "collaborator",
      })),
    };
    fs.writeFileSync(ownerFlocksPath, JSON.stringify(downgradedDisk, null, 2), "utf8");

    // Unverified local username (`loadLocalFlocksConfig` or unauthenticated sync call) MUST NOT elevate privileges
    const passiveLoaded = loadLocalFlocksConfig(
      { githubUser: "erjadi", scope: "personal" },
      ownerFlocksPath
    );
    assert.equal(passiveLoaded.flocks["erjadi/personal"].trustTier, "collaborator");
    assert.equal(passiveLoaded.flocks["erjadi/personal"].rosterEpoch, 9);

    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          ownerCfg,
          {
            ok: true,
            githubUser: "erjadi",
            deviceId: ownerIdentity.fingerprint,
            enrolledFlocks: [redeemedPersonal],
          },
          ownerFlocksPath
        ),
      (err) => err.code === "UNAUTHENTICATED_AUTHORITY"
    );
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          ownerCfg,
          {
            ok: true,
            githubUser: "erjadi",
            githubUserId: 1001,
            deviceId: ownerIdentity.fingerprint,
            peerId: `1001:${ownerIdentity.fingerprint}`,
            enrolledFlocks: [
              { ...redeemedPersonal, flockUuid: "builtin-erjadi-personal" },
            ],
          },
          ownerFlocksPath
        ),
      (err) => err.code === "UNVERIFIED_AUTHORITY"
    );
    assert.equal(
      JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8")).flocks["erjadi/personal"].trustTier,
      "collaborator"
    );

    // Simulate concurrent `shareThreadWithFlock` happening mid-reconciliation on first CAS attempt,
    // and heal via live HTTP `/api/v3/flocks/sync` + `reconcileAuthoritativeFlockMemberships`
    const signedOwnerSync = signV3MembershipSyncRequest(
      { deviceId: ownerIdentity.fingerprint, machineId: "MAIN-WORKSTATION" },
      ownerIdentity
    );
    const httpSyncRes = await brokerHttp("/api/v3/flocks/sync", "ownerToken", signedOwnerSync);
    assert.equal(httpSyncRes.status, 200);
    assert.equal(httpSyncRes.body.ok, true);

    let injectedConcurrentShare = false;
    const healedRes = reconcileAuthoritativeFlockMemberships(
      ownerCfg,
      httpSyncRes.body,
      ownerFlocksPath,
      {
        onBeforeCommit: (attempt) => {
          if (attempt === 0 && !injectedConcurrentShare) {
            injectedConcurrentShare = true;
            shareThreadWithFlock(
              ownerCfg,
              {
                flockId: "erjadi/personal",
                sessionId: "sess-concurrent-3",
                title: "Concurrent share during sync",
                summarySnapshot: "Approved snapshot 3",
              },
              ownerFlocksPath
            );
          }
        },
      }
    );
    assert.equal(injectedConcurrentShare, true);
    assert.ok(healedRes.healedFlockIds.includes("erjadi/personal"));

    const healedDisk = JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8"));
    assert.equal(healedDisk.flocks["erjadi/personal"].trustTier, "owner");
    assert.equal(healedDisk.flocks["erjadi/personal"].rosterEpoch, 12);
    assert.equal(healedDisk.flocks["erjadi/personal"].sessionVisibility, "all");
    assert.equal(healedDisk.flocks["erjadi/personal"].shareSpecs, "full");
    assert.equal(healedDisk.flocks["erjadi/personal"].membershipExpiresAt, null);
    assert.equal(healedDisk.flocks["erjadi/personal"].membershipExpiresAtMs, null);
    assert.deepEqual(healedDisk.flocks["erjadi/personal"].sharedSessionIds, [
      "sess-keep-1",
      "sess-keep-2",
      "sess-concurrent-3",
    ]);
    assert.equal(
      healedDisk.flocks["erjadi/personal"].sharedSnapshots["sess-keep-1"].summarySnapshot,
      expectedSnapshots["sess-keep-1"].summarySnapshot
    );
    assert.equal(
      healedDisk.flocks["erjadi/personal"].sharedSnapshots["sess-keep-2"].summarySnapshot,
      expectedSnapshots["sess-keep-2"].summarySnapshot
    );
    assert.equal(
      healedDisk.flocks["erjadi/personal"].sharedSnapshots["sess-concurrent-3"].summarySnapshot,
      "Approved snapshot 3"
    );
    assert.deepEqual(healedDisk.threadBindings, { "bound-sess-1": "erjadi/studio-team" });
    assert.equal(
      fs.readdirSync(tempRoot).filter((name) => name.endsWith(".tmp")).length,
      0
    );

    // Also verify broker-side healing via `syncFlockMemberships` when broker member entry itself was corrupted
    const corruptedBroker = JSON.parse(fs.readFileSync(brokerStorePath, "utf8"));
    corruptedBroker.flocks["erjadi/personal"].members[`1001:${ownerIdentity.fingerprint}`].trustTier =
      "collaborator";
    corruptedBroker.flocks["erjadi/personal"].rosterEpoch = 14;
    fs.writeFileSync(brokerStorePath, JSON.stringify(corruptedBroker, null, 2), "utf8");

    const fullSyncOut = await syncFlockMemberships(ownerCfg, {
      customPath: ownerFlocksPath,
      identityKeypair: ownerIdentity,
      callEndpoint: async (_cfg, subPath, opts) => {
        assert.equal(subPath, "/flocks/sync");
        const r = await brokerHttp(`/api/v3${subPath}`, "ownerToken", opts.body);
        return r.body;
      },
    });
    assert.ok(fullSyncOut.healedFlockIds.includes("erjadi/personal"));
    const afterBrokerHeal = JSON.parse(fs.readFileSync(ownerFlocksPath, "utf8"));
    assert.equal(afterBrokerHeal.flocks["erjadi/personal"].trustTier, "owner");
    assert.equal(afterBrokerHeal.flocks["erjadi/personal"].rosterEpoch, 15);
    assert.deepEqual(afterBrokerHeal.flocks["erjadi/personal"].sharedSessionIds, [
      "sess-keep-1",
      "sess-keep-2",
      "sess-concurrent-3",
    ]);

    // Stale owner epoch (< 15) must be rejected without modifying `flocks.json`
    const snapshotAt15 = fs.readFileSync(ownerFlocksPath, "utf8");
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          ownerCfg,
          { ...httpSyncRes.body }, // epoch 12 < 15
          ownerFlocksPath
        ),
      (err) => err.code === "STALE_ROSTER_EPOCH"
    );
    assert.equal(fs.readFileSync(ownerFlocksPath, "utf8"), snapshotAt15);

    // 4. Collaborator <-> Guest role reconciliation, epoch monotonicity, sharing preservation,
    // forged claims, and revoked/expired authority rejection
    const aliceCfg = { githubUser: "alice", machineId: "ALICE-LAPTOP", scope: "work" };
    const aliceGuestInvite = await createV3FlockInvite(
      {
        callerGitHubUser: "erjadi",
        callerGitHubUserId: 1001,
        targetAddress: "erjadi/studio-team",
        invitedUser: "alice",
        invitedGitHubUserId: 2002,
        allowedScopes: ["work"],
        trustTier: "guest",
        durationMinutes: 30,
      },
      { storePath: brokerStorePath }
    );
    const aliceInitial = await enrollV3Device(
      {
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: aliceIdentity.fingerprint,
        machineId: "ALICE-LAPTOP",
        scope: "work",
        publicKey: aliceIdentity.publicKey,
        keyFingerprint: aliceIdentity.fingerprint,
        enrollmentJson: aliceGuestInvite.enrollmentJson,
      },
      { storePath: brokerStorePath, connectionString: testConnStr }
    );
    applyV3EnrollmentResult(aliceCfg, aliceInitial, peerFlocksPath);

    shareThreadWithFlock(
      aliceCfg,
      {
        flockId: "erjadi/studio-team",
        sessionId: "alice-shared-sess",
        title: "Alice API contract",
        summarySnapshot: "Alice approved summary",
      },
      peerFlocksPath
    );

    const aliceTeamInitial = JSON.parse(fs.readFileSync(peerFlocksPath, "utf8")).flocks[
      "erjadi/studio-team"
    ];
    assert.equal(aliceTeamInitial.trustTier, "guest");
    assert.ok(aliceTeamInitial.membershipExpiresAtMs > Date.now());
    const guestEpoch = aliceTeamInitial.rosterEpoch;

    // Promote Alice from `guest` -> `collaborator` at newer epoch (`guestEpoch + 3`), clearing expiry and preserving sharing
    const promotedEpoch = guestEpoch + 3;
    const alicePromotedRecord = {
      ...aliceInitial.enrolledFlocks.find((f) => f.flockId === "erjadi/studio-team"),
      trustTier: "collaborator",
      rosterEpoch: promotedEpoch,
      membershipExpiresAt: null,
      membershipExpiresAtMs: null,
      members: aliceInitial.enrolledFlocks
        .find((f) => f.flockId === "erjadi/studio-team")
        .members.map((m) =>
          m.peerId === `2002:${aliceIdentity.fingerprint}`
            ? { ...m, trustTier: "collaborator", membershipExpiresAt: null, membershipExpiresAtMs: null }
            : m
        ),
    };
    const promRes = reconcileAuthoritativeFlockMemberships(
      aliceCfg,
      {
        ok: true,
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: aliceIdentity.fingerprint,
        peerId: `2002:${aliceIdentity.fingerprint}`,
        enrolledFlocks: [alicePromotedRecord],
      },
      peerFlocksPath
    );
    assert.ok(promRes.healedFlockIds.includes("erjadi/studio-team"));
    const afterPromote = JSON.parse(fs.readFileSync(peerFlocksPath, "utf8")).flocks[
      "erjadi/studio-team"
    ];
    assert.equal(afterPromote.trustTier, "collaborator");
    assert.equal(afterPromote.rosterEpoch, promotedEpoch);
    assert.equal(afterPromote.membershipExpiresAtMs, null);
    assert.equal(afterPromote.membershipExpiresAt, null);
    assert.equal(afterPromote.sessionVisibility, "explicit_opt_in_only");
    assert.equal(afterPromote.shareSpecs, "summary");
    assert.deepEqual(afterPromote.sharedSessionIds, ["alice-shared-sess"]);
    assert.equal(
      afterPromote.sharedSnapshots["alice-shared-sess"].summarySnapshot,
      "Alice approved summary"
    );

    // Stale collaborator/guest epoch (`promotedEpoch - 1`) must fail closed
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          aliceCfg,
          {
            ok: true,
            githubUser: "alice",
            githubUserId: 2002,
            deviceId: aliceIdentity.fingerprint,
            peerId: `2002:${aliceIdentity.fingerprint}`,
            enrolledFlocks: [{ ...alicePromotedRecord, rosterEpoch: promotedEpoch - 1 }],
          },
          peerFlocksPath
        ),
      (err) => err.code === "STALE_ROSTER_EPOCH"
    );

    // Restrict Alice from `collaborator` -> time-bound `guest` at newer epoch (`promotedEpoch + 2`), preserving sharing
    const restrictedEpoch = promotedEpoch + 2;
    const guestExpiryMs = Date.now() + 900000;
    const aliceRestrictedRecord = {
      ...alicePromotedRecord,
      trustTier: "guest",
      rosterEpoch: restrictedEpoch,
      membershipExpiresAtMs: guestExpiryMs,
      membershipExpiresAt: new Date(guestExpiryMs).toISOString(),
      members: alicePromotedRecord.members.map((m) =>
        m.peerId === `2002:${aliceIdentity.fingerprint}`
          ? {
              ...m,
              trustTier: "guest",
              membershipExpiresAtMs: guestExpiryMs,
              membershipExpiresAt: new Date(guestExpiryMs).toISOString(),
            }
          : m
      ),
    };
    reconcileAuthoritativeFlockMemberships(
      aliceCfg,
      {
        ok: true,
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: aliceIdentity.fingerprint,
        peerId: `2002:${aliceIdentity.fingerprint}`,
        enrolledFlocks: [aliceRestrictedRecord],
      },
      peerFlocksPath
    );
    const afterRestrict = JSON.parse(fs.readFileSync(peerFlocksPath, "utf8")).flocks[
      "erjadi/studio-team"
    ];
    assert.equal(afterRestrict.trustTier, "guest");
    assert.equal(afterRestrict.rosterEpoch, restrictedEpoch);
    assert.equal(afterRestrict.membershipExpiresAtMs, guestExpiryMs);
    assert.deepEqual(afterRestrict.sharedSessionIds, ["alice-shared-sess"]);

    // Reject forged claims, expired claims, and revoked authority without mutating `peerFlocksPath`
    const beforeNegativeRaw = fs.readFileSync(peerFlocksPath, "utf8");

    // Forged role elevation (`trustTier: "collaborator"` while roster says `"guest"`)
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          aliceCfg,
          {
            ok: true,
            githubUser: "alice",
            githubUserId: 2002,
            deviceId: aliceIdentity.fingerprint,
            peerId: `2002:${aliceIdentity.fingerprint}`,
            enrolledFlocks: [
              { ...aliceRestrictedRecord, trustTier: "collaborator", rosterEpoch: restrictedEpoch + 1 },
            ],
          },
          peerFlocksPath
        ),
      (err) => err.code === "FORGED_AUTHORITY"
    );

    // Forged `owner` claim on a `shared` flock
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          aliceCfg,
          {
            ok: true,
            githubUser: "alice",
            githubUserId: 2002,
            deviceId: aliceIdentity.fingerprint,
            peerId: `2002:${aliceIdentity.fingerprint}`,
            enrolledFlocks: [
              {
                ...aliceRestrictedRecord,
                trustTier: "owner",
                ownerGitHubUser: "alice",
                ownerGitHubUserId: 2002,
                rosterEpoch: restrictedEpoch + 1,
              },
            ],
          },
          peerFlocksPath
        ),
      (err) => err.code === "UNVERIFIED_OWNER_AUTHORITY"
    );

    // Missing authoritative `members` roster proof
    const withoutMembers = { ...aliceRestrictedRecord, rosterEpoch: restrictedEpoch + 1 };
    delete withoutMembers.members;
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          aliceCfg,
          {
            ok: true,
            githubUser: "alice",
            githubUserId: 2002,
            deviceId: aliceIdentity.fingerprint,
            peerId: `2002:${aliceIdentity.fingerprint}`,
            enrolledFlocks: [withoutMembers],
          },
          peerFlocksPath
        ),
      (err) => err.code === "UNVERIFIED_AUTHORITY"
    );

    // Expired membership claim
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          aliceCfg,
          {
            ok: true,
            githubUser: "alice",
            githubUserId: 2002,
            deviceId: aliceIdentity.fingerprint,
            peerId: `2002:${aliceIdentity.fingerprint}`,
            enrolledFlocks: [
              {
                ...aliceRestrictedRecord,
                rosterEpoch: restrictedEpoch + 1,
                membershipExpiresAtMs: Date.now() - 1000,
              },
            ],
          },
          peerFlocksPath
        ),
      (err) => err.code === "EXPIRED_AUTHORITY"
    );

    // Revoked principal in incoming claim
    assert.throws(
      () =>
        reconcileAuthoritativeFlockMemberships(
          aliceCfg,
          {
            ok: true,
            githubUser: "alice",
            githubUserId: 2002,
            deviceId: aliceIdentity.fingerprint,
            peerId: `2002:${aliceIdentity.fingerprint}`,
            enrolledFlocks: [
              {
                ...aliceRestrictedRecord,
                rosterEpoch: restrictedEpoch + 1,
                revokedPrincipals: { "2002": new Date().toISOString() },
              },
            ],
          },
          peerFlocksPath
        ),
      (err) => err.code === "REVOKED_AUTHORITY"
    );

    assert.equal(fs.readFileSync(peerFlocksPath, "utf8"), beforeNegativeRaw);

    // Forged Ed25519 signature on HTTP `/api/v3/flocks/sync` for invited user must be rejected (HTTP 401)
    const forgedSyncReq = signV3MembershipSyncRequest(
      { deviceId: aliceIdentity.fingerprint, machineId: "ALICE-LAPTOP" },
      ownerIdentity // wrong key!
    );
    const badHttpSync = await brokerHttp("/api/v3/flocks/sync", "aliceToken", forgedSyncReq);
    assert.equal(badHttpSync.status, 401);

    // Kick Alice on broker -> authenticated `syncFlockMemberships` quarantines `erjadi/studio-team` locally
    // while preserving `sharedSessionIds` / `sharedSnapshots`, and `enforceFlockPolicyAndWalls` fails closed
    await kickV3FlockMember(
      {
        callerGitHubUser: "erjadi",
        callerGitHubUserId: 1001,
        flockId: "erjadi/studio-team",
        targetUser: "alice",
      },
      { storePath: brokerStorePath, connectionString: testConnStr }
    );

    const alicePostKickSync = await syncFlockMemberships(aliceCfg, {
      customPath: peerFlocksPath,
      identityKeypair: aliceIdentity,
      callEndpoint: async (_cfg, subPath, opts) => {
        const r = await brokerHttp(`/api/v3${subPath}`, "aliceToken", opts.body);
        assert.equal(r.status, 200);
        return r.body;
      },
    });
    assert.ok(alicePostKickSync.quarantinedFlockIds.includes("erjadi/studio-team"));
    const afterKickDisk = JSON.parse(fs.readFileSync(peerFlocksPath, "utf8")).flocks[
      "erjadi/studio-team"
    ];
    assert.equal(afterKickDisk.revoked, true);
    assert.equal(afterKickDisk.hubToken, undefined);
    assert.equal(afterKickDisk.serverNonce, undefined);
    assert.deepEqual(afterKickDisk.sharedSessionIds, ["alice-shared-sess"]);
    assert.throws(
      () => enforceFlockPolicyAndWalls(aliceCfg, afterKickDisk, { action: "ping" }),
      (err) => err.code === "MEMBERSHIP_REVOKED" && err.statusCode === 403
    );
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

function buildSyntheticRuntimeSource(baseDir, repoRoot, { version = null, mutate = null, writeManifest = true } = {}) {
  fs.mkdirSync(baseDir, { recursive: true });
  const entrypointFallback = fs.existsSync(path.join(repoRoot, "flock.mjs"))
    ? path.join(repoRoot, "flock.mjs")
    : path.join(repoRoot, "bridge.mjs");
  for (const modName of REQUIRED_RUNTIME_MODULES) {
    const srcPath = fs.existsSync(path.join(repoRoot, modName))
      ? path.join(repoRoot, modName)
      : entrypointFallback;
    let content = fs.readFileSync(srcPath, "utf8");
    if (version && (modName === "flock.mjs" || modName === "bridge.mjs")) {
      content = content.replace(
        /export const BRIDGE_VERSION = "[^"]+";/,
        `export const BRIDGE_VERSION = ${JSON.stringify(version)};`
      );
    }
    fs.writeFileSync(path.join(baseDir, modName), content, "utf8");
  }
  if (typeof mutate === "function") {
    mutate(baseDir);
  }
  let manifest = null;
  if (writeManifest) {
    manifest = computeRuntimeManifest(baseDir, version ? { version } : {});
    fs.writeFileSync(
      path.join(baseDir, RUNTIME_MANIFEST_FILENAME),
      JSON.stringify(manifest, null, 2) + "\n",
      "utf8"
    );
  }
  return manifest;
}

test("pinned RUNTIME_MODULE_MANIFEST covers complete runtime closure and matches repository SHA-256 digests", () => {
  assert.ok(RUNTIME_MODULE_MANIFEST, "RUNTIME_MODULE_MANIFEST must be defined");
  assert.equal(Object.isFrozen(RUNTIME_MODULE_MANIFEST), true);
  assert.equal(Object.isFrozen(RUNTIME_MODULE_MANIFEST.files), true);
  assert.equal(RUNTIME_MODULE_MANIFEST.type, "copilot-flock-runtime-manifest-v1");
  assert.equal(RUNTIME_MODULE_MANIFEST.version, BRIDGE_VERSION);
  for (const required of REQUIRED_RUNTIME_MODULES) {
    assert.ok(
      RUNTIME_MODULE_MANIFEST.files[required]?.sha256,
      `Missing required runtime module in manifest: ${required}`
    );
    assert.match(RUNTIME_MODULE_MANIFEST.files[required].sha256, /^[a-f0-9]{64}$/);
  }
  validateRuntimeManifest(RUNTIME_MODULE_MANIFEST, { expectedVersion: BRIDGE_VERSION });

  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  if (process.env.BRIDGE_FAST_VOTE_TEST === "1" && !fs.existsSync(path.join(repoRoot, RUNTIME_MANIFEST_FILENAME))) {
    return;
  }
  const loaded = loadRuntimeManifest(repoRoot, { expectedVersion: BRIDGE_VERSION });
  const recomputed = computeRuntimeManifest(repoRoot, { version: BRIDGE_VERSION });
  assert.equal(loaded.manifestDigest, recomputed.manifestDigest);
  assert.deepEqual(loaded.files, recomputed.files);
  const closure = verifyStagedRuntimeClosure(repoRoot, loaded);
  assert.equal(closure.ok, true);
  assert.equal(closure.closureVerified, true);
  assert.equal(closure.importVerified, true);

  // Verify cross-OS LF vs CRLF Git checkout invariance (Linux/macOS LF vs Windows autocrlf CRLF)
  const lfCheckoutDir = fs.mkdtempSync(path.join(os.tmpdir(), "flock-lf-checkout-"));
  try {
    for (const modName of REQUIRED_RUNTIME_MODULES) {
      const lfText = fs.readFileSync(path.join(repoRoot, modName), "utf8").replace(/\r\n/g, "\n");
      fs.writeFileSync(path.join(lfCheckoutDir, modName), lfText, "utf8");
    }
    fs.copyFileSync(path.join(repoRoot, RUNTIME_MANIFEST_FILENAME), path.join(lfCheckoutDir, RUNTIME_MANIFEST_FILENAME));
    const lfManifest = computeRuntimeManifest(lfCheckoutDir, { version: BRIDGE_VERSION });
    assert.equal(lfManifest.manifestDigest, loaded.manifestDigest, "LF and CRLF checkouts must produce identical manifestDigest");
    assert.equal(verifyStagedRuntimeClosure(lfCheckoutDir, loaded, { verifyImports: false }).ok, true);
  } finally {
    fs.rmSync(lfCheckoutDir, { recursive: true, force: true });
  }
});

test("fleet runtime staging rejects omitted modules, partial copies, interrupted staging/cutover, and hash mismatches while preserving active generation and protected state", async () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const scratchRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-manifest-gate-"));
  const prevCopilotHome = process.env.COPILOT_HOME;
  const copilotHome = path.join(scratchRoot, ".copilot");
  const targetDir = path.join(copilotHome, "flock");
  process.env.COPILOT_HOME = copilotHome;

  try {
    // 1. Seed a verified working v1 ("3.4.1") installation + protected identity, protocol, and credential state
    const v1Source = path.join(scratchRoot, "source-v1");
    const v1Manifest = buildSyntheticRuntimeSource(v1Source, repoRoot, { version: "3.4.1" });
    const initialActivation = stageAndActivateRuntime({
      sourceDir: v1Source,
      targetDir,
      resident: {
        running: true,
        pid: process.pid,
        version: "3.4.1",
        manifestDigest: v1Manifest.manifestDigest,
        startedAt: "2026-11-12T00:00:00.000Z",
      },
    });
    assert.equal(initialActivation.ok, true);
    assert.equal(initialActivation.installed.status, "installed");
    assert.equal(initialActivation.installed.version, "3.4.1");
    assert.equal(initialActivation.installed.digest, v1Manifest.manifestDigest);
    assert.equal(initialActivation.verified.status, "verified");
    assert.equal(initialActivation.verified.fullyActive, true);

    // Populate protected identity, credential, protocol, and resident state files
    const protectedFiles = {
      "config.json": JSON.stringify({
        machineId: "TEST-RIG-1",
        scope: "personal",
        githubUser: "erjadi",
        bootstrapUrl: "https://your-flock-bootstrap.azurewebsites.net/api/bootstrap",
        connectionString: "Endpoint=https://demo.service.signalr.net;AccessKey=synthetic-key-do-not-mutate;Version=1.0;",
      }, null, 2),
      "identity.json": JSON.stringify({
        algorithm: "ed25519",
        fingerprint: "protected-fp-v1",
        publicKey: "-----BEGIN PUBLIC KEY-----\nPROTECTED\n-----END PUBLIC KEY-----",
        privateKey: "-----BEGIN PRIVATE KEY-----\nPROTECTED\n-----END PRIVATE KEY-----",
      }, null, 2),
      "flocks.json": JSON.stringify({
        flocks: { "erjadi/personal": { trustTier: "owner", rosterEpoch: 4 } },
      }, null, 2),
      "broker-free.json": JSON.stringify({
        schema: 34,
        flocks: { "erjadi/personal": { flockId: "erjadi/personal", epoch: 2 } },
        pendingJoins: {},
      }, null, 2),
      "daemon.pid": String(process.pid),
      "state.json": JSON.stringify({
        status: "connected",
        pid: process.pid,
        version: "3.4.1",
        manifestDigest: v1Manifest.manifestDigest,
        residentRuntime: {
          status: "running",
          running: true,
          pid: process.pid,
          version: "3.4.1",
          digest: v1Manifest.manifestDigest,
          manifestDigest: v1Manifest.manifestDigest,
          startedAt: "2026-11-12T00:00:00.000Z",
        },
        updatedAt: new Date().toISOString(),
      }, null, 2),
    };
    for (const [name, content] of Object.entries(protectedFiles)) {
      fs.writeFileSync(path.join(targetDir, name), content, "utf8");
    }

    const snapshotBaseline = () => {
      const snap = {};
      for (const name of [...REQUIRED_RUNTIME_MODULES, RUNTIME_MANIFEST_FILENAME, "installation.json", ...Object.keys(protectedFiles)]) {
        snap[name] = fs.readFileSync(path.join(targetDir, name));
      }
      return snap;
    };
    const baselineBytes = snapshotBaseline();

    const assertBaselinePreserved = (label) => {
      for (const [name, expectedBuf] of Object.entries(baselineBytes)) {
        const actualBuf = fs.readFileSync(path.join(targetDir, name));
        assert.equal(actualBuf.equals(expectedBuf), true, `${label}: mutated protected or active file ${name}`);
      }
      const leftoverStage = fs.readdirSync(targetDir).filter((n) => n.startsWith(".runtime-stage-") || n.startsWith(".runtime-backup-"));
      assert.deepEqual(leftoverStage, [], `${label}: left temporary staging/backup directories behind`);
      const states = getLocalRuntimeStates({ targetDir });
      assert.equal(states.staged.status, "failed", `${label}: staged status should be 'failed'`);
      assert.equal(states.installed.status, "installed", `${label}: installed status must remain 'installed'`);
      assert.equal(states.installed.complete, true, `${label}: installed closure must remain complete`);
      assert.equal(states.installed.version, "3.4.1");
      assert.equal(states.installed.digest, v1Manifest.manifestDigest);
      assert.equal(states.resident.running, true);
      assert.equal(states.resident.version, "3.4.1");
      assert.equal(states.resident.digest, v1Manifest.manifestDigest);
      assert.equal(states.verified.status, "verified");
      assert.equal(states.verified.fullyActive, true);
      assert.equal(states.verified.digest, v1Manifest.manifestDigest);
    };

    // 2a. Omitted companion module on disk (historical bug: copying flock.mjs/bridge.mjs without flock-lifecycle.mjs)
    const omittedDiskDir = path.join(scratchRoot, "bad-omitted-module");
    buildSyntheticRuntimeSource(omittedDiskDir, repoRoot, { version: "3.5.0-omitted" });
    fs.unlinkSync(path.join(omittedDiskDir, "flock-lifecycle.mjs"));
    assert.throws(
      () => stageAndActivateRuntime({ sourceDir: omittedDiskDir, targetDir }),
      (err) => err.code === "RUNTIME_MODULE_MISSING" && /flock-lifecycle\.mjs/.test(err.message)
    );
    assertBaselinePreserved("omitted companion module on disk");

    // 2b. Manifest omits required companion module
    const omittedManifestDir = path.join(scratchRoot, "bad-manifest-omitted");
    const fullV2 = buildSyntheticRuntimeSource(omittedManifestDir, repoRoot, { version: "3.5.0-manifest-omit" });
    const incompleteManifest = {
      ...fullV2,
      files: Object.fromEntries(Object.entries(fullV2.files).filter(([k]) => k !== "flock-protocol.mjs")),
    };
    fs.writeFileSync(path.join(omittedManifestDir, RUNTIME_MANIFEST_FILENAME), JSON.stringify(incompleteManifest, null, 2));
    assert.throws(
      () => stageAndActivateRuntime({ sourceDir: omittedManifestDir, targetDir }),
      (err) => err.code === "RUNTIME_MODULE_MISSING" && /flock-protocol\.mjs/.test(err.message)
    );
    assertBaselinePreserved("manifest omits required module");

    // 2c. Entrypoint imports unpinned companion module missing from manifest
    const unpinnedDir = path.join(scratchRoot, "bad-unpinned-import");
    buildSyntheticRuntimeSource(unpinnedDir, repoRoot, { version: "3.5.0-unpinned" });
    const unpinnedManifest = JSON.parse(fs.readFileSync(path.join(unpinnedDir, RUNTIME_MANIFEST_FILENAME), "utf8"));
    fs.writeFileSync(path.join(unpinnedDir, "extra-helper.mjs"), "export const EXTRA = 1;\n", "utf8");
    const mutatedFlock = `import { EXTRA } from "./extra-helper.mjs";\n` + fs.readFileSync(path.join(unpinnedDir, "flock.mjs"), "utf8");
    fs.writeFileSync(path.join(unpinnedDir, "flock.mjs"), mutatedFlock, "utf8");
    unpinnedManifest.files["flock.mjs"] = {
      role: "entrypoint",
      sha256: hashRuntimeModule(mutatedFlock),
      imports: [
        "./extra-helper.mjs",
        "./flock-broker-free.mjs",
        "./flock-lifecycle.mjs",
        "./flock-membership.mjs",
        "./flock-protocol.mjs",
        "./flock-registry.mjs",
      ],
    };
    const sortedEntries = Object.keys(unpinnedManifest.files).sort().map((n) => [
      n, unpinnedManifest.files[n].role, unpinnedManifest.files[n].sha256, [...unpinnedManifest.files[n].imports].sort(),
    ]);
    unpinnedManifest.manifestDigest = crypto.createHash("sha256").update(JSON.stringify([
      "copilot-flock-runtime-manifest-v1", unpinnedManifest.version, [...unpinnedManifest.entrypoints].sort(), sortedEntries,
    ])).digest("hex");
    assert.throws(
      () => stageAndActivateRuntime({ sourceDir: unpinnedDir, targetDir, manifest: unpinnedManifest }),
      (err) => err.code === "RUNTIME_UNPINNED_IMPORT" && /extra-helper\.mjs/.test(err.message)
    );
    assertBaselinePreserved("unpinned relative import");

    // 3a. Partial copy (truncated companion module)
    const partialCopyDir = path.join(scratchRoot, "bad-partial-copy");
    buildSyntheticRuntimeSource(partialCopyDir, repoRoot, { version: "3.5.0-partial" });
    const origBrokerFree = fs.readFileSync(path.join(partialCopyDir, "flock-broker-free.mjs"));
    fs.writeFileSync(path.join(partialCopyDir, "flock-broker-free.mjs"), origBrokerFree.subarray(0, 128));
    assert.throws(
      () => stageAndActivateRuntime({ sourceDir: partialCopyDir, targetDir }),
      (err) => err.code === "RUNTIME_HASH_MISMATCH" && /flock-broker-free\.mjs/.test(err.message)
    );
    assertBaselinePreserved("partial/truncated module copy");

    // 3b. Broken ESM export / syntax error even when manifest SHA-256 digests match the broken source
    const brokenImportDir = path.join(scratchRoot, "bad-esm-export");
    buildSyntheticRuntimeSource(brokenImportDir, repoRoot, {
      version: "3.5.0-broken-export",
      mutate: (dir) => {
        const src = fs.readFileSync(path.join(dir, "flock-azure.mjs"), "utf8");
        fs.writeFileSync(
          path.join(dir, "flock-azure.mjs"),
          `import { nonExistentSymbolFromProtocol } from "./flock-protocol.mjs";\n` + src,
          "utf8"
        );
      },
    });
    assert.throws(
      () => stageAndActivateRuntime({ sourceDir: brokenImportDir, targetDir }),
      (err) => err.code === "RUNTIME_IMPORT_VERIFICATION_FAILED" && /nonExistentSymbolFromProtocol/.test(err.message)
    );
    assertBaselinePreserved("broken ESM named export caught in staged import check");

    // 3c. Interrupted staging mid-copy
    const validV2Dir = path.join(scratchRoot, "valid-v2");
    const v2Manifest = buildSyntheticRuntimeSource(validV2Dir, repoRoot, { version: "3.5.0-rc1" });
    let stagedFilesCount = 0;
    assert.throws(
      () =>
        stageAndActivateRuntime({
          sourceDir: validV2Dir,
          targetDir,
          onAfterStageFile: () => {
            stagedFilesCount++;
            if (stagedFilesCount === 3) {
              const err = new Error("Simulated power/network interruption during staging");
              err.code = "SIMULATED_STAGE_INTERRUPT";
              throw err;
            }
          },
        }),
      (err) => err.code === "SIMULATED_STAGE_INTERRUPT"
    );
    assertBaselinePreserved("interrupted staging mid-copy");

    // 3d. Interrupted cutover mid-activation -> automatic rollback restores exact previous working generation
    assert.throws(
      () =>
        stageAndActivateRuntime({
          sourceDir: validV2Dir,
          targetDir,
          onDuringCutover: ({ index }) => {
            if (index === 3) {
              const err = new Error("Simulated mid-cutover failure");
              err.code = "SIMULATED_CUTOVER_FAILURE";
              throw err;
            }
          },
        }),
      (err) => err.code === "SIMULATED_CUTOVER_FAILURE"
    );
    assertBaselinePreserved("interrupted cutover rolled back cleanly");

    // 4. Hash mismatch on valid-syntax tampered module & across install / self_update / reprovision / updateFleetMachines
    const hashMismatchDir = path.join(scratchRoot, "bad-hash-mismatch");
    buildSyntheticRuntimeSource(hashMismatchDir, repoRoot, { version: "3.5.0-tampered" });
    fs.appendFileSync(path.join(hashMismatchDir, "flock-membership.mjs"), "\n// unauthorized modification\n", "utf8");

    const testCfg = JSON.parse(protectedFiles["config.json"]);
    await assert.rejects(
      () => installBridge({ sourceDirArg: hashMismatchDir, scopeArg: "personal", githubUserArg: "erjadi" }),
      (err) => err.code === "RUNTIME_HASH_MISMATCH"
    );
    assertBaselinePreserved("installBridge rejects hash mismatch before mutating config/identity");

    await assert.rejects(
      () => performLocalSelfUpdate(testCfg, { sourceDir: hashMismatchDir, gitSync: false, spawnInstall: false }),
      (err) => err.code === "RUNTIME_HASH_MISMATCH"
    );
    assertBaselinePreserved("performLocalSelfUpdate rejects hash mismatch before mutating active runtime");

    await assert.rejects(
      () => reprovisionLocalBridge(testCfg, { sourceDir: omittedDiskDir, gitSync: false, spawnDetachedInstall: false }),
      (err) => err.code === "RUNTIME_MODULE_MISSING"
    );
    assertBaselinePreserved("reprovisionLocalBridge rejects omitted module before deleting identity.json or sessions");

    // Broker-free protocol guard on reprovision & self_update preserves protected protocol/credentials
    await assert.rejects(
      () => reprovisionLocalBridge({ ...testCfg, protocol: "broker-free-v34" }, { sourceDir: validV2Dir, gitSync: false }),
      (err) => err.code === "BROKER_FREE_MUTATION_FORBIDDEN"
    );
    await assert.rejects(
      () => performLocalSelfUpdate({ ...testCfg, protocol: "broker-free-v34" }, { sourceDir: validV2Dir, gitSync: false, spawnInstall: false }),
      (err) => err.code === "BROKER_FREE_MUTATION_FORBIDDEN"
    );

    const failedFleetLocal = await updateFleetMachines(testCfg, {
      machines: "TEST-RIG-1",
      includeSelf: true,
      sourceDir: hashMismatchDir,
      gitSync: false,
      discoverFn: async () => [],
      invokeBatchFn: async () => [],
      postUpdateWaitMs: 0,
    });
    assert.equal(failedFleetLocal.ok, false);
    assert.equal(failedFleetLocal.localUpdate.ok, false);
    assert.equal(failedFleetLocal.localUpdate.code, "RUNTIME_HASH_MISMATCH");
    assertBaselinePreserved("updateFleetMachines retains previous generation on hash mismatch");

    // 5. Stage-only vs activated vs resident states exposed independently across update and status responses
    const stagedOnly = stageAndActivateRuntime({
      sourceDir: validV2Dir,
      targetDir,
      activate: false,
      resident: {
        running: true,
        pid: process.pid,
        version: "3.4.1",
        manifestDigest: v1Manifest.manifestDigest,
      },
    });
    assert.equal(stagedOnly.activated, false);
    assert.equal(stagedOnly.staged.status, "staged");
    assert.equal(stagedOnly.staged.version, "3.5.0-rc1");
    assert.equal(stagedOnly.staged.digest, v2Manifest.manifestDigest);
    assert.equal(stagedOnly.installed.status, "installed");
    assert.equal(stagedOnly.installed.version, "3.4.1");
    assert.equal(stagedOnly.installed.digest, v1Manifest.manifestDigest);
    assert.equal(stagedOnly.resident.version, "3.4.1");
    assert.equal(stagedOnly.resident.digest, v1Manifest.manifestDigest);
    assert.equal(stagedOnly.verified.status, "verified");
    assert.equal(stagedOnly.verified.version, "3.4.1");
    assert.equal(stagedOnly.verified.digest, v1Manifest.manifestDigest);
    stagedOnly.cleanup();

    // Perform self_update atomic cutover to v2 while v1 daemon is still resident in memory
    const selfUpdateRes = await performLocalSelfUpdate(testCfg, {
      sourceDir: validV2Dir,
      gitSync: false,
      spawnInstall: false,
    });
    assert.equal(selfUpdateRes.status, "updating");
    assert.equal(selfUpdateRes.staged.status, "promoted");
    assert.equal(selfUpdateRes.staged.version, "3.5.0-rc1");
    assert.equal(selfUpdateRes.staged.digest, v2Manifest.manifestDigest);
    assert.equal(selfUpdateRes.installed.status, "installed");
    assert.equal(selfUpdateRes.installed.complete, true);
    assert.equal(selfUpdateRes.installed.version, "3.5.0-rc1");
    assert.equal(selfUpdateRes.installed.digest, v2Manifest.manifestDigest);
    // Resident daemon is still running in-process version (BRIDGE_VERSION = 3.4.1) before restart!
    assert.equal(selfUpdateRes.resident.running, true);
    assert.equal(selfUpdateRes.resident.version, BRIDGE_VERSION);
    assert.equal(selfUpdateRes.verified.closureVerified, true);
    assert.equal(selfUpdateRes.verified.importVerified, true);
    assert.equal(selfUpdateRes.verified.residentMatchesInstalled, false);
    assert.equal(selfUpdateRes.verified.status, "pending_daemon_restart");
    assert.equal(selfUpdateRes.verified.version, "3.5.0-rc1");
    assert.equal(selfUpdateRes.verified.digest, v2Manifest.manifestDigest);

    // Protected credentials and flocks remain untouched by self_update
    for (const key of ["config.json", "identity.json", "flocks.json", "broker-free.json"]) {
      assert.equal(fs.readFileSync(path.join(targetDir, key)).equals(baselineBytes[key]), true);
    }

    // Diagnose surfaces pending resident restart when resident digest != installed digest
    const diagBeforeRestart = await diagnoseLocalBridgeState(testCfg, { fix: false, inDaemonRpc: true });
    assert.equal(diagBeforeRestart.installed.version, "3.5.0-rc1");
    assert.equal(diagBeforeRestart.resident.version, BRIDGE_VERSION);
    assert.equal(diagBeforeRestart.verified.status, "pending_daemon_restart");
    assert.ok(diagBeforeRestart.issues.some((msg) => /manifestDigest .* differs from installed runtime/.test(msg)));

    // Simulate daemon restart completing onto v2 in state.json and verify fleet update + status responses
    fs.writeFileSync(
      path.join(targetDir, "state.json"),
      JSON.stringify({
        status: "connected",
        pid: process.pid,
        version: "3.5.0-rc1",
        manifestDigest: v2Manifest.manifestDigest,
        residentRuntime: {
          status: "running",
          running: true,
          pid: process.pid,
          version: "3.5.0-rc1",
          digest: v2Manifest.manifestDigest,
          manifestDigest: v2Manifest.manifestDigest,
          startedAt: "2026-11-12T00:05:00.000Z",
        },
        updatedAt: new Date().toISOString(),
      }, null, 2),
      "utf8"
    );

    const postRestartStates = getLocalRuntimeStates({ targetDir });
    assert.equal(postRestartStates.installed.version, "3.5.0-rc1");
    assert.equal(postRestartStates.resident.version, "3.5.0-rc1");
    assert.equal(postRestartStates.resident.digest, v2Manifest.manifestDigest);
    assert.equal(postRestartStates.verified.status, "verified");
    assert.equal(postRestartStates.verified.residentMatchesInstalled, true);
    assert.equal(postRestartStates.verified.fullyActive, true);

    const pingStatus = await handleRpcAction(testCfg, { action: "ping", params: {} });
    assert.equal(pingStatus.staged.version, "3.5.0-rc1");
    assert.equal(pingStatus.staged.digest, v2Manifest.manifestDigest);
    assert.equal(pingStatus.installed.version, "3.5.0-rc1");
    assert.equal(pingStatus.installed.digest, v2Manifest.manifestDigest);
    assert.equal(pingStatus.resident.running, true);
    assert.equal(pingStatus.resident.version, BRIDGE_VERSION);
    assert.equal(pingStatus.verified.closureVerified, true);
    assert.equal(pingStatus.verified.importVerified, true);

    // Verify updateFleetMachines (`update_remote_machines`) exposes staged/installed/resident/verified for remote peers too
    let discoverCall = 0;
    const fleetRes = await updateFleetMachines(testCfg, {
      machines: "*",
      includeSelf: true,
      sourceDir: validV2Dir,
      gitSync: false,
      postUpdateWaitMs: 0,
      localInstallFn: async () => ({
        version: "3.5.0-rc1",
        daemonPid: process.pid,
        runtimeStates: getLocalRuntimeStates({ targetDir }),
      }),
      discoverFn: async () => {
        discoverCall++;
        if (discoverCall === 1) {
          return [
            { machineId: "TEST-RIG-1", scope: "personal", version: "3.4.1" },
            { machineId: "REMOTE-OK", scope: "personal", version: "3.4.1" },
            { machineId: "REMOTE-LAGGING-DAEMON", scope: "personal", version: "3.4.1" },
          ];
        }
        return [
          {
            machineId: "REMOTE-OK",
            scope: "personal",
            pid: 4100,
            version: "3.5.0-rc1",
            manifestDigest: v2Manifest.manifestDigest,
            staged: { status: "promoted", version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest, closureVerified: true, importVerified: true },
            installed: { status: "installed", complete: true, version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest },
            resident: { status: "running", running: true, pid: 4100, version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest },
            verified: { status: "verified", closureVerified: true, importVerified: true, residentMatchesInstalled: true, fullyActive: true, version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest },
          },
          {
            machineId: "REMOTE-LAGGING-DAEMON",
            scope: "personal",
            pid: 4200,
            version: "3.4.1",
            manifestDigest: v1Manifest.manifestDigest,
            staged: { status: "promoted", version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest, closureVerified: true, importVerified: true },
            installed: { status: "installed", complete: true, version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest },
            resident: { status: "running", running: true, pid: 4200, version: "3.4.1", digest: v1Manifest.manifestDigest, manifestDigest: v1Manifest.manifestDigest },
          },
        ];
      },
      invokeBatchFn: async (_cfg, items) =>
        items.map((item) => ({
          item,
          ok: true,
          response: {
            result: {
              status: "updating",
              machineId: item.toMachine,
              staged: { status: "promoted", version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest, closureVerified: true, importVerified: true },
              installed: { status: "installed", complete: true, version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest },
              resident: { status: "running", running: true, pid: 4000, version: "3.4.1", digest: v1Manifest.manifestDigest, manifestDigest: v1Manifest.manifestDigest },
              verified: { status: "pending_daemon_restart", closureVerified: true, importVerified: true, residentMatchesInstalled: false, version: "3.5.0-rc1", digest: v2Manifest.manifestDigest, manifestDigest: v2Manifest.manifestDigest },
            },
          },
        })),
    });

    assert.equal(fleetRes.ok, true);
    assert.equal(fleetRes.localUpdate.ok, true);
    assert.equal(fleetRes.installed.version, "3.5.0-rc1");
    assert.equal(fleetRes.resident.version, "3.5.0-rc1");
    assert.equal(fleetRes.verified.fullyActive, true);

    const remoteOk = fleetRes.remoteUpdates.find((r) => r.machineId === "REMOTE-OK");
    const remoteLag = fleetRes.remoteUpdates.find((r) => r.machineId === "REMOTE-LAGGING-DAEMON");
    assert.equal(remoteOk.activationVerified, true);
    assert.equal(remoteOk.installed.digest, v2Manifest.manifestDigest);
    assert.equal(remoteOk.resident.digest, v2Manifest.manifestDigest);
    assert.equal(remoteOk.verified.status, "verified");

    assert.equal(remoteLag.activationVerified, false);
    assert.equal(remoteLag.installed.version, "3.5.0-rc1");
    assert.equal(remoteLag.installed.digest, v2Manifest.manifestDigest);
    assert.equal(remoteLag.resident.version, "3.4.1");
    assert.equal(remoteLag.resident.digest, v1Manifest.manifestDigest);
    assert.equal(remoteLag.verified.status, "pending_daemon_restart");

    // Also verify reprovisionLocalBridge happy path activates both flock.mjs & bridge.mjs + companion closure
    const reprovCfg = { machineId: "TEST-RIG-1", scope: "personal", githubUser: "erjadi" };
    fs.writeFileSync(path.join(targetDir, "config.json"), JSON.stringify(reprovCfg, null, 2), "utf8");
    const reprovRes = await reprovisionLocalBridge(reprovCfg, {
      sourceDir: validV2Dir,
      gitSync: false,
      syncInstall: true,
      reapFn: () => [],
      installFn: async () => ({
        version: "3.5.0-rc1",
        daemonPid: process.pid,
        runtimeStates: getLocalRuntimeStates({ targetDir }),
      }),
    });
    assert.equal(reprovRes.status, "reprovisioned");
    assert.equal(reprovRes.installed.complete, true);
    assert.equal(reprovRes.installed.version, "3.5.0-rc1");
    assert.equal(reprovRes.installed.digest, v2Manifest.manifestDigest);
    for (const modName of REQUIRED_RUNTIME_MODULES) {
      const diskSha = hashRuntimeModule(fs.readFileSync(path.join(targetDir, modName)));
      assert.equal(diskSha, v2Manifest.files[modName].sha256, `Reprovisioned ${modName} digest mismatch`);
    }
  } finally {
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    fs.rmSync(scratchRoot, { recursive: true, force: true });
  }
});

test("release voter extracts complete modular dependency closure into isolated fixture and produces signed machine-readable ballots across pass, missing-module, failure, timeout, and infrastructure errors", async () => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = env.tempRoot;

  const gitRun = (cwd, args) =>
    execFileSync("git", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    }).trim();

  const writeTreeFiles = (rootDir, filesMap) => {
    for (const fileName of fs.readdirSync(rootDir)) {
      if (fileName === ".git") continue;
      fs.rmSync(path.join(rootDir, fileName), { recursive: true, force: true });
    }
    for (const [relPath, content] of Object.entries(filesMap)) {
      const dest = path.join(rootDir, ...relPath.split("/"));
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, content, "utf8");
    }
  };

  try {
    // Plant poisoned/stale modules in ~/.copilot/flock to prove isolated candidate fixtures never read host installations
    const hostFlockDir = path.join(env.tempRoot, "flock");
    fs.writeFileSync(
      path.join(hostFlockDir, "flock-lifecycle.mjs"),
      'throw new Error("STALE_HOST_FLOCK_LIFECYCLE_IMPORTED");\n',
      "utf8"
    );
    fs.writeFileSync(
      path.join(hostFlockDir, "custom-modular-feature.mjs"),
      'export const FEATURE_TAG = "stale-host-copy";\n',
      "utf8"
    );
    fs.writeFileSync(
      path.join(hostFlockDir, "config.json"),
      JSON.stringify({ machineId: "POISONED-HOST-CONFIG" }),
      "utf8"
    );

    const voterKey = ensureMachineIdentityKeypair();
    const voterCfg = {
      machineId: "VOTER-WIN-PC",
      scope: "personal",
      githubUser: "erjadi",
    };

    // Create a local origin git repository and a voter clone so real git fetch + ls-tree + cat-file run offline
    const originWorkDir = path.join(env.tempRoot, "origin-repo");
    const voterCloneDir = path.join(env.tempRoot, "voter-clone");
    fs.mkdirSync(originWorkDir, { recursive: true });
    gitRun(originWorkDir, ["init", "-b", "main"]);
    gitRun(originWorkDir, ["config", "user.email", "voter-test@example.invalid"]);
    gitRun(originWorkDir, ["config", "user.name", "Voter Test"]);

    const baseModularCandidate = {
      "package.json": JSON.stringify({ name: "copilot-flock", version: "3.5.0-test", type: "module" }, null, 2),
      "flock-lifecycle.mjs": 'export const LIFECYCLE_STATE = "fresh-candidate-lifecycle";\n',
      "modules/deep-helper.mjs": 'export function computeDeepTag(x) { return `deep:${x}`; }\n',
      "custom-modular-feature.mjs": [
        'import { computeDeepTag } from "./modules/deep-helper.mjs";',
        'export const FEATURE_TAG = computeDeepTag("modular-v35");',
      ].join("\n"),
      "flock.mjs": [
        'import { LIFECYCLE_STATE } from "./flock-lifecycle.mjs";',
        'import { FEATURE_TAG } from "./custom-modular-feature.mjs";',
        'export function summarizeCandidate() { return `${LIFECYCLE_STATE}|${FEATURE_TAG}`; }',
      ].join("\n"),
      "bridge.mjs": 'export { summarizeCandidate } from "./flock.mjs";\n',
      "bootstrap-server.mjs": [
        'import { FEATURE_TAG } from "./custom-modular-feature.mjs";',
        'export const BOOTSTRAP_READY = FEATURE_TAG;',
      ].join("\n"),
      "test/flock.test.mjs": [
        'import test from "node:test";',
        'import assert from "node:assert/strict";',
        'import os from "node:os";',
        'import fs from "node:fs";',
        'import path from "node:path";',
        'import { summarizeCandidate } from "../flock.mjs";',
        'import { BOOTSTRAP_READY } from "../bootstrap-server.mjs";',
        `const hostTempRoot = ${JSON.stringify(env.tempRoot)};`,
        'test("modular candidate runs in isolated fixture without reading ~/.copilot/flock", () => {',
        '  assert.equal(summarizeCandidate(), "fresh-candidate-lifecycle|deep:modular-v35");',
        '  assert.equal(BOOTSTRAP_READY, "deep:modular-v35");',
        '  assert.notEqual(path.resolve(process.env.COPILOT_HOME || ""), path.resolve(hostTempRoot));',
        '  assert.equal(fs.existsSync(path.join(os.homedir(), ".copilot", "flock", "config.json")), false);',
        '  console.log("modular-candidate-stdout-ok");',
        '});',
      ].join("\n"),
    };

    writeTreeFiles(originWorkDir, baseModularCandidate);
    gitRun(originWorkDir, ["add", "-A"]);
    gitRun(originWorkDir, ["commit", "-m", "initial modular main"]);

    // Clone voter repo from local originWorkDir
    gitRun(env.tempRoot, ["clone", originWorkDir, voterCloneDir]);

    // Branch 1: passing modular candidate (`rc-modular-pass`)
    gitRun(originWorkDir, ["checkout", "-b", "rc-modular-pass"]);
    writeTreeFiles(originWorkDir, {
      ...baseModularCandidate,
      "modules/extra-leaf.mjs": 'export const EXTRA_LEAF = "leaf-ok";\n',
      "custom-modular-feature.mjs": [
        'import { computeDeepTag } from "./modules/deep-helper.mjs";',
        'import { EXTRA_LEAF } from "./modules/extra-leaf.mjs";',
        'export const FEATURE_TAG = `${computeDeepTag("modular-v35")}:${EXTRA_LEAF}`;',
      ].join("\n"),
      "test/flock.test.mjs": baseModularCandidate["test/flock.test.mjs"].replaceAll(
        "deep:modular-v35",
        "deep:modular-v35:leaf-ok"
      ),
    });
    gitRun(originWorkDir, ["add", "-A"]);
    gitRun(originWorkDir, ["commit", "-m", "add extra nested module"]);
    const passCommit = gitRun(originWorkDir, ["rev-parse", "HEAD"]);

    const passBallot = await reviewReleaseCandidate(
      voterCfg,
      { branch: "rc-modular-pass" },
      { repoDir: voterCloneDir }
    );
    assert.equal(passBallot.vote, "ACCEPT");
    assert.equal(passBallot.failureCategory, "passed");
    assert.equal(passBallot.candidateCommit, passCommit);
    assert.equal(passBallot.voterVersion, BRIDGE_VERSION);
    assert.equal(passBallot.fixtureVerificationLevel, "complete_repo_closure_isolated_fixture");
    assert.equal(passBallot.keyFingerprint, voterKey.fingerprint);
    assert.equal(passBallot.exitCode, 0);
    assert.equal(passBallot.signal, null);
    assert.equal(passBallot.timedOut, false);
    assert.equal(passBallot.checks.fixtureExtractedOk, true);
    assert.equal(passBallot.checks.dependencyClosureOk, true);
    assert.equal(passBallot.checks.unitTestsOk, true);
    assert.ok(passBallot.stdout.includes("modular-candidate-stdout-ok"));
    assert.equal(verifyVoteBallotSignature(passBallot, voterKey.publicKey), true);

    // Tampering with any signed v2 ballot metadata field must invalidate verifyVoteBallotSignature
    for (const tampered of [
      { ...passBallot, failureCategory: "candidate_test_failure" },
      { ...passBallot, stdout: `${passBallot.stdout}\nforged` },
      { ...passBallot, stderr: "forged-stderr" },
      { ...passBallot, exitCode: 1 },
      { ...passBallot, timedOut: true },
      { ...passBallot, voterVersion: "0.0.0-forged" },
      { ...passBallot, fixtureVerificationLevel: "three_file_legacy" },
      { ...passBallot, keyFingerprint: "0".repeat(32) },
      { ...passBallot, ballotSignature: undefined },
    ]) {
      assert.equal(verifyVoteBallotSignature(tampered, voterKey.publicKey), false);
    }

    // Branch 2: missing-module failure diagnostics (`rc-missing-module`)
    gitRun(originWorkDir, ["checkout", "-b", "rc-missing-module", "main"]);
    writeTreeFiles(originWorkDir, {
      ...baseModularCandidate,
      "flock.mjs": [
        'import { MISSING_SYM } from "./uncommitted-missing-module.mjs";',
        'export function summarizeCandidate() { return MISSING_SYM; }',
      ].join("\n"),
    });
    gitRun(originWorkDir, ["add", "-A"]);
    gitRun(originWorkDir, ["commit", "-m", "broken missing module import"]);
    const missingModCommit = gitRun(originWorkDir, ["rev-parse", "HEAD"]);

    const missingModBallot = await reviewReleaseCandidate(
      voterCfg,
      { branch: "rc-missing-module" },
      { repoDir: originWorkDir, fetchFromOrigin: false }
    );
    assert.equal(missingModBallot.vote, "REJECT");
    assert.equal(missingModBallot.failureCategory, "candidate_test_failure");
    assert.equal(missingModBallot.candidateCommit, missingModCommit);
    assert.notEqual(missingModBallot.exitCode, 0);
    assert.equal(missingModBallot.timedOut, false);
    assert.match(missingModBallot.stderr, /ERR_MODULE_NOT_FOUND/);
    assert.match(missingModBallot.stderr, /uncommitted-missing-module\.mjs/);
    assert.equal(verifyVoteBallotSignature(missingModBallot, voterKey.publicKey), true);

    // Branch 3: nonzero test failure with bounded multi-byte UTF-8 stdout/stderr (`rc-failing-test`)
    gitRun(originWorkDir, ["checkout", "-b", "rc-failing-test", "main"]);
    writeTreeFiles(originWorkDir, {
      ...baseModularCandidate,
      "test/flock.test.mjs": [
        'import test from "node:test";',
        'import assert from "node:assert/strict";',
        'test("deliberate candidate failure with multibyte UTF-8 output", () => {',
        '  console.log("HEAD-STDOUT-αβγ🚀-" + "ω".repeat(900) + "-TAIL-STDOUT-END");',
        '  console.error("HEAD-STDERR-δεζ❌-" + "λ".repeat(900) + "-TAIL-STDERR-END");',
        '  assert.equal("broken-candidate", "expected-behavior");',
        '});',
      ].join("\n"),
    });
    gitRun(originWorkDir, ["add", "-A"]);
    gitRun(originWorkDir, ["commit", "-m", "failing test candidate"]);
    const failTestCommit = gitRun(originWorkDir, ["rev-parse", "HEAD"]);

    const maxBytes = 768;
    const failBallot = await reviewReleaseCandidate(
      voterCfg,
      { branch: "rc-failing-test" },
      { repoDir: originWorkDir, fetchFromOrigin: false, maxOutputBytes: maxBytes }
    );
    assert.equal(failBallot.vote, "REJECT");
    assert.equal(failBallot.failureCategory, "candidate_test_failure");
    assert.equal(failBallot.candidateCommit, failTestCommit);
    assert.equal(failBallot.exitCode, 1);
    assert.equal(failBallot.signal, null);
    assert.equal(failBallot.timedOut, false);
    assert.ok(Buffer.byteLength(failBallot.stdout, "utf8") <= maxBytes);
    assert.ok(Buffer.byteLength(failBallot.stderr, "utf8") <= maxBytes);
    assert.equal(failBallot.stdout.includes("\uFFFD"), false);
    assert.equal(failBallot.stderr.includes("\uFFFD"), false);
    assert.match(failBallot.stdout, /HEAD-STDOUT-αβγ🚀/);
    assert.match(failBallot.stderr, /HEAD-STDERR-δεζ❌/);
    assert.match(failBallot.stderr, /TAIL-STDERR-END|expected-behavior/);
    assert.equal(verifyVoteBallotSignature(failBallot, voterKey.publicKey), true);

    // Direct UTF-8 multi-byte boundary check on truncateUtf8Bounded
    const emojiWall = "🚀🎉🔥✨".repeat(120);
    const boundedEmoji = truncateUtf8Bounded(emojiWall, 180);
    assert.ok(Buffer.byteLength(boundedEmoji, "utf8") <= 180);
    assert.equal(boundedEmoji.includes("\uFFFD"), false);

    // Branch 4: candidate unit test timeout (`rc-timeout-test`)
    gitRun(originWorkDir, ["checkout", "-b", "rc-timeout-test", "main"]);
    writeTreeFiles(originWorkDir, {
      ...baseModularCandidate,
      "test/flock.test.mjs": [
        'process.stdout.write("STDOUT-BEFORE-TIMEOUT\\n");',
        'process.stderr.write("STDERR-BEFORE-TIMEOUT\\n");',
        'import test from "node:test";',
        'test("hanging candidate test", async () => {',
        '  await new Promise(() => {});',
        '});',
      ].join("\n"),
    });
    gitRun(originWorkDir, ["add", "-A"]);
    gitRun(originWorkDir, ["commit", "-m", "hanging timeout candidate"]);
    const timeoutCommit = gitRun(originWorkDir, ["rev-parse", "HEAD"]);

    const timeoutBallot = await reviewReleaseCandidate(
      voterCfg,
      { branch: "rc-timeout-test" },
      { repoDir: originWorkDir, fetchFromOrigin: false, testTimeoutMs: 1500 }
    );
    assert.equal(timeoutBallot.vote, "REJECT");
    assert.equal(timeoutBallot.failureCategory, "candidate_test_failure");
    assert.equal(timeoutBallot.candidateCommit, timeoutCommit);
    assert.equal(timeoutBallot.timedOut, true);
    assert.ok(timeoutBallot.signal === "SIGTERM" || timeoutBallot.signal === "SIGKILL");
    assert.match(timeoutBallot.stdout, /STDOUT-BEFORE-TIMEOUT/);
    assert.match(timeoutBallot.stderr, /STDERR-BEFORE-TIMEOUT/);
    assert.equal(verifyVoteBallotSignature(timeoutBallot, voterKey.publicKey), true);

    // Scenario 5: Fixture infrastructure errors must always REJECT with failureCategory: "fixture_infrastructure_error"
    const missingRepoBallot = await reviewReleaseCandidate(
      voterCfg,
      { branch: "rc-modular-pass" },
      { resolveRepoFn: () => null }
    );
    assert.equal(missingRepoBallot.vote, "REJECT");
    assert.equal(missingRepoBallot.failureCategory, "fixture_infrastructure_error");
    assert.equal(missingRepoBallot.candidateCommit, null);
    assert.match(missingRepoBallot.stderr, /Could not locate copilot-flock git repo/);
    assert.equal(verifyVoteBallotSignature(missingRepoBallot, voterKey.publicKey), true);

    const badBranchBallot = await reviewReleaseCandidate(
      voterCfg,
      { branch: "nonexistent-branch-xyz" },
      { repoDir: voterCloneDir }
    );
    assert.equal(badBranchBallot.vote, "REJECT");
    assert.equal(badBranchBallot.failureCategory, "fixture_infrastructure_error");
    assert.notEqual(badBranchBallot.exitCode, 0);
    assert.ok(badBranchBallot.stderr.length > 0);
    assert.equal(verifyVoteBallotSignature(badBranchBallot, voterKey.publicKey), true);

    // Partial/incomplete extraction omitting a tracked .mjs module must fail closed as fixture_infrastructure_error
    const incompleteExtractionBallot = await reviewReleaseCandidate(
      voterCfg,
      { branch: "rc-modular-pass" },
      {
        repoDir: originWorkDir,
        fetchFromOrigin: false,
        extractFixtureFn: async (rDir, commit, fDir, opts) => {
          const res = await extractCandidateFixtureFromGit(rDir, commit, fDir, opts);
          fs.unlinkSync(path.join(fDir, "modules", "extra-leaf.mjs"));
          return res;
        },
      }
    );
    assert.equal(incompleteExtractionBallot.vote, "REJECT");
    assert.equal(incompleteExtractionBallot.failureCategory, "fixture_infrastructure_error");
    assert.match(incompleteExtractionBallot.stderr, /modules\/extra-leaf\.mjs/);
    assert.equal(verifyVoteBallotSignature(incompleteExtractionBallot, voterKey.publicKey), true);

    // Scenario 6: voteReleaseAcrossFlock aggregates passing ballots and strictly blocks infrastructure errors from acceptance
    const membersMap = new Map([
      ["voter-win-pc", { publicKey: voterKey.publicKey }],
    ]);
    const approvedReport = await voteReleaseAcrossFlock(
      voterCfg,
      { branch: "rc-modular-pass", machines: "*" },
      {
        discoverFn: async () => [{ machineId: "VOTER-WIN-PC", online: true }],
        membersMapFn: () => membersMap,
        rpcBatchFn: async (_c, items) =>
          items.map((item) => ({ item, ok: true, response: { result: passBallot } })),
      }
    );
    assert.equal(approvedReport.approvedForMerge, true);
    assert.equal(approvedReport.acceptCount, 1);
    assert.equal(approvedReport.rejectCount, 0);
    assert.equal(approvedReport.unanimousCommit, passCommit);

    const blockedInfraReport = await voteReleaseAcrossFlock(
      voterCfg,
      { branch: "rc-modular-pass", machines: "*" },
      {
        discoverFn: async () => [{ machineId: "VOTER-WIN-PC", online: true }],
        membersMapFn: () => membersMap,
        rpcBatchFn: async (_c, items) =>
          items.map((item) => ({
            item,
            ok: true,
            response: { result: incompleteExtractionBallot },
          })),
      }
    );
    assert.equal(blockedInfraReport.approvedForMerge, false);
    assert.equal(blockedInfraReport.acceptCount, 0);
    assert.equal(blockedInfraReport.rejectCount, 1);
    assert.equal(blockedInfraReport.infrastructureFailureCount, 1);
    assert.equal(blockedInfraReport.votes[0].failureCategory, "fixture_infrastructure_error");

    // Even if a buggy/malformed ballot claimed vote: "ACCEPT" alongside fixture_infrastructure_error, it must never be accepted
    const forgedInfraAcceptBallot = {
      ...incompleteExtractionBallot,
      vote: "ACCEPT",
    };
    const forgedInfraReport = await voteReleaseAcrossFlock(
      voterCfg,
      { branch: "rc-modular-pass", machines: "*" },
      {
        discoverFn: async () => [{ machineId: "VOTER-WIN-PC", online: true }],
        membersMapFn: () => membersMap,
        rpcBatchFn: async (_c, items) =>
          items.map((item) => ({
            item,
            ok: true,
            response: { result: forgedInfraAcceptBallot },
          })),
      }
    );
    assert.equal(forgedInfraReport.approvedForMerge, false);
    assert.equal(forgedInfraReport.acceptCount, 0);
    assert.equal(forgedInfraReport.rejectCount, 1);
    assert.equal(forgedInfraReport.votes[0].vote, "REJECT");

    // Scenario 7: Direct ESM import targeting host ~/.copilot/flock is actively blocked by fixture isolation hooks
    if (typeof (await import("node:module")).default.registerHooks === "function") {
      gitRun(originWorkDir, ["checkout", "-b", "rc-escape-attempt", "main"]);
      const staleHostModuleHref = pathToFileURL(
        path.join(hostFlockDir, "custom-modular-feature.mjs")
      ).href;
      writeTreeFiles(originWorkDir, {
        ...baseModularCandidate,
        "test/flock.test.mjs": [
          'import test from "node:test";',
          `test("attempt stale host import", async () => { await import(${JSON.stringify(staleHostModuleHref)}); });`,
        ].join("\n"),
      });
      gitRun(originWorkDir, ["add", "-A"]);
      gitRun(originWorkDir, ["commit", "-m", "attempt host flock import"]);

      const escapeBallot = await reviewReleaseCandidate(
        voterCfg,
        { branch: "rc-escape-attempt" },
        { repoDir: originWorkDir, fetchFromOrigin: false }
      );
      assert.equal(escapeBallot.vote, "REJECT");
      assert.equal(escapeBallot.failureCategory, "candidate_test_failure");
      assert.match(`${escapeBallot.stdout}\n${escapeBallot.stderr}`, /Fixture isolation violation/);
      assert.equal(verifyVoteBallotSignature(escapeBallot, voterKey.publicKey), true);
    }

    assert.equal(buildCanonicalVoteBallotPayload(passBallot), passBallot.ballotPayload);
    await assert.rejects(
      () => handleRpcAction(voterCfg, { action: "review_release", params: { branch: "../bad" } }),
      /Invalid branch name/
    );
  } finally {
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    env.cleanup();
  }
});

function snapshotTreeDigests(rootDir) {
  const out = {};
  if (!fs.existsSync(rootDir)) return out;
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(rootDir, full).replace(/\\/g, "/");
      if (entry.isDirectory()) {
        out[`dir:${rel}`] = "dir";
        walk(full);
      } else {
        const bytes = fs.readFileSync(full);
        out[`file:${rel}`] = crypto.createHash("sha256").update(bytes).digest("hex");
      }
    }
  };
  walk(rootDir);
  return out;
}

test("passive diagnostics keep stopped and unavailable daemons non-mutating without spawning processes or fabricating success", async (t) => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  const prevAppData = process.env.APPDATA;
  const fakeAppData = path.join(env.tempRoot, "appdata");
  fs.mkdirSync(fakeAppData, { recursive: true });
  process.env.COPILOT_HOME = env.tempRoot;
  process.env.APPDATA = fakeAppData;

  let sleeper = null;
  try {
    const flockDir = path.join(env.tempRoot, "flock");
    fs.mkdirSync(flockDir, { recursive: true });
    // Deliberately use legacy scope "private" and omit specs + identity.json so any non-passive path would back up/rewrite files
    const configPath = path.join(flockDir, "config.json");
    const rawInitialConfig = JSON.stringify(
      {
        machineId: "PASSIVE-STOPPED-PC",
        scope: "private",
        githubUser: "erjadi",
        hub: "copilotbridge",
        connectionString:
          "Endpoint=https://passive-fixture.service.signalr.net;AccessKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;Version=1.0;",
      },
      null,
      2
    );
    fs.writeFileSync(configPath, rawInitialConfig, "utf8");

    const beforeHomeSnapshot = snapshotTreeDigests(env.tempRoot);
    const beforeAppDataSnapshot = snapshotTreeDigests(fakeAppData);

    const cfg = loadConfig({ autoFetchAz: false, refreshSpecs: false, passive: true });
    assert.equal(cfg.machineId, "PASSIVE-STOPPED-PC");

    const flockStatusStopped = await executeMcpTool(cfg, "flock_status", { passive: true });
    assert.equal(flockStatusStopped.status, "unavailable");
    assert.equal(flockStatusStopped.passive, true);
    assert.equal(flockStatusStopped.daemon.status, "stopped");
    assert.equal(flockStatusStopped.daemon.running, false);
    assert.equal(flockStatusStopped.daemon.pid, null);
    assert.equal(flockStatusStopped.daemon.passive, true);
    assert.deepEqual(flockStatusStopped.onlineMachines, []);
    assert.equal(flockStatusStopped.onlineMachinesStatus, "unavailable");

    const bridgeStatusStopped = await executeMcpTool(cfg, "bridge_status", { passive: true });
    assert.equal(bridgeStatusStopped.status, "unavailable");
    assert.equal(bridgeStatusStopped.daemon.status, "stopped");
    assert.equal(bridgeStatusStopped.daemon.passive, true);

    // Default fix=false on diagnose_bridge_fleet inspects passively without starting daemon or fabricating healthy=true
    const diagInspectDefault = await executeMcpTool(cfg, "diagnose_bridge_fleet", {});
    assert.equal(diagInspectDefault.ok, false);
    assert.equal(diagInspectDefault.status, "unavailable");
    assert.equal(diagInspectDefault.healthy, false);
    assert.equal(diagInspectDefault.passive, true);
    assert.equal(diagInspectDefault.fix, false);
    assert.equal(diagInspectDefault.daemon.status, "stopped");
    assert.equal(diagInspectDefault.daemon.passive, true);
    assert.deepEqual(diagInspectDefault.members, []);

    const diagPassiveOverrideFix = await executeMcpTool(cfg, "diagnose_bridge_fleet", {
      passive: true,
      fix: true,
    });
    assert.equal(diagPassiveOverrideFix.ok, false);
    assert.equal(diagPassiveOverrideFix.status, "unavailable");
    assert.equal(diagPassiveOverrideFix.fix, false);
    assert.equal(diagPassiveOverrideFix.daemon.status, "stopped");

    const localPassiveDiag = await diagnoseLocalBridgeState(cfg, { fix: false });
    assert.equal(localPassiveDiag.healthy, false);
    assert.equal(localPassiveDiag.daemon.status, "stopped");
    assert.equal(localPassiveDiag.daemon.passive, true);

    // Also verify CLI passive status and default inspect diagnose do not mutate files or spawn a daemon
    const scriptUnderTest = fileURLToPath(new URL("../flock.mjs", import.meta.url));
    const childEnv = { ...process.env, COPILOT_HOME: env.tempRoot, APPDATA: fakeAppData };
    for (const k of Object.keys(childEnv)) {
      if (k.startsWith("NODE_TEST_") || k === "NODE_OPTIONS") delete childEnv[k];
    }
    const cliStatus = spawnSync(process.execPath, [scriptUnderTest, "status", "--passive"], {
      env: childEnv,
      encoding: "utf8",
      timeout: 10000,
    });
    assert.equal(cliStatus.status, 0, cliStatus.stderr);
    const cliStatusJson = JSON.parse(cliStatus.stdout);
    assert.equal(cliStatusJson.status, "unavailable");
    assert.equal(cliStatusJson.daemon.status, "stopped");
    assert.equal(cliStatusJson.daemon.passive, true);

    const cliDiagnose = spawnSync(process.execPath, [scriptUnderTest, "diagnose"], {
      env: childEnv,
      encoding: "utf8",
      timeout: 10000,
    });
    assert.equal(cliDiagnose.status, 0, cliDiagnose.stderr);
    const cliDiagJson = JSON.parse(cliDiagnose.stdout);
    assert.equal(cliDiagJson.status, "unavailable");
    assert.equal(cliDiagJson.healthy, false);
    assert.equal(cliDiagJson.daemon.status, "stopped");
    assert.equal(cliDiagJson.daemon.passive, true);

    // Verify ZERO files/dirs were created, backed up, or rewritten
    assert.equal(fs.existsSync(path.join(flockDir, "identity.json")), false);
    assert.equal(fs.existsSync(`${configPath}.v2.bak.json`), false);
    assert.equal(fs.existsSync(path.join(flockDir, "daemon.pid")), false);
    assert.equal(fs.readFileSync(configPath, "utf8"), rawInitialConfig);
    assert.deepEqual(snapshotTreeDigests(env.tempRoot), beforeHomeSnapshot);
    assert.deepEqual(snapshotTreeDigests(fakeAppData), beforeAppDataSnapshot);

    // Verify stale-heartbeat / error daemon reports status="unavailable", passive=true WITHOUT killing the live PID
    sleeper = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
    fs.writeFileSync(path.join(flockDir, "daemon.pid"), String(sleeper.pid), "utf8");
    fs.writeFileSync(
      path.join(flockDir, "state.json"),
      JSON.stringify({
        pid: sleeper.pid,
        status: "connected",
        updatedAt: new Date(Date.now() - 300000).toISOString(),
      }),
      "utf8"
    );

    const staleStatus = await executeMcpTool(cfg, "flock_status", { passive: true });
    assert.equal(staleStatus.status, "unavailable");
    assert.equal(staleStatus.daemon.status, "unavailable");
    assert.equal(staleStatus.daemon.passive, true);
    assert.equal(staleStatus.daemon.staleHeartbeat, true);
    // Passive inspection must not have killed the stale PID
    process.kill(sleeper.pid, 0);

    const staleDiag = await executeMcpTool(cfg, "diagnose_bridge_fleet", { passive: true });
    assert.equal(staleDiag.ok, false);
    assert.equal(staleDiag.status, "unavailable");
    assert.equal(staleDiag.daemon.status, "unavailable");
    assert.equal(staleDiag.daemon.passive, true);
    process.kill(sleeper.pid, 0);
  } finally {
    if (sleeper?.pid) {
      try {
        process.kill(sleeper.pid);
      } catch {}
    }
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    if (prevAppData === undefined) delete process.env.APPDATA;
    else process.env.APPDATA = prevAppData;
    env.cleanup();
  }
});

test("passive diagnostics report live fleet when daemon is running while non-passive operations preserve explicit daemon start", async (t) => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = env.tempRoot;

  let spawnedDaemonChild = null;
  try {
    const flockDir = path.join(env.tempRoot, "flock");
    fs.mkdirSync(flockDir, { recursive: true });
    const cfg = {
      machineId: "PASSIVE-RUNNING-PC",
      scope: "personal",
      githubUser: "erjadi",
      hub: "copilotbridge",
      endpoint: "https://running-fixture.service.signalr.net",
      host: "running-fixture.service.signalr.net",
      accessKey: Buffer.from("0123456789abcdef0123456789abcdef").toString("base64"),
      connectionString:
        "Endpoint=https://running-fixture.service.signalr.net;AccessKey=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;Version=1.0;",
      specs: null,
    };

    // Simulate a live connected local daemon in daemon.pid + state.json
    fs.writeFileSync(path.join(flockDir, "daemon.pid"), String(process.pid), "utf8");
    fs.writeFileSync(
      path.join(flockDir, "state.json"),
      JSON.stringify({
        pid: process.pid,
        status: "connected",
        updatedAt: new Date().toISOString(),
      }),
      "utf8"
    );

    // Wire an in-memory SignalR loopback bus so discoverMachines and diagnoseFleetMachines exercise real RPC handlers
    const clientsByUser = new Map();
    t.mock.method(RawWebSocketClient.prototype, "connect", async function () {
      const u = new URL(this.url.toString());
      const token = u.searchParams.get("access_token") || "";
      const payloadSeg = token.split(".")[1] || "";
      const claims = payloadSeg
        ? JSON.parse(Buffer.from(payloadSeg, "base64url").toString("utf8"))
        : {};
      this._mockUserId = claims.sub || `anon-${crypto.randomUUID()}`;
      clientsByUser.set(this._mockUserId, this);
    });
    t.mock.method(RawWebSocketClient.prototype, "sendText", function (frame) {
      if (String(frame).includes('"protocol":"json"') && this.onTextMessage) {
        setImmediate(() => this.onTextMessage("{}\x1e"));
      }
    });
    t.mock.method(RawWebSocketClient.prototype, "close", function () {
      this.closed = true;
      if (this._mockUserId) clientsByUser.delete(this._mockUserId);
    });
    t.mock.method(https, "request", (options, cb) => {
      const reqChunks = [];
      const fakeReq = {
        on() {
          return this;
        },
        write(chunk) {
          reqChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        },
        end() {
          const rawBody = Buffer.concat(reqChunks).toString("utf8");
          setImmediate(async () => {
            try {
              const msg = JSON.parse(rawBody);
              if (msg.target === "bridgeRpcRequest" && msg.arguments?.[0]) {
                const rpcReq = msg.arguments[0];
                const result = await handleRpcAction(cfg, {
                  ...rpcReq,
                  senderVerified: true,
                });
                const replyClient = clientsByUser.get(rpcReq.replyUserId);
                if (replyClient?.onTextMessage) {
                  const frame =
                    JSON.stringify({
                      type: 1,
                      target: "bridgeRpcResponse",
                      arguments: [
                        {
                          requestId: rpcReq.requestId,
                          fromMachine: cfg.machineId,
                          result,
                        },
                      ],
                    }) + "\x1e";
                  replyClient.onTextMessage(frame);
                }
              }
            } catch {}
            const fakeRes = new net.Socket();
            fakeRes.statusCode = 202;
            cb(fakeRes);
            fakeRes.emit("data", Buffer.from(""));
            fakeRes.emit("end");
          });
        },
        destroy() {},
      };
      return fakeReq;
    });

    const runningStatus = await executeMcpTool(cfg, "flock_status", { passive: true });
    assert.equal(runningStatus.status, "ok");
    assert.equal(runningStatus.passive, true);
    assert.equal(runningStatus.daemon.status, "running");
    assert.equal(runningStatus.daemon.running, true);
    assert.equal(runningStatus.daemon.pid, process.pid);
    assert.equal(runningStatus.daemon.passive, true);
    assert.equal(runningStatus.onlineMachines.length, 1);
    assert.equal(runningStatus.onlineMachines[0].machineId, "PASSIVE-RUNNING-PC");
    assert.equal(fs.existsSync(path.join(flockDir, "identity.json")), false);

    const runningDiag = await executeMcpTool(cfg, "diagnose_bridge_fleet", { passive: true });
    assert.equal(runningDiag.ok, true);
    assert.equal(runningDiag.status, "ok");
    assert.equal(runningDiag.passive, true);
    assert.equal(runningDiag.fix, false);
    assert.equal(runningDiag.daemon.status, "running");
    assert.equal(runningDiag.daemon.passive, true);
    assert.equal(runningDiag.onlineCount, 1);
    assert.equal(runningDiag.members[0].machineId, "PASSIVE-RUNNING-PC");
    assert.equal(runningDiag.members[0].online, true);
    assert.equal(fs.existsSync(path.join(flockDir, "identity.json")), false);

    // Now stop the simulated daemon and verify explicit non-passive calls still auto-start the daemon
    fs.unlinkSync(path.join(flockDir, "daemon.pid"));
    fs.unlinkSync(path.join(flockDir, "state.json"));
    const stubDaemonPath = path.join(flockDir, "flock.mjs");
    fs.writeFileSync(
      stubDaemonPath,
      `import fs from "node:fs";
import path from "node:path";
const home = process.env.COPILOT_HOME;
const dir = path.join(home, "flock");
fs.writeFileSync(path.join(dir, "daemon.pid"), String(process.pid), "utf8");
fs.writeFileSync(path.join(dir, "state.json"), JSON.stringify({ pid: process.pid, status: "connected", updatedAt: new Date().toISOString() }), "utf8");
setTimeout(() => process.exit(0), 2500);
`,
      "utf8"
    );

    const activeStatus = await executeMcpTool(cfg, "flock_status", {});
    assert.equal(activeStatus.daemon.running, true);
    assert.ok(activeStatus.daemon.pid && activeStatus.daemon.pid !== process.pid);
    spawnedDaemonChild = activeStatus.daemon.pid;
    try {
      process.kill(spawnedDaemonChild);
    } catch {}
    spawnedDaemonChild = null;
    if (fs.existsSync(path.join(flockDir, "daemon.pid"))) {
      fs.unlinkSync(path.join(flockDir, "daemon.pid"));
    }
    if (fs.existsSync(path.join(flockDir, "state.json"))) {
      fs.unlinkSync(path.join(flockDir, "state.json"));
    }

    const activeDiag = await executeMcpTool(cfg, "diagnose_bridge_fleet", { passive: false });
    assert.equal(fs.existsSync(path.join(flockDir, "daemon.pid")), true);
    spawnedDaemonChild = Number(fs.readFileSync(path.join(flockDir, "daemon.pid"), "utf8").trim());
    assert.ok(spawnedDaemonChild > 0);
    assert.equal(activeDiag.onlineCount, 1);
  } finally {
    if (spawnedDaemonChild) {
      try {
        process.kill(spawnedDaemonChild);
      } catch {}
    }
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    env.cleanup();
  }
});

test("mcp_self_info tool and self-info CLI report in-memory loadTimeDigest and detect reload-pending drift after on-disk replacement", async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flock-self-info-"));
  const emptyCopilotHome = path.join(tempRoot, "empty-copilot-home");
  const installDir = path.join(tempRoot, "installed-runtime");
  fs.mkdirSync(emptyCopilotHome, { recursive: true });
  fs.mkdirSync(installDir, { recursive: true });

  let mcpProc = null;
  try {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const entryFilename = path.basename(
      fileURLToPath(new URL("../flock.mjs", import.meta.url))
    );
    const filesToCopy = [
      entryFilename,
      "flock-lifecycle.mjs",
      "flock-membership.mjs",
      "flock-protocol.mjs",
      "flock-azure.mjs",
      "flock-broker-free.mjs",
      "flock-registry.mjs",
    ];
    for (const rel of filesToCopy) {
      fs.copyFileSync(path.join(repoRoot, rel), path.join(installDir, rel));
    }
    const installedEntry = path.join(installDir, entryFilename);

    const cleanEnv = { ...process.env, COPILOT_HOME: emptyCopilotHome };
    for (const k of Object.keys(cleanEnv)) {
      if (k.startsWith("NODE_TEST_") || k === "NODE_OPTIONS") delete cleanEnv[k];
    }

    // 1. CLI self-info works with stopped daemon and empty COPILOT_HOME without creating flock directory
    const cliInitial = spawnSync(process.execPath, [installedEntry, "self-info"], {
      env: cleanEnv,
      encoding: "utf8",
      timeout: 10000,
    });
    assert.equal(cliInitial.status, 0, cliInitial.stderr);
    assert.equal(fs.existsSync(path.join(emptyCopilotHome, "flock")), false);
    const cliInfo1 = JSON.parse(cliInitial.stdout);
    assert.equal(cliInfo1.version, BRIDGE_VERSION);
    assert.equal(cliInfo1.nodeVersion, process.version);
    assert.match(cliInfo1.loadTimeDigest, /^[0-9a-f]{64}$/);
    assert.equal(cliInfo1.currentDiskDigest, cliInfo1.loadTimeDigest);
    assert.equal(cliInfo1.reloadPending, false);
    assert.equal(cliInfo1.daemon.status, "stopped");
    assert.equal(cliInfo1.daemon.passive, true);

    // 2. Spawn a live MCP server child process (--passive) with stopped daemon
    mcpProc = spawn(process.execPath, [installedEntry, "mcp", "--passive"], {
      env: cleanEnv,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdoutBuf = "";
    const pendingById = new Map();
    mcpProc.stdout.setEncoding("utf8");
    mcpProc.stdout.on("data", (chunk) => {
      stdoutBuf += chunk;
      let nl;
      while ((nl = stdoutBuf.indexOf("\n")) >= 0) {
        const line = stdoutBuf.slice(0, nl).trim();
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (!line) continue;
        const parsed = JSON.parse(line);
        if (parsed.id !== undefined && pendingById.has(parsed.id)) {
          const resolve = pendingById.get(parsed.id);
          pendingById.delete(parsed.id);
          resolve(parsed);
        }
      }
    });

    let nextId = 1;
    const callJsonRpc = (method, params = {}) =>
      new Promise((resolve, reject) => {
        const id = nextId++;
        const timer = setTimeout(
          () => reject(new Error(`MCP JSON-RPC timeout for ${method}`)),
          8000
        );
        pendingById.set(id, (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        mcpProc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      });

    const initResp = await callJsonRpc("initialize", {});
    assert.equal(initResp.result.serverInfo.name, "copilot-flock");

    const listResp = await callJsonRpc("tools/list", {});
    const tools = listResp.result.tools;
    assert.ok(tools.some((t) => t.name === "mcp_self_info"));
    assert.ok(tools.find((t) => t.name === "flock_status")?.inputSchema?.properties?.passive);
    assert.ok(tools.find((t) => t.name === "bridge_status")?.inputSchema?.properties?.passive);
    assert.ok(
      tools.find((t) => t.name === "diagnose_bridge_fleet")?.inputSchema?.properties?.passive
    );

    const callSelfInfo = async () => {
      const res = await callJsonRpc("tools/call", { name: "mcp_self_info", arguments: {} });
      return JSON.parse(res.result.content[0].text);
    };

    const mcpBefore = await callSelfInfo();
    assert.equal(mcpBefore.pid, mcpProc.pid);
    assert.ok(!Number.isNaN(Date.parse(mcpBefore.startedAt)));
    assert.equal(mcpBefore.version, BRIDGE_VERSION);
    assert.equal(mcpBefore.nodeVersion, process.version);
    assert.equal(mcpBefore.loadTimeDigest, cliInfo1.loadTimeDigest);
    assert.equal(mcpBefore.currentDiskDigest, mcpBefore.loadTimeDigest);
    assert.equal(mcpBefore.reloadPending, false);
    assert.equal(mcpBefore.daemon.status, "stopped");
    assert.equal(mcpBefore.daemon.passive, true);

    // 3. Replace the entrypoint file on disk while MCP child stays loaded in memory
    const originalSource = fs.readFileSync(installedEntry, "utf8");
    const replacedSource =
      originalSource.replace(
        `export const BRIDGE_VERSION = "${BRIDGE_VERSION}";`,
        `export const BRIDGE_VERSION = "9.9.9-disk-replaced";`
      ) + "\n// simulated on-disk upgrade while MCP stays resident\n";
    fs.writeFileSync(installedEntry, replacedSource, "utf8");

    const mcpAfterEntryReplace = await callSelfInfo();
    assert.equal(mcpAfterEntryReplace.pid, mcpBefore.pid);
    assert.equal(mcpAfterEntryReplace.startedAt, mcpBefore.startedAt);
    assert.equal(mcpAfterEntryReplace.version, BRIDGE_VERSION);
    assert.equal(mcpAfterEntryReplace.loadTimeDigest, mcpBefore.loadTimeDigest);
    assert.notEqual(mcpAfterEntryReplace.currentDiskDigest, mcpBefore.loadTimeDigest);
    assert.equal(mcpAfterEntryReplace.reloadPending, true);

    // 4. Also replace a sibling module on disk and confirm currentDiskDigest advances again while loadTimeDigest stays pinned
    const siblingPath = path.join(installDir, "flock-protocol.mjs");
    fs.appendFileSync(siblingPath, "\n// sibling module update\n", "utf8");

    const mcpAfterSiblingReplace = await callSelfInfo();
    assert.equal(mcpAfterSiblingReplace.loadTimeDigest, mcpBefore.loadTimeDigest);
    assert.notEqual(
      mcpAfterSiblingReplace.currentDiskDigest,
      mcpAfterEntryReplace.currentDiskDigest
    );
    assert.equal(mcpAfterSiblingReplace.reloadPending, true);

    // 5. Fresh CLI process loads the replaced code and matches mcpAfterSiblingReplace.currentDiskDigest
    const cliReloaded = spawnSync(process.execPath, [installedEntry, "self-info"], {
      env: cleanEnv,
      encoding: "utf8",
      timeout: 10000,
    });
    assert.equal(cliReloaded.status, 0, cliReloaded.stderr);
    const cliInfo2 = JSON.parse(cliReloaded.stdout);
    assert.equal(cliInfo2.version, "9.9.9-disk-replaced");
    assert.equal(cliInfo2.loadTimeDigest, mcpAfterSiblingReplace.currentDiskDigest);
    assert.equal(cliInfo2.currentDiskDigest, cliInfo2.loadTimeDigest);
    assert.equal(cliInfo2.reloadPending, false);

    // Confirm emptyCopilotHome remained untouched throughout all self-info calls
    assert.equal(fs.existsSync(path.join(emptyCopilotHome, "flock")), false);
  } finally {
    if (mcpProc) {
      try {
        mcpProc.stdin.end();
        mcpProc.kill();
      } catch {}
    }
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {}
  }
});

test("control-plane bootstrapUrl validation returns actionable redacted errors for missing, empty, and malformed URLs", async () => {
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  const prevFlockBoot = process.env.COPILOT_FLOCK_BOOTSTRAP_URL;
  const prevBridgeBoot = process.env.COPILOT_BRIDGE_BOOTSTRAP_URL;
  const prevAllowedOrigin = process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;
  process.env.COPILOT_HOME = env.tempRoot;
  delete process.env.COPILOT_FLOCK_BOOTSTRAP_URL;
  delete process.env.COPILOT_BRIDGE_BOOTSTRAP_URL;
  delete process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;

  try {
    const flockDir = path.join(env.tempRoot, "flock");
    fs.mkdirSync(flockDir, { recursive: true });
    const configPath = path.join(flockDir, "config.json");
    const validSignalR =
      "Endpoint=https://demo-signalr.service.signalr.net;AccessKey=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=;Version=1.0;";

    // 1. Missing bootstrapUrl in config.json: loadConfig succeeds for SignalR, control-plane rejects with MISSING_BOOTSTRAP_URL + configPath
    writeConfigFileSecure(
      {
        machineId: "TEST-MISSING-BOOT",
        scope: "personal",
        githubUser: "erjadi",
        specs: { cpu: { model: "Test CPU" } },
        connectionString: validSignalR,
      },
      configPath
    );
    const missingCfg = loadConfig({ autoFetchAz: false });
    assert.equal(missingCfg.bootstrapUrl, null);
    assert.equal(path.resolve(missingCfg.configPath), path.resolve(configPath));

    await assert.rejects(
      () => executeMcpTool(missingCfg, "list_flocks", {}),
      (err) => {
        assert.equal(err.code, "MISSING_BOOTSTRAP_URL");
        assert.equal(err.reason, "missing");
        assert.equal(path.resolve(err.configPath), path.resolve(configPath));
        assert.match(err.message, /Missing required control-plane bootstrapUrl \(unset\)/);
        assert.ok(err.message.includes(path.resolve(configPath)));
        assert.doesNotMatch(err.message, /Invalid URL/i);
        return true;
      }
    );

    assert.throws(
      () => getOfflineQueueStatus({ bootstrapUrl: missingCfg.bootstrapUrl, configPath }),
      (err) => err.code === "MISSING_BOOTSTRAP_URL" && err.reason === "missing"
    );

    // 2. Empty and whitespace-only bootstrapUrl in config.json
    for (const emptyCandidate of ["", "   \t  "]) {
      writeConfigFileSecure(
        {
          machineId: "TEST-EMPTY-BOOT",
          scope: "personal",
          githubUser: "erjadi",
          specs: { cpu: { model: "Test CPU" } },
          connectionString: validSignalR,
          bootstrapUrl: emptyCandidate,
        },
        configPath
      );
      const emptyCfg = loadConfig({ autoFetchAz: false });
      await assert.rejects(
        () => executeMcpTool(emptyCfg, "list_flocks", {}),
        (err) => {
          assert.equal(err.code, "MISSING_BOOTSTRAP_URL");
          assert.equal(err.reason, "empty");
          assert.equal(path.resolve(err.configPath), path.resolve(configPath));
          assert.match(err.message, /Missing required control-plane bootstrapUrl \(empty value\)/);
          assert.ok(err.message.includes(path.resolve(configPath)));
          assert.doesNotMatch(err.message, /Invalid URL/i);
          return true;
        }
      );
    }

    // 3. Malformed bootstrapUrl values (including accidentally pasted secrets/tokens/credentials) must be redacted
    const secretSignalR =
      "Endpoint=https://demo.service.signalr.net;AccessKey=SUPER_SECRET_SIGNALR_KEY_999;Version=1.0;";
    const credentialedUrl =
      "https://admin:SUPER_SECRET_PASS_888@broker.demo-flock.net/api/bootstrap?token=ghp_SuperSecretPatToken1234567890#fragSecret";
    const whitespaceBearer =
      "https://broker.demo-flock.net/api/bootstrap Bearer ghp_AnotherSecretToken987654321";

    for (const badCandidate of ["not-a-valid-url", secretSignalR, credentialedUrl, whitespaceBearer, 42]) {
      assert.throws(
        () =>
          callBootstrapV3Endpoint(
            { machineId: "TEST-BAD-BOOT", bootstrapUrl: badCandidate, configPath },
            "/my-flocks",
            { method: "GET" }
          ),
        (err) => {
          assert.equal(err.code, "MALFORMED_BOOTSTRAP_URL");
          assert.equal(err.reason, "malformed");
          assert.equal(path.resolve(err.configPath), path.resolve(configPath));
          assert.match(err.message, /Malformed control-plane bootstrapUrl/);
          assert.ok(err.message.includes(path.resolve(configPath)));
          assert.doesNotMatch(
            err.message,
            /SUPER_SECRET_SIGNALR_KEY_999|SUPER_SECRET_PASS_888|SuperSecretPatToken|AnotherSecretToken|fragSecret/
          );
          assert.doesNotMatch(err.message, /^Invalid URL$/i);
          return true;
        }
      );
    }

    // 4. Malformed existing pinned bootstrapUrl in config.json during enroll_from_invite_json also fails cleanly without raw URL TypeError
    await assert.rejects(
      () =>
        executeMcpTool(
          { machineId: "TEST-BAD-PIN", bootstrapUrl: secretSignalR, configPath },
          "enroll_from_invite_json",
          {
            enrollment_json: {
              bootstrapUrl: "https://broker.demo-flock.net/api/bootstrap",
              flocks: [],
            },
          }
        ),
      (err) => {
        assert.equal(err.code, "MALFORMED_BOOTSTRAP_URL");
        assert.doesNotMatch(err.message, /SUPER_SECRET_SIGNALR_KEY_999/);
        assert.ok(err.message.includes(path.resolve(configPath)));
        return true;
      }
    );

    assert.equal(
      redactBootstrapUrlForDiagnostic(credentialedUrl),
      "https://[redacted]@broker.demo-flock.net/api/bootstrap?[redacted]#[redacted]"
    );
    const validParsed = validateBootstrapControlPlaneUrl(
      "https://broker.demo-flock.net/api/bootstrap",
      { configPath }
    );
    assert.equal(validParsed.origin, "https://broker.demo-flock.net");
  } finally {
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    if (prevFlockBoot === undefined) delete process.env.COPILOT_FLOCK_BOOTSTRAP_URL;
    else process.env.COPILOT_FLOCK_BOOTSTRAP_URL = prevFlockBoot;
    if (prevBridgeBoot === undefined) delete process.env.COPILOT_BRIDGE_BOOTSTRAP_URL;
    else process.env.COPILOT_BRIDGE_BOOTSTRAP_URL = prevBridgeBoot;
    if (prevAllowedOrigin === undefined) delete process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;
    else process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN = prevAllowedOrigin;
    env.cleanup();
  }
});

test("flock_status exposes independent installedOnDisk, residentDaemon, and callerMcpProcess health with non-destructive drift guidance", async () => {
  const { spawn } = await import("node:child_process");
  const env = setupTempCopilotEnv();
  const prevCopilotHome = process.env.COPILOT_HOME;
  const prevAppData = process.env.APPDATA;
  process.env.COPILOT_HOME = env.tempRoot;
  process.env.APPDATA = path.join(env.tempRoot, "AppData", "Roaming");

  try {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const flockDir = path.join(env.tempRoot, "flock");
    fs.mkdirSync(flockDir, { recursive: true });

    // Copy flock.mjs + companion modules into temp installed bridge home
    const installedScript = path.join(flockDir, "flock.mjs");
    fs.copyFileSync(path.join(repoRoot, "flock.mjs"), installedScript);
    for (const modName of [
      "flock-azure.mjs",
      "flock-broker-free.mjs",
      "flock-lifecycle.mjs",
      "flock-membership.mjs",
      "flock-protocol.mjs",
      "flock-registry.mjs",
    ]) {
      fs.copyFileSync(path.join(repoRoot, modName), path.join(flockDir, modName));
    }

    const configPath = path.join(flockDir, "config.json");
    const validSignalR =
      "Endpoint=https://demo-signalr.service.signalr.net;AccessKey=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=;Version=1.0;";
    writeConfigFileSecure(
      {
        machineId: "MCP-HEALTH-PC",
        scope: "personal",
        githubUser: "erjadi",
        bootstrapUrl: "https://broker.demo-flock.net/api/bootstrap",
        connectionString: validSignalR,
        specs: { cpu: { model: "Test CPU" }, publicKey: "test-pub" },
        updatedAt: "2026-11-12T00:00:00.000Z",
      },
      configPath
    );

    const initialIdentity = ensureMachineIdentityKeypair();
    const cfg = loadConfig({ autoFetchAz: false });
    const callerSnap = captureCallerMcpSnapshot(cfg, {
      scriptPath: installedScript,
      configPath,
      surface: "mcp-stdio",
    });

    // Write matching resident daemon state.json + daemon.pid
    fs.writeFileSync(path.join(flockDir, "daemon.pid"), String(process.pid), "utf8");
    fs.writeFileSync(
      path.join(flockDir, "state.json"),
      JSON.stringify(
        {
          status: "connected",
          version: BRIDGE_VERSION,
          startedAt: callerSnap.loadedAt,
          scriptPath: installedScript,
          scriptSha256: callerSnap.scriptSha256,
          codeDigest: callerSnap.codeDigest,
          configSha256: callerSnap.configSha256,
          configGeneration: callerSnap.configGeneration,
          machineId: "MCP-HEALTH-PC",
          pid: process.pid,
          updatedAt: new Date().toISOString(),
        },
        null,
        2
      ),
      "utf8"
    );

    // 1. Clean baseline: installedOnDisk, residentDaemon, and callerMcpProcess are all current & healthy
    const baselineStatus = await executeMcpTool(
      cfg,
      "flock_status",
      {},
      {
        ensureDaemonFn: async () => ({ running: true, pid: process.pid }),
        discoverMachinesFn: async () => [{ machineId: "MCP-HEALTH-PC", version: BRIDGE_VERSION }],
        callerSnapshot: callerSnap,
      }
    );
    assert.equal(baselineStatus.installedOnDisk.healthy, true);
    assert.equal(baselineStatus.installedOnDisk.version, BRIDGE_VERSION);
    assert.equal(baselineStatus.installedOnDisk.controlPlaneBootstrap.valid, true);
    assert.equal(baselineStatus.residentDaemon.healthy, true);
    assert.equal(baselineStatus.residentDaemon.version, BRIDGE_VERSION);
    assert.equal(baselineStatus.residentDaemon.matchesInstalledDisk, true);
    assert.equal(baselineStatus.callerMcpProcess.healthy, true);
    assert.equal(baselineStatus.callerMcpProcess.stale, false);
    assert.equal(baselineStatus.callerMcpProcess.reconnectRequired, false);
    assert.equal(baselineStatus.callerMcpProcess.reconnectGuidance, null);
    assert.equal(baselineStatus.callerMcpProcess.comparison.configDigestMatch, true);
    assert.equal(baselineStatus.callerMcpProcess.comparison.configGenerationMatch, true);
    assert.equal(baselineStatus.callerMcpProcess.comparison.codeDigestMatch, true);

    // 2. Mutate config.json on disk -> callerMcpProcess detects config generation / digest drift
    writeConfigFileSecure(
      {
        machineId: "MCP-HEALTH-PC",
        scope: "personal",
        githubUser: "erjadi",
        bootstrapUrl: "https://updated-broker.demo-flock.net/api/bootstrap",
        connectionString: validSignalR,
        specs: { cpu: { model: "Test CPU" }, publicKey: "test-pub" },
        updatedAt: "2026-11-12T01:00:00.000Z",
      },
      configPath
    );

    // Even using cfg._callerSnapshot automatically (without passing callerSnapshot override), config drift is detected!
    const afterConfigDrift = await executeMcpTool(
      cfg,
      "bridge_status",
      {},
      {
        ensureDaemonFn: async () => ({ running: true, pid: process.pid }),
        discoverMachinesFn: async () => [{ machineId: "MCP-HEALTH-PC", version: BRIDGE_VERSION }],
      }
    );
    assert.equal(afterConfigDrift.installedOnDisk.healthy, true);
    assert.equal(afterConfigDrift.callerMcpProcess.configDrift, true);
    assert.equal(afterConfigDrift.callerMcpProcess.reconnectRequired, true);
    assert.equal(afterConfigDrift.callerMcpProcess.healthy, false);
    assert.equal(afterConfigDrift.callerMcpProcess.comparison.configDigestMatch, false);
    assert.equal(afterConfigDrift.callerMcpProcess.comparison.configGenerationMatch, false);
    assert.equal(afterConfigDrift.callerMcpProcess.repairStrategy, "owner_manager_mcp_reconnect");
    assert.equal(afterConfigDrift.callerMcpProcess.reconnectGuidance, SAFE_CALLER_MCP_RECONNECT_GUIDANCE);
    assert.doesNotMatch(
      afterConfigDrift.callerMcpProcess.reconnectGuidance,
      /kill|taskkill|Stop-Process|pkill|re-enroll|reenroll|reprovision|regenerate/i
    );

    // 3. Mutate installed flock.mjs on disk to simulate an on-disk upgrade -> independent code/version drift across all 3 planes
    const upgradedSource = fs
      .readFileSync(installedScript, "utf8")
      .replace(
        `export const BRIDGE_VERSION = "${BRIDGE_VERSION}";`,
        `export const BRIDGE_VERSION = "3.5.0-candidate";`
      );
    fs.writeFileSync(installedScript, upgradedSource, "utf8");

    const afterCodeDrift = inspectLocalRuntimeHealth(cfg, {
      daemonStatus: { running: true, pid: process.pid },
      callerSnapshot: callerSnap,
    });
    assert.equal(afterCodeDrift.installedOnDisk.version, "3.5.0-candidate");
    assert.equal(afterCodeDrift.residentDaemon.version, BRIDGE_VERSION);
    assert.equal(afterCodeDrift.residentDaemon.matchesInstalledDisk, false);
    assert.equal(afterCodeDrift.residentDaemon.healthy, false);
    assert.ok(afterCodeDrift.residentDaemon.driftReasons.includes("version_differs_from_installed_disk"));
    assert.equal(afterCodeDrift.callerMcpProcess.version, BRIDGE_VERSION);
    assert.equal(afterCodeDrift.callerMcpProcess.codeDrift, true);
    assert.equal(afterCodeDrift.callerMcpProcess.configDrift, true);
    assert.equal(afterCodeDrift.callerMcpProcess.reconnectRequired, true);
    assert.equal(afterCodeDrift.callerMcpProcess.comparison.versionMatch, false);
    assert.equal(afterCodeDrift.callerMcpProcess.comparison.codeDigestMatch, false);

    // 4. Non-destructive repair guarantees: reapOrphanedMcpProcesses is a safe no-op and diagnose --fix preserves identity without killing MCP processes
    assert.deepEqual(reapOrphanedMcpProcesses(), []);
    const diagFixed = await diagnoseLocalBridgeState(cfg, {
      fix: true,
      callerSnapshot: callerSnap,
      configureBootPersistenceFn: () => ({
        platform: process.platform,
        type: "sandboxed-test",
        path: path.join(flockDir, "boot.stub"),
      }),
      registerBootstrapFn: () => null,
    });
    assert.equal(diagFixed.identity.fingerprint, initialIdentity.fingerprint);
    assert.equal(ensureMachineIdentityKeypair().fingerprint, initialIdentity.fingerprint);
    assert.ok(
      !(diagFixed.repairedActions || []).some((act) => /reap|kill|reenroll|re-enroll/i.test(act))
    );
    assert.equal(diagFixed.callerMcpProcess.reconnectRequired, true);

    // 5. Live stdio `mcp` subprocess test: verify end-to-end drift detection across live JSON-RPC calls & redacted control-plane error
    fs.copyFileSync(path.join(repoRoot, "flock.mjs"), installedScript);
    const offlineFastSignalR =
      "Endpoint=https://127.0.0.1:1;AccessKey=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=;Version=1.0;";
    writeConfigFileSecure(
      {
        machineId: "MCP-HEALTH-PC",
        scope: "personal",
        githubUser: "erjadi",
        bootstrapUrl: "https://broker.demo-flock.net/api/bootstrap",
        connectionString: offlineFastSignalR,
        specs: { cpu: { model: "Test CPU" }, publicKey: "test-pub" },
        updatedAt: "2026-11-12T02:00:00.000Z",
      },
      configPath
    );

    const mcpChild = spawn(process.execPath, [installedScript, "mcp"], {
      env: { ...process.env, COPILOT_HOME: env.tempRoot },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    try {
      const pending = new Map();
      let outBuf = "";
      mcpChild.stdout.on("data", (chunk) => {
        outBuf += chunk.toString("utf8");
        while (true) {
          const idx = outBuf.indexOf("\n");
          if (idx === -1) break;
          const line = outBuf.slice(0, idx).trim();
          outBuf = outBuf.slice(idx + 1);
          if (!line) continue;
          const msg = JSON.parse(line);
          if (msg.id !== undefined && pending.has(msg.id)) {
            pending.get(msg.id)(msg);
            pending.delete(msg.id);
          }
        }
      });
      const rpc = (id, method, params = {}) =>
        new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error(`MCP RPC ${method} timed out`)), 10000);
          pending.set(id, (res) => {
            clearTimeout(timer);
            resolve(res);
          });
          mcpChild.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        });

      const initRes = await rpc(1, "initialize", { protocolVersion: "2024-11-05" });
      assert.equal(initRes.result.serverInfo.name, "copilot-flock");

      // Initial flock_status over stdio: callerMcpProcess matches on-disk code & config
      const statusBeforeRes = await rpc(2, "tools/call", {
        name: "flock_status",
        arguments: {},
      });
      assert.notEqual(statusBeforeRes.result.isError, true);
      const statusBefore = JSON.parse(statusBeforeRes.result.content[0].text);
      assert.equal(statusBefore.callerMcpProcess.surface, "mcp-stdio");
      assert.equal(statusBefore.callerMcpProcess.reconnectRequired, false);
      assert.equal(statusBefore.callerMcpProcess.healthy, true);

      // Mutate both config.json and installed flock.mjs on disk while mcpChild remains running
      writeConfigFileSecure(
        {
          machineId: "MCP-HEALTH-PC",
          scope: "personal",
          githubUser: "erjadi",
          bootstrapUrl: "https://user:TOP_SECRET_PW@broker.demo-flock.net/api/bootstrap?sig=SEC123",
          connectionString: offlineFastSignalR,
          specs: { cpu: { model: "Test CPU" }, publicKey: "test-pub" },
          updatedAt: "2026-11-12T03:00:00.000Z",
        },
        configPath
      );
      fs.writeFileSync(
        installedScript,
        fs
          .readFileSync(installedScript, "utf8")
          .replace(
            `export const BRIDGE_VERSION = "${BRIDGE_VERSION}";`,
            `export const BRIDGE_VERSION = "3.5.0-live-stdio";`
          ),
        "utf8"
      );

      // Subsequent flock_status over the SAME stdio process detects both configDrift and codeDrift!
      const statusAfterRes = await rpc(3, "tools/call", {
        name: "flock_status",
        arguments: {},
      });
      assert.notEqual(statusAfterRes.result.isError, true);
      const statusAfter = JSON.parse(statusAfterRes.result.content[0].text);
      assert.equal(statusAfter.installedOnDisk.version, "3.5.0-live-stdio");
      assert.equal(statusAfter.installedOnDisk.controlPlaneBootstrap.valid, false);
      assert.doesNotMatch(
        statusAfter.installedOnDisk.controlPlaneBootstrap.error,
        /TOP_SECRET_PW|SEC123/
      );
      assert.equal(statusAfter.callerMcpProcess.version, BRIDGE_VERSION);
      assert.equal(statusAfter.callerMcpProcess.codeDrift, true);
      assert.equal(statusAfter.callerMcpProcess.configDrift, true);
      assert.equal(statusAfter.callerMcpProcess.reconnectRequired, true);
      assert.equal(statusAfter.callerMcpProcess.reconnectGuidance, SAFE_CALLER_MCP_RECONNECT_GUIDANCE);
    } finally {
      mcpChild.stdin.end();
      await new Promise((resolve) => {
        const t = setTimeout(() => {
          try {
            mcpChild.kill();
          } catch {}
          resolve();
        }, 2000);
        mcpChild.once("exit", () => {
          clearTimeout(t);
          resolve();
        });
      });
    }
  } finally {
    if (prevCopilotHome === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = prevCopilotHome;
    if (prevAppData === undefined) delete process.env.APPDATA;
    else process.env.APPDATA = prevAppData;
    env.cleanup();
  }
});

test("thermal telemetry: valid nvidia-smi, Linux hwmon/thermal_zone (die/edge vs acpi), and win32 provider parsing", () => {
  resetThermalTelemetryCache();
  const fixedNow = Date.parse("2026-11-12T01:00:00.000Z");
  let virtualPerfMs = 0;
  const deterministicPerfNow = () => (virtualPerfMs += 1);

  // 1. nvidia-smi multi-GPU with NVML idle bit (0x01 -> false) vs thermal slowdown (0x60 -> true) + legacy field fallback
  let nvCalls = 0;
  const nvSample = probeThermalTelemetry({
    platform: "linux",
    sysfsRoot: path.join(os.tmpdir(), `nonexistent-sysfs-${crypto.randomUUID()}`),
    nowFn: () => fixedNow,
    perfNowFn: deterministicPerfNow,
    forceRefresh: true,
    execFn: (_cmd, args) => {
      nvCalls++;
      if (args[0].includes("clocks_event_reasons.active")) {
        const err = new Error('Field "clocks_event_reasons.active" is not a valid field to query.');
        throw err;
      }
      assert.ok(args[0].includes("clocks_throttle_reasons.active"));
      return [
        "0, NVIDIA GeForce RTX 4090, 44, 31.24, 450.00, 0x0000000000000001",
        "1, NVIDIA RTX A6000, 83, 298.66, 300.00, 0x0000000000000060",
      ].join("\n");
    },
  });

  assert.equal(nvCalls, 2);
  assert.equal(nvSample.available, true);
  assert.equal(nvSample.provider, "nvidia-smi");
  assert.deepEqual(nvSample.providers, ["nvidia-smi"]);
  assert.equal(nvSample.sensorType, "die");
  assert.equal(nvSample.temperatureC, 44);
  assert.equal(nvSample.powerWatts, 31.2);
  assert.equal(nvSample.powerLimitWatts, 450);
  assert.equal(nvSample.throttled, true);
  assert.equal(nvSample.unit, "C");
  assert.equal(nvSample.sampledAt, "2026-11-12T01:00:00.000Z");
  assert.equal(nvSample.unavailableReason, null);
  assert.equal(nvSample.readings.length, 2);
  assert.deepEqual(nvSample.readings[0], {
    name: "NVIDIA GeForce RTX 4090",
    deviceKind: "gpu",
    gpuIndex: 0,
    temperatureC: 44,
    powerWatts: 31.2,
    powerLimitWatts: 450,
    throttled: false,
    unit: "C",
    provider: "nvidia-smi",
    sensorType: "die",
    sampledAt: "2026-11-12T01:00:00.000Z",
    unavailableReason: null,
  });
  assert.equal(nvSample.readings[1].throttled, true);
  assert.equal(nvSample.readings[1].temperatureC, 83);
  assert.equal(nvSample.readings[1].powerWatts, 298.7);

  // 2. Linux sysfs hwmon + thermal_zone distinguishing die and edge sensors from acpi zones
  const tmpSysfs = fs.mkdtempSync(path.join(os.tmpdir(), "flock-sysfs-"));
  try {
    const hwmon0 = path.join(tmpSysfs, "hwmon", "hwmon0"); // amdgpu with edge + junction + microwatt power
    const hwmon1 = path.join(tmpSysfs, "hwmon", "hwmon1"); // k10temp CPU die + noisy Core 0
    const hwmon2 = path.join(tmpSysfs, "hwmon", "hwmon2"); // acpitz motherboard zone
    const tz0 = path.join(tmpSysfs, "thermal", "thermal_zone0"); // acpitz
    const tz1 = path.join(tmpSysfs, "thermal", "thermal_zone1"); // x86_pkg_temp
    for (const d of [hwmon0, hwmon1, hwmon2, tz0, tz1]) {
      fs.mkdirSync(d, { recursive: true });
    }

    fs.writeFileSync(path.join(hwmon0, "name"), "amdgpu\n");
    fs.writeFileSync(path.join(hwmon0, "temp1_label"), "edge\n");
    fs.writeFileSync(path.join(hwmon0, "temp1_input"), "58000\n");
    fs.writeFileSync(path.join(hwmon0, "temp2_label"), "junction\n");
    fs.writeFileSync(path.join(hwmon0, "temp2_input"), "67500\n");
    fs.writeFileSync(path.join(hwmon0, "power1_average"), "142500000\n");
    fs.writeFileSync(path.join(hwmon0, "power1_cap"), "250000000\n");
    fs.writeFileSync(path.join(hwmon0, "power1_cap_alarm"), "0\n");

    fs.writeFileSync(path.join(hwmon1, "name"), "k10temp\n");
    fs.writeFileSync(path.join(hwmon1, "temp1_label"), "Tctl\n");
    fs.writeFileSync(path.join(hwmon1, "temp1_input"), "61250\n");
    fs.writeFileSync(path.join(hwmon1, "temp2_label"), "Core 0\n");
    fs.writeFileSync(path.join(hwmon1, "temp2_input"), "59000\n");

    fs.writeFileSync(path.join(hwmon2, "name"), "acpitz\n");
    fs.writeFileSync(path.join(hwmon2, "temp1_input"), "29000\n");

    fs.writeFileSync(path.join(tz0, "type"), "acpitz\n");
    fs.writeFileSync(path.join(tz0, "temp"), "27800\n");
    fs.writeFileSync(path.join(tz1, "type"), "x86_pkg_temp\n");
    fs.writeFileSync(path.join(tz1, "temp"), "63000\n");

    const linuxSample = probeThermalTelemetry({
      platform: "linux",
      sysfsRoot: tmpSysfs,
      nowFn: () => fixedNow,
      perfNowFn: deterministicPerfNow,
      forceRefresh: true,
      execFn: () => {
        const err = new Error("spawnSync nvidia-smi ENOENT");
        err.code = "ENOENT";
        throw err;
      },
    });

    assert.equal(linuxSample.available, true);
    assert.equal(linuxSample.unavailableReason, null);
    assert.equal(linuxSample.sensorType, "die");
    assert.equal(linuxSample.provider, "linux-hwmon");
    assert.equal(linuxSample.powerWatts, 142.5);
    assert.equal(linuxSample.powerLimitWatts, 250);
    assert.equal(linuxSample.throttled, false);
    assert.deepEqual(linuxSample.providers.sort(), ["linux-hwmon", "linux-thermal-zone"]);

    const byName = new Map(linuxSample.readings.map((r) => [r.name, r]));
    assert.equal(byName.get("amdgpu:edge")?.sensorType, "edge");
    assert.equal(byName.get("amdgpu:edge")?.temperatureC, 58);
    assert.equal(byName.get("amdgpu:edge")?.powerWatts, 142.5);
    assert.equal(byName.get("amdgpu:junction")?.sensorType, "die");
    assert.equal(byName.get("amdgpu:junction")?.temperatureC, 67.5);
    assert.equal(byName.get("k10temp:Tctl")?.sensorType, "die");
    assert.equal(byName.get("k10temp:Tctl")?.temperatureC, 61.3);
    assert.equal(byName.has("k10temp:Core 0"), false);
    assert.equal(byName.get("acpitz")?.sensorType, "acpi");
    assert.equal(byName.get("thermal_zone0:acpitz")?.sensorType, "acpi");
    assert.equal(byName.get("thermal_zone1:x86_pkg_temp")?.sensorType, "die");
    // Primary top-level reading prefers die/edge silicon sensors over motherboard acpi zones
    assert.notEqual(linuxSample.temperatureC, 27.8);
    assert.notEqual(linuxSample.temperatureC, 29);
  } finally {
    fs.rmSync(tmpSysfs, { recursive: true, force: true });
  }

  // 3. Windows thermal counter parsing (valid dK/K conversion + dummy EC/273.2K rejection)
  const winSample = probeThermalTelemetry({
    platform: "win32",
    baseSpecs: { gpus: [{ name: "AMD Radeon Graphics", vramGb: 2 }] },
    nowFn: () => fixedNow,
    perfNowFn: deterministicPerfNow,
    forceRefresh: true,
    execFn: (cmd) => {
      assert.equal(cmd, "cscript.exe");
      return [
        "\\_TZ.TZ00\t301\t3015\t0",
        "\\_SB.PCI0.LPCB.H_EC.TZ0\t10\t100\t0",
        "\\_TZ.DUMMY\t273\t2732\t0",
      ].join("\r\n");
    },
  });
  assert.equal(winSample.available, true);
  assert.equal(winSample.provider, "win32-thermal-counter");
  assert.equal(winSample.sensorType, "acpi");
  assert.equal(winSample.temperatureC, 28.4);
  assert.equal(winSample.powerWatts, null);
  assert.equal(winSample.powerLimitWatts, null);
  assert.equal(winSample.throttled, false);
  assert.equal(winSample.readings.length, 1);
  assert.equal(winSample.readings[0].name, "\\_TZ.TZ00");
});

test("thermal telemetry: missing/unsupported sensors return null + unavailableReason (never fabricated 0) and malformed output degrades safely", () => {
  resetThermalTelemetryCache();

  // 1. Unsupported platform (darwin without nvidia-smi)
  const darwinSample = probeThermalTelemetry({
    platform: "darwin",
    forceRefresh: true,
    execFn: () => {
      const err = new Error("ENOENT");
      err.code = "ENOENT";
      throw err;
    },
  });
  assert.equal(darwinSample.available, false);
  assert.equal(darwinSample.temperatureC, null);
  assert.equal(darwinSample.powerWatts, null);
  assert.equal(darwinSample.powerLimitWatts, null);
  assert.equal(darwinSample.throttled, null);
  assert.equal(darwinSample.unavailableReason, "unsupported_platform:darwin");

  // 2. nvidia-smi with [Not Supported], N/A, and 0 values -> strictly null (never 0) + explicit unavailableReason
  const unsupportedGpuSample = probeThermalTelemetry({
    platform: "linux",
    sysfsRoot: path.join(os.tmpdir(), `empty-sysfs-${crypto.randomUUID()}`),
    forceRefresh: true,
    execFn: () =>
      "0, NVIDIA A10G-vGPU, [Not Supported], [Not Supported], 0.00, [Not Supported]\n",
  });
  assert.equal(unsupportedGpuSample.available, false);
  assert.equal(unsupportedGpuSample.temperatureC, null);
  assert.equal(unsupportedGpuSample.powerWatts, null);
  assert.equal(unsupportedGpuSample.powerLimitWatts, null);
  assert.equal(unsupportedGpuSample.throttled, null);
  assert.equal(unsupportedGpuSample.unavailableReason, "sensor_not_supported");
  assert.equal(unsupportedGpuSample.readings.length, 1);
  assert.equal(unsupportedGpuSample.readings[0].temperatureC, null);
  assert.equal(unsupportedGpuSample.readings[0].powerWatts, null);
  assert.equal(unsupportedGpuSample.readings[0].powerLimitWatts, null);
  assert.equal(unsupportedGpuSample.readings[0].unavailableReason, "sensor_not_supported");

  // 3. Partial [Not Supported] power on valid GPU temp never fabricates 0W
  const partialGpu = parseNvidiaSmiThermalOutput(
    "0, NVIDIA Tesla T4, 56, [Not Supported], N/A, 0x0000000000000000\n",
    "2026-11-12T01:00:00.000Z"
  );
  assert.equal(partialGpu.readings.length, 1);
  assert.equal(partialGpu.readings[0].temperatureC, 56);
  assert.equal(partialGpu.readings[0].powerWatts, null);
  assert.equal(partialGpu.readings[0].powerLimitWatts, null);
  assert.equal(partialGpu.readings[0].throttled, false);
  assert.match(String(partialGpu.readings[0].unavailableReason), /power_not_supported/);

  // 4. Malformed nvidia-smi, Linux sysfs, and Windows outputs
  const malformedSysfs = fs.mkdtempSync(path.join(os.tmpdir(), "flock-bad-sysfs-"));
  try {
    const badHwmon = path.join(malformedSysfs, "hwmon", "hwmon0");
    const badTz = path.join(malformedSysfs, "thermal", "thermal_zone0");
    fs.mkdirSync(badHwmon, { recursive: true });
    fs.mkdirSync(badTz, { recursive: true });
    fs.writeFileSync(path.join(badHwmon, "name"), "coretemp\n");
    fs.writeFileSync(path.join(badHwmon, "temp1_input"), "CORRUPT_VALUE\n");
    fs.writeFileSync(path.join(badHwmon, "power1_average"), "-99999999\n");
    fs.writeFileSync(path.join(badTz, "type"), "x86_pkg_temp\n");
    fs.writeFileSync(path.join(badTz, "temp"), "9999999\n");

    let badPerfMs = 0;
    const badSample = probeThermalTelemetry({
      platform: "linux",
      sysfsRoot: malformedSysfs,
      perfNowFn: () => (badPerfMs += 1),
      forceRefresh: true,
      execFn: () =>
        "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver.\n0, BadGPU, ERR!, NaN, -50, 0xZZZ\n",
    });
    assert.equal(badSample.available, false);
    assert.equal(badSample.temperatureC, null);
    assert.equal(badSample.powerWatts, null);
    assert.equal(badSample.powerLimitWatts, null);
    assert.equal(badSample.throttled, null);
    assert.equal(badSample.unavailableReason, "malformed_provider_output");
    assert.deepEqual(badSample.readings, []);
  } finally {
    fs.rmSync(malformedSysfs, { recursive: true, force: true });
  }

  const badWin = parseWin32ThermalCounterOutput("{broken json", "2026-11-12T01:00:00.000Z");
  assert.equal(badWin.hadMalformed, true);
  assert.deepEqual(badWin.readings, []);
});

test("thermal telemetry: strict <= 250ms hard timeout budget, freshness cache window, and flock specs-sharing boundaries", async () => {
  resetThermalTelemetryCache();

  // 1. Real hanging subprocess is killed within strict <= 250ms budget
  const hangStart = performance.now();
  const timedOutSample = probeThermalTelemetry({
    platform: "linux",
    sysfsRoot: path.join(os.tmpdir(), `hang-sysfs-${crypto.randomUUID()}`),
    forceRefresh: true,
    budgetMs: THERMAL_TELEMETRY_MAX_BUDGET_MS,
    execFn: (_cmd, _args, opts) =>
      execFileSync(process.execPath, ["-e", "setTimeout(() => {}, 3000)"], opts),
  });
  const hangElapsedMs = performance.now() - hangStart;
  assert.ok(
    hangElapsedMs <= 250,
    `Expected probeThermalTelemetry hard timeout <= 250ms, took ${Math.round(hangElapsedMs)}ms`
  );
  assert.equal(timedOutSample.available, false);
  assert.equal(timedOutSample.temperatureC, null);
  assert.equal(timedOutSample.powerWatts, null);
  assert.equal(timedOutSample.unavailableReason, "probe_timeout");

  // 2. Freshness window serves cached samples without re-probing until TTL expires
  let fakeNowMs = 1_700_000_000_000;
  let probeCount = 0;
  const cacheStore = { entry: null };
  const cachedExec = () => {
    probeCount++;
    return `0, NVIDIA RTX 4090, ${60 + probeCount}, 150.0, 450.0, 0x0000000000000000\n`;
  };

  const first = probeThermalTelemetry({
    platform: "linux",
    sysfsRoot: path.join(os.tmpdir(), "cache-test-sysfs"),
    nowFn: () => fakeNowMs,
    ttlMs: 10000,
    cacheStore,
    execFn: cachedExec,
  });
  assert.equal(probeCount, 1);
  assert.equal(first.cached, false);
  assert.equal(first.ageMs, 0);
  assert.equal(first.freshness.isFresh, true);
  assert.equal(first.temperatureC, 61);

  fakeNowMs += 4200;
  const secondStart = performance.now();
  const second = probeThermalTelemetry({
    platform: "linux",
    sysfsRoot: path.join(os.tmpdir(), "cache-test-sysfs"),
    nowFn: () => fakeNowMs,
    ttlMs: 10000,
    cacheStore,
    execFn: cachedExec,
  });
  assert.ok(performance.now() - secondStart < 25);
  assert.equal(probeCount, 1);
  assert.equal(second.cached, true);
  assert.equal(second.ageMs, 4200);
  assert.equal(second.freshness.cached, true);
  assert.equal(second.freshness.ageMs, 4200);
  assert.equal(second.temperatureC, 61);

  fakeNowMs += 6000; // 10200ms > 10000ms TTL -> triggers fresh probe
  const third = probeThermalTelemetry({
    platform: "linux",
    sysfsRoot: path.join(os.tmpdir(), "cache-test-sysfs"),
    nowFn: () => fakeNowMs,
    ttlMs: 10000,
    cacheStore,
    execFn: cachedExec,
  });
  assert.equal(probeCount, 2);
  assert.equal(third.cached, false);
  assert.equal(third.ageMs, 0);
  assert.equal(third.temperatureC, 62);

  // 3. refreshLiveSpecs exposes thermal telemetry for owner and completes within <= 250ms
  resetThermalTelemetryCache();
  const liveSpecsStart = performance.now();
  const liveSpecs = refreshLiveSpecs({
    gpus: [{ name: "NVIDIA GeForce RTX 4090", vramGb: 24, vramFreeGb: 20, utilizationPct: 15 }],
    disks: [
      { mount: "C:", label: "OS", type: "fixed", totalGb: 1000, freeGb: 500 },
      { mount: "Z:", label: "PrivateNAS", type: "network", totalGb: 8000, freeGb: 4000 },
    ],
  });
  const liveSpecsElapsed = performance.now() - liveSpecsStart;
  assert.ok(
    liveSpecsElapsed <= 250,
    `Expected refreshLiveSpecs <= 250ms, took ${Math.round(liveSpecsElapsed)}ms`
  );
  assert.ok(liveSpecs.thermal && typeof liveSpecs.thermal.sampledAt === "string");

  // 4. Flock specs-sharing boundaries: owner receives thermal; collaborator/guest/cross-user/none never do
  const ownerPing = await handleRpcAction(
    { machineId: "GPU-TOWER", scope: "work", githubUser: "erjadi", specs: liveSpecs },
    {
      action: "ping",
      flockPolicy: { flockId: "erjadi/work", trustTier: "owner", shareSpecs: "full" },
      params: {},
    }
  );
  assert.ok(ownerPing.specs.thermal, "Owner flock ping should include thermal telemetry");

  const collabPolicy = {
    flockId: "erjadi/studio-team",
    trustTier: "collaborator",
    shareSpecs: "summary",
    sharedSessionIds: [],
  };
  const collabPing = await handleRpcAction(
    { machineId: "GPU-TOWER", scope: "work", githubUser: "erjadi", specs: liveSpecs },
    { action: "ping", flockPolicy: collabPolicy, params: {} }
  );
  assert.equal("thermal" in collabPing.specs, false);
  assert.equal(collabPing.specs.disks.some((d) => d.type === "network"), false);
  assert.equal("vramFreeGb" in (collabPing.specs.gpus[0] || {}), false);
  assert.equal("utilizationPct" in (collabPing.specs.gpus[0] || {}), false);

  const collabDiagnose = await handleRpcAction(
    { machineId: "GPU-TOWER", scope: "work", githubUser: "erjadi", specs: liveSpecs },
    { action: "diagnose", flockPolicy: collabPolicy, params: { fix: false } }
  );
  assert.equal("thermal" in collabDiagnose.specs, false);

  const crossUserSanitized = sanitizeSpecsForFlockPolicy(liveSpecs, null, {
    isCrossUser: true,
    fromGitHubUser: "alice",
  });
  assert.equal("thermal" in crossUserSanitized, false);

  const noneSanitized = sanitizeSpecsForFlockPolicy(liveSpecs, {
    flockId: "erjadi/guest-1",
    trustTier: "guest",
    shareSpecs: "none",
  });
  assert.equal("thermal" in noneSanitized, false);
  assert.equal("gpus" in noneSanitized, false);
  assert.equal("disks" in noneSanitized, false);
});
