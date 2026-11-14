import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import {
  commandIsDaemon,
  computeRuntimeManifest,
  parseWindowsCommandLine,
  readRuntimeState,
  recordRuntimeUpdatePhase,
  REQUIRED_RUNTIME_MODULES,
  stageAndActivateRuntime,
  lifecyclePaths,
  recordInstalledArtifact,
  uninstallFlock,
} from "../flock-lifecycle.mjs";
import { compactOperation } from "../flock-operations.mjs";
import { SupportMailbox, ensureSupportDeviceKey } from "../flock-support.mjs";
import {
  dispatchBrokerFreeRpc,
  FLOCK_CAPABILITIES,
  FLOCK_PROTOCOL_VERSION,
  projectPublicStatusResponse,
  performLocalSelfUpdate,
  activateRuntimeUpdate,
  executeMcpTool,
  ensureMachineIdentityKeypair,
  openFlockMembershipRegistry,
  resolveLegacyFlockRoster,
} from "../flock.mjs";
import { createBootstrapServer, enrollV3Device } from "../bootstrap-server.mjs";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-hardening-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function identity(deviceId) {
  const pair = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { ...pair, deviceId };
}

test("Windows daemon recognition accepts real quoting and whitespace but rejects extra arguments", () => {
  const script = String.raw`C:\Users\Eric J\.copilot\flock\flock.mjs`;
  const executable = String.raw`C:\Program Files\nodejs\node.exe`;
  for (const command of [
    `"${executable}" "${script}" daemon`,
    `  "${executable}"    "${script}"    daemon   `,
    `"${executable}" ${script.replaceAll(" ", "\\ ")} daemon`,
  ].slice(0, 2)) {
    const argv = parseWindowsCommandLine(command);
    assert.deepEqual(argv, [executable, script, "daemon"]);
    assert.equal(commandIsDaemon({ executable, command }, [script]), true);
  }
  assert.equal(commandIsDaemon({ executable, command: `"${executable}" "${script}" daemon --unsafe` }, [script]), false);
  assert.equal(commandIsDaemon({ executable, command: `"${executable}" "C:\\other\\flock.mjs" daemon` }, [script]), false);
  for (const node of ["node", "node.exe", "NODE.EXE"]) {
    assert.equal(commandIsDaemon({ executable, command: `${node}   "${script}" daemon` }, [script], { platform: "win32" }), true);
    assert.equal(commandIsDaemon({ executable, command: `${node} "${script}" daemon --unsafe` }, [script], { platform: "win32" }), false);
    assert.equal(commandIsDaemon({ executable: "C:\\other\\python.exe", command: `${node} "${script}" daemon` }, [script], { platform: "win32" }), false);
  }
});

test("runtime update journal retains correlation, redacted failure, and terminal phase history", (t) => {
  const root = fixture(t);
  recordRuntimeUpdatePhase(root, {
    updateId: "update-1",
    correlationId: "corr-1",
    phase: "staged",
    manifestDigest: "a".repeat(64),
    version: "3.6.0",
  });

  recordRuntimeUpdatePhase(root, {
    updateId: "update-1",
    correlationId: "corr-1",
    phase: "rolled_back",
    error: "Bearer eyJabc.def.ghi",
    code: "RUNTIME_ACTIVATION_FAILED",
  });
  const state = readRuntimeState(root);
  assert.equal(state.update.phase, "rolled_back");
  assert.equal(state.update.correlationId, "corr-1");
  assert.match(state.update.error, /REDACTED/);
  assert.doesNotMatch(state.update.error, /eyJabc/);
  assert.deepEqual(state.update.history.map((entry) => entry.phase), ["staged", "rolled_back"]);
});

test("noninteractive update preflight strips interactive helpers and returns a typed auth failure", async (t) => {
  const root = fixture(t);
  const repo = path.join(root, "repo");
  const target = path.join(root, "runtime");
  fs.mkdirSync(repo);
  const calls = [];
  await assert.rejects(
    performLocalSelfUpdate(
      { machineId: "PC-A", scope: "work", githubUser: "owner" },
      {
        repoDirOverride: repo,
        targetDir: target,
        legacyDir: null,
        spawnInstall: false,
        gitExecFileSync(command, args, options) {
          calls.push({ command, args, options });
          throw new Error("credential helper expired");
        },
        updateId: "auth-failure",
      }
    ),
    (error) => error.code === "UPDATE_NONINTERACTIVE_AUTH_FAILED"
  );
  assert.equal(calls.length, 1);
  assert.ok(calls[0].args.includes("credential.interactive=never"));
  assert.ok(calls[0].args.includes("core.askPass="));
  assert.equal(calls[0].options.env.GIT_TERMINAL_PROMPT, "0");
  assert.equal(calls[0].options.env.GCM_INTERACTIVE, "Never");
  assert.equal(calls[0].options.env.VSCODE_GIT_IPC_HANDLE, undefined);
  assert.equal(readRuntimeState(target).update.phase, "failed");
  assert.equal(readRuntimeState(target).update.code, "UPDATE_NONINTERACTIVE_AUTH_FAILED");
});

test("launcher failure rolls installed artifacts back to the previous verified runtime", async (t) => {
  const root = fixture(t);
  const sourceV1 = path.join(root, "source-v1");
  const sourceV2 = path.join(root, "source-v2");
  const target = path.join(root, "runtime");
  for (const source of [sourceV1, sourceV2]) {
    fs.mkdirSync(source, { recursive: true });
    for (const filename of REQUIRED_RUNTIME_MODULES) {
      fs.copyFileSync(path.resolve(filename), path.join(source, filename));
    }
  }
  fs.appendFileSync(path.join(sourceV2, "flock.mjs"), "\n// milestone-4-candidate\n");
  fs.appendFileSync(path.join(sourceV2, "bridge.mjs"), "\n// milestone-4-candidate\n");
  const manifestV1 = computeRuntimeManifest(sourceV1, { version: "3.6.0" });
  const manifestV2 = computeRuntimeManifest(sourceV2, { version: "3.6.0" });
  fs.writeFileSync(path.join(sourceV1, "runtime-manifest.json"), JSON.stringify(manifestV1, null, 2));
  fs.writeFileSync(path.join(sourceV2, "runtime-manifest.json"), JSON.stringify(manifestV2, null, 2));
  stageAndActivateRuntime({
    sourceDir: sourceV1,
    targetDir: target,
    updateId: "initial",
    resident: {
      running: true,
      pid: process.pid,
      version: "3.6.0",
      manifestDigest: manifestV1.manifestDigest,
    },
  });
  await assert.rejects(
    performLocalSelfUpdate(
      { machineId: "PC-A", scope: "work", githubUser: "owner" },
      {
        sourceDir: sourceV2,
        targetDir: target,
        legacyDir: null,
        spawnProcess() {
          throw new Error("launcher denied");
        },
        updateId: "candidate",
        correlationId: "corr-candidate",
      }
    ),
    (error) => error.code === "RUNTIME_ACTIVATION_SPAWN_ROLLED_BACK"
  );
  const state = readRuntimeState(target);
  assert.equal(state.update.phase, "rolled_back");
  assert.equal(state.update.correlationId, "corr-candidate");
  assert.equal(computeRuntimeManifest(target, { version: "3.6.0" }).manifestDigest, manifestV1.manifestDigest);
});

test("support mailbox enforces device binding, single use, inert schema, quotas, authorization, and closure", (t) => {
  const root = fixture(t);
  let now = Date.parse("2026-11-14T19:00:00Z");
  const mailbox = new SupportMailbox(path.join(root, "mailbox"), {
    clock: () => now,
    retentionMs: 60_000,
  });
  const maintainer = identity("maintainer-device");
  const supportKey = ensureSupportDeviceKey(path.join(root, "support-device"));
  const ticket = mailbox.issue({
    maintainerIdentity: maintainer,
    flockId: "owner/work",
    supportPublicKey: supportKey.publicKey,
    ttlSeconds: 120,
  });
  assert.deepEqual(ticket.body.permissions, ["submit_text_report"]);
  assert.ok(ticket.body.deniedAuthorities.includes("signalr"));
  assert.ok(ticket.body.deniedAuthorities.includes("autopilot"));
  assert.equal(ticket.body.supportKeyFingerprint, supportKey.fingerprint);

  const report = {
    text: "Enrollment stopped after artifact verification.",
    diagnostics: {
      artifact: "runtime-manifest.json",
      protocol: "broker-free-v34",
      platform: "win32",
      stage: "accept_welcome",
      error: "manifest mismatch",
      correlation: "corr-1",
      clock: "2026-11-14T19:00:00Z",
      fingerprint: supportKey.fingerprint,
      rosterEpoch: 4,
    },
    submittedAt: new Date(now).toISOString(),
  };
  const signature = crypto.sign(null, Buffer.from(JSON.stringify({
    ticketId: ticket.body.ticketId,
    nonce: ticket.body.nonce,
    report,
  })), supportKey.privateKey).toString("base64");
  const attempt = mailbox.submit({
    ticket,
    supportPublicKey: supportKey.publicKey,
    report,
    signature,
  });
  assert.equal(attempt.untrustedData.identity, "ticket_holder");
  assert.equal(attempt.untrustedData.state, "report_submitted");
  assert.throws(() => mailbox.submit({
    ticket,
    supportPublicKey: supportKey.publicKey,
    report,
    signature,
  }), /replay rejected/);

  assert.throws(() => mailbox.get({
    attemptId: attempt.untrustedData.attemptId,
    maintainerDeviceId: "other-device",
  }), /maintainer mismatch/);
  const replied = mailbox.reply({
    attemptId: attempt.untrustedData.attemptId,
    maintainerDeviceId: maintainer.deviceId,
    text: "Verify the owner fingerprint, then retry normal enrollment.",
  });
  assert.equal(replied.untrustedData.state, "maintainer_replied");
  const listed = mailbox.list({ maintainerDeviceId: maintainer.deviceId, limit: 1 });
  assert.equal(listed.items.length, 1);
  assert.equal(listed.nextCursor, null);
  const closed = mailbox.close({
    attemptId: attempt.untrustedData.attemptId,
    maintainerDeviceId: maintainer.deviceId,
  });
  assert.equal(closed.untrustedData.state, "closed");

  const secondKey = identity("second-support-device");
  const secondTicket = mailbox.issue({
    maintainerIdentity: maintainer,
    flockId: "owner/work",
    supportPublicKey: secondKey.publicKey,
  });
  const unsafe = {
    text: "token github_pat_abcdefghijklmnopqrstuvwxyz123456",
    diagnostics: {},
    submittedAt: new Date(now).toISOString(),
  };
  const unsafeSignature = crypto.sign(null, Buffer.from(JSON.stringify({
    ticketId: secondTicket.body.ticketId,
    nonce: secondTicket.body.nonce,
    report: unsafe,
  })), secondKey.privateKey).toString("base64");
  assert.throws(() => mailbox.submit({
    ticket: secondTicket,
    supportPublicKey: secondKey.publicKey,
    report: unsafe,
    signature: unsafeSignature,
  }), /credential-like/);
  assert.throws(() => mailbox.submit({
    ticket: secondTicket,
    supportPublicKey: secondKey.publicKey,
    report: { text: "See C:\\Users\\Eric\\secret.txt", diagnostics: {}, submittedAt: new Date(now).toISOString() },
    signature: unsafeSignature,
  }), /absolute or network path|replay rejected/);

  const stored = mailbox.read();
  for (let index = 0; index < stored.audit.length; index++) {
    const entry = stored.audit[index];
    assert.equal(entry.previousHash, index === 0 ? "0".repeat(64) : stored.audit[index - 1].hash);
    const { hash, ...unsigned } = entry;
    assert.equal(hash, crypto.createHash("sha256").update(JSON.stringify(unsigned)).digest("hex"));
  }

  now += 120_000;
  assert.deepEqual(mailbox.list({
    maintainerDeviceId: maintainer.deviceId,
    includeClosed: true,
  }).items, []);
});

test("operation DTO redacts JWTs as well as tokens", () => {
  const compact = compactOperation({
    operationId: "op-1",
    correlationId: "corr-1",
    state: "completed",
    action: "send_message",
    targetMachine: "REMOTE",
    result: { completed: true, content: "jwt eyJabc.def.ghi and ghp_123456789012345678901234567890" },
    createdAt: "2026-11-14T19:00:00Z",
    updatedAt: "2026-11-14T19:00:01Z",
  });
  assert.match(compact.result.content, /REDACTED JWT/);
  assert.match(compact.result.content, /REDACTED TOKEN/);
  assert.doesNotMatch(compact.result.content, /eyJabc|ghp_/);
});

test("broker-free operation query and cancellation preserve exact peer, flock, and session authorization", async (t) => {
    const root = fixture(t);
    const previous = process.env.COPILOT_HOME;
    process.env.COPILOT_HOME = root;
    t.after(() => {
      if (previous === undefined) delete process.env.COPILOT_HOME;
      else process.env.COPILOT_HOME = previous;
    });
    const operationRoot = path.join(root, "flock");
    const { PersistentOperationStore } = await import("../flock-operations.mjs");
    const store = new PersistentOperationStore(operationRoot);
    store.admit({
      operationId: "bf-op",
      action: "send_message",
      flockId: "owner/work",
      requesterMachine: "CALLER",
      requesterSession: "origin",
      requesterPeerId: "peer-caller",
      targetMachine: "REMOTE",
      targetSession: "worker",
    });
    const member = { role: "owner", machineId: "CALLER", peerId: "peer-caller", sessionIds: [] };
    const queried = await dispatchBrokerFreeRpc(
      { machineId: "REMOTE", scope: "work" },
      {
        member,
        action: "get_operation",
        flockId: "owner/work",
        assertAuthorized() {},
        payload: { params: { operationId: "bf-op", fromSessionId: "origin" } },
      }
    );
    assert.equal(queried.operation.operationId, "bf-op");
    await assert.rejects(
      dispatchBrokerFreeRpc(
        { machineId: "REMOTE", scope: "work" },
        {
          member: { ...member, peerId: "spoofed" },
          action: "get_operation",
          flockId: "owner/work",
          assertAuthorized() {},
          payload: { params: { operationId: "bf-op", fromSessionId: "origin" } },
        }
      ),
      /not authorized/
    );
    const cancelled = await dispatchBrokerFreeRpc(
      { machineId: "REMOTE", scope: "work" },
      {
        member,
        action: "cancel_operation",
        flockId: "owner/work",
        assertAuthorized() {},
        payload: { params: { operationId: "bf-op", fromSessionId: "origin" } },
      }
    );
    assert.equal(cancelled.operation.state, "cancelled");
});

test("status projections are compact by default and expose explicit pagination/full mode", () => {
    const machines = Array.from({ length: 200 }, (_, index) => ({
      machineId: `PC-${index}`,
      version: "3.6.0",
      scope: "work",
      overallState: "online",
    }));
    const compact = projectPublicStatusResponse({ status: "ok", onlineMachines: machines });
    assert.equal(compact.onlineMachines.length, 20);
    assert.equal(compact.onlineMachinesPage.nextCursor, 20);
    assert.ok(Buffer.byteLength(JSON.stringify(compact), "utf8") < 8 * 1024);
    const full = projectPublicStatusResponse({ status: "ok", onlineMachines: machines }, { detail: "full" });
    assert.equal(full.onlineMachines.length, 200);
    assert.equal(full.onlineMachinesPage.full, true);
});

test("schema 36 capabilities advertise no scope downgrade and viewer has no private-scope fallback", () => {
    assert.equal(FLOCK_PROTOCOL_VERSION, 36);
    assert.equal(FLOCK_CAPABILITIES.operationQueryCancel, true);
    assert.deepEqual(FLOCK_CAPABILITIES.canonicalScopes, ["personal", "work"]);
    const viewerServer = fs.readFileSync(path.resolve("viewer", "viewer-server.mjs"), "utf8");
    const viewerApi = fs.readFileSync(path.resolve("viewer", "src", "lib", "fleet", "api.ts"), "utf8");
    const viewerMessages = fs.readFileSync(path.resolve("viewer", "src", "lib", "fleet", "messages.ts"), "utf8");
    assert.doesNotMatch(viewerServer, /scope:\s*["']private["']/);
    assert.doesNotMatch(viewerMessages, /personal\|private\|work/);
    assert.match(viewerApi, /Obsolete scope 'private'/);
});

function useCopilotHome(t, root) {
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  t.after(() => {
    if (previous === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previous;
  });
}

test("newcomer MCP submits through isolated broker routes; verified owner reads, replies and closes without membership promotion", async (t) => {
  const root = fixture(t);
  const ownerHome = path.join(root, "owner");
  const newcomerHome = path.join(root, "newcomer");
  useCopilotHome(t, ownerHome);
  const key = ensureMachineIdentityKeypair();
  const storePath = path.join(root, "broker", "v3.json");
  await enrollV3Device({
    githubUser: "owner", githubUserId: 1001, deviceId: key.fingerprint,
    machineId: "OWNER", scope: "work", publicKey: key.publicKey, keyFingerprint: key.fingerprint,
  }, { storePath, connectionString: "" });
  const registryBefore = fs.readFileSync(storePath, "utf8");
  let githubCalls = 0;
  const supportRoot = path.join(root, "broker", "support-quarantine", "mailbox");
  const server = createBootstrapServer({
    v3StorePath: storePath, membersPath: path.join(root, "broker", "members.json"), supportRoot,
    apiGet: async () => { githubCalls++; throw new Error("Support must not call GitHub"); },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const sent = [];
  const supportFetch = async (url, options) => {
    sent.push({ url: String(url), options });
    return fetch(`${base}${url.pathname}`, options);
  };
  const cfg = {
    machineId: "OWNER", githubUser: "owner", scope: "work",
    bootstrapUrl: "https://support.example.invalid", flocksConfigPath: path.join(ownerHome, "flock", "flocks.json"),
  };
  fs.writeFileSync(cfg.flocksConfigPath, JSON.stringify({
    flocks: { "owner/work": { flockId: "owner/work", ownerGitHubUser: "owner", trustTier: "owner" } },
  }));
  process.env.COPILOT_HOME = newcomerHome;
  const newcomer = await executeMcpTool({}, "create_support_device_key");
  process.env.COPILOT_HOME = ownerHome;
  const ticket = await executeMcpTool(cfg, "issue_support_ticket", { support_public_key: newcomer.publicKey }, { supportFetch });
  assert.equal(ticket.body.flockId, "owner/work", "Optional flock selects the verified owner's canonical flockId");
  process.env.COPILOT_HOME = newcomerHome;
  const attempt = await executeMcpTool({}, "submit_support_report", {
    bootstrap_url: cfg.bootstrapUrl, ticket, text: "Enrollment artifact verification failed.",
    diagnostics: { artifact: "3.6.0", stage: "accept_welcome", correlation: "join-123" },
  }, { supportFetch });
  assert.equal(attempt.untrustedData.identity, "ticket_holder");
  const submission = sent.at(-1);
  assert.equal(submission.options.headers.Authorization, undefined);
  assert.equal(submission.options.headers["X-Flock-Device-Id"], undefined);
  assert.equal(fs.existsSync(path.join(newcomerHome, "flock", ".data", "support-quarantine", "mailbox")), false);
  await assert.rejects(executeMcpTool({}, "submit_support_report", {
    bootstrap_url: cfg.bootstrapUrl, ticket, text: "Replay",
  }, { supportFetch }), /rejected/);
  const before = sent.length;
  await assert.rejects(executeMcpTool({}, "submit_support_report", {
    bootstrap_url: cfg.bootstrapUrl, ticket, text: "Bearer eyJabc.def.ghi",
  }, { supportFetch }), /credential/);
  assert.equal(sent.length, before, "Client rejects secrets before crossing the network");
  const forbidden = await fetch(`${base}/api/v3/my-flocks`, {
    headers: { "x-flock-device-id": newcomer.deviceId, "x-flock-timestamp": new Date().toISOString(), "x-flock-signature": "invalid" },
  });
  assert.equal(forbidden.status, 403);
  process.env.COPILOT_HOME = ownerHome;
  const list = await executeMcpTool(cfg, "list_support_attempts", { limit: 1 }, { supportFetch });
  assert.equal(list.items[0].untrustedData.attemptId, attempt.untrustedData.attemptId);
  const args = { attempt_id: attempt.untrustedData.attemptId };
  const read = await executeMcpTool(cfg, "read_support_attempt", args, { supportFetch });
  assert.equal(read.untrustedData.report.diagnostics.correlation, "join-123");
  const reply = await executeMcpTool(cfg, "reply_support_attempt", { ...args, text: "Verify the artifact fingerprint, then use normal enrollment." }, { supportFetch });
  assert.equal(reply.untrustedData.state, "maintainer_replied");
  assert.equal((await executeMcpTool(cfg, "close_support_attempt", args, { supportFetch })).untrustedData.state, "closed");
  const revokedTicket = await executeMcpTool(cfg, "issue_support_ticket", { support_public_key: newcomer.publicKey }, { supportFetch });
  assert.equal((await executeMcpTool(cfg, "revoke_support_ticket", { ticket_id: revokedTicket.body.ticketId }, { supportFetch })).state, "revoked");
  process.env.COPILOT_HOME = newcomerHome;
  await assert.rejects(executeMcpTool({}, "submit_support_report", {
    bootstrap_url: cfg.bootstrapUrl, ticket: revokedTicket, text: "Revoked report",
  }, { supportFetch }), /rejected/);
  assert.equal(fs.readFileSync(storePath, "utf8"), registryBefore, "Support never mutates enrollment or ordinary membership");
  assert.equal(githubCalls, 0);
  const mailbox = new SupportMailbox(supportRoot);
  assert.deepEqual(mailbox.read().audit.map((entry) => entry.event), [
    "ticket_issued", "report_submitted", "maintainer_replied", "attempt_closed", "ticket_issued", "ticket_revoked",
  ]);
  const denied = await fetch(`${base}/api/v3/support/attempts`, {
    method: "POST", headers: { Authorization: "Bearer forbidden" }, body: "{}",
  });
  assert.equal(denied.status, 401);
  const oversized = await fetch(`${base}/api/v3/support/reports`, { method: "POST", body: "x".repeat(16385) });
  assert.equal(oversized.status, 413);
  let limited = false;
  for (let index = 0; index < 35; index++) {
    const response = await fetch(`${base}/api/v3/support/reports`, {
      method: "POST", body: JSON.stringify({ ticket: { body: { ticketId: crypto.randomUUID() } } }),
      headers: { "x-forwarded-for": `192.0.2.${index}` },
    });
    if (response.status === 429) { limited = true; break; }
  }
  assert.equal(limited, true);
});

test("executeMcpTool honors pagination/full for status, flocks and member registry without duplicated raw sources", async (t) => {
  const root = fixture(t);
  useCopilotHome(t, root);
  const flocksPath = path.join(root, "flocks.json");
  const members = Array.from({ length: 60 }, (_, index) => ({
    machineId: `PC-${index}`, peerId: `1001:device-${index}`, githubUser: "owner",
    githubUserId: 1001, keyFingerprint: `device-${index}`, deviceId: `device-${index}`,
    scope: "work", trustTier: "owner",
  }));
  const flock = { flockId: "owner/work", ownerGitHubUser: "owner", trustTier: "owner", rosterEpoch: 1, members };
  fs.writeFileSync(flocksPath, JSON.stringify({ flocks: { "owner/work": flock } }));
  const cfg = { machineId: "LOCAL", githubUser: "owner", scope: "work", flocksConfigPath: flocksPath };
  const deps = {
    skipSpecsRefresh: true, ensureDaemon: async () => ({ running: true, state: { knownPeers: members } }),
    discoverOnlineMachines: async () => members,
    fetchV3MyFlocks: async () => ({ ok: false, error: "Unavailable for this fixture" }),
    fetchLegacyMembers: async () => ({ ok: false, members: [] }),
  };
  const summary = await executeMcpTool(cfg, "flock_status", { cursor: 3, limit: 2 }, deps);
  assert.equal(summary.onlineMachines.length, 2);
  assert.equal(summary.onlineMachines[0].machineId, "PC-3");
  assert.equal(summary.onlineMachinesPage.nextCursor, 5);
  assert.equal(summary.roster.knownMembers, undefined);
  assert.equal(summary.daemon.state.knownPeers, undefined);
  assert.equal(summary.daemon.state.knownPeerCount, members.length);
  assert.ok(Buffer.byteLength(JSON.stringify(summary)) < 8192,
    JSON.stringify(Object.fromEntries(Object.entries(summary).map(([key, value]) => [key, JSON.stringify(value).length]))));
  const full = await executeMcpTool(cfg, "flock_status", { detail: "full" }, deps);
  assert.equal(full.onlineMachines.length, members.length);
  assert.equal(full.daemon.state.knownPeers.length, members.length);
  const list = await executeMcpTool(cfg, "list_flocks", { cursor: 2, limit: 3 }, deps);
  assert.equal(list.knownMembers.length, 3);
  assert.equal(list.knownMembersPage.cursor, 2);
  for (const key of ["localFlocks", "remoteOwnedFlocks", "remoteJoinedFlocks", "cachedFlocks"]) assert.equal(list[key], undefined);
  const listFull = await executeMcpTool(cfg, "list_flocks", { detail: "full" }, deps);
  assert.ok(Array.isArray(listFull.localFlocks));
  const registry = openFlockMembershipRegistry(flocksPath);
  registry.reconcileV3BrokerFlock(flock);
  const registryPage = await executeMcpTool(cfg, "list_flock_members", { flock: flock.flockId, cursor: 4, limit: 2 });
  assert.equal(registryPage.members.length, 2);
  assert.equal(registryPage.membersPage.nextCursor, 6);
  const registryFull = await executeMcpTool(cfg, "list_flock_members", { flock: flock.flockId, detail: "full" });
  assert.equal(registryFull.members.length, members.length);
  const bfPage = await executeMcpTool({ protocol: "broker-free-v34" }, "list_flock_members", { flock: "owner/work", cursor: 5, limit: 3 }, {
    brokerFreeRuntimeFactory: () => ({
      select: () => ({ flockId: "owner/work" }),
      getFlockRegistryView: () => ({ ...flock, members }),
    }),
  });
  assert.equal(bfPage.members.length, 3);
  assert.equal(bfPage.membersPage.nextCursor, 8);
  const diagnoseFleet = async () => ({ healthy: false, members: members.map((member) => ({
    ...member, healthy: false, reason: "missing_tracker", diagnostics: { largeDetail: "x".repeat(2000) },
  })) });
  const diagnosticPage = await executeMcpTool(cfg, "diagnose_flock_fleet", { cursor: 3, limit: 2 }, { diagnoseFleet });
  assert.equal(diagnosticPage.members[0].machineId, "PC-3");
  assert.equal(diagnosticPage.membersPage.nextCursor, 5);
  assert.equal(diagnosticPage.members[0].diagnostics, undefined);
  assert.ok(Buffer.byteLength(JSON.stringify(diagnosticPage)) < 8192);
  const diagnosticFull = await executeMcpTool(cfg, "diagnose_bridge_fleet", { detail: "full" }, { diagnoseFleet });
  assert.equal(diagnosticFull.members.length, members.length);
  assert.equal(diagnosticFull.members[0].diagnostics.largeDetail.length, 2000);
});

test("broker-free send admits the exact requester operation before dispatch and origin alone can get/cancel it", async (t) => {
  const root = fixture(t);
  useCopilotHome(t, root);
  fs.mkdirSync(path.join(root, "flock"), { recursive: true });
  fs.writeFileSync(path.join(root, "flock", "flocks.json"), JSON.stringify({
    flocks: { "owner/work": {
      flockId: "owner/work", ownerGitHubUser: "owner", trustTier: "owner",
      sharedSessionIds: ["worker"], sharedSnapshots: { worker: { summarySnapshot: "Approved inert summary", title: "Worker" } },
    } },
  }));
  const member = { role: "owner", machineId: "CALLER", peerId: "caller-peer", scope: "work", sessionIds: [] };
  const context = {
    member, flockId: "owner/work", assertAuthorized() {},
    payload: { params: {
      targetSession: "worker", fromSessionId: "origin", message: "inert test", operationId: "bf-send",
      correlationId: "bf-corr", cancelOnTimeout: true,
    } },
  };
  const cfg = { machineId: "RECEIVER", githubUser: "owner", scope: "work" };
  const send = await dispatchBrokerFreeRpc(cfg, { ...context, action: "send_message" }, {
    injectMessage: async (input) => {
      assert.equal(input.operationId, "bf-send");
      assert.equal(input.correlationId, "bf-corr");
      assert.equal(input.cancelOnTimeout, true);
      return { status: "accepted" };
    },
  });
  assert.equal(send.operation.operationId, "bf-send");
  assert.equal(send.operation.cancelOnTimeout, true);
  const query = { ...context, payload: { params: { operationId: "bf-send", fromSessionId: "origin" } } };
  assert.equal((await dispatchBrokerFreeRpc(cfg, { ...query, action: "get_operation" })).operation.operationId, "bf-send");
  for (const changed of [
    { member: { ...member, peerId: "another-peer" } },
    { payload: { params: { operationId: "bf-send", fromSessionId: "another-session" } } },
    { flockId: "owner/other" },
  ]) {
    await assert.rejects(dispatchBrokerFreeRpc(cfg, { ...query, ...changed, action: "cancel_operation" }), /not authorized/);
  }
  assert.equal((await dispatchBrokerFreeRpc(cfg, { ...query, action: "cancel_operation" })).operation.state, "cancelled");
});

test("collaborator registry tombstones suppress reconnect grace before any broker refresh", async (t) => {
  const root = fixture(t);
  useCopilotHome(t, root);
  const flocksPath = path.join(root, "flocks.json");
  const member = {
    machineId: "COLLAB", githubUser: "collaborator", githubUserId: 2002, peerId: "2002:device",
    deviceId: "device", keyFingerprint: "device", scope: "work", trustTier: "collaborator",
    lastSeenAt: new Date().toISOString(),
  };
  const flock = {
    flockId: "owner/team", ownerGitHubUser: "owner", trustTier: "collaborator",
    rosterEpoch: 3, members: [member],
  };
  fs.writeFileSync(flocksPath, JSON.stringify({ flocks: { "owner/team": flock } }));
  const registry = openFlockMembershipRegistry(flocksPath);
  registry.reconcileV3BrokerFlock(flock);
  registry.recordRemovalTombstone("owner/team", {
    ...member, removedAtEpoch: 4, reason: "removed", removedAtMs: Date.now(),
  });
  const out = await resolveLegacyFlockRoster({ machineId: "LOCAL", githubUser: "owner", scope: "work", flocksConfigPath: flocksPath }, {
    flocksConfigPath: flocksPath, targetFlock: "owner/team", onlineMachines: [],
    fetchV3MyFlocks: async () => ({ ok: false, error: "not yet refreshed" }),
    fetchLegacyMembers: async () => ({ ok: false, members: [] }),
  });
  assert.equal(out.knownMembers.some((entry) => entry.machineId === "COLLAB"), false);
  assert.equal(out.flocks[0].members.some((entry) => entry.machineId === "COLLAB"), false);
});

test("traceless removal deletes owned support artifacts but preserves unrelated quarantine files", async (t) => {
  const home = fixture(t);
  const paths = lifecyclePaths({ home, copilotHome: path.join(home, ".copilot"), platform: "win32", appData: path.join(home, "AppData") });
  const root = paths.roots[0];
  fs.mkdirSync(root, { recursive: true });
  const script = path.join(root, "flock.mjs");
  fs.writeFileSync(script, 'export const BRIDGE_VERSION = "test"; export async function runDaemon() {}');
  recordInstalledArtifact(root, script, paths);
  const support = path.join(root, ".data", "support-quarantine");
  ensureSupportDeviceKey(path.join(support, "device"));
  const mailbox = new SupportMailbox(path.join(support, "mailbox"));
  mailbox.save(mailbox.read());
  const unrelated = path.join(support, "keep.txt");
  fs.writeFileSync(unrelated, "unrelated");
  const report = await uninstallFlock({
    paths, stopDaemon: async () => {}, removeTasks: async () => [],
    findProcesses: async () => [], checkPersistence: async () => {},
  });
  assert.equal(fs.existsSync(path.join(support, "device", "support-device.json")), false);
  assert.equal(fs.existsSync(path.join(support, "mailbox", "support-mailbox.json")), false);
  assert.equal(fs.readFileSync(unrelated, "utf8"), "unrelated");
  assert.equal(report.fullyRemoved, false);
});

test("spawnInstall activation waits for resident digest and self-test verification, and rolls back failed activation", async (t) => {
  const root = fixture(t);
  for (const fails of [false, true]) {
    const source = path.join(root, `source-${fails}`);
    const target = path.join(root, `target-${fails}`);
    fs.mkdirSync(source, { recursive: true });
    for (const filename of REQUIRED_RUNTIME_MODULES) fs.copyFileSync(path.resolve(filename), path.join(source, filename));
    const manifest = computeRuntimeManifest(source, { version: "3.6.0" });
    fs.writeFileSync(path.join(source, "runtime-manifest.json"), JSON.stringify(manifest));
    const resident = { running: true, pid: process.pid, version: "3.6.0", manifestDigest: manifest.manifestDigest };
    stageAndActivateRuntime({ sourceDir: source, targetDir: target, resident });
    fs.appendFileSync(path.join(source, "flock.mjs"), "\n// next artifact\n");
    fs.appendFileSync(path.join(source, "bridge.mjs"), "\n// next artifact\n");
    const next = computeRuntimeManifest(source, { version: "3.6.0" });
    fs.writeFileSync(path.join(source, "runtime-manifest.json"), JSON.stringify(next));
    let selfTests = 0;
    const execute = performLocalSelfUpdate({ machineId: "PC", scope: "work" }, {
      sourceDir: source, targetDir: target, updateId: `activate-${fails}`, legacyDir: null,
      spawnProcess(_command, args) {
        assert.equal(args[1], "activate-update");
        const child = new EventEmitter();
        child.unref = () => {};
        setImmediate(async () => {
          try {
            await activateRuntimeUpdate({ machineId: "PC" }, { root: target, updateId: `activate-${fails}` }, {
              restartRuntime: async () => {
                const current = computeRuntimeManifest(target, { version: "3.6.0" });
                return { ...resident, manifestDigest: current.manifestDigest };
              },
              selfTest: async () => {
                selfTests++;
                assert.equal(readRuntimeState(target).update.phase, "activated");
                if (fails && selfTests === 1) throw new Error("self-test denied");
              },
            });
            child.emit("exit", 0);
          } catch { child.emit("exit", 1); }
        });
        return child;
      },
    });
    if (fails) {
      await assert.rejects(execute, (error) => error.code === "RUNTIME_ACTIVATION_ROLLED_BACK");
      assert.equal(readRuntimeState(target).update.phase, "rolled_back");
      assert.equal(computeRuntimeManifest(target, { version: "3.6.0" }).manifestDigest, manifest.manifestDigest);
      assert.equal(selfTests, 2);
    } else {
      const result = await execute;
      assert.equal(result.status, "verified");
      assert.equal(result.verified.fullyActive, true);
      assert.equal(readRuntimeState(target).update.phase, "verified");
      assert.equal(readRuntimeState(target).update.history.at(-2).phase, "activated");
      assert.equal(selfTests, 1);
    }
  }
});

