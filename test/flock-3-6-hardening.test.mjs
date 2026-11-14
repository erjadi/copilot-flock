import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  commandIsDaemon,
  computeRuntimeManifest,
  parseWindowsCommandLine,
  readRuntimeState,
  recordRuntimeUpdatePhase,
  REQUIRED_RUNTIME_MODULES,
  stageAndActivateRuntime,
} from "../flock-lifecycle.mjs";
import { compactOperation } from "../flock-operations.mjs";
import { SupportMailbox, ensureSupportDeviceKey } from "../flock-support.mjs";
import {
  dispatchBrokerFreeRpc,
  FLOCK_CAPABILITIES,
  FLOCK_PROTOCOL_VERSION,
  projectPublicStatusResponse,
  performLocalSelfUpdate,
} from "../flock.mjs";

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

