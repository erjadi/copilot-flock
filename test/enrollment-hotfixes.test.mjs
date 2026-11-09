import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import * as flock from "../flock.mjs";
import * as bridge from "../bridge.mjs";
import { enrollV3Device, createV3FlockInvite } from "../bootstrap-server.mjs";

const entrypoints = [["flock.mjs", flock], ["bridge.mjs", bridge]];
const owner = {
  githubUser: "demo-owner", githubUserId: 1001, deviceId: "demo-device",
  machineId: "DEMO-PC", scope: "personal",
};
const keys = crypto.generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const cfg = { githubUser: "demo-owner", machineId: "DEMO-PC", scope: "personal",
  bootstrapUrl: "https://demo-broker.invalid/api/bootstrap" };

function invite(storePath, targetAddress, changes = {}) {
  return createV3FlockInvite({
    callerGitHubUser: owner.githubUser, callerGitHubUserId: owner.githubUserId,
    targetAddress, invitedUser: owner.githubUser, invitedGitHubUserId: owner.githubUserId,
    allowedScopes: ["personal"], ...changes,
  }, { storePath });
}

function enroll(storePath, changes = {}) {
  return enrollV3Device({ ...owner, publicKey: keys.publicKey, ...changes },
    { storePath, connectionString: "" });
}

test("v3 hotfix broker self-invites preserve fresh owner authority and deduplicate voucher order", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-enroll-server-"));
  const storePath = path.join(directory, "server.json");
  try {
    const rootInvite = await invite(storePath, "demo-owner");
    const scopeInvite = await invite(storePath, "demo-owner/personal");
    const boundedInvite = await invite(storePath, "demo-owner/personal", { durationMinutes: 10 });
    const vouchers = [rootInvite, scopeInvite, boundedInvite].flatMap((value) => value.enrollmentJson.flocks);
    for (const flocks of [vouchers, [...vouchers].reverse()]) {
      const result = await enroll(storePath, { enrollmentJson: { flocks } });
      assert.equal(result.enrolledFlocks.length, 2);
      assert.deepEqual(result.enrolledFlocks.map((record) => record.flockType), ["owner_root", "owner_scope"]);
      const stored = JSON.parse(fs.readFileSync(storePath, "utf8"));
      for (const record of result.enrolledFlocks) {
        assert.equal(record.trustTier, "owner");
        assert.equal(record.membershipExpiresAtMs, null);
        assert.equal(record.ownerGitHubUserId, 1001);
        assert.equal(stored.flocks[record.flockId].members[result.peerId].trustTier, "owner");
        assert.equal(stored.flocks[record.flockId].members[result.peerId].membershipExpiresAtMs, null);
      }
    }
    const recipient = { invitedUser: "demo-user", invitedGitHubUserId: 2002 };
    const collaborator = await invite(storePath, "demo-owner/studio-team", recipient);
    const guest = await invite(storePath, "demo-owner/studio-team", { ...recipient, durationMinutes: 10 });
    const sharedVouchers = [collaborator, guest].flatMap((value) => value.enrollmentJson.flocks);
    let expiresAt;
    for (const flocks of [sharedVouchers, [...sharedVouchers].reverse()]) {
      const result = await enroll(storePath, {
        githubUser: "demo-user", githubUserId: 2002, enrollmentJson: { flocks },
      });
      assert.equal(new Set(result.enrolledFlocks.map((record) => record.flockId)).size, 3);
      const shared = result.enrolledFlocks.find((record) => record.flockId === collaborator.flockId);
      assert.equal(shared.trustTier, "guest");
      assert.ok(shared.membershipExpiresAtMs > Date.now());
      if (expiresAt) assert.equal(shared.membershipExpiresAtMs, expiresAt);
      expiresAt = shared.membershipExpiresAtMs;
      const stored = JSON.parse(fs.readFileSync(storePath, "utf8"));
      assert.equal(stored.flocks[shared.flockId].members[result.peerId].trustTier, "guest");
      if (flocks === sharedVouchers) {
        stored.flocks[shared.flockId].members[result.peerId].trustTier = "owner";
        fs.writeFileSync(storePath, JSON.stringify(stored));
      }
    }
    await assert.rejects(invite(storePath, "demo-owner/studio-team", { ...recipient, trustTier: "owner" }),
      /only collaborator or guest/);
    const stored = JSON.parse(fs.readFileSync(storePath, "utf8"));
    stored.flocks[collaborator.flockId].vouchers[sharedVouchers[0].voucherId].trustTier = "owner";
    fs.writeFileSync(storePath, JSON.stringify(stored));
    await assert.rejects(enroll(storePath, {
      githubUser: "demo-user", githubUserId: 2002, enrollmentJson: collaborator.enrollmentJson,
    }), /cannot grant owner trust/);
    stored.flocks["demo-owner"].ownerGitHubUserId = 9999;
    fs.writeFileSync(storePath, JSON.stringify(stored));
    await assert.rejects(enroll(storePath), /different GitHub principal/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

async function applyThroughClient(filename, api, surface, result, storePath, clientCfg = cfg) {
  const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
  const isMcp = surface === "mcp";
  const start = isMcp
    ? source.indexOf('  if (name === "enroll_from_invite_json") {')
    : source.indexOf("  let memberRegistration = null;", source.indexOf("export async function installBridge"));
  const end = source.indexOf(isMcp ? '  if (name === "share_thread")' : "  // 1. Copy flock.mjs", start);
  assert.ok(start > 0 && end > start);
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const run = new AsyncFunction("cfg", "args", "fs", "validatePinnedBootstrapOrigin", "getConfigPath",
    "writeConfigFileSecure", "ensureMachineIdentityKeypair", "callBootstrapV3Endpoint",
    "applyV3EnrollmentResult", "registerWithBootstrapServer", "normalizeScope", "formatErrorDetail",
    `const name="enroll_from_invite_json"; const sandboxMode=false; const parsedEnrollmentJson=null;
     const activeConfigPath=getConfigPath();
     ${source.slice(start, end)}
     ${isMcp ? "" : "return {enrolledFlockCount};"}`);
  return run(clientCfg, { enrollment_json: { bootstrapUrl: cfg.bootstrapUrl, flocks: [] } }, fs,
    api.validatePinnedBootstrapOrigin, () => path.join(path.dirname(storePath), "absent-config.json"),
    api.writeConfigFileSecure, () => ({ fingerprint: owner.deviceId, publicKey: keys.publicKey }),
    (_cfg, subPath) => { assert.equal(subPath, "/enroll"); return result; },
    (currentCfg, response) => api.applyV3EnrollmentResult(currentCfg, response, storePath),
    async () => ({ ok: true }), api.normalizeScope, api.formatErrorDetail);
}

test("v3 hotfix both clients apply duplicate owner records in either order without retaining stale privileges", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-enroll-client-"));
  try {
    const result = await enroll(path.join(directory, "server.json"));
    const lowerTrust = result.enrolledFlocks.map((record) => ({
      ...record, trustTier: "collaborator", serverNonce: "lower-role-nonce",
      membershipExpiresAtMs: Date.now() + 60000,
      members: record.members.map((member) => ({ ...member, trustTier: "collaborator" })),
    }));
    const shared = {
      ...lowerTrust[0], flockId: "demo-owner/studio-team", flockType: "shared",
      sessionVisibility: "all", shareSpecs: "full",
    };
    const unrelated = { flockId: "someone/other-team", trustTier: "guest", custom: "preserve exactly" };
    const sharing = { sharedSessionIds: ["approved-session"],
      sharedSnapshots: { "approved-session": { mode: "approved-snapshot", summarySnapshot: "approved" } } };
    for (const [filename, api] of entrypoints) {
      for (const surface of ["mcp", "install"]) {
        for (const reversed of [false, true]) {
          const storePath = path.join(directory, `${filename}-${surface}-${reversed}.json`);
          fs.writeFileSync(storePath, JSON.stringify({ flocks: {
            [shared.flockId]: { ...shared, ...sharing, trustTier: "owner" },
            [unrelated.flockId]: unrelated,
          } }));
          const records = [...result.enrolledFlocks, ...lowerTrust, shared];
          const applied = await applyThroughClient(filename, api, surface,
            { ...result, enrolledFlocks: reversed ? records.reverse() : records }, storePath,
            { ...cfg, githubUser: "spoofed-caller-label" });
          assert.equal(surface === "mcp" ? applied.enrolledFlocks.length : applied.enrolledFlockCount, 3);
          const stored = JSON.parse(fs.readFileSync(storePath, "utf8"));
          for (const record of result.enrolledFlocks) {
            assert.equal(stored.flocks[record.flockId].trustTier, "owner");
            assert.equal(stored.flocks[record.flockId].sessionVisibility, "all");
            assert.equal(stored.flocks[record.flockId].shareSpecs, "full");
            assert.equal(stored.flocks[record.flockId].serverNonce, record.serverNonce);
            assert.equal(stored.flocks[record.flockId].membershipExpiresAtMs, null);
          }
          assert.equal(stored.flocks[shared.flockId].trustTier, "collaborator");
          assert.equal(stored.flocks[shared.flockId].sessionVisibility, "explicit_opt_in_only");
          assert.equal(stored.flocks[shared.flockId].shareSpecs, "summary");
          assert.deepEqual(stored.flocks[shared.flockId].sharedSessionIds, sharing.sharedSessionIds);
          assert.deepEqual(stored.flocks[shared.flockId].sharedSnapshots, sharing.sharedSnapshots);
          assert.deepEqual(stored.flocks[unrelated.flockId], unrelated);
          assert.equal(stored.flocks["spoofed-caller-label"], undefined);
        }
        for (const trustTier of ["collaborator", "guest"]) {
          const storePath = path.join(directory, `${filename}-${surface}-${trustTier}.json`);
          const record = { ...result.enrolledFlocks[1], trustTier };
          for (const field of ["hubToken", "tokenExpiresAt", "serverNonce", "members", "ownerGitHubUserId"]) {
            delete record[field];
          }
          fs.writeFileSync(storePath, JSON.stringify({ flocks: {
            [record.flockId]: { ...record, trustTier: "owner", sessionVisibility: "all", shareSpecs: "full",
              hubToken: "stale-owner-token", serverNonce: "stale-owner-nonce",
              members: result.enrolledFlocks[1].members, ownerGitHubUserId: 1001 },
          } }));
          await applyThroughClient(filename, api, surface, {
            ...result, githubUser: "demo-user", githubUserId: 2002, peerId: "2002:demo-device",
            enrolledFlocks: [record],
          }, storePath);
          const stored = JSON.parse(fs.readFileSync(storePath, "utf8"));
          assert.equal(stored.flocks[record.flockId].trustTier, trustTier);
          assert.equal(stored.flocks[record.flockId].sessionVisibility, "explicit_opt_in_only");
          assert.equal(stored.flocks[record.flockId].shareSpecs, "summary");
          for (const field of ["hubToken", "tokenExpiresAt", "serverNonce", "members", "ownerGitHubUserId"]) {
            assert.equal(stored.flocks[record.flockId][field], undefined);
          }
          assert.equal(stored.flocks["demo-owner"], undefined);
        }
      }
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("v3 hotfix owner application rejects spoofed identity, shared roles and stale membership proofs", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-enroll-spoof-"));
  try {
    const result = await enroll(path.join(directory, "server.json"));
    const record = result.enrolledFlocks[0];
    const mutations = [
      { result: { githubUser: "demo-user", githubUserId: 2002 } },
      { result: { githubUserId: 2002 } },
      { result: { peerId: "wrong-peer" } },
      { result: { deviceId: "wrong-device" } },
      { record: { flockId: "demo-owner/studio-team", flockType: "shared" } },
      { record: { targetMachineId: "DEMO-PC" } },
      { record: { ownerGitHubUser: "someone-else" } },
      { record: { ownerGitHubUserId: 2002 } },
      { record: { members: record.members.map((member) => ({ ...member, githubUserId: 2002 })) } },
      { record: { members: record.members.map((member) => ({ ...member, trustTier: "collaborator" })) } },
    ];
    for (const [filename, api] of entrypoints) {
      const storePath = path.join(directory, `${filename}-local.json`);
      const before = JSON.stringify({ flocks: { unrelated: { trustTier: "guest" } } });
      fs.writeFileSync(storePath, before);
      for (const mutation of mutations) {
        assert.throws(() => api.applyV3EnrollmentResult(cfg, {
          ...result, ...mutation.result, enrolledFlocks: [{ ...record, ...mutation.record }],
        }, storePath), /unverified owner authority/);
        assert.equal(fs.readFileSync(storePath, "utf8"), before);
      }
      for (const trustTier of ["collaborator", "guest"]) {
        const duplicates = [record, { ...record, trustTier }];
        for (const enrolledFlocks of [duplicates, [...duplicates].reverse()]) {
          assert.throws(() => api.applyV3EnrollmentResult(cfg, {
            ...result, githubUser: "demo-user", githubUserId: 2002, peerId: "2002:demo-device",
            enrolledFlocks,
          }, storePath), /unverified owner authority/);
          assert.equal(fs.readFileSync(storePath, "utf8"), before);
        }
      }
      const legacyRecord = { ...record };
      delete legacyRecord.ownerGitHubUserId;
      api.applyV3EnrollmentResult(cfg, { ...result, enrolledFlocks: [legacyRecord] }, storePath);
      assert.equal(JSON.parse(fs.readFileSync(storePath, "utf8")).flocks[record.flockId].trustTier, "owner");
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function stubBootstrapTransport(scenario) {
  return `
    (() => {
    const assert = require("node:assert/strict");
    const { EventEmitter } = require("node:events");
    const Module = require("node:module");
    const originalLoad = Module._load;
    const nativeSetTimeout = global.setTimeout;
    const nativeClearTimeout = global.clearTimeout;
    const deadlines = new Set();
    global.setTimeout = (fn, delay, ...args) => {
      const timer = nativeSetTimeout(fn, delay === 10000 && scenario === "deadline" ? 20 : delay, ...args);
      if (delay === 10000) deadlines.add(timer);
      return timer;
    };
    global.clearTimeout = (timer) => { deadlines.delete(timer); nativeClearTimeout(timer); };
    let request, response, heartbeat, timeoutDisabled = false, delivered = false;
    const scenario = ${JSON.stringify(scenario)};
    process.on("exit", () => {
      assert.equal(deadlines.size, 0, "deadline cleared");
      assert.ok(!request || request.destroyed, "request destroyed");
      assert.ok(!response || response.destroyed, "response destroyed");
      assert.ok(!request || timeoutDisabled, "socket timeout disabled");
      assert.ok(delivered, "scheduled transport events ran before exit");
    });
    Module._load = function(id, ...args) {
      if (id !== "node:https") return originalLoad.call(this, id, ...args);
      return { request(url, options, onResponse) {
        assert.equal(url.origin, "https://demo-broker.invalid");
        assert.equal(options.headers.Authorization, "Bearer " + process.env.GH_BOOT_TOKEN);
        assert.equal(options.timeout, 10000);
        if (scenario === "sync-error") { delivered = true; throw Error("synthetic transport failure"); }
        request = new EventEmitter();
        heartbeat = setInterval(() => {}, 1000);
        request.write = (body) => assert.equal(body, process.env.V3_BODY);
        request.setTimeout = (value) => { assert.equal(value, 0); timeoutDisabled = true; };
        request.destroy = () => {
          if (request.destroyed) return;
          request.destroyed = true;
          clearInterval(heartbeat);
          queueMicrotask(() => request.emit("error", Error("late socket hang up")));
        };
        const reply = (event = "end") => {
          response = new EventEmitter();
          response.complete = scenario !== "incomplete";
          response.statusCode = scenario === "http-error" ? 403 : 200;
          response.destroy = () => {
            response.destroyed = true;
            queueMicrotask(() => response.emit("close"));
          };
          onResponse(response);
          const text = scenario === "http-error" ? '{"ok":false,"error":"synthetic broker denied"}'
            : scenario === "invalid-json" ? "synthetic-body-secret"
            : scenario === "empty-json" ? "" : '{"ok":true,"value":"synthetic success"}';
          response.emit("data", Buffer.from(text.slice(0, 5)));
          response.emit("data", Buffer.from(text.slice(5)));
          response.emit(event, event === "error" ? Error("synthetic response failure") : undefined);
        };
        request.end = () => {
          if (scenario === "deadline") { delivered = true; return; }
          setImmediate(() => {
            if (scenario.startsWith("timeout")) request.emit("timeout");
            else if (scenario.startsWith("error")) request.emit("error", Error("synthetic transport failure" +
              (scenario === "error-secret" ? " " + process.env.GH_BOOT_TOKEN : "")));
            else if (scenario === "request-abort") request.emit("abort");
            else if (scenario === "request-close") request.emit("close");
            if (scenario === "timeout-error") request.emit("error", Error("socket hang up"));
            if (["error-late-response", "timeout-late-success", "success", "success-late-error",
              "http-error", "incomplete", "invalid-json", "empty-json"].includes(scenario)) reply();
            if (scenario === "response-aborted") reply("aborted");
            if (scenario === "response-error") reply("error");
            if (scenario === "response-close") reply("close");
            if (response) {
              response.emit("data", Buffer.from('{"late":"synthetic-body-secret"}'));
              response.emit("end");
              response.emit("error", Error("late response error"));
              response.emit("aborted");
            }
            if (scenario === "success-late-error") request.emit("error", Error("late request error"));
            delivered = true;
          });
        };
        return request;
      }};
    };
    })();
  `;
}

test("v3 hotfix actual bootstrap child emits one JSON result and exits cleanly for late transport events", () => {
  const cases = [
    ["success", null], ["success-late-error", null],
    ["error", /request failed: synthetic transport failure/],
    ["error-secret", /request failed: synthetic transport failure \[redacted\]/],
    ["timeout-error", /timed out/], ["error-late-response", /request failed/],
    ["timeout-late-success", /timed out/], ["deadline", /timed out/],
    ["response-aborted", /response aborted/], ["response-error", /response failed/],
    ["response-close", /closed before completion/], ["incomplete", /incomplete/],
    ["request-abort", /request aborted/], ["request-close", /closed before a response/],
    ["invalid-json", /invalid or empty JSON/], ["empty-json", /invalid or empty JSON/],
    ["sync-error", /request failed: synthetic transport failure/],
    ["http-error", /synthetic broker denied/],
  ];
  for (const [filename, api] of entrypoints) {
    for (const [scenario, error] of cases) {
      let child;
      const call = new Function("resolveLocalGitHubToken", "validatePinnedBootstrapOrigin",
        "isSandboxV3Mode", "DEFAULT_BOOTSTRAP_URL", "execFileSync",
        `return (${api.callBootstrapV3Endpoint.toString()});`)(
        () => "synthetic-github-secret", () => "https://demo-broker.invalid", () => false, "",
        (executable, args, options) => {
          assert.equal(executable, process.execPath);
          assert.equal(args[0], "-e");
          assert.equal(options.timeout, 12000);
          child = spawnSync(executable, ["-e", stubBootstrapTransport(scenario) + args[1]], {
            encoding: "utf8", timeout: 2000, windowsHide: true,
            env: { V3_URL: options.env.V3_URL, V3_METHOD: options.env.V3_METHOD,
              V3_BODY: options.env.V3_BODY, GH_BOOT_TOKEN: options.env.GH_BOOT_TOKEN },
          });
          return child.stdout;
        });
      const result = call(cfg, "/synthetic", {
        method: scenario === "success" ? "GET" : "POST", body: { private: "synthetic-body-secret" },
      });
      const label = `${filename}: ${scenario}`;
      assert.equal(child.error, undefined, label);
      assert.equal(child.status, 0, `${label}: ${child.stderr}`);
      assert.equal(child.stderr, "", label);
      assert.equal(child.stdout, JSON.stringify(result), label);
      assert.deepEqual(JSON.parse(child.stdout), result, label);
      assert.doesNotMatch(child.stdout + child.stderr, /synthetic-github-secret|synthetic-body-secret/, label);
      if (error) {
        assert.equal(result.ok, false, label);
        assert.match(result.error, error, label);
      } else {
        assert.deepEqual(result, { ok: true, value: "synthetic success" }, label);
      }
    }
  }
});
