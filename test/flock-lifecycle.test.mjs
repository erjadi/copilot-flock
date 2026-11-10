import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { lifecyclePaths, atomicJson, recordInstalledArtifact, uninstallFlock as runUninstall, stopPinnedDaemon,
  assertNoLinks, inspectProcess, findRuntimeClients } from "../flock-lifecycle.mjs";
import { matchesMember, signLeave, verifyLeave } from "../flock-membership.mjs";
import { leaveV3Device, kickV3FlockMember, planV3DeviceLeave } from "../bootstrap-server.mjs";

const uninstallFlock = (options) => runUninstall({ findProcesses: async () => [], ...options });

function fixture(platform = "win32") {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "flock-uninstall-test-"));
  const paths = lifecyclePaths({ home, platform, copilotHome: path.join(home, ".copilot"),
    appData: path.join(home, "AppData", "Roaming") });
  const root = paths.roots[0];
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "flock.mjs"),
    'export const BRIDGE_VERSION = "test";\nexport async function runDaemon() {}');
  recordInstalledArtifact(root, path.join(root, "flock.mjs"), paths);
  const identity = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  atomicJson(path.join(root, "identity.json"), { ...identity, fingerprint: "device-a" });
  atomicJson(path.join(root, "config.json"), { machineId: "PC-A", bootstrapUrl: "https://broker.example.invalid" });
  atomicJson(path.join(root, "flocks.json"), { flocks: { "owner/personal": {}, "owner/team": {} } });
  const preserved = path.join(paths.copilotHome, "session-state", "test-session");
  fs.mkdirSync(preserved, { recursive: true });
  fs.writeFileSync(path.join(preserved, "events.jsonl"), "conversation");
  fs.writeFileSync(path.join(paths.copilotHome, "data.db"), "unrelated");
  return { home, paths, root, identity, preserved,
    close: () => fs.rmSync(home, { recursive: true, force: true }) };
}
const confirm = async ({ request }) => ({ confirmed: true, flockId: request.flockId });

test("member selectors are conjunctive, require a selector and never match a sibling device", () => {
  const member = { githubUser: "owner", githubUserId: 1, deviceId: "a", machineId: "PC-A" };
  assert.equal(matchesMember(member, { targetUser: "owner", targetDeviceId: "a" }), true);
  for (const selector of [{ targetUser: "owner", targetDeviceId: "b" },
    { targetUser: "other", targetDeviceId: "a" }, { targetUser: "owner", targetGitHubUserId: 2 },
    { targetDeviceId: "a", targetMachineId: "PC-B" }]) assert.equal(matchesMember(member, selector), false);
  assert.throws(() => matchesMember(member, {}), /selector/);
});

test("device leave is signed, bound to every selector, fresh and unforgeable", () => {
  const key = crypto.generateKeyPairSync("ed25519");
  const request = signLeave({ flockId: "owner/team", deviceId: "a", machineId: "PC-A" }, key.privateKey);
  verifyLeave(request, key.publicKey);
  for (const field of ["flockId", "deviceId", "machineId", "requestId", "timestamp"]) {
    assert.throws(() => verifyLeave({ ...request, [field]: "changed" }, key.publicKey));
  }
  assert.throws(() => verifyLeave(request, key.publicKey, Date.now() + 400000), /expired/);
});

test("legacy kick with user AND device leaves the owner's other machines and vouchers intact", async () => {
  const f = fixture();
  try {
    const storePath = path.join(f.home, "store.json");
    const member = { githubUser: "owner", githubUserId: 1, deviceId: "a", machineId: "PC-A", peerId: "peer-a" };
    atomicJson(storePath, { flocks: { "owner/team": { flockId: "owner/team", ownerGitHubUser: "owner",
      members: { a: member, b: { ...member, deviceId: "b", peerId: "peer-b", machineId: "PC-B" } },
      vouchers: { keep: { invitedUser: "owner" } }, revokedPrincipals: {}, rosterEpoch: 1 } } });
    const result = await kickV3FlockMember({ callerGitHubUser: "owner", flockId: "owner/team",
      targetUser: "owner", targetDeviceId: "a", targetMachineId: "PC-A" }, { storePath, connectionString: "" });
    assert.equal(result.kickedCount, 1);
    const flock = JSON.parse(fs.readFileSync(storePath)).flocks["owner/team"];
    assert.deepEqual(Object.keys(flock.members), ["b"]);
    assert.ok(flock.vouchers.keep);
  } finally { f.close(); }
});

test("leave acknowledges only after exact subscription deletion and eviction; retry never targets sibling", async () => {
  const f = fixture();
  try {
    const storePath = path.join(f.home, "store.json");
    const member = { githubUser: "owner", deviceId: "device-a", machineId: "PC-A", peerId: "peer-a",
      publicKey: f.identity.publicKey };
    atomicJson(storePath, { flocks: { "owner/team": { flockId: "owner/team", members: {
      a: member, b: { ...member, peerId: "peer-b", deviceId: "device-b", machineId: "PC-B" },
    } } } });
    const request = signLeave({ flockId: "owner/team", deviceId: "device-a", machineId: "PC-A" }, f.identity.privateKey);
    let attempts = 0;
    const adapters = { storePath, deleteSubscription: async (target) => {
      assert.equal(target.peerId, "peer-a"); attempts++;
      return { confirmed: attempts > 1 };
    }, evict: async (target) => { assert.equal(target.peerId, "peer-a"); return { evicted: true }; } };
    assert.equal((await leaveV3Device(request, adapters)).confirmed, false);
    assert.equal((await leaveV3Device(request, adapters)).confirmed, true);
    assert.equal((await leaveV3Device(request, adapters)).confirmed, true);
    assert.equal(attempts, 2);
    assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(storePath)).flocks["owner/team"].members), ["b"]);
    await assert.rejects(leaveV3Device({ ...request, deviceId: "device-b", machineId: "PC-B" }, adapters), /Invalid|selectors/);
    const plan = signLeave({ flockId: "*", deviceId: "device-a", machineId: "PC-A" }, f.identity.privateKey);
    assert.deepEqual(planV3DeviceLeave(plan, { storePath }).flockIds, []);
  } finally { f.close(); }
});

for (const platform of ["win32", "linux", "darwin"]) {
  test(`${platform}: removes only owned artifacts, preserves conversations and other MCP servers, twice safely`, async () => {
    const f = fixture(platform);
    try {
      for (const config of f.paths.configs) {
        fs.mkdirSync(path.dirname(config.path), { recursive: true });
        atomicJson(config.path, { theme: "keep", [config.key]: {
          unrelated: { command: "unrelated" },
          "copilot-flock": { command: process.execPath, args: [path.join(f.root, "flock.mjs"), "mcp"] },
          "copilot-signalr-bridge": { command: "node", args: [path.join(f.home, "user-script.mjs"), "mcp"] },
        } });
      }
      for (const artifact of [...f.paths.skills.slice(0, 2), f.paths.persistence[0]]) {
        fs.mkdirSync(path.dirname(artifact), { recursive: true });
        fs.writeFileSync(artifact, "test-owned-content");
        recordInstalledArtifact(f.root, artifact, f.paths);
      }
      const disabled = [];
      const result = await uninstallFlock({ paths: f.paths, leave: confirm,
        disable: async (filename) => disabled.push(filename), removeTasks: async () => [] });
      assert.equal(result.fullyRemoved, true, JSON.stringify(result));
      assert.deepEqual(disabled, [f.paths.persistence[0]]);
      assert.equal(fs.existsSync(f.root), false);
      for (const config of f.paths.configs) {
        const content = JSON.parse(fs.readFileSync(config.path));
        assert.equal(content.theme, "keep");
        assert.ok(content[config.key].unrelated);
        assert.ok(content[config.key]["copilot-signalr-bridge"]);
        assert.equal(content[config.key]["copilot-flock"], undefined);
      }
      assert.equal(fs.readFileSync(path.join(f.preserved, "events.jsonl"), "utf8"), "conversation");
      assert.equal(fs.readFileSync(path.join(f.paths.copilotHome, "data.db"), "utf8"), "unrelated");
      assert.equal((await uninstallFlock({ paths: f.paths, leave: confirm })).fullyRemoved, true);
    } finally { f.close(); }
  });
}

test("offline and partial leaves retain recovery, retry skips confirmed flocks and cannot report fully removed", async () => {
  const f = fixture();
  try {
    const calls = [];
    let offline = true;
    const leave = async ({ request }) => {
      calls.push(request.flockId);
      if (offline && request.flockId === "owner/team") throw new Error("offline");
      return confirm({ request });
    };
    const first = await uninstallFlock({ paths: f.paths, leave });
    assert.equal(first.fullyRemoved, false);
    assert.equal(first.pending.length, 1);
    assert.ok(fs.existsSync(path.join(f.root, "identity.json")));
    offline = false;
    const second = await uninstallFlock({ paths: f.paths, leave, removeTasks: async () => [] });
    assert.equal(second.fullyRemoved, true);
    assert.deepEqual(calls, ["owner/personal", "owner/team", "owner/team"]);
  } finally { f.close(); }
});

test("unknown/modified skills, source checkouts and artifacts survive with honest retention", async () => {
  const f = fixture();
  try {
    const skill = f.paths.skills[0];
    fs.mkdirSync(path.dirname(skill), { recursive: true });
    fs.writeFileSync(skill, "installed");
    recordInstalledArtifact(f.root, skill, f.paths);
    fs.writeFileSync(skill, "user-authored content");
    fs.writeFileSync(path.join(f.root, "custom-notes.txt"), "preserve");
    const report = await uninstallFlock({ paths: f.paths, leave: confirm, removeTasks: async () => [] });
    assert.equal(report.fullyRemoved, false);
    assert.equal(fs.readFileSync(skill, "utf8"), "user-authored content");
    assert.equal(fs.readFileSync(path.join(f.root, "custom-notes.txt"), "utf8"), "preserve");
  } finally { f.close(); }
});

test("each canonical/legacy runtime script requires its own unchanged ownership hash, including retries", async () => {
  for (const name of ["flock.mjs", "bridge.mjs", "flock-lifecycle.mjs"]) {
    for (const change of ["modified", "unmanifested"]) {
      const f = fixture();
      try {
        const canonical = path.join(f.root, "flock.mjs");
        const target = path.join(f.root, name);
        fs.copyFileSync(canonical, path.join(f.root, "bridge.mjs"));
        recordInstalledArtifact(f.root, path.join(f.root, "bridge.mjs"), f.paths);
        if (name === "flock-lifecycle.mjs") {
          fs.writeFileSync(target, "export const owned = true;");
          recordInstalledArtifact(f.root, target, f.paths);
        }
        if (change === "modified") fs.appendFileSync(target, "\n// locally modified");
        else {
          const manifestPath = path.join(f.root, "installation.json");
          const manifest = JSON.parse(fs.readFileSync(manifestPath));
          delete manifest.artifacts[target];
          atomicJson(manifestPath, manifest);
        }
        const expected = fs.readFileSync(target);
        let leaves = 0;
        const options = { paths: f.paths, leave: async (request) => { leaves++; return confirm(request); },
          removeTasks: async () => { throw new Error("Must retain runtime before local cleanup"); } };
        for (let retry = 0; retry < 2; retry++) {
          const report = await uninstallFlock(options);
          assert.equal(report.fullyRemoved, false);
          assert.ok(report.retained.some((entry) => entry.path === target && /ownership hash/.test(entry.reason)), JSON.stringify(report));
          assert.deepEqual(fs.readFileSync(target), expected);
          assert.ok(fs.existsSync(path.join(f.root, "installation.json")));
          assert.ok(fs.existsSync(path.join(f.root, "identity.json")));
          assert.ok(fs.existsSync(path.join(f.preserved, "events.jsonl")));
        }
        assert.equal(leaves, 2, "Confirmed leaves are not repeated when artifact cleanup is retained");
      } finally { f.close(); }
    }
  }
});

test("runtime changes after preflight are preserved with their ownership manifest", async () => {
  const f = fixture();
  try {
    const target = path.join(f.root, "flock.mjs");
    const report = await uninstallFlock({ paths: f.paths, leave: confirm, removeTasks: async () => [],
      findProcesses: async () => { fs.appendFileSync(target, "\n// concurrent edit"); return []; } });
    assert.equal(report.fullyRemoved, false);
    assert.ok(report.retained.some((entry) => entry.path === target && /changed during cleanup/.test(entry.reason)));
    assert.match(fs.readFileSync(target, "utf8"), /concurrent edit/);
    assert.ok(fs.existsSync(path.join(f.root, "installation.json")));
  } finally { f.close(); }
});

test("Linux process inspection never treats access denial as proof that a process exited", () => {
  const pid = 2147483647;
  const read = fs.readFileSync;
  const link = fs.readlinkSync;
  try {
    fs.readFileSync = (filename, ...args) => filename === `/proc/${pid}/stat`
      ? `${pid} (node) S ${Array(25).fill("1").join(" ")}` : read(filename, ...args);
    for (const code of ["EACCES", "EPERM", "ESRCH", "ENOENT", "EIO"]) {
      fs.readlinkSync = (filename, ...args) => {
        if (filename === `/proc/${pid}/exe`) throw Object.assign(new Error(`fixture ${code}`), { code });
        return link(filename, ...args);
      };
      if (code === "ESRCH" || code === "ENOENT") assert.equal(inspectProcess(pid, "linux"), null);
      else assert.throws(() => inspectProcess(pid, "linux"), (error) => error.code === code);
    }
  } finally { fs.readFileSync = read; fs.readlinkSync = link; }
});

test("Linux enumeration skips proven other-user processes but retains denied same-user/unknown clients", async () => {
  const f = fixture("linux");
  try {
    const inspected = [];
    const options = {
      uid: 1000,
      readdir: () => ["1", "42", "43", "44", "45", "46", "47", "48", "49"],
      stat: (filename) => {
        const pid = Number(path.basename(filename));
        if (pid === 48 || pid === 49) throw Object.assign(new Error("fixture ownership unavailable"), { code: pid === 48 ? "EACCES" : "ESRCH" });
        return { uid: pid === 1 ? 0 : 1000 };
      },
      inspect: (pid) => {
        inspected.push(pid);
        const code = { 1: "EACCES", 42: "EACCES", 43: "EPERM", 44: "ESRCH", 45: "ENOENT" }[pid];
        if (code) throw Object.assign(new Error("fixture inaccessible process"), { code });
        return { pid, argv: [process.execPath, pid === 47 ? path.join(f.root, "flock.mjs") : "unrelated.mjs"] };
      },
    };
    const clients = findRuntimeClients(f.paths, options);
    assert.deepEqual(clients.map((client) => client.pid), [42, 43, 47, 48]);
    assert.equal(inspected.includes(1), false, "Root-owned /proc/1/exe must not be inspected by another user's cleanup");
    const retained = await uninstallFlock({ paths: f.paths, leave: confirm, removeTasks: async () => [],
      findProcesses: () => findRuntimeClients(f.paths, options) });
    assert.equal(retained.fullyRemoved, false);
    assert.ok(retained.retained.some((entry) => entry.path === "Process:42"));
    assert.ok(fs.existsSync(path.join(f.root, "identity.json")));
    const removed = await uninstallFlock({ paths: f.paths, leave: confirm, removeTasks: async () => [],
      findProcesses: () => findRuntimeClients(f.paths, { ...options, readdir: () => ["1"] }) });
    assert.equal(removed.fullyRemoved, true, JSON.stringify(removed));
  } finally { f.close(); }
});

test("unproven live clients and service failures keep recovery instead of claiming full removal", async () => {
  for (const stage of ["process", "service", "inventory"]) {
    const f = fixture();
    try {
      if (stage === "service") {
        const startup = f.paths.persistence[0];
        fs.mkdirSync(path.dirname(startup), { recursive: true });
        fs.writeFileSync(startup, "owned-startup");
        recordInstalledArtifact(f.root, startup, f.paths);
      }
      const report = await uninstallFlock({ paths: f.paths, leave: confirm, removeTasks: async () => [],
        findProcesses: async () => stage === "process" ? [{ pid: 123, reason: "unproven client" }] : [],
        disable: async () => { throw Error("service stop denied"); },
        ...(stage === "inventory" ? { inventory: async () => { throw Error("inventory offline"); } } : {}),
      });
      assert.equal(report.fullyRemoved, false);
      assert.ok(fs.existsSync(path.join(f.root, "identity.json")));
      assert.ok(fs.existsSync(path.join(f.root, "flock.mjs")));
    } finally { f.close(); }
  }
});

test("atomic JSON retries transient replacement locks without unlinking the destination", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-atomic-retry-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const rename = fs.renameSync;
  const delays = [];
  t.mock.method(Atomics, "wait", (_buffer, _index, _value, timeout) => {
    delays.push(timeout);
    return "timed-out";
  });
  let calls = 0;
  let code;
  t.mock.method(fs, "renameSync", (source, destination) => {
    assert.deepEqual(JSON.parse(fs.readFileSync(destination)), { before: true });
    if (++calls <= 2) throw Object.assign(new Error("fixture replacement lock"), { code });
    return rename(source, destination);
  });
  for (code of ["EPERM", "EACCES", "EBUSY"]) {
    const filename = path.join(root, `${code}.json`);
    const before = Buffer.from('{"before":true}');
    fs.writeFileSync(filename, before);
    calls = 0;
    delays.length = 0;
    atomicJson(filename, { after: true }, before);
    assert.equal(calls, 3);
    assert.deepEqual(delays, [10, 20]);
    assert.deepEqual(JSON.parse(fs.readFileSync(filename)), { after: true });
  }
  assert.deepEqual(fs.readdirSync(root).sort(), ["EACCES.json", "EBUSY.json", "EPERM.json"]);
});

test("atomic JSON bounds replacement retries and propagates permanent errors without changing the original", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-atomic-denied-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const delays = [];
  t.mock.method(Atomics, "wait", (_buffer, _index, _value, timeout) => {
    delays.push(timeout);
    return "timed-out";
  });
  let calls = 0;
  let failure;
  t.mock.method(fs, "renameSync", () => { calls++; throw failure; });
  for (const code of ["EPERM", "EACCES", "EBUSY", "EIO", "ENOSPC"]) {
    const filename = path.join(root, `${code}.json`);
    const before = Buffer.from('{"before":true}');
    fs.writeFileSync(filename, before);
    failure = Object.assign(new Error("fixture replacement denied"), { code });
    calls = 0;
    delays.length = 0;
    assert.throws(() => atomicJson(filename, { after: true }, before), (error) => error === failure);
    const retryable = ["EPERM", "EACCES", "EBUSY"].includes(code);
    assert.equal(calls, retryable ? 9 : 1);
    assert.deepEqual(delays, retryable ? [10, 20, 40, 80, 160, 200, 200, 200] : []);
    assert.deepEqual(fs.readFileSync(filename), before);
  }
  assert.equal(fs.readdirSync(root).length, 5, "Failed staged writes must be cleaned up");
});

test("atomic JSON replacement retries reject intervening shared-config writes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-atomic-concurrent-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const filename = path.join(root, "config.json");
  fs.writeFileSync(filename, '{"before":true}');
  const concurrent = Buffer.from('{"external":"preserve"}');
  let calls = 0;
  t.mock.method(Atomics, "wait", () => "timed-out");
  t.mock.method(fs, "renameSync", () => {
    calls++;
    fs.writeFileSync(filename, concurrent);
    throw Object.assign(new Error("fixture replacement lock"), { code: "EPERM" });
  });
  assert.throws(() => atomicJson(filename, { after: true }), /Concurrent config change/);
  assert.equal(calls, 1, "A retry must not overwrite an intervening write");
  assert.deepEqual(fs.readFileSync(filename), concurrent);
  assert.deepEqual(fs.readdirSync(root), ["config.json"]);
});

test("atomic JSON replacement retries and cleanup reject a parent junction swap", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-atomic-path-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, "owned");
  const retained = path.join(root, "retained");
  const outside = path.join(root, "outside");
  fs.mkdirSync(directory);
  fs.mkdirSync(outside);
  const filename = path.join(directory, "config.json");
  fs.writeFileSync(filename, '{"before":true}');
  fs.writeFileSync(path.join(outside, "config.json"), '{"external":"preserve"}');
  const rename = fs.renameSync;
  let displacedTemporary;
  let calls = 0;
  t.mock.method(Atomics, "wait", () => "timed-out");
  t.mock.method(fs, "renameSync", (source) => {
    calls++;
    rename(directory, retained);
    displacedTemporary = path.join(outside, path.basename(source));
    fs.writeFileSync(displacedTemporary, "external evidence");
    fs.symlinkSync(outside, directory, process.platform === "win32" ? "junction" : "dir");
    throw Object.assign(new Error("fixture replacement lock"), { code: "EPERM" });
  });
  assert.throws(() => atomicJson(filename, { after: true }), /link|junction|escape/);
  assert.equal(calls, 1);
  assert.equal(fs.readFileSync(displacedTemporary, "utf8"), "external evidence");
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(outside, "config.json"))), { external: "preserve" });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(retained, "config.json"))), { before: true });
  assert.equal(fs.readdirSync(retained).length, 2, "Unsafe-path cleanup retains the original staged evidence");
});

test("source checkout and concurrent shared-config writes are rejected without erasing evidence", async () => {
  const f = fixture();
  try {
    fs.mkdirSync(path.join(f.root, ".git"));
    await assert.rejects(uninstallFlock({ paths: f.paths, leave: confirm }), /source checkout/);
    assert.ok(fs.existsSync(path.join(f.root, "flock.mjs")));
    const config = f.paths.configs[0].path;
    fs.writeFileSync(config, '{"new":"user edit"}');
    assert.throws(() => atomicJson(config, { old: "stale" }, Buffer.from('{"old":"base"}')), /Concurrent/);
    assert.deepEqual(JSON.parse(fs.readFileSync(config)), { new: "user edit" });
  } finally { f.close(); }
});

test("junction/symlink escape rejected without touching destination", async () => {
  const f = fixture();
  try {
    const outside = path.join(f.home, "outside");
    fs.mkdirSync(outside);
    const link = path.join(f.home, "link");
    fs.symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => assertNoLinks(path.join(link, "file")), /link|junction|escape/);
    assert.throws(() => lifecyclePaths({ home: f.home, copilotHome: f.home }), /dedicated/);
  } finally { f.close(); }
});

test("stale PID never kills unrelated process; pinned identity must match immediately before signalling", async () => {
  const f = fixture();
  try {
    const pid = 123456;
    fs.writeFileSync(path.join(f.root, "daemon.pid"), String(pid));
    const unrelated = { pid, start: "old", executable: process.execPath, argv: [process.execPath, "unrelated.mjs"] };
    let killed = 0;
    await stopPinnedDaemon(f.root, f.paths, { inspect: () => unrelated, kill: () => killed++ });
    assert.equal(killed, 0);
    const live = { pid, start: "created", executable: process.execPath,
      argv: [process.execPath, path.join(f.root, "flock.mjs"), "daemon"] };
    await assert.rejects(stopPinnedDaemon(f.root, f.paths, { inspect: () => live, kill: () => killed++ }), /creation-identity/);
    atomicJson(path.join(f.root, "daemon-identity.json"), { ...live, script: path.join(f.root, "flock.mjs") });
    await stopPinnedDaemon(f.root, f.paths, { inspect: () => killed ? null : live, kill: () => killed++ });
    assert.equal(killed, 1);
    assert.ok(inspectProcess(process.pid)?.start);
  } finally { f.close(); }
});

test("invalid shared config fails explicitly and retains runtime for retry; no silent local-only fallback", async () => {
  const f = fixture();
  try {
    const config = f.paths.configs[0].path;
    fs.writeFileSync(config, "{invalid");
    const report = await uninstallFlock({ paths: f.paths, leave: confirm, removeTasks: async () => [] });
    assert.equal(report.ok, false);
    assert.ok(report.retained.some((item) => item.path === config));
    assert.ok(fs.existsSync(path.join(f.root, "flock.mjs")));
    await assert.rejects(uninstallFlock({ paths: f.paths, localOnly: true }), /explicit approval/);
  } finally { f.close(); }
});

test("canonical and legacy CLI uninstall in a synthetic home without live transports/processes", () => {
  for (const [entry, args] of [["flock.mjs", ["uninstall"]], ["bridge.mjs", ["flock", "unenroll", "--traceless"]]]) {
    const f = fixture(process.platform);
    try {
      const persistence = f.paths.persistence[0];
      fs.mkdirSync(path.dirname(persistence), { recursive: true });
      fs.writeFileSync(persistence, "owned synthetic persistence");
      recordInstalledArtifact(f.root, persistence, f.paths);
      const preload = path.join(f.home, "isolate.mjs");
      fs.writeFileSync(preload, `
import os from "node:os";
import cp from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { syncBuiltinESMExports } from "node:module";
os.homedir = () => process.env.FIXTURE_HOME;
const readdir = fs.readdirSync;
fs.readdirSync = (filename, ...args) => filename === "/proc" ? [] : readdir(filename, ...args);
cp.execFileSync = (command, args) => {
  if (command === "powershell.exe" && /FLOCK_TASK_NAMES|FLOCK_RUNTIME_SCRIPTS/.test(args.at(-1))) return "[]";
  if (command === "systemctl" && JSON.stringify(args) === JSON.stringify(["--user", "disable", "--now", path.basename(process.env.FIXTURE_PERSISTENCE)])) return "";
  if (command === "launchctl" && JSON.stringify(args) === JSON.stringify(["bootout", "gui/" + process.getuid(), process.env.FIXTURE_PERSISTENCE])) return "";
  if (command === "ps" && JSON.stringify(args) === JSON.stringify(["-axo", "uid=,pid="])) return "";
  throw new Error("Unexpected native command in isolated uninstall fixture: " + command);
};
syncBuiltinESMExports();
`);
      const env = { ...process.env, COPILOT_HOME: f.paths.copilotHome, FIXTURE_HOME: f.home,
        APPDATA: path.join(f.home, "AppData", "Roaming"), FIXTURE_PERSISTENCE: persistence };
      for (const key of Object.keys(env)) {
        if (key.startsWith("NODE_TEST_") || key === "NODE_OPTIONS") delete env[key];
      }
      const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href,
        fileURLToPath(new URL(`../${entry}`, import.meta.url)), ...args, "--local-only", "--approve-local-only"], {
        encoding: "utf8", timeout: 15000, env,
      });

      assert.equal(result.status, 0, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.equal(report.ok, true);
      assert.equal(report.fullyRemoved, false);
      assert.equal(report.localOnly, true);
      assert.equal(report.pending.length, 2);
      assert.equal(fs.existsSync(path.join(f.root, "flock.mjs")), false);
      assert.ok(fs.existsSync(path.join(f.preserved, "events.jsonl")));
    } finally { f.close(); }
  }
});

test("MCP initialize remains functional with lifecycle tooling registered and no daemon side effects", () => {
  const f = fixture();
  try {
    const driver = path.join(f.home, "mcp-fixture.mjs");
    const source = new URL("../flock.mjs", import.meta.url).href;
    fs.writeFileSync(driver, `
import os from "node:os";
import cp from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
os.homedir=()=>process.env.FIXTURE_HOME;
cp.spawn=()=>{throw Error("No daemon process allowed in MCP fixture");};
cp.execFileSync=()=>{throw Error("No native process allowed in MCP fixture");};
syncBuiltinESMExports();
const {runMcpServer}=await import(${JSON.stringify(source)});
await runMcpServer({});
`);
    const env = { ...process.env, COPILOT_HOME: f.paths.copilotHome, FIXTURE_HOME: f.home };
    for (const key of Object.keys(env)) {
      if (key.startsWith("NODE_TEST_") || key === "NODE_OPTIONS") delete env[key];
    }
    const result = spawnSync(process.execPath, [driver], {
      env, encoding: "utf8", timeout: 15000,
      input: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n',
    });
    assert.equal(result.status, 0, result.stderr);
    const messages = result.stdout.trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(messages.find((message) => message.id === 1).result.serverInfo.name, "copilot-flock");
    assert.ok(messages.find((message) => message.id === 2).result.tools.some((tool) => tool.name === "unenroll_flock"));
  } finally { f.close(); }
});
