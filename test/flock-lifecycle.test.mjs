import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { lifecyclePaths, atomicJson, recordInstalledArtifact, uninstallFlock as runUninstall, stopPinnedDaemon,
  assertNoLinks, inspectProcess, findRuntimeClients, assertLinuxUnitsQuiescent,
  assertLinuxDaemonCgroupSafe, disablePersistence, buildLinuxSystemdUnit,
  configureLinuxSystemdPersistence, activateLinuxSystemdDaemon, readLinuxCgroupPids,
  prepareOutsideLinuxServiceCgroupSpawn, spawnSessionSafeProcess } from "../flock-lifecycle.mjs";
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

function unitFixture(paths) {
  const unit = path.basename(paths.persistence[0]);
  const properties = { Id: unit, LoadState: "loaded", FragmentPath: paths.persistence[0],
    ActiveState: "inactive", MainPID: "0", ControlGroup: "" };
  const commands = [];
  const query = (args) => {
    commands.push(args);
    if (args[0] === "list-units") {
      assert.deepEqual(args, ["list-units", "--all", "--output=json", "--no-pager",
        "--type=service", ...paths.persistence.map((filename) => path.basename(filename))]);
      return JSON.stringify([{ unit }]);
    }
    if (args[0] === "show") {
      assert.deepEqual(args, ["show", unit, "--property=Id,LoadState,FragmentPath,ActiveState,MainPID,ControlGroup"]);
      return Object.entries(properties).map(([key, value]) => `${key}=${value}`).join("\n") + "\n";
    }
    assert.deepEqual(args, ["disable", unit]);
    return "";
  };
  return { properties, commands, query };
}

test("Linux daemon stops reject service cgroups, unreadable boundaries and creation changes without a signal", async () => {
  const f = fixture("linux");
  try {
    const script = path.join(f.root, "flock.mjs");
    const pin = { pid: 123456, start: "boot:start", executable: process.execPath,
      argv: [process.execPath, script, "daemon"] };
    fs.writeFileSync(path.join(f.root, "daemon.pid"), String(pin.pid));
    atomicJson(path.join(f.root, "daemon-identity.json"), { ...pin, script });
    const check = (text) => assertLinuxDaemonCgroupSafe(pin.pid, { uid: 1000, read: () => text });
    for (const text of [
      "0::/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-flock.service\n",
      "0::/system.slice/custom-worker.service/nested\n", "0::/user.slice/user@1001.service/app.scope\n",
      "1:name=systemd:/legacy\n", "0::/bad/../path\n", "0::/bad//path\n", "",
    ]) {
      let signals = 0;
      await assert.rejects(stopPinnedDaemon(f.root, f.paths, {
        inspect: () => pin, kill: () => { signals++; }, checkLinuxCgroup: () => check(text),
      }), /unproven/);
      assert.equal(signals, 0);
      assert.throws(() => assertLinuxUnitsQuiescent(f.paths, {
        query: () => "[]", inspect: () => pin, checkCgroup: () => check(text),
      }), /unproven/, "Unknown service cgroups must block even when the named unit inventory is empty");
    }
    assert.throws(() => assertLinuxDaemonCgroupSafe(pin.pid, {
      read: () => { throw Object.assign(new Error("cgroup inspection denied"), { code: "EACCES" }); },
    }), /inspection denied/);
    check("0::/user.slice/user-1000.slice/user@1000.service/app.slice/terminal.scope\n");
    let reads = 0;
    let signals = 0;
    await assert.rejects(stopPinnedDaemon(f.root, f.paths, {
      inspect: () => ++reads === 1 ? pin : { ...pin, start: "boot:replacement" },
      kill: () => { signals++; },
      checkLinuxCgroup: () => check("0::/user.slice/user-1000.slice/user@1000.service/app.slice/terminal.scope\n"),
    }), /identity changed/);
    assert.equal(signals, 0);
    await stopPinnedDaemon(f.root, f.paths, {
      inspect: () => signals ? null : pin, kill: () => { signals++; },
      checkLinuxCgroup: () => check("0::/user.slice/user-1000.slice/user@1000.service/app.slice/terminal.scope\n"),
    });
    assert.equal(signals, 1);
  } finally { f.close(); }
});

test("Linux cleanup requires inactive, empty exact units and rejects missing or malformed proof", () => {
  const f = fixture("linux");
  try {
    const u = unitFixture(f.paths);
    assertLinuxUnitsQuiescent(f.paths, { query: u.query });
    assertLinuxUnitsQuiescent(f.paths, { query: () => "[]" });
    for (const [key, value] of [
      ["ActiveState", "active"], ["ActiveState", "deactivating"], ["MainPID", "123"],
      ["MainPID", ""], ["ControlGroup", "/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-flock.service"],
      ["FragmentPath", "/other/copilot-flock.service"], ["Id", "unrelated.service"], ["LoadState", "not-found"],
    ]) {
      const before = u.properties[key];
      u.properties[key] = value;
      assert.throws(() => assertLinuxUnitsQuiescent(f.paths, { query: u.query }), /unproven/);
      u.properties[key] = before;
    }
    delete u.properties.ControlGroup;
    assert.throws(() => assertLinuxUnitsQuiescent(f.paths, { query: u.query }), /unproven/);
    u.properties.ControlGroup = "";
    for (const output of ["{}", "null", "[null]", '[{"unit":"unrelated.service"}]',
      JSON.stringify([{ unit: u.properties.Id }, { unit: u.properties.Id }])]) {
      assert.throws(() => assertLinuxUnitsQuiescent(f.paths, {
        query: (args) => args[0] === "list-units" ? output : u.query(args),
      }), /inventory/);
    }
    for (const output of ["MainPID=0\nMainPID=0\n", "missing-properties", ""]) {
      assert.throws(() => assertLinuxUnitsQuiescent(f.paths, {
        query: (args) => args[0] === "show" ? output : u.query(args),
      }), /properties|unproven/);
    }
    assert.throws(() => assertLinuxUnitsQuiescent(f.paths, {
      query: () => { throw Object.assign(new Error("user manager inaccessible"), { code: "EACCES" }); },
    }), /inaccessible/);
    assert.throws(() => assertLinuxUnitsQuiescent(f.paths, { query: () => "{broken" }), SyntaxError);
    const legacy = path.basename(f.paths.persistence[1]);
    assert.throws(() => assertLinuxUnitsQuiescent(f.paths, {
      query: (args) => args[0] === "list-units" ? JSON.stringify([{ unit: legacy }])
        : Object.entries({ ...u.properties, Id: legacy, FragmentPath: f.paths.persistence[1],
          ActiveState: "active", MainPID: "456" }).map(([key, value]) => `${key}=${value}`).join("\n"),
    }), /unproven/, "A loaded legacy unit must still block cleanup when its file is absent");
  } finally { f.close(); }
});

test("Linux shared-cgroup or unavailable proof blocks all local cleanup and preserves acknowledged retry", async () => {
  for (const mode of ["shared-cgroup", "unit-file-missing", "inspection-denied", "missing-cgroup"]) {
    const f = fixture("linux");
    try {
      const targets = [f.paths.skills[0], f.paths.configs[0].path];
      if (mode !== "unit-file-missing") targets.push(f.paths.persistence[0]);
      for (const filename of targets) {
        fs.mkdirSync(path.dirname(filename), { recursive: true });
        fs.writeFileSync(filename, filename === f.paths.configs[0].path
          ? JSON.stringify({ mcpServers: { "copilot-flock": {
            command: process.execPath, args: [path.join(f.root, "flock.mjs"), "mcp"],
          }, unrelated: { command: "keep" } } }) : "owned");
        if (filename !== f.paths.configs[0].path) recordInstalledArtifact(f.root, filename, f.paths);
      }
      const retained = [...targets, ...["flock.mjs", "identity.json", "config.json", "flocks.json",
        "installation.json"].map((name) => path.join(f.root, name))];
      const before = retained.map((filename) => fs.readFileSync(filename));
      const u = unitFixture(f.paths);
      u.properties.ActiveState = "active";
      u.properties.MainPID = "123";
      u.properties.ControlGroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-flock.service";
      const leaves = [];
      let mutations = 0;
      const forbidden = async () => { mutations++; throw new Error("Local mutation forbidden before unit proof"); };
      const options = { paths: f.paths,
        leave: async (request) => { leaves.push(request.request.flockId); return confirm(request); },
        checkPersistence: (paths) => {
          if (mode === "inspection-denied") throw new Error("unit/cgroup inspection denied");
          if (mode === "missing-cgroup") delete u.properties.ControlGroup;
          assertLinuxUnitsQuiescent(paths, { query: u.query });
        }, disable: forbidden, removeTasks: forbidden, stopDaemon: forbidden, findProcesses: forbidden };
      for (let retry = 0; retry < 2; retry++) {
        const result = await uninstallFlock(options);
        assert.equal(result.fullyRemoved, false);
        assert.equal(result.ok, false);
        assert.deepEqual(result.removed, []);
        assert.ok(result.retained.some((entry) => /unproven|inspection denied/.test(entry.reason)));
        retained.forEach((filename, index) => assert.deepEqual(fs.readFileSync(filename), before[index]));
        assert.ok(Object.values(JSON.parse(fs.readFileSync(path.join(f.root, "uninstall-progress.json"))).leaves)
          .every((entry) => entry.confirmed === true));
      }
      assert.equal(mutations, 0);
      assert.deepEqual(leaves, ["owner/personal", "owner/team"]);
      Object.assign(u.properties, { ActiveState: "inactive", MainPID: "0", ControlGroup: "" });
      const result = await uninstallFlock({ ...options,
        checkPersistence: (paths) => assertLinuxUnitsQuiescent(paths, { query: u.query }),
        disable: (filename, paths) => disablePersistence(filename, paths, { query: u.query }),
        removeTasks: async () => [], stopDaemon: async () => {}, findProcesses: async () => [],
      });
      assert.equal(result.fullyRemoved, true, JSON.stringify(result));
      assert.deepEqual(leaves, ["owner/personal", "owner/team"], "Retry must not repeat acknowledged leaves");
      assert.equal(u.commands.some((args) => args.includes("--now") || args.includes("stop")), false);
      assert.equal(fs.readFileSync(path.join(f.preserved, "events.jsonl"), "utf8"), "conversation");
    } finally { f.close(); }
  }
});

test("Linux disable rechecks quiescence and never stops a unit or removes skills after a service failure", async () => {
  const f = fixture("linux");
  try {
    for (const filename of [f.paths.persistence[0], f.paths.skills[0]]) {
      fs.mkdirSync(path.dirname(filename), { recursive: true });
      fs.writeFileSync(filename, "owned");
      recordInstalledArtifact(f.root, filename, f.paths);
    }
    const u = unitFixture(f.paths);
    let stops = 0;
    const result = await uninstallFlock({ paths: f.paths, leave: confirm,
      checkPersistence: (paths) => assertLinuxUnitsQuiescent(paths, { query: u.query }),
      removeTasks: async () => { u.properties.ActiveState = "active"; return []; },
      disable: (filename, paths) => disablePersistence(filename, paths, { query: u.query }),
      stopDaemon: async () => { stops++; },
    });
    assert.equal(result.fullyRemoved, false);
    assert.deepEqual(result.removed, []);
    assert.equal(stops, 0);
    assert.equal(u.commands.some((args) => args[0] === "disable"), false);
    for (const filename of [f.paths.persistence[0], f.paths.skills[0], path.join(f.root, "identity.json")]) {
      assert.ok(fs.existsSync(filename));
    }
  } finally { f.close(); }
});

test("Linux rechecks unit activation before pinned-daemon stop even after persistence removal", async () => {
  const f = fixture("linux");
  try {
    const filename = f.paths.persistence[0];
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    fs.writeFileSync(filename, "owned");
    recordInstalledArtifact(f.root, filename, f.paths);
    const u = unitFixture(f.paths);
    let stops = 0;
    const result = await uninstallFlock({ paths: f.paths, leave: confirm,
      checkPersistence: (paths) => assertLinuxUnitsQuiescent(paths, { query: u.query }),
      removeTasks: async () => [],
      disable: async (target, paths) => {
        await disablePersistence(target, paths, { query: u.query });
        Object.assign(u.properties, { ActiveState: "active", MainPID: "456" });
      },
      stopDaemon: async () => { stops++; },
    });
    assert.equal(result.fullyRemoved, false);
    assert.equal(stops, 0);
    assert.deepEqual(u.commands.filter((args) => args[0] === "disable"), [["disable", path.basename(filename)]]);
    assert.ok(fs.existsSync(path.join(f.root, "identity.json")));
    assert.ok(fs.existsSync(path.join(f.root, "flock.mjs")));
    assert.ok(fs.existsSync(path.join(f.root, "uninstall-progress.json")));
  } finally { f.close(); }
});

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
        checkPersistence: async () => {},
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
      checkPersistence: async () => {},
      findProcesses: () => findRuntimeClients(f.paths, options) });
    assert.equal(retained.fullyRemoved, false);
    assert.ok(retained.retained.some((entry) => entry.path === "Process:42"));
    assert.ok(fs.existsSync(path.join(f.root, "identity.json")));
    const removed = await uninstallFlock({ paths: f.paths, leave: confirm, removeTasks: async () => [],
      checkPersistence: async () => {},
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

test("Windows daemon ownership accepts independent executable and script quoting with exact process pins", async () => {
  const f = fixture();
  try {
    const pid = 123456;
    fs.writeFileSync(path.join(f.root, "daemon.pid"), String(pid));
    const plainScript = path.join(f.root, "flock.mjs");
    const spacedScript = path.join(f.root, "with spaces", "flock.mjs");
    const spacedExe = "C:\\Program Files\\nodejs\\node.exe";
    const plainExe = "C:\\Node\\node.exe";
    for (const [executable, script, command] of [
      [spacedExe, spacedScript, `"${spacedExe}" "${spacedScript}" daemon`],
      [spacedExe, plainScript, `"${spacedExe}" ${plainScript} daemon`],
      [plainExe, spacedScript, `${plainExe} "${spacedScript}" daemon`],
      [plainExe, plainScript, `${plainExe} ${plainScript} daemon`],
    ]) {
      const live = { pid, start: "created", executable, command };
      atomicJson(path.join(f.root, "daemon-identity.json"), { ...live, script });
      let killed = 0;
      await stopPinnedDaemon(f.root, { ...f.paths, scripts: [script] }, {
        inspect: () => killed ? null : live,
        kill: (target) => { assert.equal(target, pid); killed++; },
      });
      assert.equal(killed, 1, `Exact pinned daemon was not recognized: ${command}`);
    }
  } finally { f.close(); }
});

test("Windows daemon quoting never admits extra arguments, different scripts or a changed creation identity", async () => {
  const f = fixture();
  try {
    const pid = 123456;
    const executable = "C:\\Program Files\\nodejs\\node.exe";
    const script = path.join(f.root, "flock.mjs");
    const command = `"${executable}" ${script} daemon`;
    fs.writeFileSync(path.join(f.root, "daemon.pid"), String(pid));
    let killed = 0;
    for (const invalid of [
      `${command} --other`, `${command} && other`, `"${executable}" ${script}.other daemon`,
      `"${executable}" ${script} not-daemon`,
    ]) {
      const live = { pid, start: "created", executable, command: invalid };
      atomicJson(path.join(f.root, "daemon-identity.json"), { ...live, script });
      await stopPinnedDaemon(f.root, f.paths, { inspect: () => live, kill: () => killed++ });
      assert.equal(killed, 0);
    }
    const live = { pid, start: "created", executable, command };
    atomicJson(path.join(f.root, "daemon-identity.json"), { ...live, start: "reused", script });
    await assert.rejects(stopPinnedDaemon(f.root, f.paths, { inspect: () => live, kill: () => killed++ }),
      /stored creation identity/);
    atomicJson(path.join(f.root, "daemon-identity.json"), { ...live, script });
    let reads = 0;
    await assert.rejects(stopPinnedDaemon(f.root, f.paths, {
      inspect: () => ++reads === 1 ? live : { ...live, start: "replaced" },
      kill: () => killed++,
    }), /identity changed/);
    assert.equal(killed, 0);
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
  if (command === "systemctl" && JSON.stringify(args) === JSON.stringify(["--user", "list-units", "--all", "--output=json", "--no-pager", "--type=service", "copilot-flock.service", "copilot-signalr-bridge.service"])) return "[]";
  if (command === "systemctl" && JSON.stringify(args) === JSON.stringify(["--user", "disable", path.basename(process.env.FIXTURE_PERSISTENCE)])) return "";
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

test("Linux systemd unit generation sets KillMode=process and persistence avoids disable --now", () => {
  const f = fixture("linux");
  try {
    const script = path.join(f.root, "flock.mjs");
    const unitText = buildLinuxSystemdUnit({ home: f.home, targetScript: script, execPath: "/opt/node/bin/node" });
    assert.match(unitText, /\nKillMode=process\n/);
    assert.match(unitText, /\nRestart=always\n/);
    assert.match(unitText, /ExecStart="\/opt\/node\/bin\/node" /);

    const legacyPath = f.paths.persistence[1];
    fs.mkdirSync(path.dirname(legacyPath), { recursive: true });
    fs.writeFileSync(legacyPath, "legacy-unit", "utf8");
    const commands = [];
    let legacyActive = true;
    const query = (args) => {
      commands.push(args);
      if (args[0] === "show" && args[1] === "copilot-signalr-bridge.service") {
        return [
          "Id=copilot-signalr-bridge.service",
          "LoadState=loaded",
          `FragmentPath=${legacyPath}`,
          `ActiveState=${legacyActive ? "active" : "inactive"}`,
          `MainPID=${legacyActive ? "4100" : "0"}`,
          `ControlGroup=${legacyActive ? "/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-signalr-bridge.service" : ""}`,
        ].join("\n") + "\n";
      }
      return "";
    };
    const activeMigration = configureLinuxSystemdPersistence(script, f.paths, {
      strict: true,
      execPath: process.execPath,
      query,
      checkLinger: () => "yes\n",
      username: () => "demo",
    });
    assert.equal(activeMigration.killMode, "process");
    assert.equal(activeMigration.systemdReady, true);
    assert.match(fs.readFileSync(f.paths.persistence[0], "utf8"), /\nKillMode=process\n/);
    assert.equal(commands.some((args) => args.includes("--now")), false, "Must never run disable --now on active legacy unit");
    assert.equal(fs.existsSync(legacyPath), true, "Active legacy unit remains on disk until guarded activation handoff");

    legacyActive = false;
    configureLinuxSystemdPersistence(script, f.paths, {
      strict: true,
      execPath: process.execPath,
      query,
      checkLinger: () => "yes\n",
      username: () => "demo",
    });
    assert.equal(fs.existsSync(legacyPath), false, "Quiescent legacy unit is cleaned up after disable without --now");
  } finally { f.close(); }
});

test("outside-cgroup child supervision wraps Linux service children in transient user scopes", () => {
  const serviceCgroup = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-flock.service\n";
  const scopeCgroup = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/terminal.scope\n";

  const wrapped = prepareOutsideLinuxServiceCgroupSpawn("/usr/bin/copilot", ["-p", "hello"], {
    platform: "linux",
    pid: 2000,
    uid: 1000,
    read: () => serviceCgroup,
    probeScope: () => true,
    unitPrefix: "copilot-flock-session",
    unitId: "req-42",
  });
  assert.equal(wrapped.supervisedOutsideCgroup, true);
  assert.equal(wrapped.mode, "systemd-transient-scope");
  assert.equal(wrapped.scopeUnit, "copilot-flock-session-req-42.scope");
  assert.equal(wrapped.command, "systemd-run");
  assert.deepEqual(wrapped.args, [
    "--user", "--scope", "--collect", "--quiet", "--unit=copilot-flock-session-req-42",
    "--", "/usr/bin/copilot", "-p", "hello",
  ]);

  let spawnedCall = null;
  const child = spawnSessionSafeProcess("/usr/bin/copilot", ["-p", "hello"], { cwd: "/tmp" }, {
    platform: "linux",
    pid: 2000,
    uid: 1000,
    read: () => serviceCgroup,
    probeScope: () => true,
    unitId: "abc",
    spawnImpl: (cmd, args, opts) => {
      spawnedCall = { cmd, args, opts };
      return { pid: 9999 };
    },
  });
  assert.equal(spawnedCall.cmd, "systemd-run");
  assert.equal(child.outsideCgroupSupervision.mode, "systemd-transient-scope");

  const alreadyOutside = prepareOutsideLinuxServiceCgroupSpawn("/usr/bin/copilot", ["-p", "hello"], {
    platform: "linux",
    pid: 2000,
    uid: 1000,
    read: () => scopeCgroup,
    probeScope: () => { throw new Error("Should not probe systemd-run when already outside .service cgroup"); },
  });
  assert.equal(alreadyOutside.supervisedOutsideCgroup, true);
  assert.equal(alreadyOutside.mode, "already-outside-service-cgroup");
  assert.equal(alreadyOutside.command, "/usr/bin/copilot");

  assert.throws(() => prepareOutsideLinuxServiceCgroupSpawn("/usr/bin/copilot", [], {
    platform: "linux",
    pid: 2000,
    uid: 1000,
    read: () => serviceCgroup,
    probeScope: () => false,
    requireOutsideCgroup: true,
    unitId: "strict-1",
  }), /outside-cgroup transient scope supervision is unavailable/);

  const fallback = prepareOutsideLinuxServiceCgroupSpawn("/usr/bin/copilot", ["-s"], {
    platform: "linux",
    pid: 2000,
    uid: 1000,
    read: () => serviceCgroup,
    probeScope: () => false,
    unitId: "fallback-1",
  });
  assert.equal(fallback.supervisedOutsideCgroup, false);
  assert.equal(fallback.mode, "service-cgroup-fallback");
});

test("Linux activation preserves real active child PID/start-time, signals only pinned daemon, and restores policy on success or failure", async (t) => {
  const f = fixture("linux");
  const liveChild = spawn(process.execPath, ["-e", "setInterval(() => {}, 60000)"], { stdio: "ignore", windowsHide: true });
  t.after(() => {
    try { liveChild.kill(); } catch {}
    f.close();
  });
  await new Promise((resolve, reject) => {
    liveChild.once("spawn", resolve);
    liveChild.once("error", reject);
  });
  const initialChildIdentity = inspectProcess(liveChild.pid);
  assert.ok(initialChildIdentity?.start, "Expected real OS process identity for active child");

  const script = path.join(f.root, "flock.mjs");
  const unitPath = f.paths.persistence[0];
  const dropInPath = `${unitPath}.d${path.sep}90-flock-session-handoff.conf`;
  fs.mkdirSync(path.dirname(unitPath), { recursive: true });
  fs.writeFileSync(unitPath, buildLinuxSystemdUnit({ home: f.home, targetScript: script }), "utf8");

  // Also verify recursive cgroup.procs enumeration with nested sub-cgroups
  const cgroupRoot = path.join(f.home, "fake-cgroup");
  const controlGroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-flock.service";
  const nestedCgroupDir = path.join(cgroupRoot, ...controlGroup.split("/").filter(Boolean), "child-subscope");
  fs.mkdirSync(nestedCgroupDir, { recursive: true });
  const daemonPid = 424242;
  const newDaemonPid = 434343;
  fs.writeFileSync(path.join(path.dirname(nestedCgroupDir), "cgroup.procs"), `${daemonPid}\n`, "utf8");
  fs.writeFileSync(path.join(nestedCgroupDir, "cgroup.procs"), `${liveChild.pid}\n`, "utf8");
  assert.deepEqual(readLinuxCgroupPids(controlGroup, { cgroupRoot }).sort((a, b) => a - b),
    [liveChild.pid, daemonPid].sort((a, b) => a - b));

  const daemonLive = {
    pid: daemonPid,
    start: "boot:daemon-v1",
    executable: process.execPath,
    argv: [process.execPath, script, "daemon"],
  };
  const newDaemonLive = {
    pid: newDaemonPid,
    start: "boot:daemon-v2",
    executable: process.execPath,
    argv: [process.execPath, script, "daemon"],
  };
  fs.writeFileSync(path.join(f.root, "daemon.pid"), String(daemonPid), "utf8");
  atomicJson(path.join(f.root, "daemon-identity.json"), { ...daemonLive, script });

  const state = {
    activeState: "active",
    mainPid: String(daemonPid),
    killMode: "process",
    restart: "always",
    forceIgnoreDropIn: false,
    failStart: false,
    daemonRunning: true,
    reloads: 0,
    commands: [],
  };
  const readEffectivePolicy = () => {
    if (!state.forceIgnoreDropIn && fs.existsSync(dropInPath)) {
      const content = fs.readFileSync(dropInPath, "utf8");
      return {
        killMode: /KillMode=(\S+)/.exec(content)?.[1] || state.killMode,
        restart: /Restart=(\S+)/.exec(content)?.[1] || state.restart,
      };
    }
    return { killMode: state.killMode, restart: state.restart };
  };
  const query = (args) => {
    state.commands.push(args);
    if (args[0] === "list-units") return JSON.stringify([{ unit: "copilot-flock.service" }]);
    if (args[0] === "daemon-reload") { state.reloads++; return ""; }
    if (args[0] === "show" && args[1] === "copilot-flock.service") {
      const eff = readEffectivePolicy();
      return [
        "Id=copilot-flock.service",
        "LoadState=loaded",
        `FragmentPath=${unitPath}`,
        `ActiveState=${state.activeState}`,
        `MainPID=${state.mainPid}`,
        `ControlGroup=${controlGroup}`,
        `KillMode=${eff.killMode}`,
        `Restart=${eff.restart}`,
      ].join("\n") + "\n";
    }
    if (args[0] === "start" && args[1] === "copilot-flock.service") {
      assert.equal(fs.existsSync(dropInPath), false, "Handoff drop-in must be removed before starting new daemon");
      if (state.failStart) throw new Error("simulated systemd start failure");
      state.activeState = "active";
      state.mainPid = String(newDaemonPid);
      return "";
    }
    throw new Error(`Unexpected systemctl command: ${args.join(" ")}`);
  };
  const inspect = (pid) => {
    if (pid === liveChild.pid) {
      try {
        process.kill(liveChild.pid, 0);
        return { pid: liveChild.pid, start: initialChildIdentity.start, executable: initialChildIdentity.executable, argv: [initialChildIdentity.executable] };
      } catch {
        return null;
      }
    }
    if (pid === daemonPid) return state.daemonRunning ? daemonLive : null;
    if (pid === newDaemonPid) return state.mainPid === String(newDaemonPid) ? newDaemonLive : null;
    return null;
  };

  // 1. Failure path: if higher-precedence override blocks handoff policy, refuse with 0 signals and restore drop-in
  state.forceIgnoreDropIn = true;
  const refusedSignals = [];
  await assert.rejects(activateLinuxSystemdDaemon({
    root: f.root,
    paths: f.paths,
    uid: 1000,
    query,
    inspect,
    readCgroup: () => `0::${controlGroup}\n`,
    readCgroupProcs: (cg) => readLinuxCgroupPids(cg, { cgroupRoot }),
    kill: (pid) => refusedSignals.push(pid),
    delay: async () => {},
  }), /did not adopt session-preserving handoff policy/);
  assert.deepEqual(refusedSignals, []);
  assert.equal(fs.existsSync(dropInPath), false, "Temporary handoff drop-in must be cleaned up on refusal");
  assert.equal(fs.existsSync(`${unitPath}.d`), false, "Created .service.d directory must be cleaned up on refusal");

  // 2. Failure path: start fails after pinned daemon stop -> original policy is still restored and active child survives
  state.forceIgnoreDropIn = false;
  state.failStart = true;
  const failedStartSignals = [];
  await assert.rejects(activateLinuxSystemdDaemon({
    root: f.root,
    paths: f.paths,
    uid: 1000,
    query,
    inspect,
    readCgroup: () => `0::${controlGroup}\n`,
    readCgroupProcs: (cg) => readLinuxCgroupPids(cg, { cgroupRoot }),
    kill: (pid) => {
      failedStartSignals.push(pid);
      // Confirm KillMode=process and Restart=no are active at the exact moment the daemon is signaled
      assert.deepEqual(readEffectivePolicy(), { killMode: "process", restart: "no" });
      state.daemonRunning = false;
      state.activeState = "inactive";
      state.mainPid = "0";
    },
    delay: async () => {},
  }), /simulated systemd start failure/);
  assert.deepEqual(failedStartSignals, [daemonPid]);
  assert.equal(fs.existsSync(dropInPath), false, "Original policy must be restored when start fails");
  assert.deepEqual(readEffectivePolicy(), { killMode: "process", restart: "always" });
  assert.equal(inspectProcess(liveChild.pid)?.start, initialChildIdentity.start, "Active child must survive failed start");

  // 3. Happy path: active daemon restarts cleanly, signaling ONLY pinned daemon, restoring policy, preserving live child PID + start time
  state.failStart = false;
  state.daemonRunning = true;
  state.activeState = "active";
  state.mainPid = String(daemonPid);
  state.commands.length = 0;
  const signals = [];
  const activated = await activateLinuxSystemdDaemon({
    root: f.root,
    paths: f.paths,
    uid: 1000,
    query,
    inspect,
    readCgroup: () => `0::${controlGroup}\n`,
    readCgroupProcs: (cg) => readLinuxCgroupPids(cg, { cgroupRoot }),
    kill: (pid) => {
      signals.push(pid);
      assert.deepEqual(readEffectivePolicy(), { killMode: "process", restart: "no" });
      state.daemonRunning = false;
      state.activeState = "inactive";
      state.mainPid = "0";
    },
    delay: async () => {},
  });
  assert.equal(activated.activated, true);
  assert.equal(activated.mode, "restarted-session-preserving");
  assert.equal(activated.pid, newDaemonPid);
  assert.equal(activated.policyRestored, true);
  assert.deepEqual(signals, [daemonPid], "Only the pinned daemon process may be signaled");
  assert.equal(state.commands.some((args) => args[0] === "restart" || args[0] === "stop"), false);
  assert.equal(fs.existsSync(dropInPath), false);
  const afterChildIdentity = inspectProcess(liveChild.pid);
  assert.ok(afterChildIdentity, "Real child process must still be alive after daemon restart");
  assert.equal(afterChildIdentity.pid, initialChildIdentity.pid);
  assert.equal(afterChildIdentity.start, initialChildIdentity.start);
  assert.deepEqual(activated.preservedChildren, [{ pid: liveChild.pid, start: initialChildIdentity.start }]);
});

test("Linux activation refuses unproven child-preservation paths before signalling unless explicit maintenance consent is supplied", async () => {
  const f = fixture("linux");
  try {
    const script = path.join(f.root, "flock.mjs");
    const unitPath = f.paths.persistence[0];
    fs.mkdirSync(path.dirname(unitPath), { recursive: true });
    fs.writeFileSync(unitPath, buildLinuxSystemdUnit({ home: f.home, targetScript: script }), "utf8");
    const controlGroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-flock.service";
    const daemonPid = 515151;
    const daemonLive = {
      pid: daemonPid,
      start: "boot:pinned",
      executable: process.execPath,
      argv: [process.execPath, script, "daemon"],
    };

    const makeScenario = (overrides = {}) => {
      const commands = [];
      const signals = [];
      let restarted = false;
      const props = {
        Id: "copilot-flock.service",
        LoadState: "loaded",
        FragmentPath: unitPath,
        ActiveState: "active",
        MainPID: String(daemonPid),
        ControlGroup: controlGroup,
        KillMode: "process",
        Restart: "always",
        ...overrides.props,
      };
      const query = (args) => {
        commands.push(args);
        if (args[0] === "list-units") return JSON.stringify([{ unit: "copilot-flock.service" }]);
        if (args[0] === "show") {
          return Object.entries({
            ...props,
            ...(restarted ? { ActiveState: "active", MainPID: "626262" } : {}),
          }).map(([k, v]) => `${k}=${v}`).join("\n") + "\n";
        }
        if (args[0] === "restart") { restarted = true; return ""; }
        return "";
      };
      return { commands, signals, query };
    };

    // Case A: Missing daemon-identity.json pin -> refuses with 0 signals and 0 systemctl restart/stop
    fs.writeFileSync(path.join(f.root, "daemon.pid"), String(daemonPid), "utf8");
    const unpinned = makeScenario();
    await assert.rejects(activateLinuxSystemdDaemon({
      root: f.root,
      paths: f.paths,
      uid: 1000,
      query: unpinned.query,
      inspect: (pid) => pid === daemonPid ? daemonLive : null,
      readCgroup: () => `0::${controlGroup}\n`,
      readCgroupProcs: () => [daemonPid, 7777],
      kill: (pid) => unpinned.signals.push(pid),
      delay: async () => {},
    }), /without explicit maintenance consent/);
    assert.deepEqual(unpinned.signals, []);
    assert.equal(unpinned.commands.some((args) => args[0] === "restart" || args[0] === "stop"), false);

    // Case B: Pinned daemon, but target unit KillMode=control-group -> refuses with 0 signals
    atomicJson(path.join(f.root, "daemon-identity.json"), { ...daemonLive, script });
    const controlGroupKillMode = makeScenario({ props: { KillMode: "control-group" } });
    await assert.rejects(activateLinuxSystemdDaemon({
      root: f.root,
      paths: f.paths,
      uid: 1000,
      query: controlGroupKillMode.query,
      inspect: (pid) => pid === daemonPid ? daemonLive : null,
      readCgroup: () => `0::${controlGroup}\n`,
      readCgroupProcs: () => [daemonPid],
      kill: (pid) => controlGroupKillMode.signals.push(pid),
      delay: async () => {},
    }), /KillMode=control-group.*without explicit maintenance consent/);
    assert.deepEqual(controlGroupKillMode.signals, []);
    assert.equal(controlGroupKillMode.commands.some((args) => args[0] === "restart" || args[0] === "stop"), false);

    // Case C: Unreadable cgroup.procs -> refuses with 0 signals
    const unreadableProcs = makeScenario();
    await assert.rejects(activateLinuxSystemdDaemon({
      root: f.root,
      paths: f.paths,
      uid: 1000,
      query: unreadableProcs.query,
      inspect: (pid) => pid === daemonPid ? daemonLive : null,
      readCgroup: () => `0::${controlGroup}\n`,
      readCgroupProcs: () => { throw Object.assign(new Error("permission denied"), { code: "EACCES" }); },
      kill: (pid) => unreadableProcs.signals.push(pid),
      delay: async () => {},
    }), /Cannot inspect cgroup processes.*without explicit maintenance consent/);
    assert.deepEqual(unreadableProcs.signals, []);

    // Case D: Explicit maintenance consent permits managed restart when KillMode/pin was unproven
    const consented = makeScenario({ props: { KillMode: "control-group" } });
    const consentedRes = await activateLinuxSystemdDaemon({
      root: f.root,
      paths: f.paths,
      uid: 1000,
      maintenanceConsent: true,
      query: consented.query,
      inspect: (pid) => pid === daemonPid ? daemonLive : pid === 626262 ? { ...daemonLive, pid: 626262, start: "boot:new" } : null,
      readCgroup: () => `0::${controlGroup}\n`,
      readCgroupProcs: () => [daemonPid],
      kill: (pid) => consented.signals.push(pid),
      delay: async () => {},
    });
    assert.equal(consentedRes.activated, true);
    assert.equal(consentedRes.mode, "maintenance-restart");
    assert.equal(consentedRes.maintenanceConsentUsed, true);
    assert.equal(consentedRes.pid, 626262);

    // Case E: Unowned third-party/system service cgroup is refused EVEN WITH maintenance consent
    const thirdParty = makeScenario();
    await assert.rejects(activateLinuxSystemdDaemon({
      root: f.root,
      paths: f.paths,
      uid: 1000,
      maintenanceConsent: true,
      query: thirdParty.query,
      inspect: (pid) => pid === daemonPid ? daemonLive : null,
      readCgroup: () => "0::/system.slice/third-party-worker.service\n",
      readCgroupProcs: () => [daemonPid],
      kill: (pid) => thirdParty.signals.push(pid),
      delay: async () => {},
    }), /unowned service cgroup/);
    assert.deepEqual(thirdParty.signals, []);
    assert.equal(thirdParty.commands.some((args) => args[0] === "restart" || args[0] === "stop"), false);

    // Case F: Active legacy copilot-signalr-bridge.service (KillMode=control-group) hands off to copilot-flock.service preserving children
    const legacyRoot = f.paths.roots[1];
    fs.mkdirSync(legacyRoot, { recursive: true });
    const legacyScript = path.join(legacyRoot, "bridge.mjs");
    fs.writeFileSync(legacyScript, 'export const BRIDGE_VERSION = "test";\nexport async function runDaemon() {}', "utf8");
    const legacyUnitPath = f.paths.persistence[1];
    fs.writeFileSync(legacyUnitPath, "legacy-control-group-unit", "utf8");
    fs.unlinkSync(path.join(f.root, "daemon.pid"));
    fs.unlinkSync(path.join(f.root, "daemon-identity.json"));
    const legacyDaemon = {
      pid: 717171,
      start: "boot:legacy-daemon",
      executable: process.execPath,
      argv: [process.execPath, legacyScript, "daemon"],
    };
    const survivingChild = { pid: 818181, start: "boot:active-copilot-child", executable: process.execPath, argv: ["copilot"] };
    fs.writeFileSync(path.join(legacyRoot, "daemon.pid"), String(legacyDaemon.pid), "utf8");
    atomicJson(path.join(legacyRoot, "daemon-identity.json"), { ...legacyDaemon, script: legacyScript });
    const legacyCg = "/user.slice/user-1000.slice/user@1000.service/app.slice/copilot-signalr-bridge.service";
    const legacyDropIn = `${legacyUnitPath}.d${path.sep}90-flock-session-handoff.conf`;
    let legacyRunning = true;
    let newStarted = false;
    const legacySignals = [];
    const legacyCommands = [];
    const legacyQuery = (args) => {
      legacyCommands.push(args);
      if (args[0] === "list-units") {
        return JSON.stringify([{ unit: "copilot-flock.service" }, { unit: "copilot-signalr-bridge.service" }]);
      }
      if (args[0] === "show" && args[1] === "copilot-signalr-bridge.service") {
        const dropInActive = fs.existsSync(legacyDropIn);
        return [
          "Id=copilot-signalr-bridge.service",
          "LoadState=loaded",
          `FragmentPath=${legacyUnitPath}`,
          `ActiveState=${legacyRunning ? "active" : "inactive"}`,
          `MainPID=${legacyRunning ? String(legacyDaemon.pid) : "0"}`,
          `ControlGroup=${legacyCg}`,
          `KillMode=${dropInActive ? "process" : "control-group"}`,
          `Restart=${dropInActive ? "no" : "always"}`,
        ].join("\n") + "\n";
      }
      if (args[0] === "show" && args[1] === "copilot-flock.service") {
        return [
          "Id=copilot-flock.service",
          "LoadState=loaded",
          `FragmentPath=${unitPath}`,
          `ActiveState=${newStarted ? "active" : "inactive"}`,
          `MainPID=${newStarted ? "919191" : "0"}`,
          "ControlGroup=",
          "KillMode=process",
          "Restart=always",
        ].join("\n") + "\n";
      }
      if (args[0] === "start" && args[1] === "copilot-flock.service") { newStarted = true; return ""; }
      return "";
    };
    const handoff = await activateLinuxSystemdDaemon({
      root: f.root,
      paths: f.paths,
      uid: 1000,
      query: legacyQuery,
      inspect: (pid) => {
        if (pid === legacyDaemon.pid) return legacyRunning ? legacyDaemon : null;
        if (pid === survivingChild.pid) return survivingChild;
        if (pid === 919191) return newStarted ? { ...daemonLive, pid: 919191, start: "boot:new-flock" } : null;
        return null;
      },
      readCgroup: () => `0::${legacyCg}\n`,
      readCgroupProcs: () => legacyRunning ? [legacyDaemon.pid, survivingChild.pid] : [survivingChild.pid],
      kill: (pid) => {
        assert.equal(fs.existsSync(legacyDropIn), true, "Legacy KillMode=control-group unit must have KillMode=process drop-in active before signal");
        legacySignals.push(pid);
        legacyRunning = false;
      },
      delay: async () => {},
    });
    assert.deepEqual(legacySignals, [legacyDaemon.pid]);
    assert.equal(handoff.pid, 919191);
    assert.equal(fs.existsSync(legacyDropIn), false, "Temporary handoff drop-in on legacy unit must be restored");
    assert.equal(fs.existsSync(legacyUnitPath), true, "Legacy unit with surviving child cgroup remains disabled without deletion");
    assert.equal(legacyCommands.some((args) => args.includes("--now") || args[0] === "stop"), false);
    assert.deepEqual(handoff.preservedChildren, [{ pid: survivingChild.pid, start: survivingChild.start }]);
  } finally { f.close(); }
});

