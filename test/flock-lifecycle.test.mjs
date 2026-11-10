import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { lifecyclePaths, atomicJson, recordInstalledArtifact, uninstallFlock as runUninstall, stopPinnedDaemon,
  assertNoLinks, inspectProcess } from "../flock-lifecycle.mjs";
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
    const f = fixture();
    try {
      const preload = path.join(f.home, "isolate.mjs");
      fs.writeFileSync(preload, `
import os from "node:os";
import cp from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
os.homedir = () => process.env.FIXTURE_HOME;
cp.execFileSync = (command, args) => {
  if (command === "powershell.exe" && /FLOCK_TASK_NAMES|FLOCK_RUNTIME_SCRIPTS/.test(args.at(-1))) return "[]";
  throw new Error("Unexpected native command in isolated uninstall fixture: " + command);
};
syncBuiltinESMExports();
`);
      const env = { ...process.env, COPILOT_HOME: f.paths.copilotHome, FIXTURE_HOME: f.home,
        APPDATA: path.join(f.home, "AppData", "Roaming") };
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
