import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as flock from "../flock.mjs";
import * as bridge from "../bridge.mjs";
import * as broker from "../bootstrap-server.mjs";

test("scope and address inputs reject retired private aliases and invalid values", () => {
  for (const normalize of [flock.normalizeScope, bridge.normalizeScope, broker.normalizeV3Scope]) {
    assert.equal(normalize("personal"), "personal");
    assert.equal(normalize(" WORK "), "work");
    assert.equal(normalize(undefined, null), null);
    for (const scope of ["private", "PRIVATE", "unknown", "corp", "corporate", false, 0]) {
      assert.throws(() => normalize(scope), { code: "INVALID_SCOPE" });
    }
    assert.throws(() => normalize(undefined, "private"), { code: "INVALID_SCOPE" });
  }
  for (const api of [flock, bridge, broker]) {
    assert.throws(() => api.parseFlockAddress("example/private/EXAMPLE-PC"), { code: "INVALID_SCOPE" });
    assert.equal(api.parseFlockAddress("example/personal/EXAMPLE-PC").canonicalPath, "example/personal/EXAMPLE-PC");
  }
});

test("legacy stored-scope migration preserves identity, enrollment and recovery/session metadata", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-scope-migration-"));
  const keys = ["COPILOT_HOME", "COPILOT_BRIDGE_SCOPE", "COPILOT_FLOCK_SCOPE",
    "COPILOT_BRIDGE_SANDBOX", "COPILOT_FLOCK_SANDBOX", "COPILOT_BRIDGE_GITHUB_USER"];
  const previous = new Map(keys.map((key) => [key, process.env[key]]));
  for (const key of keys) delete process.env[key];
  process.env.COPILOT_BRIDGE_GITHUB_USER = "example";
  try {
    for (const [index, api] of [flock, bridge].entries()) {
      process.env.COPILOT_HOME = path.join(root, String(index));
      const home = path.join(process.env.COPILOT_HOME, "flock");
      fs.mkdirSync(home, { recursive: true });
      const configPath = path.join(home, "config.json");
      const original = JSON.stringify({
        scope: "private", machineId: "EXAMPLE-PC", githubUser: "example",
        connectionString: "Endpoint=https://example.invalid;AccessKey=synthetic;",
        specs: { cpu: { model: "Synthetic CPU" } },
        coordinatorSessionId: "synthetic-coordinator", threadTrackerSessionId: "synthetic-tracker",
        recoveryMarker: "synthetic-recovery-preserved",
      });
      fs.writeFileSync(configPath, original, { mode: 0o600 });
      fs.writeFileSync(path.join(home, "identity.json"), "synthetic identity must remain unchanged");
      fs.writeFileSync(path.join(home, "flocks.json"), "synthetic enrollment must remain unchanged");
      assert.equal(api.loadConfig({ autoFetchAz: false }).scope, "personal");
      const migrated = JSON.parse(fs.readFileSync(configPath, "utf8"));
      assert.equal(migrated.scope, "personal");
      assert.equal(migrated.coordinatorSessionId, "synthetic-coordinator");
      assert.equal(migrated.threadTrackerSessionId, "synthetic-tracker");
      assert.equal(migrated.recoveryMarker, "synthetic-recovery-preserved");
      assert.equal(fs.readFileSync(`${configPath}.v2.bak.json`, "utf8"), original);
      assert.equal(fs.readFileSync(path.join(home, "identity.json"), "utf8"), "synthetic identity must remain unchanged");
      assert.equal(fs.readFileSync(path.join(home, "flocks.json"), "utf8"), "synthetic enrollment must remain unchanged");
    }
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("canonical and compatibility CLI help advertise personal for fresh and explicit legacy profiles", (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "flock-help-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  for (const script of ["flock.mjs", "bridge.mjs"]) {
    for (const architecture of [[], ["--architecture", "legacy"]]) {
      const result = spawnSync(process.execPath, [
        fileURLToPath(new URL(`../${script}`, import.meta.url)), ...architecture, "--help",
      ], { encoding: "utf8", timeout: 5000, env: {
        ...process.env, COPILOT_HOME: home, COPILOT_FLOCK_INVITE_FILE: "",
        COPILOT_FLOCK_BOOTSTRAP_URL: "", COPILOT_BRIDGE_SCOPE: "", COPILOT_FLOCK_SCOPE: "",
      } });
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, architecture.length ? /Copilot Flock v/ : /Copilot Flock .*Zero-Broker candidate/);
      assert.match(result.stdout, architecture.length ? /--scope work\|personal/ : /--scope <personal\|work>/);
      assert.doesNotMatch(result.stdout, /work\|private|Copilot SignalR Thread Bridge/);
    }
  }
});

function temporary(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-contracts-"));
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = root;
  t.after(() => {
    if (previous === undefined) delete process.env.COPILOT_HOME;
    else process.env.COPILOT_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  });
  return root;
}

test("Desktop control files validate first lines without accepting later metadata as credentials", (t) => {
  const root = temporary(t);
  const run = path.join(root, "run");
  fs.mkdirSync(run);
  for (const api of [flock, bridge]) {
    for (const newline of ["\n", "\r\n"]) {
      fs.writeFileSync(path.join(run, "ws.port"), `\uFEFF12345${newline}999`);
      fs.writeFileSync(path.join(run, "ws.token"), `\uFEFFsynthetic-token${newline}999`);
      assert.deepEqual(api.getLocalWsConnectionInfo(), { port: 12345, token: "synthetic-token" });
    }
    for (const port of ["", "\n12345", "0", "65536", "-1", "1.5", "1e3", "invalid"]) {
      fs.writeFileSync(path.join(run, "ws.port"), port);
      assert.throws(() => api.getLocalWsConnectionInfo(), /Invalid local Copilot Desktop control files/);
    }
    fs.writeFileSync(path.join(run, "ws.port"), "12345");
    for (const token of ["", "\nsynthetic-token", "invalid\u0000token"]) {
      fs.writeFileSync(path.join(run, "ws.token"), token);
      assert.throws(() => api.getLocalWsConnectionInfo(), /Invalid local Copilot Desktop control files/);
    }
    fs.unlinkSync(path.join(run, "ws.token"));
    assert.equal(api.getLocalWsConnectionInfo(), null);
  }
});

test("file transfer options reject unknown destinations and missing values", () => {
  for (const api of [flock, bridge]) {
    assert.throws(() => api.validateFileTransferCliArgs("invalid"), /Unsupported file-transfer/);
    assert.doesNotThrow(() => api.validateFileTransferCliArgs("send-file", { file: "example.txt", "remote-path": "target.txt" }));
    assert.doesNotThrow(() => api.validateFileTransferCliArgs("pull-file", {}, ["source.txt", "target.txt"]));
    for (const command of ["send-file", "pull-file"]) {
      for (const key of ["source", "dest", "remote"]) assert.throws(() => api.validateFileTransferCliArgs(command, { [key]: "example.txt" }), /Unknown option/);
      assert.throws(() => api.validateFileTransferCliArgs(command, { file: true }), /Missing value/);
      assert.throws(() => api.validateFileTransferCliArgs(command, {}), /Missing --/);
      assert.throws(() => api.validateFileTransferCliArgs(command, {}, ["a", "b", "c"]), /Too many positional/);
    }
  }
});

test("published legacy MCP scope filters use personal and current coordinator names", () => {
  for (const api of [flock, bridge]) {
    const tools = api.MCP_TOOLS.filter((tool) => tool.inputSchema.properties.scope);
    assert.equal(tools.length, 5);
    for (const tool of tools) {
      assert.deepEqual(tool.inputSchema.properties.scope.enum, ["work", "personal", "all"]);
      assert.doesNotMatch(tool.description, /\bprivate\b/);
    }
    const diagnostics = api.MCP_TOOLS.find((tool) => tool.name === "diagnose_bridge_fleet");
    assert.match(diagnostics.description, /Copilot Flock Coordinator/);
    assert.match(diagnostics.description, /Copilot Flock Thread Tracker/);
  }
});

test("legacy owner discovery is preserved without granting same-owner guests external access", (t) => {
  const root = temporary(t);
  const cfg = { machineId: "EXAMPLE-PC", scope: "personal", githubUser: "example" };
  for (const api of [flock, bridge]) {
    const statePath = path.join(root, "flocks.json");
    const config = api.loadLocalFlocksConfig(cfg, statePath);
    const request = { action: "get_transcript", params: { session: "unshared-session" } };
    for (const owner of [config.flocks.example, config.flocks["example/personal"]]) {
      assert.doesNotThrow(() => api.enforceFlockPolicyAndWalls(cfg, owner, request));
      for (const trustTier of ["collaborator", "guest"]) {
        const restricted = { ...owner, trustTier, sharedSessionIds: [], sharedSnapshots: {} };
        const caller = { fromGitHubUser: "example", senderVerified: true, isCrossUser: false };
        assert.throws(() => api.enforceFlockPolicyAndWalls(cfg, restricted, request, caller), { code: "SESSION_NOT_SHARED" });
        assert.throws(() => api.enforceFlockPolicyAndWalls(cfg, restricted, { action: "create_session" }, caller), { code: "FLOCK_MUTATION_FORBIDDEN" });
      }
    }
  }
});

test("ambiguous legacy offline dispatch is quarantined while ACK recovery never redispatches", async (t) => {
  const root = temporary(t);
  for (const [index, api] of [flock, bridge].entries()) {
    const requestId = `synthetic-uncertain-${index}`;
    const statePath = path.join(root, `state-${index}.json`);
    let dispatches = 0;
    const options = {
      statePath,
      drainFn: async () => ({ messages: [{ requestId, rpcPayload: { requestId, action: "send_message" } }] }),
      ackFn: async () => ({ ok: false }),
      handleFn: async () => { dispatches++; throw new Error("Synthetic failure after possible admission"); },
    };
    await api.drainAndProcessOfflineQueue({ machineId: "EXAMPLE-PC" }, options);
    await api.drainAndProcessOfflineQueue({ machineId: "EXAMPLE-PC" }, options);
    assert.equal(dispatches, 1);
    assert.deepEqual(api.loadProcessedOfflineState(statePath).ambiguousIds, [requestId]);
    assert.deepEqual(api.loadProcessedOfflineState(statePath).pendingAckIds, [requestId]);
    await api.drainAndProcessOfflineQueue({ machineId: "EXAMPLE-PC" }, { ...options, ackFn: async () => ({ ok: true }) });
    assert.equal(dispatches, 1);
    assert.deepEqual(api.loadProcessedOfflineState(statePath).pendingAckIds, []);
    assert.deepEqual(api.loadProcessedOfflineState(statePath).ambiguousIds, [requestId]);
  }
});

test("invalid transfer flags fail before profile initialization or daemon startup", (t) => {
  const root = temporary(t);
  for (const script of ["flock.mjs", "bridge.mjs"]) {
    const profile = path.join(root, script);
    const result = spawnSync(process.execPath, [fileURLToPath(new URL(`../${script}`, import.meta.url)), "send-file", "--file", "example.txt", "--dest", "target.txt"],
      { encoding: "utf8", timeout: 5000, env: { ...process.env, COPILOT_HOME: profile } });
    assert.equal(result.error, undefined);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unknown option "--dest"/);
    assert.equal(fs.existsSync(profile), false);
  }
});
