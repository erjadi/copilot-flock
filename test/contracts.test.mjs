import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as flock from "../flock.mjs";
import * as bridge from "../bridge.mjs";

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
