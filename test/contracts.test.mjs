import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as flock from "../flock.mjs";
import * as bridge from "../bridge.mjs";
import * as broker from "../bootstrap-server.mjs";
import { materializeReleaseCandidate } from "../zero-broker-release.mjs";

function git(directory, ...args) {
  return execFileSync("git", ["-C", directory, ...args], {
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  }).trim();
}

function releaseFixture(root) {
  const producer = path.join(root, "producer");
  const remote = path.join(root, "origin.git");
  const checkout = path.join(root, "checkout");
  fs.mkdirSync(producer);
  fs.mkdirSync(remote);
  git(remote, "init", "--quiet", "--bare");
  git(producer, "init", "--quiet", "--initial-branch=main");
  git(producer, "config", "user.name", "Synthetic Fixture");
  git(producer, "config", "user.email", "fixture@example.invalid");
  git(producer, "config", "core.autocrlf", "false");
  fs.writeFileSync(path.join(producer, "flock.mjs"), "export const VERSION = 'installed';\n");
  fs.copyFileSync(path.join(producer, "flock.mjs"), path.join(producer, "bridge.mjs"));
  fs.writeFileSync(path.join(producer, "zero-broker-fixture.mjs"), "export const fixture = true;\n");
  fs.writeFileSync(path.join(producer, "README.md"), "Installed source\n");
  git(producer, "add", ".");
  git(producer, "commit", "--quiet", "-m", "Synthetic installed source");
  const installed = git(producer, "rev-parse", "HEAD");
  git(producer, "remote", "add", "origin", remote);
  git(producer, "push", "--quiet", "origin", "main");
  git(root, "-c", "core.autocrlf=false", "clone", "--quiet", "--branch", "main", remote, checkout);
  git(checkout, "config", "user.name", "Synthetic Fixture");
  git(checkout, "config", "user.email", "fixture@example.invalid");
  git(checkout, "config", "core.autocrlf", "false");
  fs.writeFileSync(path.join(producer, "flock.mjs"), "export const VERSION = 'candidate';\n");
  fs.copyFileSync(path.join(producer, "flock.mjs"), path.join(producer, "bridge.mjs"));
  git(producer, "add", ".");
  git(producer, "commit", "--quiet", "-m", "Synthetic published candidate");
  const candidate = git(producer, "rev-parse", "HEAD");
  git(producer, "push", "--quiet", "origin", "main");
  const exec = (program, args, options) => {
    if (program === "git" && args.includes("fetch")) {
      assert.equal(args[1], checkout);
      assert.ok(args.includes("--no-write-fetch-head"));
      assert.ok(args.includes("https://github.com/erjadi/copilot-flock.git"));
      args = args.map((arg) => arg === "https://github.com/erjadi/copilot-flock.git" ? remote : arg);
    }
    return execFileSync(program, args, options);
  };
  return { producer, remote, checkout, installed, candidate, exec };
}

function namedFunction(source, name) {
  const start = source.search(new RegExp(`(?:export )?(?:async )?function ${name}\\(`));
  assert.ok(start >= 0, name);
  const next = source.slice(start + 1).search(/\n(?:export )?(?:async )?function [A-Za-z]/);
  return source.slice(start, next < 0 ? source.length : start + 1 + next).replace(/^export /, "");
}

test("pinned legacy release installation preserves user work, branch, origin and FETCH_HEAD", async (t) => {
  const root = temporary(t);
  const f = releaseFixture(root);
  git(f.checkout, "checkout", "--quiet", "-b", "user-work");
  fs.writeFileSync(path.join(f.checkout, "user-commit.txt"), "Unmerged user commit\n");
  git(f.checkout, "add", ".");
  git(f.checkout, "commit", "--quiet", "-m", "Synthetic unmerged work");
  fs.writeFileSync(path.join(f.checkout, "README.md"), "Staged user edit\n");
  git(f.checkout, "add", "README.md");
  fs.writeFileSync(path.join(f.checkout, "flock.mjs"), "Unstaged user edit\n");
  fs.writeFileSync(path.join(f.checkout, "untracked.txt"), "Untracked user work\n");
  git(f.checkout, "fetch", "--quiet", "origin", "main");
  const before = {
    head: git(f.checkout, "rev-parse", "HEAD"),
    branch: git(f.checkout, "branch", "--show-current"),
    status: git(f.checkout, "status", "--porcelain=v1", "--untracked-files=all"),
    origin: git(f.checkout, "remote", "get-url", "origin"),
    index: fs.readFileSync(path.join(f.checkout, ".git", "index")),
    fetch: fs.readFileSync(path.join(f.checkout, ".git", "FETCH_HEAD")),
  };
  for (const api of [flock, bridge]) {
    const release = await api.prepareBridgeReleaseSource(f.checkout, { exec: f.exec });
    assert.equal(release.commit, f.candidate);
    assert.equal(fs.readFileSync(release.scriptPath, "utf8"), "export const VERSION = 'candidate';\n");
    assert.equal(api.getInstalledSourceProvenance(release.directory).sourceCommit, f.candidate);
    const installed = api.installPreparedBridgeRelease(release, { scope: "personal", githubUser: "example" }, {
      exec: (program, args, options) => {
        assert.equal(program, process.execPath);
        assert.ok(args.includes(release.scriptPath));
        assert.deepEqual(args.slice(-6), ["--architecture", "legacy", "--scope", "personal", "--github-user", "example"]);
        assert.equal(options.cwd, release.directory);
        assert.equal(fs.readFileSync(release.scriptPath, "utf8"), "export const VERSION = 'candidate';\n");
        return '{"version":"synthetic-candidate","daemonPid":123}';
      },
    });
    assert.equal(installed.version, "synthetic-candidate");
    assert.equal(fs.existsSync(release.directory), false);
    const failed = await api.prepareBridgeReleaseSource(f.checkout, { exec: f.exec });
    assert.throws(() => api.installPreparedBridgeRelease(failed, { scope: "personal" }, {
      exec: () => { throw new Error("Synthetic installer failure"); },
    }), /Synthetic installer failure/);
    assert.equal(fs.existsSync(failed.directory), false);
    await assert.rejects(() => api.prepareBridgeReleaseSource(f.checkout, {
      exec: () => { throw new Error("Synthetic fetch failure"); },
    }), /Synthetic fetch failure/);
    assert.equal(git(f.checkout, "rev-parse", "HEAD"), before.head);
    assert.equal(git(f.checkout, "branch", "--show-current"), before.branch);
    assert.equal(git(f.checkout, "status", "--porcelain=v1", "--untracked-files=all"), before.status);
    assert.equal(git(f.checkout, "remote", "get-url", "origin"), before.origin);
    assert.deepEqual(fs.readFileSync(path.join(f.checkout, ".git", "index")), before.index);
    assert.deepEqual(fs.readFileSync(path.join(f.checkout, ".git", "FETCH_HEAD")), before.fetch);
    assert.equal(fs.readFileSync(path.join(f.checkout, "README.md"), "utf8"), "Staged user edit\n");
    assert.equal(fs.readFileSync(path.join(f.checkout, "flock.mjs"), "utf8"), "Unstaged user edit\n");
    assert.equal(fs.readFileSync(path.join(f.checkout, "untracked.txt"), "utf8"), "Untracked user work\n");
  }
});

test("repository lookup is read-only and reprovision refuses failed source preflight before local mutations", async (t) => {
  const root = temporary(t);
  const f = releaseFixture(root);
  for (const filename of ["flock.mjs", "bridge.mjs"]) {
    const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
    let mutations = 0;
    const context = vm.createContext({
      fs, path, __dirname: f.checkout, HOME_DIR: root,
      getBridgeHome: () => path.join(root, "profile"),
      getLegacyBridgeHome: () => path.join(root, "legacy"),
      execFileSync: () => assert.fail("Lookup must not change an existing repository"),
    });
    vm.runInContext(`${namedFunction(source, "resolveOrFindBridgeGitRepo")}\nthis.resolveRepo = resolveOrFindBridgeGitRepo;`, context);
    assert.equal(context.resolveRepo(), f.checkout);
    assert.equal(git(f.checkout, "remote", "get-url", "origin"), f.remote);
    context.resolveOrFindBridgeGitRepo = () => f.checkout;
    context.prepareBridgeReleaseSource = async () => { throw new Error("Synthetic preflight failure"); };
    for (const name of ["ensureBridgeDir", "reapOrphanedMcpProcesses", "deleteOldBridgeSessions",
      "ensureMachineIdentityKeypair", "getLocalWsConnectionInfo"]) context[name] = () => { mutations++; };
    vm.runInContext(`${namedFunction(source, "reprovisionLocalBridge")}\nthis.reprovision = reprovisionLocalBridge;`, context);
    await assert.rejects(() => context.reprovision({ machineId: "EXAMPLE-PC" }), /Synthetic preflight failure/);
    assert.equal(mutations, 0);
    assert.doesNotMatch(source, /["']reset["'],\s*["']--hard["']/);
    const release = { directory: root, scriptPath: path.join(root, "flock.mjs"), commit: f.candidate };
    const calls = [];
    context.cfg = { machineId: "EXAMPLE-PC", scope: "personal", githubUser: "example" };
    context.action = "self_update";
    context.BRIDGE_VERSION = "synthetic-installed";
    context.prepareBridgeReleaseSource = async (directory) => {
      assert.equal(directory, f.checkout);
      calls.push("prepare");
      return release;
    };
    context.schedulePreparedBridgeRelease = (prepared) => {
      assert.equal(prepared, release);
      calls.push("schedule");
      return { installerPid: 123 };
    };
    const action = source.slice(source.indexOf('if (action === "self_update")'), source.indexOf('if (action === "diagnose")'));
    const result = await vm.runInContext(`(async () => { ${action} })()`, context);
    assert.equal(result.targetCommit, f.candidate);
    assert.deepEqual(calls, ["prepare", "schedule"]);
    context.discoverMachines = async () => [];
    context.filterBroadcastTargets = () => [];
    context.matchesSelectorList = () => true;
    context.installPreparedBridgeRelease = (prepared) => {
      assert.equal(prepared, release);
      calls.push("install");
      return { version: "synthetic-candidate", daemonPid: 123 };
    };
    vm.runInContext(`${namedFunction(source, "updateFleetMachines")}\nthis.update = updateFleetMachines;`, context);
    const updated = await context.update(context.cfg);
    assert.equal(updated.localUpdate.version, "synthetic-candidate");
    assert.deepEqual(calls, ["prepare", "schedule", "prepare", "install"]);
  }
});

test("installed runtime provenance never substitutes refreshed origin or a version for the actual baseline", (t) => {
  const root = temporary(t);
  const f = releaseFixture(root);
  for (const [index, api] of [flock, bridge].entries()) {
    const installedHome = path.join(root, `installed-${index}`);
    fs.mkdirSync(installedHome);
    for (const name of ["flock.mjs", "bridge.mjs", "zero-broker-fixture.mjs"]) {
      fs.copyFileSync(path.join(f.checkout, name), path.join(installedHome, name));
    }
    assert.equal(api.getInstalledSourceProvenance(installedHome).status, "unrecorded");
    assert.equal(api.recordInstalledSourceProvenance(f.checkout, installedHome).sourceCommit, f.installed);
    git(f.checkout, "fetch", "--quiet", "origin", "+refs/heads/main:refs/remotes/origin/main");
    assert.equal(git(f.checkout, "diff", "--stat", `origin/main..${f.candidate}`), "");
    const recorded = api.getInstalledSourceProvenance(installedHome);
    assert.equal(recorded.sourceCommit, f.installed);
    assert.notEqual(git(f.checkout, "diff", "--stat", `${recorded.sourceCommit}..${f.candidate}`), "");
    fs.appendFileSync(path.join(installedHome, "flock.mjs"), "// Synthetic local modification\n");
    assert.equal(api.getInstalledSourceProvenance(installedHome).sourceCommit, null);
    assert.equal(api.getInstalledSourceProvenance(installedHome).status, "modified_runtime");
  }
});

test("actual release comparison distinguishes empty published diff from changed or unknown installed runtime", (t) => {
  const root = temporary(t);
  const f = releaseFixture(root);
  for (const [index, api] of [flock, bridge].entries()) {
    const installedHome = path.join(root, `baseline-${index}`);
    fs.mkdirSync(installedHome);
    for (const name of ["flock.mjs", "bridge.mjs", "zero-broker-fixture.mjs"]) {
      fs.copyFileSync(path.join(f.checkout, name), path.join(installedHome, name));
    }
    api.recordInstalledSourceProvenance(f.checkout, installedHome);
    const source = fs.readFileSync(new URL(`../${index ? "bridge" : "flock"}.mjs`, import.meta.url), "utf8");
    const from = source.indexOf("    const installedSource = getInstalledSourceProvenance();");
    const to = source.indexOf("    // Extract candidate", from);
    assert.ok(from > 0 && to > from);
    const compare = (failDiff = false) => vm.runInNewContext(`${source.slice(from, to)}
      ({ installedSource, candidateCommit, diffStat, publishedMainComparisonError, installedDiffStat, installedComparisonError });`, {
      params: { branch: "main" }, branch: "main", repoDir: f.checkout,
      getInstalledSourceProvenance: () => api.getInstalledSourceProvenance(installedHome),
      execFileSync: (program, args, options) => {
        if (program === "git" && args.includes("fetch")) args = args.map((arg) =>
          arg === "https://github.com/erjadi/copilot-flock.git" ? f.remote : arg);
        if (failDiff && args.includes("diff")) throw new Error("Synthetic diff failure");
        return execFileSync(program, Array.from(args), options);
      },
    });
    const result = compare();
    assert.equal(result.candidateCommit, f.candidate);
    assert.equal(result.diffStat, "");
    assert.equal(result.publishedMainComparisonError, null);
    assert.notEqual(result.installedDiffStat, "");
    assert.equal(result.installedComparisonError, null);
    const failed = compare(true);
    assert.equal(failed.diffStat, null);
    assert.match(failed.publishedMainComparisonError, /Synthetic diff failure/);
    assert.equal(failed.installedDiffStat, null);
    assert.match(failed.installedComparisonError, /Synthetic diff failure/);
    fs.appendFileSync(path.join(installedHome, "flock.mjs"), "// Synthetic local modification\n");
    const modified = compare();
    assert.equal(modified.installedSource.sourceCommit, null);
    assert.equal(modified.installedDiffStat, null);
    assert.match(modified.installedComparisonError, /modified_runtime/);
  }
});

test("deferred pinned installer owns cleanup and explicitly records failed completion", (t) => {
  const root = temporary(t);
  for (const filename of ["flock.mjs", "bridge.mjs"]) {
    const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
    for (const exit of [0, 7]) {
      const directory = fs.mkdtempSync(path.join(root, "release-"));
      const scriptPath = path.join(directory, "flock.mjs");
      fs.writeFileSync(scriptPath, "Synthetic source; never executed");
      let captured;
      const context = vm.createContext({
        fs, path, process,
        ensureBridgeDir() {}, getBridgeHome: () => root, getCopilotDir: () => root,
        bridgeReleaseInstallArguments: () => [scriptPath, "install"],
        spawn: (_program, args) => {
          captured = args;
          return { pid: 123, once() {}, unref() {} };
        },
      });
      vm.runInContext(`${namedFunction(source, "schedulePreparedBridgeRelease")}\nthis.schedule = schedulePreparedBridgeRelease;`, context);
      const job = context.schedule({ directory, scriptPath }, { scope: "personal" });
      assert.equal(job.installerPid, 123);
      const errors = [];
      const childProcess = { argv: ["synthetic-node", directory, scriptPath, "install"], execPath: "synthetic-node", exitCode: 0 };
      vm.runInNewContext(captured[1], {
        require: (name) => name === "node:fs" ? fs : {
          spawnSync: (_program, args) => {
            assert.deepEqual(Array.from(args), [scriptPath, "install"]);
            return { status: exit };
          },
        },
        process: childProcess, setTimeout: (callback) => callback(),
        console: { error: (message) => errors.push(String(message)) },
      });
      assert.equal(childProcess.exitCode, exit);
      assert.equal(fs.existsSync(directory), false);
      assert.equal(errors.length, exit ? 1 : 0);
      if (exit) assert.match(errors[0], /failed with exit status 7/);
    }
  }
});

test("shared immutable source extraction rejects unsupported Git entries and unsafe paths", () => {
  for (const entry of [
    "120000 blob " + "1".repeat(40) + "\tlink",
    "100644 blob " + "1".repeat(40) + "\t../escape",
    "100644 blob " + "1".repeat(40) + "\tC:/escape",
    "100644 blob " + "1".repeat(40) + "\tnested\\escape",
  ]) {
    assert.throws(() => materializeReleaseCandidate({
      repoDir: "synthetic-unused", commit: "a".repeat(40),
      exec: () => Buffer.from(entry + "\0"),
    }), /unsupported entry|Unsafe release tree path/);
  }
});

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
