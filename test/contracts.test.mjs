import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as flock from "../flock.mjs";
import * as bridge from "../bridge.mjs";
import * as broker from "../bootstrap-server.mjs";
import { RELEASE_VALIDATION_POLICY, RELEASE_VALIDATION_POLICY_HASH, createReleaseCoverage } from "../release-policy.mjs";

test("expected release SHA rejects moved branches while preserving Git checkout and metadata", (t) => {
  const root = temporary(t);
  const f = releaseFixture(root);
  fs.writeFileSync(path.join(f.checkout, ".git", "FETCH_HEAD"), "Synthetic preserved fetch marker\n");
  const before = { head: git(f.checkout, "rev-parse", "HEAD"), origin: git(f.checkout, "remote", "get-url", "origin"),
    index: fs.readFileSync(path.join(f.checkout, ".git", "index")),
    fetch: fs.readFileSync(path.join(f.checkout, ".git", "FETCH_HEAD")),
    status: git(f.checkout, "status", "--porcelain=v1", "--untracked-files=all") };
  for (const api of [flock, bridge]) {
    let executions = 0;
    assert.throws(() => api.resolveExpectedReleaseCommit({ repoDir: f.checkout, branch: "main", exec: () => executions++ }), { code: "RELEASE_COMMIT_REQUIRED" });
    assert.equal(executions, 0);
    assert.throws(() => api.resolveExpectedReleaseCommit({ repoDir: f.checkout, branch: "main", expectedCommit: f.installed, exec: f.exec }), { code: "RELEASE_COMMIT_MISMATCH" });
    assert.equal(api.resolveExpectedReleaseCommit({ repoDir: f.checkout, branch: "main", expectedCommit: f.candidate, exec: f.exec }), f.candidate);
    assert.equal(git(f.checkout, "rev-parse", "HEAD"), before.head);
    assert.equal(git(f.checkout, "remote", "get-url", "origin"), before.origin);
    assert.equal(git(f.checkout, "status", "--porcelain=v1", "--untracked-files=all"), before.status);
    assert.deepEqual(fs.readFileSync(path.join(f.checkout, ".git", "index")), before.index);
    assert.deepEqual(fs.readFileSync(path.join(f.checkout, ".git", "FETCH_HEAD")), before.fetch);
  }
});

test("actual release vote caller freezes intent, denies ungated peers and forwards exact SHA to every voter", async (t) => {
  const root = temporary(t);
  const expectedCommit = "a".repeat(40);
  const keys = crypto.generateKeyPairSync("ed25519");
  const targets = [{ machineId: "FIRST-PC" }, { machineId: "SECOND-PC" }];
  const inventory = createReleaseCoverage([...RELEASE_VALIDATION_POLICY.requiredModules, ...RELEASE_VALIDATION_POLICY.requiredTests]);
  for (const [index, api] of [flock, bridge].entries()) {
    const source = fs.readFileSync(new URL(`../${index ? "bridge" : "flock"}.mjs`, import.meta.url), "utf8");
    const method = namedFunction(source, "voteReleaseAcrossFlock").replace(
      'const { RELEASE_REVIEW_TIMEOUT_MS } = await import("./zero-broker-release.mjs");', "const RELEASE_REVIEW_TIMEOUT_MS = 450000;");
    assert.ok(!method.includes('await import("./zero-broker-release.mjs")'));
    const calls = [];
    let protocolSupported = false;
    let ballotCommit = expectedCommit;
    const context = vm.createContext({
      fs, path, RELEASE_VALIDATION_POLICY_HASH,
      assertExpectedReleaseCommit: api.assertExpectedReleaseCommit,
      resolveOrFindBridgeGitRepo: () => root,
      resolveExpectedReleaseCommit: ({ expectedCommit: value }) => { assert.equal(value, expectedCommit); calls.push("freeze"); return value; },
      readExpectedReleaseCoverage: () => inventory,
      discoverMachines: async () => { calls.push("discover"); return targets; },
      getCachedBootstrapMembersMap: () => new Map(targets.map((target) => [target.machineId.toLowerCase(), { publicKey: keys.publicKey }])),
      filterBroadcastTargets: () => targets,
      verifyVoteBallotSignature: api.verifyVoteBallotSignature, summarizeReleaseVotes: api.summarizeReleaseVotes,
      ensureBridgeDir() {}, getBridgeHome: () => root,
      invokeRemoteRpcBatch: async (_cfg, items) => items.map((item) => {
        calls.push(item.action);
        if (item.action === "ping") return { item, ok: true, response: { result: protocolSupported ? {
          releaseReviewProtocol: { version: 3, expectedCommitRequired: true, localExecutionApprovalRequired: true,
            validationPolicyHash: RELEASE_VALIDATION_POLICY_HASH },
        } : {} } };
        assert.equal(item.params.expectedCommit, expectedCommit);
        const ballot = { machineId: item.toMachine, branch: "main", candidateCommit: ballotCommit,
          vote: "ACCEPT", voteSignatureVersion: 3,
          verificationLevel: "complete_candidate_syntax_root_tests_and_ed25519_signature",
          checks: { modulesSyntaxOk: true, bridgeSyntaxOk: true, bootstrapSyntaxOk: true,
            unitTestsOk: true, localExecutionConsentVerified: true, ...inventory,
            moduleCount: inventory.coverage.modules.length, testFileCount: inventory.coverage.testFiles.length,
            verificationLevel: "complete_candidate_syntax_and_root_tests" } };
        ballot.voteSignature = crypto.sign(null, Buffer.from(api.releaseVoteSigningPayload(ballot)), keys.privateKey).toString("base64");
        return { item, ok: true, response: { result: ballot } };
      }),
    });
    vm.runInContext(`${method}\nthis.vote = voteReleaseAcrossFlock;`, context);
    await assert.rejects(() => context.vote({}, { branch: "main" }), { code: "RELEASE_COMMIT_REQUIRED" });
    assert.deepEqual(calls, []);
    await assert.rejects(() => context.vote({}, { branch: "main", expectedCommit }), /capability preflight/);
    assert.deepEqual(calls, ["freeze", "discover", "ping", "ping"]);
    protocolSupported = true;
    calls.length = 0;
    const report = await context.vote({}, { branch: "main", expectedCommit });
    assert.equal(report.approvedForMerge, true);
    assert.equal(report.expectedCommit, expectedCommit);
    assert.deepEqual(calls, ["freeze", "discover", "ping", "ping", "review_release", "review_release"]);
    ballotCommit = "b".repeat(40);
    const moved = await context.vote({}, { branch: "main", expectedCommit });
    assert.equal(moved.approvedForMerge, false);
  }
});

test("local release execution approval binds reviewed host code to exact SHA, device, key and expiry", (t) => {
  const root = temporary(t);
  const now = Date.now();
  const commit = "a".repeat(40);
  for (const [index, api] of [flock, bridge].entries()) {
    process.env.COPILOT_HOME = path.join(root, String(index));
    const cfg = { machineId: "SYNTHETIC-PC", architecture: "legacy" };
    const approvalPath = path.join(api.getBridgeHome(), "release-execution-approvals", `${commit}.json`);
    assert.throws(() => api.approveLocalReleaseExecution(cfg, commit), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    assert.throws(() => api.approveLocalReleaseExecution(cfg, commit, { ackReviewedHostCode: true }), { code: "RPC_LOCAL_ENROLLMENT_REQUIRED" });
    assert.equal(fs.existsSync(api.getBridgeHome()), false);
    const identity = api.ensureMachineIdentityKeypair();
    const identityPath = path.join(api.getBridgeHome(), "identity.json");
    const originalIdentity = fs.readFileSync(identityPath);
    const approval = api.approveLocalReleaseExecution(cfg, commit, { ackReviewedHostCode: true, now });
    assert.equal(api.assertLocalReleaseExecutionApproved(cfg, commit, now).publicKey, identity.publicKey);
    assert.throws(() => api.assertLocalReleaseExecutionApproved(cfg, "b".repeat(40), now), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    assert.throws(() => api.assertLocalReleaseExecutionApproved({ ...cfg, machineId: "OTHER-PC" }, commit, now), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    assert.throws(() => api.assertLocalReleaseExecutionApproved({ ...cfg, architecture: "zero-broker" }, commit, now), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    assert.throws(() => api.assertLocalReleaseExecutionApproved(cfg, commit, now - 1), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    assert.throws(() => api.assertLocalReleaseExecutionApproved(cfg, commit, approval.expiresAt), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    assert.throws(() => api.assertLocalReleaseExecutionApproved(cfg, commit, NaN), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    for (const patch of [{ commit: "b".repeat(40) }, { issuedAt: now + 1, expiresAt: approval.expiresAt + 1 },
      { ackReviewedHostCode: false }, { signature: Buffer.alloc(64).toString("base64") },
      { signature: crypto.sign(null, Buffer.from("a release ballot is not an execution approval"), identity.privateKey).toString("base64") }]) {
      fs.writeFileSync(approvalPath, JSON.stringify({ ...approval, ...patch }));
      assert.throws(() => api.assertLocalReleaseExecutionApproved(cfg, commit, now), { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    }
    fs.writeFileSync(approvalPath, JSON.stringify(approval));
    fs.writeFileSync(identityPath, "{}");
    assert.throws(() => api.assertLocalReleaseExecutionApproved(cfg, commit, now), { code: "RPC_LOCAL_IDENTITY_INVALID" });
    assert.equal(fs.readFileSync(identityPath, "utf8"), "{}");
    fs.writeFileSync(identityPath, originalIdentity);
    assert.deepEqual(fs.readFileSync(identityPath), originalIdentity);
    assert.equal(api.MCP_TOOLS.some((tool) => /approve.*release.*execution/.test(tool.name)), false);
  }
});

test("actual release handler denies smoke and worker execution before local exact-source approval", async (t) => {
  const root = temporary(t);
  for (const [index, api] of [flock, bridge].entries()) {
    process.env.COPILOT_HOME = path.join(root, String(index));
    const source = fs.readFileSync(new URL(`../${index ? "bridge" : "flock"}.mjs`, import.meta.url), "utf8");
    const from = source.indexOf('  if (action === "review_release")');
    const to = source.indexOf('  throw new Error(`Unsupported bridge RPC action:', from);
    assert.ok(from > 0 && to > from);
    const commit = "a".repeat(40);
    const cfg = { machineId: "SYNTHETIC-PC", architecture: "legacy" };
    let executions = 0;
    let expireDuringExecution = false;
    const run = () => vm.runInNewContext(`(async () => { ${source.slice(from, to)} })()`, {
      action: "review_release", params: { branch: "untrusted-branch", expectedCommit: commit }, cfg, fs, path, os, process, crypto, Buffer,
      assertExpectedReleaseCommit: api.assertExpectedReleaseCommit,
      resolveExpectedReleaseCommit: () => commit,
      resolveOrFindBridgeGitRepo: () => root,
      getInstalledSourceProvenance: () => ({ sourceCommit: null, status: "unrecorded" }),
      assertLocalReleaseExecutionApproved: api.assertLocalReleaseExecutionApproved,
      releaseVoteSigningPayload: api.releaseVoteSigningPayload,
      execFileSync: (program, args) => {
        if (program !== "git") {
          executions++;
          if (expireDuringExecution) api.approveLocalReleaseExecution(cfg, commit, {
            ackReviewedHostCode: true, now: Date.now() - 30 * 60 * 1000,
          });
          return "";
        }
        if (args.includes("rev-parse")) return commit;
        if (args.includes("show")) return "// Synthetic candidate; never executed\n";
        return "";
      },
    });
    await assert.rejects(run, { code: "RELEASE_EXECUTION_NOT_APPROVED" });
    assert.equal(executions, 0);
    assert.equal(fs.existsSync(api.getBridgeHome()), false);
    api.ensureMachineIdentityKeypair();
    api.approveLocalReleaseExecution(cfg, commit, { ackReviewedHostCode: true });
    const result = await run();
    assert.ok(executions > 0);
    assert.equal(result.candidateCommit, commit);
    // The synthetic VM does not load the real worker; incomplete evidence cannot ACCEPT.
    assert.equal(result.vote, "REJECT");
    expireDuringExecution = true;
    await assert.rejects(run, { code: "RELEASE_EXECUTION_NOT_APPROVED" });
  }
});

test("release consent expiry before each launch prevents smoke or worker execution without retracting launched work", async (t) => {
  const root = temporary(t);
  const commit = "a".repeat(40);
  for (const [index, api] of [flock, bridge].entries()) {
    process.env.COPILOT_HOME = path.join(root, String(index));
    const cfg = { machineId: "SYNTHETIC-PC", architecture: "legacy" };
    const identity = api.ensureMachineIdentityKeypair();
    const source = fs.readFileSync(new URL(`../${index ? "bridge" : "flock"}.mjs`, import.meta.url), "utf8");
    const from = source.indexOf('  if (action === "review_release")');
    const to = source.indexOf('  throw new Error(`Unsupported bridge RPC action:', from);
    assert.ok(from > 0 && to > from);
    const handler = source.slice(from, to);
    const importExpression = 'await import("./zero-broker-release.mjs")';
    assert.equal(handler.split(importExpression).length, 2);
    const coverage = createReleaseCoverage([...RELEASE_VALIDATION_POLICY.requiredModules, ...RELEASE_VALIDATION_POLICY.requiredTests]);
    for (const expireAt of ["never", "before-smoke", "before-worker", "during-import", "during-worker"]) {
      let now = Date.now();
      const approval = api.approveLocalReleaseExecution(cfg, commit, { ackReviewedHostCode: true, now });
      let smokeCalls = 0;
      let workerCalls = 0;
      const run = () => vm.runInNewContext(`(async () => { ${handler.replace(importExpression, "await releaseWorkerFixture")} })()`, {
        action: "review_release", params: { branch: "reviewed-branch", expectedCommit: commit }, cfg, fs, path, os, process, crypto, Buffer,
        assertExpectedReleaseCommit: api.assertExpectedReleaseCommit,
        resolveExpectedReleaseCommit: () => commit,
        resolveOrFindBridgeGitRepo: () => root,
        getInstalledSourceProvenance: () => ({ sourceCommit: null, status: "unrecorded" }),
        assertLocalReleaseExecutionApproved: (config, sha) => api.assertLocalReleaseExecutionApproved(config, sha, now),
        releaseVoteSigningPayload: api.releaseVoteSigningPayload,
        releaseWorkerFixture: Promise.resolve().then(() => {
          if (expireAt === "during-import") now = approval.expiresAt;
          return { validateReleaseCandidateInWorker: async () => {
            workerCalls++;
            if (expireAt === "during-worker") now = approval.expiresAt;
            return { ...coverage, modulesSyntaxOk: true, unitTestsOk: true,
              moduleCount: coverage.coverage.modules.length, testFileCount: coverage.coverage.testFiles.length,
              candidateCommit: commit, verificationLevel: "complete_candidate_syntax_and_root_tests" };
          } };
        }),
        execFileSync: (program, args) => {
          if (program === "git") {
            if (expireAt === "before-smoke" && args.some((arg) => arg.endsWith(":test/local-rpc-fixture.mjs"))) now = approval.expiresAt;
            return args.includes("show") ? "// Synthetic source; never executed\n" : "";
          }
          if (args.includes("--test")) {
            smokeCalls++;
            if (expireAt === "before-worker") now = approval.expiresAt;
          }
          return "";
        },
      });
      if (expireAt === "never") {
        const result = await run();
        assert.equal(result.vote, "ACCEPT");
        assert.equal(api.verifyVoteBallotSignature(result, identity.publicKey), true);
      } else {
        await assert.rejects(run, { code: "RELEASE_EXECUTION_NOT_APPROVED" });
      }
      assert.equal(smokeCalls, expireAt === "before-smoke" ? 0 : 1);
      assert.equal(workerCalls, ["never", "during-worker"].includes(expireAt) ? 1 : 0);
    }
  }
});

test("release execution CLI refuses unacknowledged or missing identity without profile initialization", (t) => {
  const root = temporary(t);
  for (const script of ["flock.mjs", "bridge.mjs"]) {
    const profile = path.join(root, script);
    const args = [fileURLToPath(new URL(`../${script}`, import.meta.url)), "approve-release-execution", "--commit", "a".repeat(40)];
    const env = { ...process.env, COPILOT_HOME: profile };
    const invalidVote = spawnSync(process.execPath, [args[0], "vote-release", "--branch", "main"],
      { env, encoding: "utf8", timeout: 5000 });
    assert.notEqual(invalidVote.status, 0);
    assert.match(invalidVote.stderr, /independently expected full release commit SHA/);
    assert.equal(fs.existsSync(profile), false);
    for (const flags of [[], ["--ack-reviewed-host-code"]]) {
      const result = spawnSync(process.execPath, [...args, ...flags], { env, encoding: "utf8", timeout: 5000 });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /explicitly acknowledge|existing local legacy identity/);
      assert.equal(fs.existsSync(profile), false);
    }
    const help = spawnSync(process.execPath, [...args, "--help"], { env, encoding: "utf8", timeout: 5000 });
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /not in an OS sandbox/);
    assert.equal(fs.existsSync(profile), false);
    const home = path.join(profile, "flock");
    fs.mkdirSync(home, { recursive: true });
    const keys = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const identity = { ...keys, fingerprint: crypto.createHash("sha256").update(keys.publicKey.trim()).digest("hex").slice(0, 32) };
    fs.writeFileSync(path.join(home, "config.json"), JSON.stringify({ architecture: "legacy", machineId: "SYNTHETIC-PC" }));
    fs.writeFileSync(path.join(home, "identity.json"), JSON.stringify(identity));
    const before = fs.readFileSync(path.join(home, "identity.json"));
    const approved = spawnSync(process.execPath, [...args, "--ack-reviewed-host-code"], { env, encoding: "utf8", timeout: 5000 });
    assert.equal(approved.status, 0, approved.stderr);
    const record = JSON.parse(approved.stdout);
    assert.equal(record.commit, "a".repeat(40));
    assert.equal(record.ackReviewedHostCode, true);
    assert.ok(fs.existsSync(path.join(home, "release-execution-approvals", `${record.commit}.json`)));
    assert.deepEqual(fs.readFileSync(path.join(home, "identity.json")), before);
    assert.equal(fs.existsSync(path.join(profile, "mcp-config.json")), false);
  }
});
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
      params: { branch: "main", expectedCommit: f.candidate }, branch: "main", expectedCommit: f.candidate, repoDir: f.checkout,
      resolveExpectedReleaseCommit: () => f.candidate,
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

test("offline broker capacity and corrupt state fail closed without losing accepted work or publishing", async (t) => {
  const root = temporary(t);
  const queuePath = path.join(root, "queue.json");
  const items = Array.from({ length: 500 }, (_, index) => ({
    requestId: `synthetic-${index}`, toMachine: "EXAMPLE-PC", expiresAtMs: Date.now() + 60000,
  }));
  broker.saveOfflineQueueStore({ items }, queuePath);
  const original = fs.readFileSync(queuePath);
  let published = 0;
  const options = { toMachine: "EXAMPLE-PC", rpcPayload: { requestId: "synthetic-overflow" }, queuePath,
    publishFn: async () => { published++; return { published: true }; } };
  await assert.rejects(() => broker.enqueueOfflineStoreItem(options), { code: "QUEUE_CAPACITY_EXHAUSTED", statusCode: 503 });
  assert.equal(published, 0);
  assert.deepEqual(fs.readFileSync(queuePath), original);
  assert.throws(() => broker.saveOfflineQueueStore({ items: [...items, items[0]] }, queuePath), { code: "QUEUE_CAPACITY_EXHAUSTED" });
  assert.throws(() => broker.saveOfflineQueueStore({}, queuePath), { code: "QUEUE_STORAGE_ERROR" });
  assert.deepEqual(fs.readFileSync(queuePath), original);
  fs.writeFileSync(queuePath, "{synthetic-private-corrupt-state-canary");
  const corrupt = fs.readFileSync(queuePath);
  await assert.rejects(() => broker.enqueueOfflineStoreItem(options), { code: "QUEUE_STORAGE_ERROR" });
  assert.throws(() => broker.loadOfflineQueueStore(queuePath), (error) =>
    error.code === "QUEUE_STORAGE_ERROR" && !error.message.includes("synthetic-private-corrupt-state-canary"));
  assert.equal(published, 0);
  assert.deepEqual(fs.readFileSync(queuePath), corrupt);
});

test("offline broker persists before publish, deduplicates before network and never resurrects an acknowledged claim", async (t) => {
  const root = temporary(t);
  const queuePath = path.join(root, "queue.json");
  let started;
  let release;
  let published = 0;
  const ready = new Promise((resolve) => { started = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const options = { toMachine: "EXAMPLE-PC", rpcPayload: { requestId: "synthetic-first", action: "send_message" }, queuePath,
    publishFn: async () => {
      published++;
      assert.equal(broker.loadOfflineQueueStore(queuePath).items[0].requestId, "synthetic-first");
      started();
      await gate;
      return { published: true };
    } };
  const pending = broker.enqueueOfflineStoreItem(options);
  await ready;
  try {
    const duplicate = await broker.enqueueOfflineStoreItem(options);
    assert.equal(duplicate.deduplicated, true);
    assert.equal(duplicate.serviceBusPublished, false);
    assert.equal(duplicate.serviceBusPublication, "unconfirmed");
    assert.equal(published, 1);
    await assert.rejects(() => broker.enqueueOfflineStoreItem({ ...options, toMachine: "OTHER-PC" }), { code: "QUEUE_REQUEST_MISMATCH" });
    const second = await broker.enqueueOfflineStoreItem({ ...options, rpcPayload: { requestId: "synthetic-second" }, publishFn: null });
    assert.equal(second.ok, true, "Network I/O must not hold the global store lock");
    const ack = await broker.ackOfflineStoreItems({ requestIds: ["synthetic-first"], queuePath });
    assert.equal(ack.ackedCount, 1);
  } finally { release(); }
  const completed = await pending;
  assert.equal(completed.serviceBusPublished, true);
  assert.equal(completed.pendingInBootstrapQueue, false);
  assert.equal(completed.status, "no_longer_pending");
  assert.deepEqual(broker.loadOfflineQueueStore(queuePath).items.map((item) => item.requestId), ["synthetic-second"]);
});

test("offline broker duplicate receipts preserve publication metadata and explicit publisher failures", async (t) => {
  const root = temporary(t);
  const queuePath = path.join(root, "queue.json");
  let published = 0;
  const options = { toMachine: "EXAMPLE-PC", rpcPayload: { requestId: "synthetic-published", action: "send_message" }, queuePath,
    publishFn: async () => { published++; return { published: true }; } };
  const first = await broker.enqueueOfflineStoreItem(options);
  const second = await broker.enqueueOfflineStoreItem({ ...options,
    rpcPayload: { action: "send_message", requestId: "synthetic-published" } });
  assert.equal(published, 1);
  assert.equal(second.serviceBusPublished, true);
  assert.equal(second.enqueuedAt, first.enqueuedAt);
  assert.equal(second.expiresAt, first.expiresAt);
  const failed = await broker.enqueueOfflineStoreItem({ ...options, rpcPayload: { requestId: "synthetic-publisher-failure" },
    publishFn: async () => { throw new Error("Synthetic publication failure"); } });
  assert.equal(failed.ok, true);
  assert.equal(failed.pendingInBootstrapQueue, true);
  assert.equal(failed.serviceBusPublished, false);
  assert.equal(failed.serviceBusPublicationError, "publisher_error");
  assert.equal(broker.loadOfflineQueueStore(queuePath).items.length, 2);
});

test("offline status reflects confirmed publication, old dedup receipts and unconfirmed runtime admission", () => {
  for (const api of [flock, bridge]) {
    assert.equal(api.offlineQueueMetadata({ ok: true, serviceBusPublished: false }).deliveryStage, "persisted_in_bootstrap_queue");
    assert.equal(api.offlineQueueMetadata({ ok: true, serviceBusPublished: true }).deliveryStage, "queued_in_servicebus");
    const old = api.offlineQueueMetadata({ ok: true, deduplicated: true, queuedItem: {
      serviceBusPublished: true, enqueuedAt: "synthetic-original", expiresAtMs: 2000000000000,
    } });
    assert.equal(old.serviceBusPublished, true);
    assert.equal(old.enqueuedAt, "synthetic-original");
    const consumed = api.offlineQueueMetadata({ serviceBusPublished: false, pendingInBootstrapQueue: false });
    assert.equal(consumed.deliveryStage, "bootstrap_queue_no_longer_pending");
    assert.equal(consumed.runtimeAdmission, "unconfirmed");
    assert.equal(consumed.executionConfirmed, false);
  }
});

test("actual offline reprovision producer reports bootstrap fallback without claiming Service Bus or execution", async () => {
  for (const filename of ["flock.mjs", "bridge.mjs"]) {
    const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
    const api = filename === "flock.mjs" ? flock : bridge;
    const request = { requestId: "synthetic-reprovision", auth: { v: 3 } };
    const target = { machineId: "EXAMPLE-PC" };
    const context = vm.createContext({
      discoverMachines: async () => [],
      fetchBootstrapMembers: () => [target],
      matchesSelectorList: () => true,
      invokeRemoteRpcBatch: async () => [{ item: { target }, ok: false,
        error: "Timed out after 20000ms waiting for response from machine", request }],
      enqueueOfflineMessage: (options) => {
        assert.equal(options.rpcPayload, request);
        return { ok: true, serviceBusPublished: false, enqueuedAt: "synthetic-original" };
      },
      offlineQueueMetadata: api.offlineQueueMetadata,
      diagnoseFleetMachines: async () => ({ synthetic: true }),
    });
    vm.runInContext(`${namedFunction(source, "reprovisionFleetMachines")}\nthis.run = reprovisionFleetMachines;`, context);
    const result = await context.run({ machineId: "SYNTHETIC-SOURCE", bootstrapUrl: "https://trusted.invalid/api/bootstrap",
      bootstrapOriginPin: "https://trusted.invalid" });
    const queued = result.reprovisionResults[0].result;
    assert.equal(queued.deliveryStage, "persisted_in_bootstrap_queue");
    assert.equal(queued.serviceBusPublished, false);
    assert.equal(queued.runtimeAdmission, "unconfirmed");
    assert.equal(queued.executionConfirmed, false);
    assert.doesNotMatch(queued.note, /will execute automatically/);
  }
});

test("existing malformed legacy identity is retained rather than silently rotated", (t) => {
  const root = temporary(t);
  for (const [index, api] of [flock, bridge].entries()) {
    process.env.COPILOT_HOME = path.join(root, String(index));
    const home = path.join(process.env.COPILOT_HOME, "flock");
    fs.mkdirSync(home, { recursive: true });
    const identity = path.join(home, "identity.json");
    const original = "{synthetic corrupt identity must not be replaced";
    fs.writeFileSync(identity, original);
    assert.throws(() => api.ensureMachineIdentityKeypair());
    assert.equal(fs.readFileSync(identity, "utf8"), original);
  }
});

test("legacy production timeout remains UNKNOWN until Desktop admission is observed", async () => {
  for (const filename of ["flock.mjs", "bridge.mjs"]) {
    const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
    const initial = Date.now();
    let clock = initial, admitted = false, closed = false;
    const delayed = [], receipts = [];
    class Clock extends Date {
      constructor(...args) { super(...(args.length ? args : [clock])); }
      static now() { return clock; }
    }
    const context = vm.createContext({
      crypto, path, Date: Clock, fs: { existsSync: () => false },
      getCopilotDir: () => path.resolve("synthetic-profile-never-accessed"),
      getLocalWsConnectionInfo: () => ({ port: 12345, token: "synthetic-token-never-used" }),
      resolveLocalSession: () => ({ session_id: "synthetic-session", title: "Synthetic session" }),
      createIncrementalEventReader: () => ({
        readNewEvents: () => admitted ? [{ type: "user.message", data: { turnId: "synthetic-turn" } }] : [],
      }),
      buildCrossSessionEnvelope: () => "Synthetic prompt",
      normalizeScope: (value) => value || "personal", normalizeGitHubUser: (value) => value || null,
      isMatchingDispatchedUserEvent: () => admitted,
      RawWebSocketClient: class {
        async connect() {}
        sendText() {}
        close() { closed = true; }
      },
      setTimeout: (callback, ms) => {
        clock += ms;
        if (clock - initial <= 3000) queueMicrotask(callback);
        else delayed.push(callback);
      },
      sendSignalRBroadcast: async (_cfg, _target, receipt) => { receipts.push(receipt); },
    });
    vm.runInContext(`${namedFunction(source, "injectLocalSessionMessage")}\nthis.inject = injectLocalSessionMessage;`, context);
    const result = await context.inject({
      cfg: { machineId: "SYNTHETIC-TARGET", connectionString: "synthetic-not-used" },
      targetSession: "synthetic-session", message: "Synthetic message", fromMachine: "SYNTHETIC-SOURCE",
      fromScope: "personal", waitForReply: false, dispatchTimeoutMs: 3000,
    });
    assert.equal(result.status, "unknown");
    assert.equal(result.deliveryStage, "awaiting_desktop_admission");
    assert.equal(result.dispatchedToRuntime, false);
    assert.equal(result.admissionConfirmed, false);
    assert.equal(result.queuedBehindActiveTurn, null);
    assert.equal(result.lateAdmissionPending, true);
    assert.equal(result.deliveredAt, undefined);
    assert.equal(closed, false, "Keep the pending Desktop adapter alive without fabricating admission");
    assert.equal(receipts.length, 0);
    admitted = true;
    for (const callback of delayed.splice(0)) callback();
    await Promise.resolve();
    await Promise.resolve();
    assert.equal(closed, true);
    assert.equal(receipts[0].stage, "admitted_after_queue");
  }
});

test("malformed existing flock enrollment is never replaced by a sharing operation", (t) => {
  const root = temporary(t);
  const cfg = { githubUser: "example", scope: "personal", machineId: "EXAMPLE-PC" };
  for (const [index, api] of [flock, bridge].entries()) {
    const file = path.join(root, `flocks-${index}.json`);
    const original = "{synthetic-private-enrollment-corrupt-canary";
    fs.writeFileSync(file, original);
    assert.throws(() => api.shareThreadWithFlock(cfg, {
      flockId: "example/studio-team", sessionId: "synthetic-session", summarySnapshot: "Approved synthetic summary",
    }, file), { code: "FLOCK_STATE_INVALID" });
    assert.equal(fs.readFileSync(file, "utf8"), original);
    assert.throws(() => api.listSharedThreadsForMachine(cfg, file), (error) =>
      error.code === "FLOCK_STATE_INVALID" && !error.message.includes("synthetic-private-enrollment-corrupt-canary"));
  }
});

test("valid flock sharing preserves future metadata and object-like owner names without silent schema defaults", (t) => {
  const root = temporary(t);
  for (const [index, api] of [flock, bridge].entries()) {
    const file = path.join(root, `valid-${index}.json`);
    const cfg = { githubUser: "constructor", scope: "personal", machineId: "EXAMPLE-PC" };
    fs.writeFileSync(file, JSON.stringify({ metadata: { recoveryMarker: "synthetic-preserved" }, flocks: {} }));
    const loaded = api.loadLocalFlocksConfig(cfg, file);
    assert.equal(Object.hasOwn(loaded.flocks, "constructor"), true);
    api.shareThreadWithFlock(cfg, { flockId: "constructor/studio-team", sessionId: "synthetic-session", summarySnapshot: "Approved summary" }, file);
    const stored = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.equal(stored.metadata.recoveryMarker, "synthetic-preserved");
    assert.equal(stored.flocks["constructor/studio-team"].sharedSnapshots["synthetic-session"].summarySnapshot, "Approved summary");
    const original = fs.readFileSync(file);
    assert.throws(() => api.saveLocalFlocksConfig({}, file), { code: "FLOCK_STATE_INVALID" });
    assert.deepEqual(fs.readFileSync(file), original);
    for (const invalid of ["null", "[]", "{}", '{"flocks":[]}', '{"flocks":{"bad":null}}']) {
      fs.writeFileSync(file, invalid);
      assert.throws(() => api.unshareThreadFromFlock(cfg, { sessionId: "synthetic-session" }, file), { code: "FLOCK_STATE_INVALID" });
      assert.equal(fs.readFileSync(file, "utf8"), invalid);
    }
  }
});

test("atomic flock-state replacement failure retains prior bytes and removes only its own temporary file", (t) => {
  const root = temporary(t);
  for (const [index, api] of [flock, bridge].entries()) {
    const source = fs.readFileSync(new URL(`../${index ? "bridge" : "flock"}.mjs`, import.meta.url), "utf8");
    const file = path.join(root, `atomic-${index}.json`);
    const original = '{"flocks":{},"metadata":"synthetic-original"}';
    fs.writeFileSync(file, original);
    const before = fs.readdirSync(root).sort();
    const context = vm.createContext({
      crypto, process,
      fs: { ...fs, renameSync: () => { throw new Error("Synthetic atomic replacement failure"); } },
      writeConfigFileSecure: api.writeConfigFileSecure,
    });
    vm.runInContext(`${namedFunction(source, "validLocalFlocksState")}\n${namedFunction(source, "saveLocalFlocksConfig")}\nthis.save = saveLocalFlocksConfig;`, context);
    assert.throws(() => context.save({ flocks: {}, metadata: "synthetic-new" }, file), /Synthetic atomic replacement failure/);
    assert.equal(fs.readFileSync(file, "utf8"), original);
    assert.deepEqual(fs.readdirSync(root).sort(), before);
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

test("public flock MCP and CLI metadata exclude stored and future credential fields without changing transport state", async (t) => {
  const root = temporary(t);
  const cfg = { architecture: "legacy", machineId: "SYNTHETIC-PC", scope: "personal", githubUser: "example" };
  const secrets = {
    hubToken: "SYNTHETIC_BEARER_SENTINEL", privateKey: "SYNTHETIC_PRIVATE_KEY_SENTINEL",
    connectionString: "SYNTHETIC_CONNECTION_SENTINEL", futureCredential: { nested: "SYNTHETIC_NESTED_SENTINEL" },
  };
  const entry = {
    flockId: "example/team", flockUuid: "synthetic-flock", hubName: "synthetic-hub",
    ownerGitHubUser: "example", flockType: "shared", trustTier: "collaborator",
    allowedScopes: ["personal", { ...secrets }], rosterEpoch: 4, memberCount: 1,
    members: [{ peerId: "synthetic-peer", machineId: "SYNTHETIC-PC", publicKey: "synthetic-public-key",
      keyFingerprint: "synthetic-public-fingerprint", active: true, ...secrets }],
    sharedSnapshots: { privateSession: { summarySnapshot: "SYNTHETIC_SNAPSHOT_SENTINEL" } },
    ...secrets,
  };
  for (const [filename, api] of [["flock.mjs", flock], ["bridge.mjs", bridge]]) {
    const statePath = path.join(root, `${filename}-flocks.json`);
    api.saveLocalFlocksConfig({ flocks: { "example/team": entry } }, statePath);
    const original = fs.readFileSync(statePath);
    const source = fs.readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
    const extract = (name) => {
      const match = source.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n\\}`));
      assert.ok(match, `Actual ${name} function must be exercised`);
      return match[0];
    };
    const output = [];
    const context = vm.createContext({
      process: { argv: ["node", filename, "flocks"] }, fs,
      getConfigPath: () => path.join(root, "absent-config.json"), loadConfig: () => cfg,
      normalizeScope: api.normalizeScope,
      loadLocalFlocksConfig: () => api.loadLocalFlocksConfig(cfg, statePath),
      projectPublicFlockMetadata: api.projectPublicFlockMetadata,
      callBootstrapV3Endpoint: () => ({ ownedFlocks: [entry], joinedFlocks: [entry] }),
      console: { log: (value) => output.push(value) },
    });
    vm.runInContext(`${extract("parseCliArgs")}\n${extract("executeMcpTool")}\n${extract("main")}\nthis.invoke = executeMcpTool; this.cli = main;`, context);
    const result = await context.invoke(cfg, "list_flocks", {});
    await context.cli();
    assert.deepEqual(JSON.parse(output[0]), JSON.parse(JSON.stringify(result)));
    for (const entries of [result.localFlocks, result.remoteOwnedFlocks, result.remoteJoinedFlocks]) {
      const visible = entries.find((value) => value.flockId === "example/team");
      assert.equal(visible.hubName, entry.hubName);
      assert.equal(visible.members[0].publicKey, "synthetic-public-key");
      assert.equal(visible.members[0].active, true);
      assert.deepEqual(Array.from(visible.allowedScopes), ["personal"]);
    }
    const json = JSON.stringify(result);
    for (const sentinel of ["SYNTHETIC_BEARER", "SYNTHETIC_PRIVATE", "SYNTHETIC_CONNECTION", "SYNTHETIC_NESTED", "SYNTHETIC_SNAPSHOT"]) {
      assert.equal(json.includes(sentinel), false);
    }
    assert.ok(fs.readFileSync(statePath).equals(original));
    assert.equal(api.loadLocalFlocksConfig(cfg, statePath).flocks["example/team"].hubToken, secrets.hubToken);
    const group = { flockUuid: "synthetic-zero", label: "example/zero", rootFingerprint: "synthetic-root", ...secrets };
    let closed = 0;
    Object.assign(context, {
      getZeroBrokerApi: async () => ({ openZeroBrokerGroup: () => ({
        state: { get: () => ({ rosterEpoch: 1, leaseExpiresAt: new Date(Date.now() + 60000).toISOString(), members: [] }) },
        device: { opaquePeerId: "synthetic-local" }, close: () => closed++,
      }) }),
      getBridgeHome: () => root, createZeroBrokerNativeHost: () => ({}), getLocalWsConnectionInfo: () => null,
    });
    vm.runInContext(`${extract("executeZeroBrokerTool")}\nthis.zero = executeZeroBrokerTool;`, context);
    for (const name of ["list_flocks", "flock_status", "bridge_status"]) {
      const status = await context.zero({ groups: [group] }, name, {});
      assert.deepEqual(JSON.parse(JSON.stringify(status.groups)), [{ flockUuid: group.flockUuid, label: group.label, rootFingerprint: group.rootFingerprint }]);
      assert.equal(JSON.stringify(status).includes("SENTINEL"), false);
    }
    assert.equal(closed, 3);
    assert.equal(group.hubToken, secrets.hubToken);
  }
});

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
