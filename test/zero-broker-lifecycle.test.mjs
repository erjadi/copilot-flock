import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import * as core from "../zero-broker-roster.mjs";
import * as lifecycle from "../zero-broker-lifecycle.mjs";
import { createZeroBrokerNativeHost, getMcpToolDefinitions, installZeroBrokerIntegration, zeroBrokerNodeFlags, releaseVoteSigningPayload, summarizeReleaseVotes, verifyVoteBallotSignature } from "../flock.mjs";
import { RELEASE_REVIEW_TIMEOUT_MS, validateReleaseCandidateInWorker } from "../zero-broker-release.mjs";
import { RELEASE_VALIDATION_POLICY, createReleaseCoverage, verifyReleaseCoverage, releaseCoveragePayload, readExpectedReleaseCoverage } from "../release-policy.mjs";

const subscriptionId = "11111111-2222-4333-8444-555555555555";
const sessionId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

test("full-scope signed release ballots reject legacy smoke, tampering, missing voters and mixed commits", () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const commit = "a".repeat(40);
  const branch = "synthetic-candidate";
  const inventory = createReleaseCoverage([...RELEASE_VALIDATION_POLICY.requiredModules, ...RELEASE_VALIDATION_POLICY.requiredTests]);
  function ballot(machineId, changes = {}) {
    const result = {
      machineId, branch, candidateCommit: commit, vote: "ACCEPT", voteSignatureVersion: 3,
      verificationLevel: "complete_candidate_syntax_root_tests_and_ed25519_signature",
      checks: { modulesSyntaxOk: true, bridgeSyntaxOk: true, bootstrapSyntaxOk: true,
        unitTestsOk: true, moduleCount: inventory.coverage.modules.length, testFileCount: 7,
        localExecutionConsentVerified: true, ...inventory,
        verificationLevel: "complete_candidate_syntax_and_root_tests" }, ...changes,
    };
    result.voteSignature = crypto.sign(null, Buffer.from(releaseVoteSigningPayload(result)), keys.privateKey).toString("base64");
    return result;
  }
  const first = ballot("FIRST-PC");
  const second = ballot("SECOND-PC");
  function summarize(items, onlineMachines = ["FIRST-PC", "SECOND-PC"]) {
    return summarizeReleaseVotes({ branch, expectedCommit: commit, expectedCoverageHash: inventory.coverageHash, onlineMachines,
      votes: items.map((item) => ({ ...item, signatureVerified: verifyVoteBallotSignature(item, keys.publicKey) })) });
  }
  assert.equal(summarize([first, second]).approvedForMerge, true);
  assert.equal(summarize([first]).approvedForMerge, false);
  assert.equal(summarize([first, first]).approvedForMerge, false);
  assert.equal(summarize([]).approvedForMerge, false);
  assert.equal(summarize([first, ballot("SECOND-PC", { candidateCommit: "b".repeat(40) })]).approvedForMerge, false);
  assert.equal(summarize([ballot("FIRST-PC", { candidateCommit: commit.slice(0, 7) }), second]).approvedForMerge, false);
  assert.equal(summarize([ballot("FIRST-PC", { branch: "other-branch" }), second]).approvedForMerge, false);
  const legacy = ballot("FIRST-PC", { voteSignatureVersion: 1 });
  assert.equal(verifyVoteBallotSignature(legacy, keys.publicKey), true);
  assert.equal(summarize([legacy, second]).approvedForMerge, false);
  const v2 = ballot("FIRST-PC", { voteSignatureVersion: 2 });
  assert.equal(verifyVoteBallotSignature(v2, keys.publicKey), true);
  assert.equal(summarize([v2, second]).approvedForMerge, false);
  assert.equal(summarize([ballot("FIRST-PC", { candidateCommit: "b".repeat(40) }),
    ballot("SECOND-PC", { candidateCommit: "b".repeat(40) })]).approvedForMerge, false);
  for (const field of ["modulesSyntaxOk", "bridgeSyntaxOk", "bootstrapSyntaxOk", "unitTestsOk"]) {
    const changed = { ...first, checks: { ...first.checks, [field]: false } };
    assert.equal(verifyVoteBallotSignature(changed, keys.publicKey), false);
    assert.equal(summarize([changed, second]).approvedForMerge, false);
    assert.equal(summarize([ballot("FIRST-PC", { checks: changed.checks }), second]).approvedForMerge, false);
  }
  assert.equal(verifyVoteBallotSignature({ ...first, verificationLevel: "smoke" }, keys.publicKey), false);
  assert.equal(verifyVoteBallotSignature({ ...first, checks: { ...first.checks, moduleCount: 1 } }, keys.publicKey), false);
  assert.equal(summarize([ballot("FIRST-PC", { checks: { ...first.checks, testFileCount: 1 } }), second]).approvedForMerge, false);
  assert.equal(summarize([ballot("FIRST-PC", { checks: { ...first.checks, testFileCount: 6 } }), second]).approvedForMerge, false);
  assert.equal(verifyVoteBallotSignature(first, crypto.generateKeyPairSync("ed25519").publicKey), false);
  assert.equal(summarizeReleaseVotes({ branch, expectedCommit: commit, expectedCoverageHash: inventory.coverageHash, onlineMachines: ["FIRST-PC"], votes: [{ ...first, signatureVerified: false }] }).approvedForMerge, false);
  assert.throws(() => summarizeReleaseVotes({ branch, onlineMachines: [], votes: [] }), { code: "RELEASE_COMMIT_REQUIRED" });
  assert.equal(summarize([ballot("FIRST-PC", { checks: { ...first.checks, localExecutionConsentVerified: false } }), second]).approvedForMerge, false);
  const substituted = createReleaseCoverage([...RELEASE_VALIDATION_POLICY.requiredModules,
    ...RELEASE_VALIDATION_POLICY.requiredTests.filter((name) => !name.includes("rpc-security")),
    "test/unapproved-substitute.test.mjs"]);
  assert.equal(verifyReleaseCoverage({ ...first.checks, ...substituted }), false);
  assert.equal(verifyVoteBallotSignature({ ...first, checks: { ...first.checks, ...substituted } }, keys.publicKey), false);
  assert.equal(summarize([ballot("FIRST-PC", { checks: { ...first.checks, ...substituted } }), second]).approvedForMerge, false);
  const policyChange = { ...first.checks, coverage: { ...first.checks.coverage, policyHash: "b".repeat(64) } };
  policyChange.coverageHash = crypto.createHash("sha256").update(releaseCoveragePayload(policyChange.coverage)).digest("hex");
  assert.equal(summarize([ballot("FIRST-PC", { checks: policyChange }), second]).approvedForMerge, false);
  const extra = createReleaseCoverage([...RELEASE_VALIDATION_POLICY.requiredModules,
    ...RELEASE_VALIDATION_POLICY.requiredTests, "extra-surface.mjs"]);
  const extraChecks = { ...first.checks, ...extra, moduleCount: extra.coverage.modules.length };
  assert.equal(verifyReleaseCoverage(extraChecks), true);
  assert.equal(summarize([ballot("FIRST-PC", { checks: extraChecks }), second]).approvedForMerge, false);
});

test("immutable release validation runs in a bounded worker without blocking the parent event loop", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-worker-fixture-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.mkdirSync(path.join(directory, "test"));
  fs.mkdirSync(path.join(directory, "no-hooks"));
  for (const name of ["flock", "bridge", "bootstrap-server", "zero-broker-roster", "zero-broker-transport",
    "zero-broker-runtime", "zero-broker-lifecycle", "zero-broker-enrollment", "zero-broker-release", "release-policy"]) {
    fs.writeFileSync(path.join(directory, `${name}.mjs`), "export const syntheticFixture = true;");
  }
  for (const name of ["flock", "bridge", "setup", "contracts", "rpc-security", "zero-broker-lifecycle"]) {
    fs.writeFileSync(path.join(directory, "test", `${name}.test.mjs`), "export const syntheticFixture = true;");
  }
  const testPath = path.join(directory, "test", "zero-broker-roster.test.mjs");
  fs.writeFileSync(testPath, 'import test from "node:test"; import { setTimeout } from "node:timers/promises"; test("synthetic worker", async () => { await setTimeout(150); });');
  const git = (...args) => execFileSync("git", ["-C", directory, ...args], { encoding: "utf8", windowsHide: true, timeout: 10000 });
  git("init", "--quiet", "--object-format=sha1");
  git("add", ".");
  const commit = () => {
    git("-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
      "-c", "commit.gpgsign=false", "-c", `core.hooksPath=${path.join(directory, "no-hooks")}`,
      "commit", "--quiet", "-m", "Synthetic validation fixture");
    return git("rev-parse", "HEAD").trim();
  };
  const sha = commit();
  let heartbeatTicks = 0;
  const timer = setInterval(() => heartbeatTicks++, 10);
  try {
    const result = await validateReleaseCandidateInWorker({ repoDir: directory, commit: sha });
    assert.equal(result.candidateCommit, sha);
    assert.equal(result.moduleCount, 17);
    assert.equal(result.testFileCount, 7);
    assert.equal(result.unitTestsOk, true);
    assert.equal(verifyReleaseCoverage(result), true);
    assert.equal(readExpectedReleaseCoverage({ repoDir: directory, expectedCommit: sha }).coverageHash, result.coverageHash);
    assert.ok(heartbeatTicks >= 2, "Parent event-loop heartbeat must continue during validation");
    assert.ok(RELEASE_REVIEW_TIMEOUT_MS > RELEASE_VALIDATION_POLICY.workerTimeoutMs, "RPC budget must cover the bounded worker and Git preflight");
    assert.equal(RELEASE_VALIDATION_POLICY.testTimeoutMs, 600000);
    assert.equal(RELEASE_VALIDATION_POLICY.workerTimeoutMs, 660000);
  } finally { clearInterval(timer); }
  await assert.rejects(() => validateReleaseCandidateInWorker({ repoDir: directory, commit: "main" }), /immutable commit SHA/);
  fs.writeFileSync(testPath, 'import test from "node:test"; test("synthetic failure", () => { throw new Error("Synthetic candidate rejection"); });');
  git("add", ".");
  const failingSha = commit();
  await assert.rejects(() => validateReleaseCandidateInWorker({ repoDir: directory, commit: failingSha }), /Synthetic candidate rejection/);
  const rpcTestPath = path.join(directory, "test", "rpc-security.test.mjs");
  fs.unlinkSync(rpcTestPath);
  git("add", ".");
  await assert.rejects(() => validateReleaseCandidateInWorker({ repoDir: directory, commit: commit() }), /lacks required/);
  fs.writeFileSync(rpcTestPath, "export const syntheticFixture = true;");
  fs.unlinkSync(path.join(directory, "bridge.mjs"));
  git("add", ".");
  await assert.rejects(() => validateReleaseCandidateInWorker({ repoDir: directory, commit: commit() }), /lacks required/);
});

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-lifecycle-"));
  const contents = new Map();
  const queues = new Map();
  const calls = [];
  const services = [];
  let clock = Date.now();
  let closeStatus = 202;
  let losePublication = false;
  t.after(() => { for (const service of services.reverse()) service.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  const response = (status, value = {}, headers = {}) => ({ status, text: JSON.stringify(value), headers: new Headers(headers) });
  function enqueue(url, envelope) {
    const key = url.split("/messages")[0];
    const list = queues.get(key) || [];
    list.push(envelope);
    queues.set(key, list);
  }
  async function request(input, options = {}) {
    const url = new URL(input);
    const method = options.method || "GET";
    calls.push({ url: url.href, method, body: options.body });
    if (url.hostname === "api.github.com") {
      if (url.pathname === "/user") return response(200, { login: "demo-owner" });
      const base = "/repos/demo-owner/rosters";
      if (url.pathname === base) return response(200, { private: false, permissions: { admin: true }, default_branch: "main" });
      if (url.pathname.includes("/git/ref/")) return response(200, { object: { sha: "a".repeat(40) } });
      if (url.pathname.endsWith("/pages")) return response(200, { build_type: "workflow" });
      if (url.pathname.startsWith(`${base}/contents/`)) {
        const filename = decodeURIComponent(url.pathname.slice(`${base}/contents/`.length));
        const existing = contents.get(filename);
        if (method === "PUT") {
          const body = JSON.parse(options.body);
          if (existing && body.sha !== existing.sha) return response(409);
          const content = Buffer.from(body.content, "base64").toString("utf8");
          const sha = crypto.createHash("sha1").update(`${content}:${calls.length}`).digest("hex");
          contents.set(filename, { content, sha });
          if (losePublication && filename.endsWith("flock-roster.json")) {
            losePublication = false;
            throw Object.assign(new Error("Synthetic response lost after publication"), { ambiguous: true });
          }
          return response(existing ? 200 : 201);
        }
        return existing ? response(200, { encoding: "base64", sha: existing.sha, content: Buffer.from(existing.content).toString("base64") }) : response(404);
      }
    }
    if (url.hostname === "demo-owner.github.io") {
      const file = contents.get(url.pathname.replace(/^\/rosters\//, ""));
      return file ? { ...response(200), text: file.content } : response(404);
    }
    if (url.hostname === "demo.service.signalr.net") {
      if (url.pathname.includes(":closeConnections")) return response(closeStatus);
      if (method === "POST") return response(202);
    }
    if (url.hostname === "demo-servicebus.servicebus.windows.net") {
      if (url.pathname.endsWith("/messages") && method === "POST") {
        enqueue(url.origin + url.pathname, JSON.parse(options.body));
        return response(201);
      }
      if (url.pathname.endsWith("/messages/head") && method === "POST") {
        const topic = url.pathname.split("/")[1];
        const recipient = url.pathname.match(/subscriptions\/sub-(peer_[0-9a-f]{24})-e/)[1];
        const list = queues.get(`${url.origin}/${topic}`) || [];
        const index = list.findIndex((packet) => (packet.toOpaquePeerId || packet.bundle?.recipientOpaquePeerId) === recipient);
        if (index < 0) return response(204);
        const packet = list.splice(index, 1)[0];
        return response(201, packet, { location: url.href.replace("head?timeout=5", crypto.randomUUID()) });
      }
      if (method === "DELETE") return response(204);
    }
    throw new Error(`Unexpected mock request: ${method} ${url.hostname}${url.pathname}`);
  }
  async function runAz(args) {
    assert.ok(args.includes("--subscription") && args.includes(subscriptionId));
    calls.push({ azure: args });
    return args.includes("keys") ? { primaryKey: `synthetic-rule-${crypto.randomUUID()}` } : null;
  }
  const host = {
    reportError: () => {},
    listSessions: () => [{ session_id: sessionId, title: "Synthetic existing session" }],
    readTranscript: async () => ({ messages: [{ content: "Approved synthetic live text" }] }),
    sendMessage: async ({ allowed }) => { assert.equal(allowed(), true); return { status: "DELIVERED", result: { admitted: true } }; },
  };
  const home = (name) => path.join(directory, name);
  const options = { repository: "demo-owner/rosters", resourceGroup: "rg-demo", namespaceName: "demo-servicebus", subscriptionId, signalr: { endpoint: "https://demo.service.signalr.net", accessKey: "synthetic-signalr-key" }, publishConsent: true, request, runAz, getToken: async () => "synthetic-owner-token", now: () => clock };
  async function initialize(extra = {}) { return await lifecycle.initializeZeroBrokerOwner({ home: home("owner"), ...options, ...extra }); }
  function open(name, group, customHost = host) {
    const service = lifecycle.openZeroBrokerGroup({ home: home(name), group, host: customHost, ...options });
    services.push(service);
    return service;
  }
  return { home, options, calls, contents, request, initialize, open, host, advance: (ms) => { clock += ms; }, failClose: (status) => { closeStatus = status; }, losePublication: () => { losePublication = true; } };
}

test("owner initialization is consented, private, subscription-pinned and refuses legacy migration", async (t) => {
  const f = fixture(t);
  await assert.rejects(f.initialize({ publishConsent: false }), /consent/);
  assert.equal(f.calls.length, 0);
  const config = await f.initialize();
  assert.equal(config.architecture, "zero-broker");
  assert.equal(config.groups.length, 1);
  const serialized = [...f.contents.values()].map((value) => value.content).join("");
  assert.ok(!serialized.includes("synthetic-signalr-key") && !serialized.includes("PRIVATE KEY") && !serialized.includes("demo-owner"));
  core.writePrivateJson(f.home("legacy"), "config.json", { connectionString: "synthetic legacy configuration" });
  await assert.rejects(f.initialize({ home: f.home("legacy") }), /unchanged/);
  assert.equal(core.readPrivateJson(f.home("legacy"), "config.json").connectionString, "synthetic legacy configuration");
});

test("two distinct owner PCs preserve selected-session grants and confirm one durable admission", async (t) => {
  const f = fixture(t);
  const config = await f.initialize();
  const group = config.groups[0];
  const owner = f.open("owner", group);
  const card = lifecycle.prepareZeroBrokerEnrollment({ home: f.home("peer"), flockUuid: group.flockUuid });
  const invite = await owner.invite({ recipient: card, role: "owner", verifiedSigningFingerprint: card.signingFingerprint, verifiedEncFingerprint: card.encFingerprint });
  await lifecycle.enrollZeroBrokerDevice({ home: f.home("peer"), invite, verifiedRootFingerprint: group.rootFingerprint, request: f.request, resolveGitHubUser: async () => "demo-owner", now: f.options.now });
  let admissions = 0;
  const peer = f.open("peer", group, { ...f.host, sendMessage: async ({ allowed }) => { assert.equal(allowed(), true); admissions++; return { status: "DELIVERED", result: { admitted: true } }; } });
  assert.equal(peer.state.get(group.flockUuid).sealedOwnerVault[peer.device.opaquePeerId], undefined);
  peer.setGrants({ rootSessions: [sessionId], snapshots: {} });
  const initialGrantRevision = peer.grants().revision;
  assert.match(initialGrantRevision, /^[0-9a-f-]{36}$/);
  peer.setGrants({ ...peer.grants(), revision: "caller-cannot-reuse-this-revision" });
  assert.notEqual(peer.grants().revision, initialGrantRevision);
  assert.notEqual(peer.grants().revision, "caller-cannot-reuse-this-revision");
  const ownerDaemon = f.open("owner", group);
  assert.notEqual(ownerDaemon.runtime, owner.runtime);
  let polling = Promise.resolve();
  const timer = setInterval(() => { polling = polling.then(() => Promise.all([ownerDaemon.poll(), peer.poll()])); }, 20);
  try {
    const result = await owner.runtime.request({ toOpaquePeerId: peer.device.opaquePeerId, action: "send_message", params: { sessionId, message: "Synthetic task" }, timeoutMs: 3000 });
    assert.equal(result.status, "DELIVERED");
    assert.equal(admissions, 1);
    const discovered = await peer.runtime.request({ toOpaquePeerId: owner.device.opaquePeerId, action: "list_sessions", params: {}, timeoutMs: 3000 });
    assert.equal(discovered.status, "DELIVERED");
    const transcriptDenied = await peer.runtime.request({ toOpaquePeerId: owner.device.opaquePeerId, action: "get_transcript", params: { sessionId }, timeoutMs: 3000 });
    assert.equal(transcriptDenied.status, "DENIED");
    peer.setGrants({ rootSessions: [], snapshots: {} });
    const denied = await owner.runtime.request({ toOpaquePeerId: peer.device.opaquePeerId, action: "send_message", params: { sessionId, message: "No grant" }, timeoutMs: 3000 });
    assert.equal(denied.status, "DENIED");
    assert.equal(admissions, 1);
  } finally { clearInterval(timer); await polling; }
  f.advance(core.MAX_LEASE_MS + 1);
  await assert.rejects(owner.runtime.request({ toOpaquePeerId: peer.device.opaquePeerId, action: "send_message", params: { sessionId, message: "Expired lease" }, timeoutMs: 1000 }), /lease.*expired/i);
  assert.equal(admissions, 1);
  const expiredEpoch = owner.state.get(group.flockUuid).rosterEpoch;
  assert.equal(await owner.renewAndPrune(), true);
  assert.equal(owner.state.get(group.flockUuid).rosterEpoch, expiredEpoch + 1);
  await owner.runtime.refresh();
  assert.ok(Date.parse(owner.state.get(group.flockUuid).leaseExpiresAt) > f.options.now());
});

test("provisional claims are recipient-sealed, independently approved and pruned at expiry", async (t) => {
  const f = fixture(t);
  const config = await f.initialize({ shared: true, flockName: "team", enrollmentKeys: { namespaceHost: "demo-servicebus.servicebus.windows.net", topicName: "copilot-bridge-offline", sendRuleKey: "synthetic-enrollment-send", listenRuleKey: "synthetic-enrollment-listen" } });
  const group = config.groups[0];
  const owner = f.open("owner", group);
  const invitation = await owner.createVoucher({ durationMinutes: 10 });
  const claim = await lifecycle.claimZeroBrokerVoucher({ home: f.home("guest"), invitation, githubUser: "alice", verifiedRootFingerprint: group.rootFingerprint, request: f.request, now: f.options.now });
  assert.equal(claim.provisional, true);
  const body = f.calls.find((call) => call.url?.includes("/copilot-bridge-offline/messages") && call.method === "POST").body;
  assert.ok(!body.includes("alice") && !body.includes("githubUser"));
  await owner.pollEnrollment();
  const claimId = Object.keys(owner.pendingClaims())[0];
  await assert.rejects(owner.approveClaim({ claimId, signingFingerprint: "wrong", encFingerprint: claim.encFingerprint }), /verification/);
  const approved = await owner.approveClaim({ claimId, signingFingerprint: claim.signingFingerprint, encFingerprint: claim.encFingerprint, durationMinutes: 1 });
  assert.equal(approved.admitted, true);
  await assert.rejects(owner.approveClaim({ claimId, signingFingerprint: claim.signingFingerprint, encFingerprint: claim.encFingerprint }), /consumed/);
  const guest = f.open("guest", group);
  await guest.runtime.refresh();
  const denied = await guest.runtime.request({ toOpaquePeerId: owner.device.opaquePeerId, action: "send_message", params: { message: "Must not execute" }, timeoutMs: 100 });
  assert.equal(denied.status, "DENIED");
  f.advance(61000);
  await owner.renewAndPrune();
  assert.ok(!owner.state.get(group.flockUuid).members.some((member) => member.opaquePeerId === guest.device.opaquePeerId));
  assert.ok(f.calls.some((call) => call.url?.includes(":closeConnections")));
});

test("Zero-Broker MCP surfaces expose verification fields and hide legacy privileged fallbacks", () => {
  const tools = getMcpToolDefinitions({ architecture: "zero-broker" });
  assert.ok(tools.some((tool) => tool.name === "approve_zero_broker_enrollment_claim"));
  assert.ok(tools.find((tool) => tool.name === "enroll_from_invite_json").inputSchema.properties.verified_root_fingerprint);
  assert.ok(!tools.some((tool) => ["create_remote_session", "send_remote_file", "update_remote_machines"].includes(tool.name)));
});

test("ambiguous genesis publication resumes the exact saved identity without re-staging", async (t) => {
  const f = fixture(t);
  f.losePublication();
  await assert.rejects(f.initialize(), /retained private recovery state/);
  const pending = core.readPrivateJson(f.home("owner"), "initialization-pending.json");
  const azureCalls = f.calls.filter((call) => call.azure).length;
  await assert.rejects(f.initialize(), /resume-init/);
  const config = await lifecycle.resumeZeroBrokerInitialization({ home: f.home("owner"), host: f.host, ...f.options });
  assert.equal(config.groups[0].flockUuid, pending.flockUuid);
  assert.equal(f.calls.filter((call) => call.azure).length, azureCalls);
  assert.equal(fs.existsSync(path.join(f.home("owner"), "initialization-pending.json")), false);
  f.advance(core.MAX_LEASE_MS + 1000);
  const owner = f.open("owner", config.groups[0]);
  assert.equal(await owner.renewAndPrune(), true);
  assert.ok(Date.parse(owner.state.get(pending.flockUuid).leaseExpiresAt) > f.options.now());
});

test("owner-control tampering is rejected and another GitHub identity gets no implicit owner data", async (t) => {
  const f = fixture(t);
  const config = await f.initialize();
  const group = config.groups[0];
  const owner = f.open("owner", group);
  const card = lifecycle.prepareZeroBrokerEnrollment({ home: f.home("delegate"), flockUuid: group.flockUuid });
  const invite = await owner.invite({ recipient: card, role: "owner", canMintTokens: true, verifiedSigningFingerprint: card.signingFingerprint, verifiedEncFingerprint: card.encFingerprint });
  await assert.rejects(lifecycle.enrollZeroBrokerDevice({ home: f.home("delegate"), invite: { ...invite, shared: true }, verifiedRootFingerprint: group.rootFingerprint, request: f.request, now: f.options.now }), /owner-signed/);
  const enrolled = await lifecycle.enrollZeroBrokerDevice({ home: f.home("delegate"), invite, verifiedRootFingerprint: group.rootFingerprint, request: f.request, resolveGitHubUser: async () => "another-user", now: f.options.now });
  assert.notEqual(enrolled.metadataDiscovery, "same-owner scope");
  const delegate = f.open("delegate", group);
  assert.equal(delegate.configuration().issuer, true);
  assert.equal(delegate.grants().discovery, false);
  assert.throws(() => delegate.setGrants({ rootSessions: [sessionId], snapshots: {} }), /verified private owner/);
});

test("committed cutover retains an idempotent close plan through failure", async (t) => {
  const f = fixture(t);
  const config = await f.initialize({ shared: true, flockName: "team" });
  const group = config.groups[0];
  const owner = f.open("owner", group);
  const card = lifecycle.prepareZeroBrokerEnrollment({ home: f.home("guest"), flockUuid: group.flockUuid });
  await owner.invite({ recipient: card, verifiedSigningFingerprint: card.signingFingerprint, verifiedEncFingerprint: card.encFingerprint, membershipExpiresAt: new Date(f.options.now() + 60000).toISOString() });
  f.failClose(503);
  await assert.rejects(owner.kick(card.opaquePeerId), /cutover committed/);
  assert.ok(!owner.state.get(group.flockUuid).members.some((member) => member.opaquePeerId === card.opaquePeerId));
  const epoch = owner.state.get(group.flockUuid).rosterEpoch;
  f.failClose(202);
  await owner.retryPendingCloses();
  assert.equal(owner.state.get(group.flockUuid).rosterEpoch, epoch);
  assert.equal(fs.existsSync(path.join(f.home("owner"), "zero-broker", group.flockUuid, "pending-cutover.json")), false);
});

test("headless native adapter denies admission without spawning a replacement session", async (t) => {
  const f = fixture(t);
  const previous = process.env.COPILOT_HOME;
  process.env.COPILOT_HOME = f.home("headless");
  try {
    const result = await createZeroBrokerNativeHost({ scope: "personal", machineId: "synthetic-peer" }).sendMessage({ sessionId, message: "No fallback", allowed: () => true, expiresAt: Date.now() + 1000 });
    assert.equal(result.status, "DENIED");
    assert.match(result.result.reason, /no headless spawn/);
  } finally { if (previous === undefined) delete process.env.COPILOT_HOME; else process.env.COPILOT_HOME = previous; }
});

test("installer isolates package and MCP destinations, preserves other servers and surfaces startup failure", async (t) => {
  const f = fixture(t);
  const previous = process.env.COPILOT_HOME;
  const copilotHome = f.home("integration");
  const home = path.join(copilotHome, "flock");
  const config = await f.initialize({ home });
  core.writePrivateJson(copilotHome, "mcp-config.json", { mcpServers: { unrelated: { command: "synthetic-existing-server" } } });
  process.env.COPILOT_HOME = copilotHome;
  let starts = 0;
  const options = {
    skillRoots: [path.join(copilotHome, "isolated-skills")],
    configureStartup: (script, { strict }) => { assert.equal(script, path.join(home, "flock.mjs")); assert.equal(strict, true); return { type: "synthetic-startup" }; },
    startDaemon: async (actual) => { starts++; assert.equal(actual, config); return { running: true, status: "ready" }; },
  };
  try {
    const result = await installZeroBrokerIntegration(config, options);
    assert.equal(result.daemon.status, "ready");
    assert.equal(starts, 1);
    for (const name of fs.readdirSync(path.resolve(import.meta.dirname, "..")).filter((name) => name.endsWith(".mjs"))) {
      assert.equal(fs.readFileSync(path.join(home, name), "utf8"), fs.readFileSync(path.resolve(import.meta.dirname, "..", name), "utf8"));
    }
    const mcp = JSON.parse(fs.readFileSync(path.join(copilotHome, "mcp-config.json"), "utf8"));
    assert.equal(mcp.mcpServers.unrelated.command, "synthetic-existing-server");
    assert.equal(mcp.mcpServers["copilot-flock"].env.COPILOT_HOME, copilotHome);
    assert.deepEqual(mcp.mcpServers["copilot-flock"].args, [...zeroBrokerNodeFlags(), path.join(home, "flock.mjs"), "mcp"]);
    assert.match(fs.readFileSync(path.join(options.skillRoots[0], "copilot-flock", "SKILL.md"), "utf8"), /No privileged headless fallback/);
    await assert.rejects(installZeroBrokerIntegration(config, { ...options, configureStartup: () => null }), /startup persistence unavailable/);
    assert.equal(starts, 1);
    assert.deepEqual(zeroBrokerNodeFlags("22.5.0"), ["--experimental-sqlite"]);
    assert.deepEqual(zeroBrokerNodeFlags("22.13.0"), []);
    assert.deepEqual(zeroBrokerNodeFlags("23.0.0"), ["--experimental-sqlite"]);
    assert.deepEqual(zeroBrokerNodeFlags("23.4.0"), []);
  } finally { if (previous === undefined) delete process.env.COPILOT_HOME; else process.env.COPILOT_HOME = previous; }
});
