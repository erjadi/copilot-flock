import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { handleTodoRequest } from "../viewer/todo-api.mjs";
import {
  DELIVERY_STAGES,
  TODO_DIMENSIONS,
  VERIFICATION_TIERS,
  appendTodoReadinessEvidence,
  assertEvidenceHistoryPreserved,
  getTodoVerificationPrompt,
  resolveTodoReadiness,
  sanitizeTodoText,
  sortTodoIssues,
  summarizeTodosForFlock,
  MAX_TODO_STALE_AFTER_MINUTES,
  beginTodoRefresh,
  createTodoRefreshState,
  describeTodoTimings,
  formatTodoElapsedAge,
  parseTodoStaleAfterMinutes,
  refreshTodoState,
  validateTodoSnapshot,
} from "../viewer/todo-snapshot.mjs";
import { publishTodos } from "../viewer/publish-todos.mjs";

const issue = (number, rank = number) => ({
  todoId: `demo-${number}`, number, rank, title: `Synthetic item ${number}`,
  type: number === 1 ? "bug" : "architecture", status: "pending",
  rankingBasis: "Provisional, not approved severity", rankingExplanation: "Editorial rationale",
  evidence: "Reported, not independently reproduced", implementationStatus: "Not started",
  nextStep: "Investigate; no fix selected", details: ["Proposal only"], relatedIssues: [],
});
const snapshot = () => ({
  schemaVersion: 1, revision: 1, updatedAt: "2026-11-11T17:00:00Z",
  source: "Synthetic test tracker", issues: [issue(2), issue(1)],
});
const scores = (value) => Object.fromEntries(TODO_DIMENSIONS.map(({ key }) => [key, value]));
const progress = () => ({
  stage: "in_progress", workerSessionId: "synthetic-worker", model: "synthetic-model",
  branch: "synthetic-feature", commitSha: null, changedFiles: [], testSummary: null,
  mergedIn35Candidate: false, flockReviewStatus: "pending",
});

test("optional implementation tracking preserves unknown and reported outcomes without inferring completion", () => {
  assert.equal(Object.hasOwn(validateTodoSnapshot(snapshot()).issues[0], "implementationDetails"), false);
  const value = snapshot();
  value.issues[0].implementationDetails = { ...progress(), secret: "not projected" };
  assert.deepEqual(validateTodoSnapshot(value).issues[1].implementationDetails, progress());
  value.issues[0].status = "done";
  value.issues[0].implementationDetails = {
    ...progress(), stage: "implemented", commitSha: "a".repeat(40), changedFiles: ["viewer/synthetic.ts"],
    testSummary: "Reported: 2 passed; deployment not verified", mergedIn35Candidate: true, flockReviewStatus: "pending",
  };
  const projected = validateTodoSnapshot(value).issues[1];
  assert.deepEqual(projected.implementationDetails, value.issues[0].implementationDetails);
  assert.equal(projected.implementationDetails.flockReviewStatus, "pending");
  for (const change of [
    () => null, () => [], () => ({}), p => ({ ...p, stage: "" }),
    p => ({ ...p, workerSessionId: null }), p => ({ ...p, model: "" }), p => ({ ...p, branch: false }),
    p => ({ ...p, commitSha: 42 }), p => ({ ...p, changedFiles: "file.ts" }),
    p => ({ ...p, changedFiles: [" "] }), p => ({ ...p, testSummary: {} }),
    p => ({ ...p, mergedIn35Candidate: "false" }), p => ({ ...p, flockReviewStatus: null }),
  ]) {
    const invalid = snapshot(); invalid.issues[0].implementationDetails = change(progress());
    assert.throws(() => validateTodoSnapshot(invalid), /Invalid TODO snapshot/);
  }
});

test("optional scoring contract preserves old snapshots and rejects partial or invalid supplied metadata", () => {
  const legacy = validateTodoSnapshot(snapshot()).issues[0];
  assert.equal(Object.hasOwn(legacy, "scores"), false);
  assert.equal(Object.hasOwn(legacy, "evidenceConfidence"), false);
  assert.equal(Object.hasOwn(legacy, "acceptanceCriteria"), false);
  const value = snapshot();
  Object.assign(value.issues[0], {
    scores: { ...scores(3), effortAndChangeRisk: 5, secret: "not projected" },
    evidenceConfidence: "reported", acceptanceCriteria: ["Reproduce the reported omission", "Verify scoped behavior"],
  });
  const result = validateTodoSnapshot(value).issues.find(item => item.number === 2);
  assert.deepEqual(result.scores, { ...scores(3), effortAndChangeRisk: 5 });
  assert.equal(result.evidenceConfidence, "reported");
  assert.deepEqual(result.acceptanceCriteria, value.issues[0].acceptanceCriteria);
  for (const metadata of [
    { scores: {} }, { scores: null }, { scores: scores(0) }, { scores: scores(6) },
    { scores: scores(1.5) }, { scores: scores("3") },
    { evidenceConfidence: "probably true" }, { evidenceConfidence: null },
    { acceptanceCriteria: "Done" }, { acceptanceCriteria: [" "] },
  ]) {
    const invalid = snapshot(); Object.assign(invalid.issues[0], metadata);
    assert.throws(() => validateTodoSnapshot(invalid), /Invalid TODO snapshot/);
  }
});

test("all six dimension sorts support both directions, stable editorial ties and unscored-last without confidence penalties", () => {
  for (const { key } of TODO_DIMENSIONS) {
    const low = { ...issue(1), scores: { ...scores(5), [key]: 1 }, evidenceConfidence: "independently_verified" };
    const high = { ...issue(2), scores: { ...scores(1), [key]: 5 }, evidenceConfidence: "reported" };
    const tied = { ...issue(3), scores: high.scores };
    const missing = { ...issue(4), rank: 1 };
    const input = [missing, tied, high, low];
    assert.deepEqual(sortTodoIssues(input, key, "asc").map(i => i.number), [1, 2, 3, 4], key);
    assert.deepEqual(sortTodoIssues(input, key, "desc").map(i => i.number), [2, 3, 1, 4], key);
    assert.deepEqual(input.map(i => i.number), [4, 3, 2, 1]);
  }
  const tied = [issue(1, 2), issue(2, 2)].reverse();
  assert.deepEqual(sortTodoIssues(tied).map(i => i.number), [1, 2]);
  assert.deepEqual(sortTodoIssues([issue(2), issue(1)]).map(i => i.rank), [1, 2]);
  assert.deepEqual(sortTodoIssues([issue(1), issue(2)], "editorial", "desc").map(i => i.rank), [2, 1]);
});

test("TODO contract sorts explicit ranks, projects only approved fields and rejects ambiguous/incomplete data", () => {
  const data = snapshot();
  data.secret = "must not be returned";
  data.issues[0].source = { sessionId: "not exported" };
  const result = validateTodoSnapshot(data);
  assert.deepEqual(result.issues.map((item) => item.number), [1, 2]);
  assert.equal(result.secret, undefined);
  assert.equal(result.issues[1].source, undefined);
  for (const change of [
    (value) => { value.issues[1].rank = 2; },
    (value) => { value.issues[1].todoId = "demo-2"; },
    (value) => { value.issues[1].evidence = ""; },
    (value) => { value.issues[1].status = "probably fixed"; },
    (value) => { value.issues[1].relatedIssues = [99]; },
    (value) => { value.updatedAt = "yesterday"; },
  ]) {
    const invalid = snapshot(); change(invalid);
    assert.throws(() => validateTodoSnapshot(invalid), /Invalid TODO snapshot/);
  }
  assert.deepEqual(validateTodoSnapshot({ ...snapshot(), issues: [] }).issues, []);
});

test("TODO endpoint is opt-in, read-only, same-origin and reloads durable data without a seed fallback", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "flock-todos-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "snapshot.json");
  let configured;
  const errors = [];
  const server = http.createServer(async (req, res) => {
    if (!await handleTodoRequest(req, res, { snapshotPath: configured, log: (message) => errors.push(message) })) {
      res.writeHead(404); res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(`${base}/api/todos`)).status, 503);
  configured = file;
  assert.equal((await fetch(`${base}/api/todos`)).status, 503);
  await writeFile(file, JSON.stringify(snapshot()));
  const response = await fetch(`${base}/api/todos`, { headers: { Origin: base } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("access-control-allow-origin"), null);
  assert.deepEqual((await response.json()).issues.map((item) => item.rank), [1, 2]);
  for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
    assert.equal((await fetch(`${base}/api/todos`, { method })).status, 405);
  }
  assert.equal((await fetch(`${base}/api/todos`, { headers: { Origin: "https://other.invalid" } })).status, 403);
  assert.equal((await fetch(`${base}/api/todos`, { headers: { "Sec-Fetch-Site": "cross-site" } })).status, 403);
  const updated = { ...snapshot(), revision: 2 };
  Object.assign(updated.issues[0], { scores: scores(4), evidenceConfidence: "reproduced", acceptanceCriteria: ["Verify result"], implementationDetails: progress() });
  await writeFile(file, JSON.stringify(updated));
  const scored = await (await fetch(`${base}/api/todos`)).json();
  assert.equal(scored.revision, 2);
  assert.deepEqual(scored.issues[1].scores, scores(4));
  assert.equal(scored.issues[1].evidenceConfidence, "reproduced");
  assert.deepEqual(scored.issues[1].implementationDetails, progress());
  await writeFile(file, "{broken");
  const failed = await fetch(`${base}/api/todos`);
  assert.equal(failed.status, 503);
  assert.deepEqual(await failed.json(), { error: "TODO snapshot is unreadable or invalid" });
  await writeFile(file, " ".repeat(1024 * 1024 + 1));
  assert.equal((await fetch(`${base}/api/todos`)).status, 503);
  assert.ok(errors.length >= 2);
  assert.equal((await fetch(`${base}/other`)).status, 404);
});

test("TODO publication is private, atomic and refuses stale/conflicting updates", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "flock-publish-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const source = path.join(dir, "incoming.json"), destination = path.join(dir, "runtime.json");
  await writeFile(source, JSON.stringify(snapshot()));
  await publishTodos(source, destination);
  if (process.platform !== "win32") assert.equal((await stat(destination)).mode & 0o777, 0o600);
  await publishTodos(source, destination);
  const newer = { ...snapshot(), revision: 2, updatedAt: "2026-11-11T18:00:00Z" };
  Object.assign(newer.issues[0], { scores: scores(5), evidenceConfidence: "reported", acceptanceCriteria: ["Scoped acceptance"], implementationDetails: progress() });
  await writeFile(source, JSON.stringify(newer));
  await publishTodos(source, destination);
  const published = JSON.parse(await readFile(destination, "utf8"));
  assert.deepEqual(published.issues[1].scores, scores(5));
  assert.deepEqual(published.issues[1].implementationDetails, progress());
  assert.deepEqual(published.issues[1].acceptanceCriteria, ["Scoped acceptance"]);
  await writeFile(source, JSON.stringify(snapshot()));
  await assert.rejects(publishTodos(source, destination), /older TODO revision/);
  await writeFile(source, JSON.stringify({ ...newer, issues: [issue(1)] }));
  await assert.rejects(publishTodos(source, destination), /new revision/);
  await writeFile(source, JSON.stringify({ ...newer, revision: 3, updatedAt: "2026-11-11T16:00:00Z" }));
  await assert.rejects(publishTodos(source, destination), /older TODO timestamp/);
  assert.equal(JSON.parse(await readFile(destination, "utf8")).revision, 2);
  await writeFile(source, JSON.stringify(snapshot()));
  await assert.rejects(publishTodos(source, fileURLToPath(new URL("../viewer/not-written.json", import.meta.url))), /outside the repository/);
  const oversized = snapshot();
  oversized.issues[0].details = Array(60).fill("x".repeat(20000));
  await writeFile(source, JSON.stringify(oversized));
  await assert.rejects(publishTodos(source, destination), /exceeds 1 MiB/);
});

test("configured private TODO data rejects non-loopback sockets regardless of proxy headers", async () => {
  for (const remoteAddress of ["192.0.2.10", "::ffff:192.0.2.10", undefined]) {
    let status, body;
    await handleTodoRequest({
      url: "/api/todos", method: "GET", socket: { remoteAddress },
      headers: { host: "localhost", "x-forwarded-for": "127.0.0.1" },
    }, {
      writeHead(code) { status = code; }, end(value) { body = JSON.parse(value); },
    }, { snapshotPath: "must-not-be-read.json" });
    assert.equal(status, 403);
    assert.match(body.error, /restricted to loopback/);
  }
});

test("configured LAN access permits only its exact subnet and loopback without trusting forwarded addresses", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "flock-lan-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "snapshot.json");
  await writeFile(file, JSON.stringify(snapshot()));
  const request = async (remoteAddress, lanCidr = "192.168.42.0/24", headers = {}) => {
    let status, body;
    await handleTodoRequest({
      url: "/api/todos", method: "GET", socket: { remoteAddress },
      headers: { host: "viewer.example:8099", ...headers },
    }, {
      writeHead(code) { status = code; }, end(value) { body = JSON.parse(value); },
    }, { snapshotPath: file, lanCidr, log() {} });
    return { status, body };
  };
  for (const address of ["192.168.42.1", "192.168.42.254", "::ffff:192.168.42.17", "127.0.0.1", "::1", "::ffff:127.0.0.1"]) {
    const result = await request(address);
    assert.equal(result.status, 200, address);
    assert.equal(result.body.revision, 1);
  }
  for (const address of ["192.168.41.255", "192.168.43.0", "10.1.2.3", "172.20.0.1", "100.70.20.234", "::ffff:100.70.20.234", "203.0.113.8", "2001:db8::1", undefined]) {
    const result = await request(address, "192.168.42.0/24", {
      "x-forwarded-for": "192.168.42.1", "x-real-ip": "127.0.0.1",
      forwarded: "for=192.168.42.1", origin: "http://viewer.example:8099",
    });
    assert.equal(result.status, 403, String(address));
    assert.equal(result.body.issues, undefined);
  }
  assert.equal((await request("192.168.42.17", "")).status, 403);
  assert.equal((await request("192.168.42.17", "192.168.42.17/32")).status, 200);
  assert.equal((await request("192.168.42.18", "192.168.42.17/32")).status, 403);
  assert.equal((await request("192.168.42.17", "192.168.42.0/24", { origin: "http://other.example" })).status, 403);
  for (const cidr of ["192.168.42.1/24", "0.0.0.0/0", "192.168.42.0/33", "192.168.42.0", "192.168.42.0/24,10.0.0.0/8", "::/0"]) {
    assert.equal((await request("127.0.0.1", cidr)).status, 503, cidr);
  }
});

const receipt = (overrides = {}) => ({
  candidateSha: "52c9f1a7e513dac0c96afe77fa9219baff5bc7ef",
  hostId: "DESKTOP-ALPHA",
  os: "win32-x64",
  command: "node --test test/viewer-todos.test.mjs",
  capturedAt: "2026-11-12T01:15:00Z",
  passCount: 8,
  failCount: 0,
  skipCount: 0,
  prerequisites: ["Node.js >= 22.5"],
  evidenceDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  confidence: "independently_verified",
  verificationTier: "unit_synthetic",
  ...overrides,
});

test("merged implementation, readiness and freshness metadata survives publication and repeated refresh together", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "flock-unified-todos-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const source = path.join(dir, "incoming.json"), destination = path.join(dir, "runtime.json");
  const raw = { ...snapshot(), staleAfterMinutes: 60 };
  Object.assign(raw.issues[0], {
    implementationDetails: { ...progress(), stage: "implemented", commitSha: receipt().candidateSha },
    candidateSha: receipt().candidateSha, verificationTier: "unit_synthetic",
    readinessEvidence: [receipt()],
  });
  await writeFile(source, JSON.stringify(raw));
  await publishTodos(source, destination);
  const load = async () => JSON.parse(await readFile(destination, "utf8"));
  let state = await refreshTodoState(createTodoRefreshState(), load, { now: Date.parse("2026-11-12T10:00:00Z") });
  state = await refreshTodoState(state, load, { now: Date.parse("2026-11-12T10:05:00Z") });
  const item = state.snapshot.issues.find(i => i.number === 2);
  assert.deepEqual(item.implementationDetails, raw.issues[0].implementationDetails);
  assert.equal(resolveTodoReadiness(item).effectiveVerificationTier, "unit_synthetic");
  assert.equal(state.unchangedRevision, true);
  assert.equal(state.lastSuccessfulFetchAt, "2026-11-12T10:05:00.000Z");
  assert.equal(describeTodoTimings(state, { now: Date.parse("2026-11-12T10:05:00Z") }).freshnessState, "stale");
  const summary = summarizeTodosForFlock(state.snapshot, { format: "json" });
  assert.equal(summary.issues.find(i => i.number === 2).verificationTier, "unit_synthetic");
  assert.equal(state.snapshot.updatedAt, raw.updatedAt);
});

test("readiness evidence schema is backward-compatible, projects approved fields and rejects malformed receipts", () => {
  assert.deepEqual(VERIFICATION_TIERS, ["unverified", "source_reviewed", "unit_synthetic", "live_multi_pc"]);
  assert.deepEqual(DELIVERY_STAGES, ["proposed", "approved", "implemented", "deployed", "verified"]);

  const legacy = validateTodoSnapshot(snapshot()).issues[0];
  for (const key of ["candidateSha", "verificationTier", "deliveryStage", "verificationPrompt", "readinessEvidence"]) {
    assert.equal(Object.hasOwn(legacy, key), false, key);
  }

  const valid = snapshot();
  Object.assign(valid.issues[0], {
    candidateSha: "52C9F1A7E513DAC0C96AFE77FA9219BAFF5BC7EF",
    verificationTier: "live_multi_pc",
    deliveryStage: "implemented",
    verificationPrompt: "Run node --test test/viewer-todos.test.mjs on two hosts and record receipts.",
    readinessEvidence: [
      { ...receipt({ prerequisites: [], deliveryStage: "implemented", extraSecret: "stripped" }) },
    ],
  });
  const normalized = validateTodoSnapshot(valid).issues.find((item) => item.number === 2);
  assert.equal(normalized.candidateSha, "52c9f1a7e513dac0c96afe77fa9219baff5bc7ef");
  assert.equal(normalized.verificationTier, "live_multi_pc");
  assert.equal(normalized.deliveryStage, "implemented");
  assert.equal(normalized.readinessEvidence.length, 1);
  assert.equal(normalized.readinessEvidence[0].extraSecret, undefined);
  assert.deepEqual(normalized.readinessEvidence[0].prerequisites, []);

  for (const invalidPatch of [
    { candidateSha: "not-a-sha" },
    { candidateSha: "123456" },
    { verificationTier: "fully_tested" },
    { deliveryStage: "shipped" },
    { verificationPrompt: "  " },
    { readinessEvidence: "none" },
    { readinessEvidence: [receipt({ hostId: "" })] },
    { readinessEvidence: [receipt({ os: " " })] },
    { readinessEvidence: [receipt({ command: "bad\u0007cmd" })] },
    { readinessEvidence: [receipt({ capturedAt: "2026-11-12" })] },
    { readinessEvidence: [receipt({ passCount: -1 })] },
    { readinessEvidence: [receipt({ failCount: 1.2 })] },
    { readinessEvidence: [receipt({ skipCount: -3 })] },
    { readinessEvidence: [receipt({ prerequisites: [" "] })] },
    { readinessEvidence: [receipt({ evidenceDigest: "trust-me" })] },
    { readinessEvidence: [receipt({ failCount: 1, disposition: "accepted" })] },
    { readinessEvidence: [receipt({ verificationTier: "unverified", confidence: "independently_verified" })] },
    { readinessEvidence: [receipt({ passCount: 0, failCount: 0, disposition: "accepted" })] },
    { readinessEvidence: [receipt(), receipt()] },
  ]) {
    const bad = snapshot();
    Object.assign(bad.issues[0], invalidPatch);
    assert.throws(() => validateTodoSnapshot(bad), /Invalid TODO snapshot/);
  }
});

test("done or implemented alone cannot display as independently_verified, live_multi_pc or verified without matching receipts", () => {
  const doneWithoutReceipts = resolveTodoReadiness({
    ...issue(5),
    status: "done",
    deliveryStage: "verified",
    evidenceConfidence: "independently_verified",
    verificationTier: "live_multi_pc",
    candidateSha: "aaaa1111bbbb2222",
  });
  assert.equal(doneWithoutReceipts.effectiveVerificationTier, "unverified");
  assert.equal(doneWithoutReceipts.effectiveConfidence, "reported");
  assert.equal(doneWithoutReceipts.effectiveDeliveryStage, "implemented");
  assert.ok(doneWithoutReceipts.unverifiedCompletionNote);
  assert.equal(doneWithoutReceipts.downgradeReasons.length, 3);

  const mismatchedSha = resolveTodoReadiness({
    ...issue(5),
    status: "done",
    deliveryStage: "implemented",
    evidenceConfidence: "independently_verified",
    verificationTier: "live_multi_pc",
    candidateSha: "bbbb2222cccc3333",
    readinessEvidence: [
      receipt({ candidateSha: "aaaa1111bbbb2222", hostId: "PC-1", verificationTier: "live_multi_pc" }),
      receipt({
        candidateSha: "aaaa1111bbbb2222",
        hostId: "PC-2",
        os: "linux-x64",
        verificationTier: "live_multi_pc",
        evidenceDigest: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      }),
    ],
  });
  assert.equal(mismatchedSha.effectiveVerificationTier, "unverified");
  assert.notEqual(mismatchedSha.effectiveConfidence, "independently_verified");
  assert.equal(mismatchedSha.supersededEntries.length, 2);

  const singleHostClaimingMultiPc = resolveTodoReadiness({
    ...issue(5),
    status: "done",
    deliveryStage: "implemented",
    evidenceConfidence: "independently_verified",
    verificationTier: "live_multi_pc",
    candidateSha: "52c9f1a7e513dac0c96afe77fa9219baff5bc7ef",
    readinessEvidence: [
      receipt({ hostId: "DESKTOP-ALPHA", capturedAt: "2026-11-12T01:00:00Z", verificationTier: "live_multi_pc" }),
      receipt({
        hostId: "desktop-alpha",
        capturedAt: "2026-11-12T01:10:00Z",
        verificationTier: "live_multi_pc",
        evidenceDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      }),
    ],
  });
  assert.equal(singleHostClaimingMultiPc.effectiveVerificationTier, "unit_synthetic");
  assert.equal(singleHostClaimingMultiPc.effectiveConfidence, "independently_verified");
  assert.equal(singleHostClaimingMultiPc.acceptedEntries.length, 1);
  assert.equal(singleHostClaimingMultiPc.supersededEntries.length, 1);

  const splitHostsAcrossDifferentShas = resolveTodoReadiness({
    ...issue(5),
    status: "done",
    verificationTier: "live_multi_pc",
    evidenceConfidence: "independently_verified",
    readinessEvidence: [
      receipt({ candidateSha: "11111111aaaa2222", hostId: "DESKTOP-ALPHA", verificationTier: "live_multi_pc" }),
      receipt({
        candidateSha: "33333333bbbb4444",
        hostId: "DESKTOP-BETA",
        verificationTier: "live_multi_pc",
        evidenceDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      }),
    ],
  });
  assert.equal(splitHostsAcrossDifferentShas.effectiveVerificationTier, "unverified");
  assert.notEqual(splitHostsAcrossDifferentShas.effectiveConfidence, "independently_verified");

  const verifiedMultiPc = resolveTodoReadiness({
    ...issue(5),
    status: "done",
    deliveryStage: "verified",
    evidenceConfidence: "independently_verified",
    verificationTier: "live_multi_pc",
    candidateSha: "52c9f1a7e513dac0c96afe77fa9219baff5bc7ef",
    readinessEvidence: [
      receipt({ hostId: "DESKTOP-ALPHA", os: "win32-x64", verificationTier: "live_multi_pc" }),
      receipt({
        hostId: "VM-LINUX-BETA",
        os: "linux-x64",
        verificationTier: "live_multi_pc",
        evidenceDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      }),
    ],
  });
  assert.equal(verifiedMultiPc.effectiveVerificationTier, "live_multi_pc");
  assert.equal(verifiedMultiPc.effectiveConfidence, "independently_verified");
  assert.equal(verifiedMultiPc.effectiveDeliveryStage, "verified");
  assert.deepEqual(verifiedMultiPc.downgradeReasons, []);
});

test("results from another host or SHA preserve rejected and superseded evidence history across append and publish", async (t) => {
  let tracked = issue(1);
  tracked = appendTodoReadinessEvidence(
    tracked,
    receipt({
      candidateSha: "aaaa1111bbbb2222",
      hostId: "DESKTOP-ALPHA",
      passCount: 4,
      failCount: 2,
      confidence: "reproduced",
      evidenceDigest: "sha256:aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000",
    }),
  );
  tracked = appendTodoReadinessEvidence(
    tracked,
    receipt({
      candidateSha: "aaaa1111bbbb2222",
      hostId: "DESKTOP-BETA",
      os: "linux-x64",
      passCount: 6,
      failCount: 0,
      verificationTier: "live_multi_pc",
      evidenceDigest: "sha256:bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111",
    }),
  );
  const onSameShaWithFailingPeer = resolveTodoReadiness({
    ...tracked,
    status: "done",
    verificationTier: "live_multi_pc",
    evidenceConfidence: "independently_verified",
  });
  assert.equal(onSameShaWithFailingPeer.rejectedEntries.length, 1);
  assert.equal(onSameShaWithFailingPeer.effectiveVerificationTier, "unverified");
  assert.notEqual(onSameShaWithFailingPeer.effectiveConfidence, "independently_verified");
  assert.deepEqual(onSameShaWithFailingPeer.failingHosts, ["DESKTOP-ALPHA"]);

  tracked = appendTodoReadinessEvidence(
    tracked,
    receipt({
      candidateSha: "cccc3333dddd4444",
      hostId: "DESKTOP-ALPHA",
      capturedAt: "2026-11-12T02:00:00Z",
      passCount: 9,
      failCount: 0,
      verificationTier: "unit_synthetic",
      evidenceDigest: "sha256:cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222cccc2222",
    }),
    { promoteCandidate: true },
  );
  assert.equal(tracked.candidateSha, "cccc3333dddd4444");
  assert.equal(tracked.readinessEvidence.length, 3);
  assert.equal(tracked.readinessEvidence[0].disposition, "rejected");
  assert.equal(tracked.readinessEvidence[1].disposition, "superseded");
  assert.equal(tracked.readinessEvidence[2].disposition, "accepted");

  const rev1 = { ...snapshot(), revision: 1, updatedAt: "2026-11-12T02:05:00Z", issues: [tracked, issue(2)] };
  const droppedRejected = {
    ...rev1,
    revision: 2,
    updatedAt: "2026-11-12T02:10:00Z",
    issues: [{ ...tracked, readinessEvidence: tracked.readinessEvidence.slice(1) }, issue(2)],
  };
  assert.throws(() => assertEvidenceHistoryPreserved(rev1, droppedRejected), /overwrite or drop readiness evidence history/);

  const resurrectedSuperseded = {
    ...rev1,
    revision: 2,
    updatedAt: "2026-11-12T02:10:00Z",
    issues: [
      {
        ...tracked,
        readinessEvidence: tracked.readinessEvidence.map((entry, idx) => (idx === 1 ? { ...entry, disposition: "accepted" } : entry)),
      },
      issue(2),
    ],
  };
  assert.throws(() => assertEvidenceHistoryPreserved(rev1, resurrectedSuperseded), /resurrect superseded readiness evidence/);

  const dir = await mkdtemp(path.join(os.tmpdir(), "flock-evidence-history-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const source = path.join(dir, "source.json");
  const destination = path.join(dir, "runtime.json");
  await writeFile(source, JSON.stringify(rev1));
  await publishTodos(source, destination);
  await writeFile(source, JSON.stringify(droppedRejected));
  await assert.rejects(publishTodos(source, destination), /overwrite or drop readiness evidence history/);

  const appendedNextHost = appendTodoReadinessEvidence(
    tracked,
    receipt({
      candidateSha: "cccc3333dddd4444",
      hostId: "DESKTOP-BETA",
      os: "linux-x64",
      capturedAt: "2026-11-12T02:15:00Z",
      passCount: 9,
      failCount: 0,
      verificationTier: "live_multi_pc",
      evidenceDigest: "sha256:dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333",
    }),
  );
  const rev2 = { ...rev1, revision: 2, updatedAt: "2026-11-12T02:20:00Z", issues: [appendedNextHost, issue(2)] };
  await writeFile(source, JSON.stringify(rev2));
  const published = await publishTodos(source, destination);
  assert.equal(published.issues[0].readinessEvidence.length, 4);

  const lateBackdated = appendTodoReadinessEvidence(
    appendedNextHost,
    receipt({
      candidateSha: "cccc3333dddd4444",
      hostId: "DESKTOP-BETA",
      os: "linux-x64",
      capturedAt: "2026-11-12T02:01:00Z",
      passCount: 9,
      failCount: 0,
      verificationTier: "live_multi_pc",
      evidenceDigest: "sha256:eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444",
    }),
  );
  assert.equal(lateBackdated.readinessEvidence.at(-1).disposition, "superseded");
  assert.equal(lateBackdated.readinessEvidence.at(-2).disposition, "accepted");
});

test("remote Flock summary helper filters by effective tier, redacts secrets/paths and keeps verification prompts copy-only", async () => {
  const raw = snapshot();
  raw.source = "Session export C:\\Users\\ericj\\.copilot\\session-state\\abc\\todos.json Bearer super-secret-token";
  Object.assign(raw.issues[0], {
    status: "done",
    deliveryStage: "implemented",
    evidenceConfidence: "independently_verified",
    verificationTier: "live_multi_pc",
    nextStep: "Inspect /home/erjadi/.copilot/flock/config.json with SharedAccessKey=topsecret123; and ghp_ABCDEF1234567890token",
    verificationPrompt: "Verify candidate on remote host using api_key=mysecretvalue and ~/.copilot/flock/config.json",
  });
  Object.assign(raw.issues[1], {
    status: "done",
    deliveryStage: "verified",
    candidateSha: "52c9f1a7e513dac0c96afe77fa9219baff5bc7ef",
    verificationTier: "unit_synthetic",
    evidenceConfidence: "independently_verified",
    readinessEvidence: [
      receipt({
        verificationPrompt: "Receipt fallback prompt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sigvalue",
      }),
    ],
  });

  assert.match(getTodoVerificationPrompt(raw.issues[1]), /Receipt fallback prompt/);
  assert.equal(
    sanitizeTodoText("\u001b[31m-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\u001b[0m"),
    "[redacted private key]",
  );

  const { json, text } = summarizeTodosForFlock(raw);
  assert.equal(json.readOnly, true);
  assert.equal(json.executable, false);
  assert.equal(json.counts.byVerificationTier.unit_synthetic, 1);
  assert.equal(json.counts.byVerificationTier.unverified, 1);
  assert.equal(json.counts.byVerificationTier.live_multi_pc, 0);
  assert.equal(Object.hasOwn(json.issues[0], "verificationPrompt"), false);
  for (const leaked of ["super-secret-token", "C:\\Users\\ericj", "/home/erjadi", "topsecret123", "ghp_ABCDEF", "mysecretvalue"]) {
    assert.equal(text.includes(leaked), false, leaked);
    assert.equal(JSON.stringify(json).includes(leaked), false, leaked);
  }

  const onlyUnit = summarizeTodosForFlock(raw, {
    format: "json",
    verificationTier: "unit_synthetic",
    includeVerificationPrompt: true,
  });
  assert.equal(onlyUnit.issues.length, 1);
  assert.equal(onlyUnit.issues[0].number, 1);
  assert.match(onlyUnit.issues[0].verificationPrompt, /\[redacted JWT\]/);

  const onlyMultiPc = summarizeTodosForFlock(raw, { format: "json", verificationTier: "live_multi_pc" });
  assert.equal(onlyMultiPc.issues.length, 0);

  const uiSource = await readFile(new URL("../viewer/src/components/fleet/TodosView.tsx", import.meta.url), "utf8");
  assert.match(uiSource, /aria-label="TODO verification tier"/);
  assert.match(uiSource, /Copy verification prompt/);
  assert.match(uiSource, /navigator\.clipboard\.writeText/);
});
test("controlled clock distinguishes source updatedAt age from lastSuccessfulFetchAt across unchanged and updated revisions", async () => {
  let clockMs = Date.parse("2026-11-12T10:00:00Z");
  const now = () => clockMs;
  const rev4 = { ...snapshot(), revision: 4, updatedAt: "2026-11-12T08:00:00Z" };

  let state = await refreshTodoState(createTodoRefreshState(), async () => rev4, { now });
  assert.equal(state.error, null);
  assert.equal(state.unchangedRevision, false);
  assert.equal(state.snapshot.revision, 4);
  assert.equal(state.snapshot.updatedAt, "2026-11-12T08:00:00Z");
  assert.equal(state.lastSuccessfulFetchAt, "2026-11-12T10:00:00.000Z");

  let timings = describeTodoTimings(state, { now });
  assert.equal(timings.revision, 4);
  assert.equal(timings.sourceUpdatedAt, "2026-11-12T08:00:00Z");
  assert.equal(timings.sourceAgeLabel, "2h ago");
  assert.equal(timings.lastSuccessfulFetchAt, "2026-11-12T10:00:00.000Z");
  assert.equal(timings.fetchAgeLabel, "0s ago");
  assert.equal(timings.freshnessState, "age_only");
  assert.equal(timings.isStale, null);
  assert.equal(timings.machinePresenceInferred, false);

  // Advance clock 15m 30s without refreshing: both ages advance independently.
  clockMs = Date.parse("2026-11-12T10:15:30Z");
  timings = describeTodoTimings(state, { now });
  assert.equal(timings.sourceAgeLabel, "2h 15m ago");
  assert.equal(timings.fetchAgeLabel, "15m 30s ago");

  // Refreshing an unchanged revision advances lastSuccessfulFetchAt without making source data appear newly authored.
  state = await refreshTodoState(state, async () => ({ ...rev4 }), { now });
  assert.equal(state.unchangedRevision, true);
  assert.equal(state.snapshot.revision, 4);
  assert.equal(state.snapshot.updatedAt, "2026-11-12T08:00:00Z");
  assert.equal(state.lastSuccessfulFetchAt, "2026-11-12T10:15:30.000Z");
  timings = describeTodoTimings(state, { now });
  assert.equal(timings.sourceAgeLabel, "2h 15m ago");
  assert.equal(timings.fetchAgeLabel, "0s ago");
  assert.equal(timings.unchangedRevision, true);

  // Refreshing a newly authored revision updates updatedAt, revision, and clears unchangedRevision.
  clockMs = Date.parse("2026-11-12T10:20:00Z");
  const rev5 = { ...snapshot(), revision: 5, updatedAt: "2026-11-12T10:18:00Z" };
  state = await refreshTodoState(state, async () => rev5, { now });
  assert.equal(state.unchangedRevision, false);
  assert.equal(state.snapshot.revision, 5);
  timings = describeTodoTimings(state, { now });
  assert.equal(timings.sourceAgeLabel, "2m ago");
  assert.equal(timings.fetchAgeLabel, "0s ago");

  // Clock skew where updatedAt is slightly ahead of the local clock is explicit and non-negative.
  assert.equal(formatTodoElapsedAge("2026-11-12T10:20:05Z", clockMs), "0s ago (ahead of local clock)");
  const skewedState = await refreshTodoState(createTodoRefreshState(), async () => ({
    ...snapshot(), revision: 6, updatedAt: "2026-11-12T10:20:05Z",
  }), { now });
  const skewedTimings = describeTodoTimings(skewedState, { now });
  assert.equal(skewedTimings.sourceAheadOfClock, true);
  assert.equal(skewedTimings.sourceElapsedMs, 0);
  assert.equal(skewedTimings.sourceAgeLabel, "0s ago (ahead of local clock)");
});

test("optional freshness threshold policy evaluates source age only and never infers machine online/offline state", async (t) => {
  assert.equal(parseTodoStaleAfterMinutes(undefined), null);
  assert.equal(parseTodoStaleAfterMinutes(""), null);
  assert.equal(parseTodoStaleAfterMinutes(60), 60);
  assert.equal(parseTodoStaleAfterMinutes("120"), 120);
  for (const invalid of [0, -1, 1.5, MAX_TODO_STALE_AFTER_MINUTES + 1, "0", "-5", "060", "60m", false, {}]) {
    assert.throws(() => parseTodoStaleAfterMinutes(invalid), /Invalid TODO freshness threshold/);
  }
  for (const badField of [null, 0, -5, 2.5, "60", MAX_TODO_STALE_AFTER_MINUTES + 1]) {
    assert.throws(() => validateTodoSnapshot({ ...snapshot(), staleAfterMinutes: badField }), /Invalid TODO snapshot/);
  }
  assert.equal(Object.hasOwn(validateTodoSnapshot(snapshot()), "staleAfterMinutes"), false);
  assert.equal(validateTodoSnapshot({ ...snapshot(), staleAfterMinutes: 90 }).staleAfterMinutes, 90);

  let clockMs = Date.parse("2026-11-12T09:00:00Z");
  const now = () => clockMs;
  const policySnapshot = { ...snapshot(), revision: 7, updatedAt: "2026-11-12T08:00:00Z", staleAfterMinutes: 60 };
  let state = await refreshTodoState(createTodoRefreshState(), async () => policySnapshot, { now });

  // Exact 60m boundary is still fresh.
  let timings = describeTodoTimings(state, { now });
  assert.equal(timings.staleAfterMinutes, 60);
  assert.equal(timings.freshnessState, "fresh");
  assert.equal(timings.isStale, false);
  assert.equal(timings.machinePresenceInferred, false);

  // 1s past the 60m source threshold becomes stale, and refreshing the unchanged revision does not clear staleness.
  clockMs = Date.parse("2026-11-12T09:00:01Z");
  state = await refreshTodoState(state, async () => policySnapshot, { now });
  timings = describeTodoTimings(state, { now });
  assert.equal(timings.fetchAgeLabel, "0s ago");
  assert.equal(timings.sourceAgeLabel, "1h ago");
  assert.equal(timings.freshnessState, "stale");
  assert.equal(timings.isStale, true);
  assert.equal(timings.machinePresenceInferred, false);
  assert.doesNotMatch(timings.freshnessSummary, /online|offline/i);

  // Explicit null override reverts to age-only presentation.
  const ageOnly = describeTodoTimings(state, { now, staleAfterMinutes: null });
  assert.equal(ageOnly.freshnessState, "age_only");
  assert.equal(ageOnly.isStale, null);

  // Server-level VIEWER_TODOS_STALE_AFTER_MINUTES applies valid policy and fails closed with 503 when malformed.
  const dir = await mkdtemp(path.join(os.tmpdir(), "flock-todos-policy-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "snapshot.json");
  await writeFile(file, JSON.stringify(snapshot()));
  const callApi = async (staleAfterMinutes) => {
    let status, body;
    await handleTodoRequest({
      url: "/api/todos", method: "GET", socket: { remoteAddress: "127.0.0.1" }, headers: { host: "localhost" },
    }, {
      writeHead(code) { status = code; }, end(payload) { body = JSON.parse(payload); },
    }, { snapshotPath: file, staleAfterMinutes, log() {} });
    return { status, body };
  };
  const unconfigured = await callApi("");
  assert.equal(unconfigured.status, 200);
  assert.equal(Object.hasOwn(unconfigured.body, "staleAfterMinutes"), false);
  const configured = await callApi("45");
  assert.equal(configured.status, 200);
  assert.equal(configured.body.staleAfterMinutes, 45);
  for (const invalidPolicy of ["0", "-10", "abc", "1.5"]) {
    const rejected = await callApi(invalidPolicy);
    assert.equal(rejected.status, 503, invalidPolicy);
    assert.match(rejected.body.error, /freshness policy configuration is invalid/);
  }
});

test("failed or invalid refreshes retain explicit errors without substituting stale rankings or advancing lastSuccessfulFetchAt", async () => {
  let clockMs = Date.parse("2026-11-12T11:00:00Z");
  const now = () => clockMs;

  // Initial failure leaves snapshot and lastSuccessfulFetchAt null.
  const initialDenied = await refreshTodoState(createTodoRefreshState(), async () => { throw new Error("403"); }, { now });
  assert.equal(initialDenied.snapshot, null);
  assert.equal(initialDenied.lastSuccessfulFetchAt, null);
  assert.match(initialDenied.error, /configured home LAN or an authenticated SSH connection/);

  // Succeed at 11:05:00Z.
  clockMs = Date.parse("2026-11-12T11:05:00Z");
  const good = await refreshTodoState(initialDenied, async () => snapshot(), { now });
  assert.equal(good.error, null);
  assert.equal(good.snapshot.issues.length, 2);
  assert.equal(good.lastSuccessfulFetchAt, "2026-11-12T11:05:00.000Z");

  // Starting a refresh clears active rankings immediately without advancing lastSuccessfulFetchAt.
  clockMs = Date.parse("2026-11-12T11:25:00Z");
  const inFlight = beginTodoRefresh(good);
  assert.equal(inFlight.snapshot, null);
  assert.equal(inFlight.error, null);
  assert.equal(inFlight.lastSuccessfulFetchAt, "2026-11-12T11:05:00.000Z");

  // HTTP failure, network failure, and invalid snapshot payloads all clear rankings and preserve the 11:05:00Z fetch timestamp.
  for (const failingLoader of [
    async () => { throw new Error("503"); },
    async () => { throw new Error("403"); },
    async () => ({ ...snapshot(), updatedAt: "not-a-timestamp" }),
    async () => ({ schemaVersion: 1, revision: 2 }),
    async () => null,
  ]) {
    const failed = await refreshTodoState(good, failingLoader, { now });
    assert.equal(failed.snapshot, null);
    assert.equal(failed.lastSuccessfulFetchAt, "2026-11-12T11:05:00.000Z");
    assert.ok(failed.error);
    const timings = describeTodoTimings(failed, { now });
    assert.equal(timings.sourceUpdatedAt, null);
    assert.equal(timings.lastSuccessfulFetchAt, "2026-11-12T11:05:00.000Z");
    assert.equal(timings.fetchAgeLabel, "20m ago");
  }
});

test("end-to-end /api/todos refresh lifecycle with controlled clock separates fetch freshness from snapshot authoring and preserves failure invariants", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "flock-todos-e2e-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "runtime.json");
  await writeFile(file, JSON.stringify({ ...snapshot(), revision: 10, updatedAt: "2026-11-12T06:00:00Z" }));

  let stalePolicy = "180";
  const server = http.createServer(async (req, res) => {
    if (!await handleTodoRequest(req, res, { snapshotPath: file, staleAfterMinutes: stalePolicy, log() {} })) {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/api/todos`;
  const fetchTodos = async () => {
    const res = await fetch(url);
    if (!res.ok) throw new Error(String(res.status));
    return res.json();
  };

  let clockMs = Date.parse("2026-11-12T08:30:00Z");
  const now = () => clockMs;

  // Initial fetch at 08:30Z: source is 2h 30m old (within 180m threshold), fetch is 0s old.
  let state = await refreshTodoState(createTodoRefreshState(), fetchTodos, { now });
  let timings = describeTodoTimings(state, { now });
  assert.equal(timings.revision, 10);
  assert.equal(timings.sourceAgeLabel, "2h 30m ago");
  assert.equal(timings.fetchAgeLabel, "0s ago");
  assert.equal(timings.freshnessState, "fresh");

  // Refresh same file at 09:10Z: fetch advances to 09:10Z (0s ago), source stays 06:00Z (3h 10m ago -> stale > 180m).
  clockMs = Date.parse("2026-11-12T09:10:00Z");
  state = await refreshTodoState(state, fetchTodos, { now });
  timings = describeTodoTimings(state, { now });
  assert.equal(state.unchangedRevision, true);
  assert.equal(timings.lastSuccessfulFetchAt, "2026-11-12T09:10:00.000Z");
  assert.equal(timings.fetchAgeLabel, "0s ago");
  assert.equal(timings.sourceUpdatedAt, "2026-11-12T06:00:00Z");
  assert.equal(timings.sourceAgeLabel, "3h 10m ago");
  assert.equal(timings.freshnessState, "stale");
  assert.equal(timings.machinePresenceInferred, false);

  // Corrupt runtime file and refresh at 09:25Z: 503 hides rankings and keeps lastSuccessfulFetchAt at 09:10Z.
  await writeFile(file, "{corrupt");
  clockMs = Date.parse("2026-11-12T09:25:00Z");
  state = await refreshTodoState(state, fetchTodos, { now });
  timings = describeTodoTimings(state, { now });
  assert.equal(state.snapshot, null);
  assert.match(state.error, /503/);
  assert.equal(state.lastSuccessfulFetchAt, "2026-11-12T09:10:00.000Z");
  assert.equal(timings.fetchAgeLabel, "15m ago");

  // Restore valid file without threshold policy at 09:30Z -> recovers cleanly in age-only mode.
  stalePolicy = "";
  await writeFile(file, JSON.stringify({ ...snapshot(), revision: 11, updatedAt: "2026-11-12T09:28:00Z" }));
  clockMs = Date.parse("2026-11-12T09:30:00Z");
  state = await refreshTodoState(state, fetchTodos, { now });
  timings = describeTodoTimings(state, { now });
  assert.equal(state.error, null);
  assert.equal(state.unchangedRevision, false);
  assert.equal(timings.revision, 11);
  assert.equal(timings.sourceAgeLabel, "2m ago");
  assert.equal(timings.fetchAgeLabel, "0s ago");
  assert.equal(timings.freshnessState, "age_only");
});
