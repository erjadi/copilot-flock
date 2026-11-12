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
  Object.assign(updated.issues[0], { scores: scores(4), evidenceConfidence: "reproduced", acceptanceCriteria: ["Verify result"] });
  await writeFile(file, JSON.stringify(updated));
  const scored = await (await fetch(`${base}/api/todos`)).json();
  assert.equal(scored.revision, 2);
  assert.deepEqual(scored.issues[1].scores, scores(4));
  assert.equal(scored.issues[1].evidenceConfidence, "reproduced");
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
  Object.assign(newer.issues[0], { scores: scores(5), evidenceConfidence: "reported", acceptanceCriteria: ["Scoped acceptance"] });
  await writeFile(source, JSON.stringify(newer));
  await publishTodos(source, destination);
  const published = JSON.parse(await readFile(destination, "utf8"));
  assert.deepEqual(published.issues[1].scores, scores(5));
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
