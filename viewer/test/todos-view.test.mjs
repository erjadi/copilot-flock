import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { createTodoRefreshState, refreshTodoState } from "../todo-snapshot.mjs";

const { outputFiles } = await build({
  absWorkingDir: fileURLToPath(new URL("..", import.meta.url)),
  stdin: {
    contents: `
      export { TodosView } from "./src/components/fleet/TodosView";
      export { createElement } from "react";
      export { renderToStaticMarkup } from "react-dom/server";
    `,
    resolveDir: fileURLToPath(new URL("..", import.meta.url)),
  },
  bundle: true,
  write: false,
  platform: "node",
  format: "cjs",
});
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "todos-view-test-"));
let compiled;
try {
  const filename = path.join(directory, "fixture.cjs");
  fs.writeFileSync(filename, outputFiles[0].contents);
  compiled = createRequire(import.meta.url)(filename);
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
const { TodosView, createElement, renderToStaticMarkup } = compiled;

const sampleSnapshot = (extra = {}) => ({
  schemaVersion: 1,
  revision: 3,
  updatedAt: "2026-11-12T08:00:00Z",
  source: "Flock TODO & Issues Tracker",
  issues: [{
    todoId: "flock-issue-6",
    number: 6,
    rank: 12,
    title: "Distinguish TODO snapshot age from last successful refresh",
    type: "architecture",
    status: "in_progress",
    rankingBasis: "Provisional editorial ranking",
    rankingExplanation: "Prevents mistaking a fresh HTTP poll for newly authored tracker data.",
    evidence: "Independently verified in TodosView.tsx",
    implementationStatus: "In progress",
    nextStep: "Display distinct source and refresh ages",
    details: ["Separate updatedAt from lastSuccessfulFetchAt"],
    relatedIssues: [],
  }],
  ...extra,
});

test("TodosView renders distinct source updatedAt and lastSuccessfulFetchAt timestamps, unchanged-revision state, threshold policy, and failure preservation", async () => {
  let clockMs = Date.parse("2026-11-12T10:00:00Z");
  const now = () => clockMs;

  // 1. Initial load without threshold -> age-only mode.
  let state = await refreshTodoState(createTodoRefreshState(), async () => sampleSnapshot(), { now });
  let html = renderToStaticMarkup(createElement(TodosView, { initialState: state, now }));
  assert.match(html, /revision <span[^>]*>3<\/span>/);
  assert.match(html, /Source snapshot updated/);
  assert.match(html, /dateTime="2026-11-12T08:00:00Z"/);
  assert.match(html, /\(2h ago\)/);
  assert.match(html, /Last successful refresh/);
  assert.match(html, /dateTime="2026-11-12T10:00:00\.000Z"/);
  assert.match(html, /\(0s ago\)/);
  assert.match(html, /Age only \(no staleness threshold configured\)/);
  assert.match(html, /never indicates machine online or offline state/);
  assert.doesNotMatch(html, /Unchanged revision on last refresh/);

  // 2. Refresh unchanged revision 25 minutes later -> fetch age resets while source age grows to 2h 25m ago; stale policy triggers when threshold=120m.
  clockMs = Date.parse("2026-11-12T10:25:00Z");
  state = await refreshTodoState(state, async () => sampleSnapshot({ staleAfterMinutes: 120 }), { now });
  html = renderToStaticMarkup(createElement(TodosView, { initialState: state, now }));
  assert.match(html, /Unchanged revision on last refresh/);
  assert.match(html, /Stale snapshot \(exceeds 120m source age threshold\)/);
  assert.match(html, /dateTime="2026-11-12T08:00:00Z"/);
  assert.match(html, /\(2h 25m ago\)/);
  assert.match(html, /dateTime="2026-11-12T10:25:00\.000Z"/);
  assert.match(html, /\(0s ago\)/);
  assert.match(html, /content was not re-authored/);

  // 3. Subsequent failed refresh 10 minutes later hides rankings while keeping prior lastSuccessfulFetchAt un-advanced.
  clockMs = Date.parse("2026-11-12T10:35:00Z");
  const failed = await refreshTodoState(state, async () => { throw new Error("503"); }, { now });
  html = renderToStaticMarkup(createElement(TodosView, { initialState: failed, now }));
  assert.match(html, /Refresh failed - no ranking shown/);
  assert.match(html, /dateTime="2026-11-12T10:25:00\.000Z"/);
  assert.match(html, /\(10m ago\)/);
  assert.match(html, /Failed refresh did not advance this timestamp/);
  assert.doesNotMatch(html, /flock-issue-6/);
});

test("unified TODO card renders implementation progress alongside candidate readiness and snapshot timing", async () => {
  const now = () => Date.parse("2026-11-12T10:00:00Z");
  const raw = sampleSnapshot({ staleAfterMinutes: 60 });
  const sha = "a".repeat(40);
  Object.assign(raw.issues[0], {
    implementationDetails: {
      stage: "implemented", workerSessionId: "synthetic-worker", model: "synthetic-model",
      branch: "synthetic-branch", commitSha: sha, changedFiles: ["viewer/synthetic.ts"],
      testSummary: "Reported: 8 passed", mergedIn35Candidate: false, flockReviewStatus: "pending",
    },
    candidateSha: sha, verificationTier: "live_multi_pc", readinessEvidence: [{
      candidateSha: sha, hostId: "SYNTHETIC-HOST", os: "synthetic-os", command: "synthetic test",
      capturedAt: "2026-11-12T09:00:00Z", passCount: 8, failCount: 0, skipCount: 0,
      prerequisites: [], evidenceDigest: "b".repeat(64), confidence: "reproduced",
      verificationTier: "unit_synthetic",
    }],
  });
  const state = await refreshTodoState(createTodoRefreshState(), async () => raw, { now });
  const html = renderToStaticMarkup(createElement(TodosView, { initialState: state, now }));
  for (const text of [
    "Implementation tracking", "synthetic-worker", "synthetic-branch", "viewer/synthetic.ts",
    "Reported: 8 passed", "Readiness &amp; verification evidence", "SYNTHETIC-HOST",
    "Unit / synthetic", "Last successful refresh", "Source snapshot updated",
    "Stale snapshot", "Copy verification prompt",
  ]) assert.ok(html.includes(text), text);
  assert.match(html, /Tracker-reported progress, not independent verification/);
  assert.match(html, /aria-label="TODO verification tier"/);
});
