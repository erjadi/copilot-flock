import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const { outputFiles } = await build({
  absWorkingDir: fileURLToPath(new URL("..", import.meta.url)),
  stdin: { contents: `
    export { currentFlocks, fetchFlocks, filterFlock, seedFlocks } from "./src/lib/fleet/flocks";
    export { getSeed } from "./src/lib/fleet/api";
    export { FlocksView } from "./src/components/fleet/FlocksView";
    export { createElement } from "react";
    export { renderToStaticMarkup } from "react-dom/server";
  `, resolveDir: fileURLToPath(new URL("..", import.meta.url)) },
  bundle: true, write: false, platform: "node", format: "cjs",
});
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-state-test-"));
let compiled;
try {
  const filename = path.join(directory, "fixture.cjs");
  fs.writeFileSync(filename, outputFiles[0].contents);
  compiled = createRequire(import.meta.url)(filename);
} finally { fs.rmSync(directory, { recursive: true, force: true }); }
const { currentFlocks, fetchFlocks, filterFlock, seedFlocks, getSeed, FlocksView, createElement, renderToStaticMarkup } = compiled;
const overview = getSeed();
const preview = seedFlocks(overview.members);
const empty = () => ({ flocks: [], sharedThreads: [], maintainer: {} });
const authority = { ...empty(), flocks: [{ ...preview.flocks[0], flockId: "actual/empty", members: [] }] };
const snapshot = (base, mode, state, error = null) => ({ base, mode, state, error });

function assertUnavailable(result) {
  assert.deepEqual(result.state, empty());
  assert.ok(result.error);
  const filtered = filterFlock(overview, result.state.flocks[0], result.state.sharedThreads);
  assert.deepEqual([filtered.members, filtered.sessions, filtered.events], [[], [], []]);
  assert.deepEqual(filtered.topology, { nodes: [], edges: [] });
  const html = renderToStaticMarkup(createElement(FlocksView, {
    ctx: { base: "", mode: "live", flockId: "", data: filtered },
    state: result.state, setState() {}, refresh: async () => {}, error: result.error,
  }));
  assert.doesNotMatch(html, /<article/);
  assert.match(html, /0 flocks/);
  assert.match(html, /Sharing audit unavailable/);
}

test("preview memberships never cross the initial or preview-to-live authority boundary", () => {
  assertUnavailable(currentFlocks(null, "", "seed", null));
  const seeded = snapshot("", "seed", preview);
  assert.equal(currentFlocks(seeded, "", "seed", "").state, preview);
  assertUnavailable(currentFlocks(seeded, "", "live", ""));
  assertUnavailable(currentFlocks(null, "", "live", ""));
});

test("live502 and malformed authority cannot become seeded cards or membership filters", async () => {
  const original = globalThis.fetch;
  try {
    for (const roster of [new Response("unavailable", { status: 502 }), Response.json({ flocks: [{ flockId: "invalid" }] })]) {
      globalThis.fetch = async (url) => url.endsWith("/my-flocks") ? roster : Response.json({});
      await assert.rejects(fetchFlocks("https://source.example"));
      assertUnavailable(currentFlocks(snapshot("https://source.example", "live", empty(), "Flock authority unavailable"), "https://source.example", "live", "https://source.example"));
    }
  } finally { globalThis.fetch = original; }
});

test("source changes gate old authority until current-source recovery, including real empty flocks", async () => {
  const old = snapshot("https://old.example", "live", preview);
  assertUnavailable(currentFlocks(old, "https://new.example", "live", "https://old.example"));
  assertUnavailable(currentFlocks(old, "https://new.example", "live", "https://new.example"));
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => Response.json(url.endsWith("/my-flocks") ? authority : {});
    const state = await fetchFlocks("https://new.example");
    const recovered = currentFlocks(snapshot("https://new.example", "live", state), "https://new.example", "live", "https://new.example");
    assert.equal(recovered.error, null);
    assert.deepEqual(recovered.state.flocks.map((f) => f.flockId), ["actual/empty"]);
    assert.deepEqual(recovered.state.flocks[0].members, []);
    assertUnavailable(currentFlocks(snapshot("https://new.example", "live", state), "https://new.example", "seed", "https://new.example"));
  } finally { globalThis.fetch = original; }
});
