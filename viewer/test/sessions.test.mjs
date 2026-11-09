import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

let server, rel, SessionsView, api;
before(async () => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  server = await createServer({
    root, configFile: path.join(root, "vite.config.ts"),
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] }, appType: "custom",
  });
  ({ rel } = await server.ssrLoadModule(path.join(root, "src", "components", "fleet", "ui.tsx")));
  ({ SessionsView } = await server.ssrLoadModule(path.join(root, "src", "components", "fleet", "SessionsView.tsx")));
  api = await server.ssrLoadModule(path.join(root, "src", "lib", "fleet", "api.ts"));
});
after(async () => { await server?.close(); });

test("missing or invalid timestamps are explicitly unknown", () => {
  for (const value of [null, "", "not-a-timestamp"]) assert.equal(rel(value), "unknown");
  assert.equal(rel(new Date().toISOString()), "0s ago");
});

test("chat and repository-backed sessions render optional repository and branch metadata", () => {
  for (const [repo, branch, label] of [[null, null, "No repository"], ["example/project", "main", "project:main"], ["project", null, "project"]]) {
    const session = {
      machineId: "EXAMPLE-PC", scope: "personal", githubUser: "example",
      session_id: "example-chat", workspace_id: null, title: "Untitled chat",
      session_type: "general_chat", is_running: false, mode: "interactive",
      model: null, repo, branch, path: null, updated_at: new Date().toISOString(),
    };
    const ctx = { data: { sessions: [session], members: [] }, base: "", mode: "seed" };
    const html = renderToStaticMarkup(createElement(SessionsView, { ctx, selected: session, setSelected() {} }));
    assert.match(html, /Untitled chat/);
    assert.ok(html.includes(label), `Expected repository label: ${label}`);
  }
});

test("failed live transcript and project reads never return synthetic data", async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("Synthetic API outage"); };
  const session = { machineId: "EXAMPLE-PC", session_id: "example-chat", title: "Example", repo: "example/project", branch: "main", updated_at: new Date().toISOString() };
  try {
    await assert.rejects(() => api.fetchTranscript("", "live", session), /Synthetic API outage/);
    await assert.rejects(() => api.fetchProjects("", "live", "EXAMPLE-PC", [session], "personal"), /Synthetic API outage/);
  } finally { globalThis.fetch = previousFetch; }
});

test("synthetic transcripts and projects remain explicitly available in preview mode", async () => {
  const session = { machineId: "EXAMPLE-PC", session_id: "example-chat", title: "Example", repo: "example/project", branch: "main", updated_at: new Date().toISOString() };
  assert.equal((await api.fetchTranscript("", "seed", session)).simulated, true);
  assert.equal((await api.fetchProjects("", "seed", "EXAMPLE-PC", [session], "personal")).simulated, true);
});
