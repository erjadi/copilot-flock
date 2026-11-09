import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
import vm from "node:vm";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

let server, rel, SessionsView, api, flocks;
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
  flocks = await server.ssrLoadModule(path.join(root, "src", "lib", "fleet", "flocks.ts"));
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

test("invite validation rejects private as a retired scope before a request", () => {
  const input = { targetPath: "example/private/EXAMPLE-PC", githubHandle: "example", durationMinutes: null, maxDevices: 1 };
  assert.match(flocks.validateInvite(input), /retired/);
  assert.equal(flocks.validateInvite({ ...input, targetPath: "example/personal/EXAMPLE-PC" }), null);
});

function viewerHttpFixture() {
  const source = fs.readFileSync(new URL("../viewer-server.mjs", import.meta.url), "utf8");
  const functionsFrom = source.indexOf("function sendJson(");
  const handlerFrom = source.indexOf("const server = http.createServer(");
  const handlerTo = source.indexOf("\nloadInitialCorridors();", handlerFrom);
  assert.ok(functionsFrom > 0 && handlerFrom > functionsFrom && handlerTo > handlerFrom);
  const handler = source.slice(handlerFrom, handlerTo)
    .replace("const server = http.createServer(", "this.handler = (");
  const actions = [];
  const origins = new Set();
  const context = vm.createContext({
    URL, crypto, Buffer, HOST: "127.0.0.1", PORT: 8099, VIEWER_ALLOWED_ORIGINS: origins,
    cfg: { machineId: "SYNTHETIC-SOURCE", scope: "personal", githubUser: "example" },
    VIEWER_HOST_LABEL: "synthetic-only", lastHttpActivityAt: 0,
    pushWireEvent() {}, recordCorridorRpc() {}, recordCorridorMessage() {}, setTimeout() {},
    invokeRemoteRpc: async (_cfg, request) => {
      actions.push(request.action);
      return { result: request.action === "get_transcript"
        ? { session: { session_id: "synthetic-session" }, messages: [{ content: "Synthetic private text" }] }
        : { created: true, sessionId: "synthetic-session" } };
    },
  });
  vm.runInContext(source.slice(functionsFrom, handlerFrom) + handler, context);
  async function request({ method = "GET", url = "/api/transcript?machine=SYNTHETIC-TARGET", headers = {}, body } = {}) {
    const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]);
    Object.assign(req, { method, url, headers: { host: "127.0.0.1:8099", ...headers } });
    const result = { headers: {} };
    const res = {
      setHeader(name, value) { result.headers[name] = value; },
      writeHead(status, responseHeaders) { result.status = status; Object.assign(result.headers, responseHeaders); },
      end(value) { result.body = value; },
    };
    await context.handler(req, res);
    return result;
  }
  return { request, actions, origins, source };
}

test("viewer rejects foreign origins and rebinding hosts before private reads or owner RPC dispatch", async () => {
  const f = viewerHttpFixture();
  for (const request of [
    { headers: { origin: "https://untrusted.invalid" } },
    { method: "OPTIONS", headers: { origin: "https://untrusted.invalid" } },
    { method: "POST", url: "/api/create-session", headers: { origin: "https://untrusted.invalid" },
      body: { toMachine: "SYNTHETIC-TARGET", title: "Not authorized" } },
    { headers: { origin: "null" } },
    { headers: { host: "untrusted.invalid:8099" } },
    { headers: { host: "127.0.0.1:9999" } },
    { headers: { "sec-fetch-site": "cross-site" } },
  ]) {
    const result = await f.request(request);
    assert.equal(result.status, 403);
    assert.equal(result.headers["Access-Control-Allow-Origin"], undefined);
  }
  assert.equal(f.actions.length, 0);
  const read = await f.request({ headers: { origin: "http://127.0.0.1:8099" } });
  assert.equal(read.status, 200);
  assert.equal(read.headers["Access-Control-Allow-Origin"], "http://127.0.0.1:8099");
  assert.equal(read.headers["X-Frame-Options"], "DENY");
  assert.equal(read.headers["Content-Security-Policy"], "frame-ancestors 'none'");
  assert.match(read.body, /Synthetic private text/);
  const native = await f.request();
  assert.equal(native.status, 200);
  assert.equal(native.headers["Access-Control-Allow-Origin"], undefined);
  const sent = await f.request({ method: "POST", url: "/api/create-session",
    headers: { origin: "http://127.0.0.1:8099" }, body: { toMachine: "SYNTHETIC-TARGET" } });
  assert.equal(sent.status, 200);
  assert.equal(f.actions.at(-1), "create_session");
});

test("viewer development origins require explicit approval and never wildcard preflight trust", async () => {
  const f = viewerHttpFixture();
  const request = { method: "OPTIONS", headers: { origin: "http://localhost:5173" } };
  assert.equal((await f.request(request)).status, 403);
  f.origins.add("http://localhost:5173");
  const allowed = await f.request(request);
  assert.equal(allowed.status, 204);
  assert.equal(allowed.headers["Access-Control-Allow-Origin"], "http://localhost:5173");
  assert.equal(allowed.headers.Vary, "Origin");
  assert.equal((await f.request({ ...request, headers: { ...request.headers, host: "localhost:5173" } })).status, 403);
  const start = f.source.indexOf("const VIEWER_ALLOWED_ORIGINS =");
  const end = f.source.indexOf("\nconst DIST_DIR", start);
  assert.ok(start > 0 && end > start);
  for (const origin of ["*", "null", "https://user:password@trusted.invalid", "https://trusted.invalid/path", "file:///example"]) {
    assert.throws(() => vm.runInNewContext(f.source.slice(start, end), {
      URL, process: { env: { VIEWER_ALLOWED_ORIGINS: origin } },
    }));
  }
  assert.doesNotThrow(() => vm.runInNewContext(f.source.slice(start, end), {
    URL, process: { env: { VIEWER_ALLOWED_ORIGINS: "http://localhost:5173,https://approved.invalid" } },
  }));
});
