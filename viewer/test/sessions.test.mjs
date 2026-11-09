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
import ts from "typescript";

let server, rel, SessionsView, api, flocks, governance;
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
  governance = await server.ssrLoadModule(path.join(root, "src", "lib", "fleet", "governance.ts"));
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

function viewerHttpFixture(overrides = {}) {
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
    BRIDGE_VERSION: "synthetic", lastRefreshAt: Date.now(), hubConnected: true, wireEvents: [],
    fleetCache: { members: [{ machineId: "ACTUAL-DISCOVERED", online: true }], sessions: [], lastUpdatedAt: "synthetic-time" },
    buildTopologySnapshot: () => ({ nodes: [], edges: [] }),
    pushWireEvent() {}, recordCorridorRpc() {}, recordCorridorMessage() {}, setTimeout() {},
    invokeRemoteRpc: async (_cfg, request) => {
      actions.push(request.action);
      return { result: request.action === "get_transcript"
        ? { session: { session_id: "synthetic-session" }, messages: [{ content: "Synthetic private text" }] }
        : { created: true, sessionId: "synthetic-session" } };
    }, ...overrides,
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

function componentFixture(file, apiOverrides = {}) {
  const slots = [];
  let cursor = 0, pending = [], lateWrites = 0, mounted = true;
  const timers = [];
  const memo = (fn, deps) => {
    const index = cursor++, previous = slots[index];
    if (!previous || !deps || deps.some((item, i) => item !== previous.deps[i])) slots[index] = { value: fn(), deps };
    return slots[index].value;
  };
  const hooks = {
    useState(initial) {
      const index = cursor++;
      if (!(index in slots)) slots[index] = { value: typeof initial === "function" ? initial() : initial };
      return [slots[index].value, (value) => { if (!mounted) lateWrites++; slots[index].value = typeof value === "function" ? value(slots[index].value) : value; }];
    },
    useRef(initial) { return memo(() => ({ current: initial }), []); },
    useMemo: memo,
    useCallback(fn, deps) { return memo(() => fn, deps); },
    useEffect(fn, deps) {
      const index = cursor++, previous = slots[index];
      if (!previous || !deps || deps.some((item, i) => item !== previous.deps[i])) {
        slots[index] = { deps, cleanup: previous?.cleanup };
        pending.push(() => { slots[index].cleanup?.(); slots[index].cleanup = fn(); });
      }
    },
  };
  const source = fs.readFileSync(new URL(`../src/components/fleet/${file}.tsx`, import.meta.url), "utf8");
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } }).outputText;
  const jsx = (type, props, key) => ({ type, props, key });
  const context = vm.createContext({
    exports: {}, Date, JSON, Set, Error,
    setInterval(fn, ms) { timers.push({ fn, ms }); return timers.length; }, clearInterval() {},
    localStorage: { getItem() { return null; } },
    document: { documentElement: { classList: { add() {}, remove() {} } } },
    EventSource: class { addEventListener() {} close() {} },
    require(name) {
      if (name === "react") return hooks;
      if (name === "react/jsx-runtime") return { jsx, jsxs: jsx, Fragment: "fragment" };
      if (name.endsWith("/api")) return { ...api, ...apiOverrides };
      if (name.endsWith("/flocks")) return { ...flocks, fetchFlocks: async () => ({ flocks: [], sharedThreads: [], maintainer: {} }) };
      if (name.endsWith("/theme")) return { resolveTheme: () => "dark", THEME_KEY: "synthetic-theme" };
      if (name.endsWith("/seed")) return { fakeEvent: () => [] };
      if (name.endsWith("/governance")) return governance;
      if (name.endsWith("/utils")) return { cn: (...args) => args.filter(Boolean).join(" ") };
      return new Proxy({}, { get: (_target, key) => String(key) });
    },
  });
  vm.runInContext(code + (file === "Console" ? "\nexports.Connection = ConsoleConnection;" : ""), context);
  return {
    render(name, props = {}) {
      cursor = 0;
      const tree = context.exports[name](props);
      const effects = pending; pending = []; effects.forEach((effect) => effect());
      return tree;
    },
    unmount() { slots.forEach((slot) => slot.cleanup?.()); mounted = false; },
    tick(ms) { timers.filter((timer) => timer.ms === ms).forEach((timer) => timer.fn()); },
    get lateWrites() { return lateWrites; },
  };
}

function elements(tree) {
  if (!tree || typeof tree !== "object") return [];
  return [tree, ...[tree.props?.children].flat(Infinity).flatMap(elements)];
}
function text(tree) {
  if (typeof tree === "string" || typeof tree === "number") return String(tree);
  if (!tree || typeof tree !== "object") return "";
  return [tree?.props?.children].flat(Infinity).map(text).join(" ");
}

test("live overview outages never switch modes or simulate a write; preview is explicit", async () => {
  const previousFetch = globalThis.fetch;
  let simulations = 0;
  try {
    globalThis.fetch = async () => { throw new Error("Synthetic initial outage"); };
    await assert.rejects(() => api.fetchOverview(""), /initial outage/);
    await assert.rejects(() => api.post("", "live", "/api/send", {}, () => { simulations++; return { ok: true }; }), /initial outage/);
    globalThis.fetch = async () => new Response(JSON.stringify({ ...api.emptyOverview(), hub: { ...api.emptyOverview().hub, machineId: "REAL-FIXTURE" } }), { headers: { "content-type": "application/json" } });
    assert.equal((await api.fetchOverview("")).data.hub.machineId, "REAL-FIXTURE");
    globalThis.fetch = async () => new Response("Unavailable", { status: 503 });
    await assert.rejects(() => api.fetchOverview(""), /503/);
    await assert.rejects(() => api.post("", "live", "/api/send", {}, () => { simulations++; return { ok: true }; }), /503/);
    assert.equal(simulations, 0);
    assert.equal((await api.fetchOverview("", "seed")).mode, "seed");
    assert.equal((await api.post("", "seed", "/api/send", {}, () => { simulations++; return { ok: true }; })).simulated, true);
    assert.equal(simulations, 1);
    await assert.rejects(() => api.post("", "invalid", "/api/send", {}, () => { simulations++; }), /explicitly selected/);
  } finally { globalThis.fetch = previousFetch; }
});

test("actual Console shows initial live errors and retains a stale real snapshot after 503", async () => {
  const reads = [];
  const fixture = componentFixture("Console", { fetchOverview: (base, mode) => new Promise((resolve, reject) => reads.push({ base, mode, resolve, reject })) });
  const props = { base: "", mode: "live", setSource() { assert.fail("A read must never change the selected source"); } };
  let tree = fixture.render("Connection", props);
  assert.match(text(tree), /Live API/);
  assert.doesNotMatch(text(tree), /fictional data; all actions are simulated/);
  reads[0].reject(new Error("503"));
  await new Promise(setImmediate);
  tree = fixture.render("Connection", props);
  assert.match(text(tree), /Live unavailable: 503.*No live snapshot loaded/);
  assert.ok(elements(tree).some((node) => node.props?.role === "alert"));
  fixture.tick(10000);
  const data = api.emptyOverview();
  data.hub.machineId = "REAL-FIXTURE";
  data.hub.lastUpdatedAt = "fixture-time";
  reads[1].resolve({ mode: "live", data });
  await new Promise(setImmediate);
  assert.match(text(fixture.render("Connection", props)), /Live API.*REAL-FIXTURE/);
  fixture.tick(10000);
  reads[2].reject(new Error("503"));
  await new Promise(setImmediate);
  assert.match(text(fixture.render("Connection", props)), /Showing stale snapshot from fixture-time/);
  assert.equal(reads.every((read) => read.mode === "live"), true);
  fixture.unmount();
});

test("source changes remount the Console and discard late old-source results", async () => {
  const root = componentFixture("Console");
  const live = root.render("Console");
  live.props.setSource({ base: "http://synthetic.invalid", mode: "seed" });
  const preview = root.render("Console");
  assert.notEqual(live.key, preview.key);
  assert.equal(preview.props.mode, "seed");
  preview.props.setSource({ base: "http://other.invalid", mode: "seed" });
  assert.notEqual(root.render("Console").key, preview.key);
  let complete;
  const old = componentFixture("Console", { fetchOverview: () => new Promise((resolve) => { complete = resolve; }) });
  old.render("Connection", { base: "", mode: "live", setSource() {} });
  await new Promise(setImmediate);
  old.unmount();
  complete({ mode: "live", data: api.getSeed() });
  await new Promise(setImmediate);
  assert.equal(old.lateWrites, 0);
  const explicit = componentFixture("Console");
  const tree = explicit.render("Connection", { base: "", mode: "seed", setSource() {} });
  assert.match(text(tree), /Preview.*fictional data; all actions are simulated/);
  await new Promise(setImmediate);
  explicit.unmount();
  root.unmount();
});

test("actual viewer callback requires full expected SHA and leaves electorate discovery to the canonical helper", async () => {
  const calls = [], events = [];
  const expectedCommit = "a".repeat(40);
  const baseline = { expectedCommit, branch: "main", approvedForMerge: false, acceptCount: 0, onlineVoterCount: 1, votes: [{ machineId: "ACTUAL-DISCOVERED" }] };
  let result = baseline;
  const f = viewerHttpFixture({
    voteReleaseAcrossFlock: async (cfg, options) => { calls.push({ cfg, options }); return result; },
    pushWireEvent: (event) => events.push(event),
  });
  for (const sha of [undefined, null, "demo-04", "a".repeat(39), "G".repeat(40)]) {
    const response = await f.request({ method: "POST", url: "/api/vote-release", body: { expectedCommit: sha, sha: expectedCommit } });
    assert.equal(response.status, 400);
  }
  assert.equal(calls.length, 0);
  assert.equal(f.actions.length, 0);
  const valid = await f.request({ method: "POST", url: "/api/vote-release", body: { expectedCommit, machines: ["FICTIONAL-SUBSET"] } });
  assert.equal(valid.status, 200);
  assert.equal(JSON.parse(valid.body).approvedForMerge, false);
  assert.equal(calls[0].options.expectedCommit, expectedCommit);
  assert.equal(calls[0].options.machines, undefined);
  assert.equal(events[0].toMachine, "ACTUAL-DISCOVERED");
  assert.equal(events[0].fromMachine, "SYNTHETIC-SOURCE");
  for (const malformed of [
    { approvedForMerge: undefined }, { expectedCommit: "b".repeat(40) }, { acceptCount: "1" },
    { approvedForMerge: true, acceptCount: 1, votersComplete: false },
    { approvedForMerge: true, acceptCount: 1, votersComplete: true, votes: [] },
  ]) {
    result = { ...baseline, ...malformed };
    assert.equal((await f.request({ method: "POST", url: "/api/vote-release", body: { expectedCommit } })).status, 502);
  }
  result = { ...baseline, approvedForMerge: true, acceptCount: 1, votersComplete: true };
  const approved = await f.request({ method: "POST", url: "/api/vote-release", body: { expectedCommit } });
  assert.equal(approved.status, 200);
  assert.equal(JSON.parse(approved.body).approvedForMerge, true);
});

test("live vote parsing blocks missing approval, fake counts and mismatched source", () => {
  const expectedCommit = "a".repeat(40);
  const valid = { expectedCommit, approvedForMerge: true, accepted: 2, total: 2 };
  assert.equal(api.readVoteResult(valid, expectedCommit).approvedForMerge, true);
  assert.equal(api.readVoteResult({ ...valid, approvedForMerge: false }, expectedCommit).approvedForMerge, false);
  for (const value of [null, {}, { ...valid, approvedForMerge: undefined }, { ...valid, accepted: undefined },
    { ...valid, accepted: 1 }, { ...valid, total: -1 }, { ...valid, expectedCommit: "b".repeat(40) }]) {
    assert.throws(() => api.readVoteResult(value, expectedCommit), /merge remains blocked/);
  }
});

test("actual Governance callbacks use entered SHA, no sample targets, real tallies and no rollout permission", async () => {
  const calls = [], events = [], expectedCommit = "c".repeat(40);
  let result = { expectedCommit, approvedForMerge: false, accepted: 1, total: 2 };
  const f = componentFixture("GovernanceView", { post: async (_base, mode, route, body) => { calls.push({ mode, route, body }); return result; } });
  const ctx = { base: "", mode: "live", data: api.emptyOverview(), pushEvents: (items) => events.push(...items) };
  ctx.data.hub.machineId = "ACTUAL-LOCAL";
  let tree = f.render("GovernanceView", { ctx });
  const vote = () => elements(tree).find((node) => node.type === "Btn" && text(node).includes("Run exact-SHA vote"));
  assert.equal(vote().props.disabled, true);
  await vote().props.onClick();
  assert.equal(calls.length, 0);
  elements(tree).find((node) => node.props?.id === "expected-release-sha").props.onChange({ target: { value: expectedCommit } });
  tree = f.render("GovernanceView", { ctx });
  await vote().props.onClick();
  tree = f.render("GovernanceView", { ctx });
  assert.equal(calls[0].body.expectedCommit, expectedCommit);
  assert.equal(calls[0].body.machines, undefined);
  assert.match(text(tree), /1\/2 ACCEPT.*merge blocked/);
  assert.doesNotMatch(text(tree), /quorum reported|rollout.*permitted/);
  assert.equal(events[0].fromMachine, "ACTUAL-LOCAL");
  result = {};
  await vote().props.onClick();
  tree = f.render("GovernanceView", { ctx });
  assert.match(text(tree), /Vote failed/);
  assert.doesNotMatch(text(tree), /quorum reported/);
  result = { expectedCommit, approvedForMerge: true, accepted: 2, total: 2 };
  await vote().props.onClick();
  tree = f.render("GovernanceView", { ctx });
  assert.match(text(tree), /2\/2 ACCEPT.*quorum reported/);
  assert.ok(elements(tree).some((node) => node.type === "SmartMessage" && /does not authorize deployment, restart/.test(node.props.text)));
  assert.doesNotMatch(text(tree), /rollout.*permitted/);
  result = { results: [{ machineId: "ACTUAL-DISCOVERED", ok: false, detail: "Synthetic unavailable" }] };
  await elements(tree).find((node) => node.type === "Btn" && text(node).includes("Run read-only diagnose")).props.onClick();
  tree = f.render("GovernanceView", { ctx });
  assert.equal(calls.at(-1).body.fix, false);
  assert.equal(calls.at(-1).body.machines, undefined);
  assert.match(text(tree), /0\/1 diagnostic responses healthy/);
  assert.match(text(tree), /Fictional preview quorum/);
  f.unmount();
});

test("viewer overview and send-event attribution use cfg.machineId rather than caller labels", async () => {
  const events = [];
  const f = viewerHttpFixture({ pushWireEvent: (event) => events.push(event) });
  const overview = await f.request({ url: "/api/overview" });
  assert.equal(JSON.parse(overview.body).hub.machineId, "SYNTHETIC-SOURCE");
  await f.request({ method: "POST", url: "/api/send", body: { toMachine: "ACTUAL-DISCOVERED", message: "[ping] fixture", dryRun: true, fromMachine: "FICTIONAL-CALLER" } });
  assert.equal(events[0].fromMachine, "SYNTHETIC-SOURCE");
  assert.equal(f.actions.at(-1), "ping");
});

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
