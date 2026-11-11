import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { handleTodoRequest } from "../viewer/todo-api.mjs";
import { validateTodoSnapshot } from "../viewer/todo-snapshot.mjs";
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
  const updated = { ...snapshot(), revision: 2, issues: [] };
  await writeFile(file, JSON.stringify(updated));
  assert.equal((await (await fetch(`${base}/api/todos`)).json()).revision, 2);
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
  const newer = { ...snapshot(), revision: 2, updatedAt: "2026-11-11T18:00:00Z", issues: [] };
  await writeFile(source, JSON.stringify(newer));
  await publishTodos(source, destination);
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
