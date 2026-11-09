#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { pathToFileURL, fileURLToPath } from "node:url";
import { generate } from "selfsigned";
import { Store, endpoint, fingerprint, LIMITS, SESSION } from "./store.mjs";
import { DesktopAdapter } from "./desktop.mjs";
import { PeerServer, request } from "./transport.mjs";

export async function makeIdentity() {
  const pems = await generate([{ name: "commonName", value: "copilot-lan-trial" }], {
    keySize: 2048, algorithm: "sha256",
    notBeforeDate: new Date(Date.now() - 60000),
    notAfterDate: new Date(Date.now() + 90 * 86400000),
    extensions: [
      { name: "basicConstraints", cA: true },
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true, keyCertSign: true },
      { name: "extKeyUsage", serverAuth: true, clientAuth: true },
    ],
  });
  return { cert: pems.cert, key: pems.private };
}

function privateDirectory(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform === "win32") {
    const user = execFileSync("whoami.exe", [], { encoding: "utf8" }).trim();
    execFileSync("icacls.exe", [dir, "/inheritance:r", "/grant:r", `${user}:(OI)(CI)F`], { stdio: "pipe" });
  } else fs.chmodSync(dir, 0o700);
}
function writeNew(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", { flag: "wx", mode: 0o600 });
}
function options(args) {
  const result = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!args[i].startsWith("--") || args[i + 1] === undefined) throw new Error("Options require explicit values");
    const key = args[i].slice(2);
    if (key in result) throw new Error("Duplicate option");
    result[key] = args[i + 1];
  }
  return result;
}
function load(dir) {
  const config = JSON.parse(fs.readFileSync(path.join(dir, "trial.json"), "utf8"));
  endpoint(config.endpoint);
  const identity = JSON.parse(fs.readFileSync(path.join(dir, "identity.json"), "utf8"));
  return { config, identity };
}
function canonicalTarget(dir) {
  let parent = dir;
  const tail = [];
  while (!fs.existsSync(parent)) {
    tail.unshift(path.basename(parent));
    parent = path.dirname(parent);
  }
  return path.join(fs.realpathSync(parent), ...tail);
}
export function isInsideDirectory(parent, target) {
  const rel = path.relative(parent, target);
  return !rel || (rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
}
export async function mcp(store, identity) {
  const tools = [
    { name: "lan_peer_status", description: "Check a manually paired online same-LAN peer." },
    { name: "lan_shared_sessions", description: "List only sessions explicitly shared by the receiver." },
    { name: "lan_approved_transcript", description: "Read only a bounded locally approved snapshot, not raw history." },
    { name: "lan_send_message", description: "Message a selected existing Desktop session without changing its permissions. DELIVERED confirms admission, not execution. UNKNOWN must not be retried automatically." },
  ].map((t) => ({ ...t, inputSchema: {
    type: "object", properties: {
      peer: { type: "string", pattern: "^[0-9a-f]{64}$" },
      ...(t.name === "lan_approved_transcript" || t.name === "lan_send_message" ? {
        session: { type: "string", pattern: SESSION.source },
      } : {}),
      ...(t.name === "lan_send_message" ? { message: { type: "string", minLength: 1, maxLength: LIMITS.text } } : {}),
    }, required: ["peer", ...(t.name === "lan_approved_transcript" || t.name === "lan_send_message" ? ["session"] : []),
      ...(t.name === "lan_send_message" ? ["message"] : [])], additionalProperties: false,
  } }));
  let buffer = Buffer.alloc(0);
  const out = (value) => process.stdout.write(JSON.stringify(value) + "\n");
  const handle = async (msg) => {
    if (msg.jsonrpc !== "2.0") throw new Error("Invalid JSON-RPC");
    if (msg.id === undefined) return;
    let result;
    if (msg.method === "initialize") result = {
      protocolVersion: "2024-11-05", capabilities: { tools: {} },
      serverInfo: { name: "copilot-lan-trial", version: "0.1.0" },
    };
    else if (msg.method === "ping") result = {};
    else if (msg.method === "tools/list") result = { tools };
    else if (msg.method === "tools/call") {
      const tool = tools.find((t) => t.name === msg.params?.name);
      const a = msg.params?.arguments;
      if (!tool || !a || Object.keys(a).some((k) => !(k in tool.inputSchema.properties)) ||
          tool.inputSchema.required.some((k) => typeof a[k] !== "string") ||
          !/^[0-9a-f]{64}$/.test(a.peer)) throw new Error("Invalid tool arguments");
      const action = { lan_peer_status: "status", lan_shared_sessions: "sessions",
        lan_approved_transcript: "transcript", lan_send_message: "message" }[tool.name];
      const value = await request({ store, identity, pin: a.peer, action, session: a.session || "", payload: a.message || "" });
      result = { content: [{ type: "text", text: JSON.stringify(value) }], isError: value.status !== "DELIVERED" };
    } else throw new Error("Unsupported method");
    out({ jsonrpc: "2.0", id: msg.id, result });
  };
  // Sequential, bounded input: no unbounded application queue.
  for await (const chunk of process.stdin) {
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.length > LIMITS.frame) throw new Error("MCP input exceeded bound");
    let nl;
    while ((nl = buffer.indexOf(10)) !== -1) {
      const line = buffer.subarray(0, nl).toString("utf8");
      buffer = buffer.subarray(nl + 1);
      if (!line.trim()) continue;
      let msg;
      try {
        msg = JSON.parse(line);
        await handle(msg);
      } catch (error) {
        out({ jsonrpc: "2.0", id: msg?.id ?? null, error: { code: -32602, message: error.message } });
      }
    }
  }
}

export async function main(args = process.argv.slice(2)) {
  const [command, ...rest] = args;
  const o = options(rest);
  const allowed = {
    init: ["state", "host", "port"], approve: ["state", "offer", "fingerprint"],
    revoke: ["state", "peer"], unshare: ["state", "peer", "session"],
    share: ["state", "peer", "session", "title", "snapshot", "message", "transcript"],
    peers: ["state"], request: ["state", "peer", "action", "session", "message"],
    serve: ["state"], mcp: ["state"],
  };
  if (!allowed[command] || Object.keys(o).some((key) => !allowed[command].includes(key))) {
    throw new Error("Unsupported command or option");
  }
  if (!o.state || !path.isAbsolute(o.state)) throw new Error("An explicit absolute --state trial directory is required");
  const dir = canonicalTarget(path.resolve(o.state));
  // Trial commands must not address either full-Flock state or the Copilot profile.
  const copilot = path.join(os.homedir(), ".copilot");
  if (isInsideDirectory(canonicalTarget(copilot), dir)) {
    throw new Error("Trial state must be outside the full Copilot profile");
  }
  if (command === "init") {
    const url = endpoint(`wss://${o.host}:${o.port}/`);
    if (fs.existsSync(dir)) throw new Error("Choose a new, dedicated trial directory");
    privateDirectory(dir);
    const identity = await makeIdentity();
    writeNew(path.join(dir, "identity.json"), identity);
    writeNew(path.join(dir, "trial.json"), { endpoint: url.href });
    writeNew(path.join(dir, "offer.json"), { cert: identity.cert, endpoint: url.href, fingerprint: fingerprint(identity.cert) });
    // This is a fragment, not a modification of any installed MCP configuration.
    writeNew(path.join(dir, "mcp-fragment.json"), {
      mcpServers: { "copilot-lan-trial": {
        command: process.execPath, args: [fileURLToPath(import.meta.url), "mcp", "--state", dir],
      } },
    });
    const store = new Store(dir); store.close();
    console.log(JSON.stringify({ status: "INITIALIZED", fingerprint: fingerprint(identity.cert), offer: path.join(dir, "offer.json") }));
    return;
  }
  const { config, identity } = load(dir);
  const store = new Store(dir);
  try {
    if (command === "approve") {
      const offer = JSON.parse(fs.readFileSync(o.offer, "utf8"));
      console.log(JSON.stringify({ approved: store.approve(offer, o.fingerprint) }));
    } else if (command === "revoke") {
      store.revoke(o.peer); console.log(JSON.stringify({ status: "REVOKED" }));
    } else if (command === "share") {
      new DesktopAdapter(copilot).events(o.session);
      if (!["true", "false"].includes(o.message) || !["true", "false"].includes(o.transcript)) {
        throw new Error("Share requires explicit --message true|false and --transcript true|false");
      }
      store.share(o.peer, o.session, {
        title: o.title, snapshot: o.snapshot || "", message: o.message === "true", transcript: o.transcript === "true",
      });
      console.log(JSON.stringify({ status: "SHARED" }));
    } else if (command === "unshare") {
      store.unshare(o.peer, o.session); console.log(JSON.stringify({ status: "UNSHARED" }));
    } else if (command === "peers") {
      console.log(JSON.stringify(store.peers().map(({ pin, endpoint: url }) => ({ pin, endpoint: url }))));
    } else if (command === "request") {
      console.log(JSON.stringify(await request({ store, identity, pin: o.peer, action: o.action,
        session: o.session || "", payload: o.message || "" })));
    } else if (command === "mcp") await mcp(store, identity);
    else if (command === "serve") {
      const url = endpoint(config.endpoint);
      const server = new PeerServer({ store, identity, host: url.hostname, port: +url.port, adapter: new DesktopAdapter(copilot) });
      await server.start();
      console.log(JSON.stringify({ status: "LISTENING", endpoint: config.endpoint }));
      await new Promise((resolve) => { process.once("SIGINT", resolve); process.once("SIGTERM", resolve); });
      await server.stop();
    } else throw new Error("Commands: init, approve, revoke, share, unshare, peers, request, serve, mcp");
  } finally { store.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => { console.error(`copilot-lan-trial: ${error.message}`); process.exitCode = 1; });
}
