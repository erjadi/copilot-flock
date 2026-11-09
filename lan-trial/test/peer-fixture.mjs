import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import { randomUUID } from "node:crypto";
import { WebSocketServer } from "ws";
import { Store } from "../store.mjs";
import { PeerServer, request } from "../transport.mjs";
import { DesktopAdapter } from "../desktop.mjs";
import { installLoopbackEgressGuard } from "./egress-guard.mjs";

// A separate Desktop-protocol fixture, never the user's running Desktop.
const dir = process.argv[2];
const { connections, denied: deniedEgress } = installLoopbackEgressGuard();
const setup = JSON.parse(fs.readFileSync(path.join(dir, "fixture.json"), "utf8"));
const store = new Store(dir, setup.capacity ? { capacity: setup.capacity } : {});
const desktopDir = path.join(dir, "desktop-fixture");
fs.mkdirSync(path.join(desktopDir, "run"), { recursive: true });
let handshakes = 0;
const heldHandshakes = [];
const desktop = new WebSocketServer({
  host: "127.0.0.1", port: 0, maxPayload: 32768,
  verifyClient: (info, done) => {
    handshakes++;
    if (setup.holdHandshake) { heldHandshakes.push(done); return; }
    setTimeout(() =>
      done(new URL(info.req.url, "http://127.0.0.1").searchParams.get("token") === "fixture-only-not-a-desktop-token"),
    setup.openDelay || 0);
  },
});
await new Promise((resolve) => desktop.once("listening", resolve));
fs.writeFileSync(path.join(desktopDir, "run", "ws.port"),
  setup.portFile ?? `${desktop.address().port}${setup.portSuffix || ""}`);
fs.writeFileSync(path.join(desktopDir, "run", "ws.token"),
  setup.tokenFile ?? `fixture-only-not-a-desktop-token${setup.tokenSuffix || ""}`);
for (const session of setup.sessions) {
  fs.mkdirSync(path.join(desktopDir, "session-state", session), { recursive: true });
  const file = path.join(desktopDir, "session-state", session, "events.jsonl");
  if (!fs.existsSync(file)) fs.writeFileSync(file, "");
}
const frames = [];
const broadcasts = [];
const admissionEvents = [];
function appendAdmission(frame, mode = "observed") {
  const now = new Date().toISOString();
  const event = {
    type: "user.message", id: randomUUID(), timestamp: now, parentId: null,
    data: {
      content: frame.display_prompt,
      transformedContent: `<current_datetime>${now}</current_datetime>\n\n${frame.prompt}`,
      attachments: [], agentMode: "interactive", messageId: randomUUID(),
      delivery: frame.delivery_mode || "immediate", turnId: "0", interactionId: randomUUID(),
    },
  };
  if (mode === "wrong-request") {
    event.data.transformedContent = event.data.transformedContent.replace(`request ${frame.request_id} `, `request ${randomUUID()} `);
  } else if (mode === "wrong-nonce") {
    event.data.transformedContent = event.data.transformedContent.replace(/ admission [0-9a-f-]+;/, ` admission ${randomUUID()};`);
  } else if (mode === "wrong-content") event.data.content += "not-exact";
  else if (mode === "missing-transformed") delete event.data.transformedContent;
  else if (mode === "wrong-peer") {
    event.data.transformedContent = event.data.transformedContent.replace(/\[Untrusted LAN peer [0-9a-f]{64} /,
      `[Untrusted LAN peer ${"0".repeat(64)} `);
  } else if (mode === "assistant") event.type = "assistant.message";
  else if (mode === "legacy-id-only") {
    event.data = { requestId: frame.request_id, content: frame.display_prompt };
  } else if (mode === "wrong-type-transformed") event.data.transformedContent = { prompt: frame.prompt };
  else if (mode === "quoted") event.data.transformedContent = `Quote: ${frame.prompt}`;
  else if (mode === "nested") event.data.transformedContent = `<user_quote>${frame.prompt}</user_quote>`;
  else if (mode === "duplicate-date") event.data.transformedContent = `<current_datetime>${now}</current_datetime>\n\n${event.data.transformedContent}`;
  else if (mode === "arbitrary-suffix") event.data.transformedContent += " appended untrusted prose";
  else if (mode === "direct") event.data.transformedContent = frame.prompt;
  else if (mode === "system-suffix") event.data.transformedContent += "\n\n<system_reminder>Fixture system context</system_reminder>";
  else if (mode === "crlf-chunked") {
    event.data.transformedContent = `<current_datetime>${now}</current_datetime>\r\n\r\n${frame.prompt}`;
  }
  admissionEvents.push(event);
  const file = path.join(desktopDir, "session-state", frame.session_id, "events.jsonl");
  const bytes = Buffer.from(JSON.stringify(event) + (mode === "crlf-chunked" ? "\r\n" : "\n"));
  if (mode === "crlf-chunked") {
    const boundary = bytes.findIndex((byte) => byte >= 0xc2);
    if (boundary < 0) throw new Error("Chunked fixture needs a multibyte character");
    fs.appendFileSync(file, bytes.subarray(0, boundary + 1));
    setTimeout(() => fs.appendFileSync(file, bytes.subarray(boundary + 1, bytes.length - 1)), 80);
    setTimeout(() => fs.appendFileSync(file, bytes.subarray(bytes.length - 1)), 160);
  } else fs.appendFileSync(file, bytes);
}
function broadcast(ws) {
  const broadcastBytes = setup.broadcastBytes ?? 68626;
  const base = JSON.stringify({ type: "system.message", content: "" });
  const message = JSON.stringify({ type: "system.message", content: "x".repeat(broadcastBytes - Buffer.byteLength(base)) });
  broadcasts.push(Buffer.byteLength(message));
  if (ws.readyState === 1) ws.send(message);
}
desktop.on("connection", (ws) => {
  ws.on("error", () => {});
  ws.on("message", (bytes) => {
    const frame = JSON.parse(bytes.toString());
    frames.push(frame);
    if (!setup.broadcastAfterAdmission) broadcast(ws);
    if (setup.errorAfterSend) {
      ws.send(JSON.stringify({ type: "error", request_id: frame.request_id }));
      return;
    }
    if (setup.closeAfterSend) ws.close();
    if (setup.terminateAfterSend) ws.terminate();
    if (setup.neverAdmit) return;
    if (setup.ackOnly) {
      ws.send(JSON.stringify({ type: "ack", request_id: frame.request_id, status: "accepted" }));
      return;
    }
    const index = frames.length - 1;
    const mode = setup.admissionModes?.[index] || setup.admissionMode || "observed";
    setTimeout(() => {
      if (mode === "previous-only") appendAdmission(frames[index - 1]);
      else if (mode === "previous-then-current") {
        appendAdmission(frames[index - 1]);
        setTimeout(() => appendAdmission(frame), 250);
      } else appendAdmission(frame, mode);
      if (setup.broadcastAfterAdmission) broadcast(ws);
    }, setup.admitDelay || 0);
  });
});
const adapter = new DesktopAdapter(desktopDir, { timeout: 1000 });
if (setup.finalScanOnly) {
  const send = adapter.send.bind(adapter);
  adapter.send = (...args) => {
    const interval = globalThis.setInterval;
    globalThis.setInterval = (callback, delay, ...values) => interval(callback, delay === 25 ? 2000 : delay, ...values);
    try { return send(...args); }
    finally { globalThis.setInterval = interval; }
  };
}
const server = new PeerServer({
  store, identity: setup.identity, host: "127.0.0.1", port: setup.port,
  adapter: setup.unshareAfterAdmission ? {
    async send(session, text, context) {
      const result = await adapter.send(session, text, context);
      store.unshare(context.peer, session);
      return result;
    },
  } : adapter, allowLoopback: true,
});
await server.start();
process.send({ type: "ready" });
process.on("message", async (m) => {
  try {
    let result;
    if (m.command === "request") result = await request({ store, identity: setup.identity, ...m.options, allowLoopback: true });
    else if (m.command === "frames") result = frames;
    else if (m.command === "admission-events") result = admissionEvents;
    else if (m.command === "broadcasts") result = broadcasts;
    else if (m.command === "adapter-probe") result = await adapter.send(setup.sessions[0], "fixture probe", {
      signal: new AbortController().signal, authorize: () => true, id: m.requestId, peer: m.peer,
    });
    else if (m.command === "wait-frame") {
      const deadline = Date.now() + 2000;
      while (frames.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      if (frames.length === 0) throw new Error("No Desktop frame observed within fixture deadline");
      result = frames.length;
    }
    else if (m.command === "wait-handshake") {
      const deadline = Date.now() + 2000;
      while (handshakes === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      if (handshakes === 0) throw new Error("No local Desktop handshake observed");
      result = handshakes;
    }
    else if (m.command === "connections") result = connections;
    else if (m.command === "denied-egress") result = deniedEgress;
    else if (m.command === "probe-egress") {
      const before = deniedEgress.length;
      try { net.createConnection({ host: "example.com", port: 443 }); }
      catch (error) { result = { code: error.code, denied: deniedEgress.length }; }
      finally { deniedEgress.splice(before); }
    }
    else if (m.command === "revoke") { store.revoke(m.pin); result = true; }
    else if (m.command === "unshare") {
      store.unshare(m.pin, m.session);
      for (const done of heldHandshakes.splice(0)) done(false);
      result = true;
    }
    else if (m.command === "share") { store.share(m.pin, m.session, m.share); result = true; }
    else if (m.command === "break-store") { store.close(); result = true; }
    else if (m.command === "stop") {
      for (const done of heldHandshakes.splice(0)) done(false);
      await server.stop();
      for (const ws of desktop.clients) ws.terminate();
      await new Promise((resolve) => desktop.close(resolve));
      try { store.close(); } catch { /* Fixture can intentionally close storage early. */ }
      process.send({ id: m.id, result: true }, () => process.exit(0));
      return;
    }
    process.send({ id: m.id, result });
  } catch (error) { process.send({ id: m.id, error: error.message }); }
});
