import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import tls from "node:tls";
import { setImmediate as nextTurn } from "node:timers/promises";
import * as canonical from "../flock.mjs";
import * as legacy from "../bridge.mjs";

const implementations = [canonical, legacy];
const cfg = { protocol: "broker-free-v34", endpoint: "https://fixture.service.signalr.net",
  host: "fixture.service.signalr.net", hub: "fixture-forbidden", clientToken: "fixture-private-token",
  credentialExpiresAt: Number.MAX_SAFE_INTEGER };

test("both SignalR entrypoints surface delayed rejected upgrades without leaking credentials or unhandled handshake rejections", async (t) => {
  const sockets = new Set();
  const closed = [];
  let status = 401;
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    socket.once("data", () => {
      setImmediate(() => socket.end(`HTTP/1.1 ${status} Fixture denial\r\nContent-Length: 28\r\n\r\nfixture-private-response-body`));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  });
  t.mock.method(tls, "connect", (options) => {
    assert.equal(options.host, cfg.host);
    const socket = net.connect({ host: "127.0.0.1", port: server.address().port });
    closed.push(new Promise((resolve) => socket.once("close", resolve)));
    socket.once("connect", () => socket.emit("secureConnect"));
    return socket;
  });
  for (const implementation of implementations) {
    for (status of [401, 403, 400]) {
      let closes = 0;
      await assert.rejects(implementation.connectSignalRClient(cfg, { userId: "fixture-peer",
        onClose: () => { closes++; } }),
      { message: `Scoped SignalR WebSocket failed (HTTP ${status}); credential-bearing details withheld` });
      await closed.at(-1);
      assert.equal(closes, 1);
    }
  }
  await nextTurn();
});

test("both SignalR entrypoints reject an early close even if upgrade never settles and ignore a late upgrade", async (t) => {
  for (const implementation of implementations) {
    let finishUpgrade;
    let ws;
    let sends = 0;
    t.mock.method(implementation.RawWebSocketClient.prototype, "connect", function () {
      ws = this;
      setImmediate(() => this.onClose({ code: 1006, reason: "fixture-early-close" }));
      return new Promise((resolve) => { finishUpgrade = resolve; });
    });
    t.mock.method(implementation.RawWebSocketClient.prototype, "sendText", () => { sends++; });
    let closes = 0;
    const connecting = implementation.connectSignalRClient(cfg, { userId: "fixture-peer",
      onClose: () => { closes++; } });
    await assert.rejects(connecting, /connection closed before handshake completed/);
    assert.equal(ws.closed, true);
    assert.equal(closes, 1);
    finishUpgrade();
    await nextTurn();
    assert.equal(sends, 0, "A late upgrade must not send or start a new handshake after failure");
  }
});

test("both SignalR entrypoints preserve JSON handshake errors received during upgrade", async (t) => {
  for (const implementation of implementations) {
    let ws;
    t.mock.method(implementation.RawWebSocketClient.prototype, "connect", function () {
      ws = this;
      this.onTextMessage(JSON.stringify({ error: "fixture-handshake-rejected" }) + "\x1e");
      return Promise.resolve();
    });
    await assert.rejects(implementation.connectSignalRClient(cfg, { userId: "fixture-peer" }),
      /SignalR handshake error: fixture-handshake-rejected/);
    assert.equal(ws.closed, true);
    await nextTurn();
  }
});

test("both SignalR entrypoints reject JSON handshake timeout explicitly and close the socket", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const implementation of implementations) {
    let ws;
    let sends = 0;
    t.mock.method(implementation.RawWebSocketClient.prototype, "connect", function () {
      ws = this;
      return Promise.resolve();
    });
    t.mock.method(implementation.RawWebSocketClient.prototype, "sendText", () => { sends++; });
    const connecting = implementation.connectSignalRClient(cfg, { userId: "fixture-peer" });
    const rejected = assert.rejects(connecting, /SignalR JSON handshake timed out after 10000ms/);
    await nextTurn();
    assert.equal(sends, 1);
    t.mock.timers.tick(10000);
    await rejected;
    assert.equal(ws.closed, true);
    ws.onClose({ code: 1006, reason: "fixture-timeout-close" });
    await nextTurn();
    t.mock.timers.tick(350);
  }
});

test("both SignalR entrypoints retain successful handshake, invocation and close behavior without a stale handshake timer", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const implementation of implementations) {
    let ws;
    const messages = [];
    t.mock.method(implementation.RawWebSocketClient.prototype, "connect", function () {
      ws = this;
      return Promise.resolve();
    });
    t.mock.method(implementation.RawWebSocketClient.prototype, "sendText", () => {});
    const connecting = implementation.connectSignalRClient(cfg, { userId: "fixture-peer",
      onInvocation: (target, args) => messages.push({ target, args }) });
    await nextTurn();
    ws.onTextMessage("{}\x1e");
    const connected = await connecting;
    ws.onTextMessage(JSON.stringify({ type: 1, target: "flock34", arguments: [{ fixture: true }] }) + "\x1e");
    assert.deepEqual(messages, [{ target: "flock34", args: [{ fixture: true }] }]);
    t.mock.timers.tick(10000);
    assert.equal(ws.closed, false);
    connected.close();
    assert.equal(ws.closed, true);
    t.mock.timers.tick(350);
  }
});
