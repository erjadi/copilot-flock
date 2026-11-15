import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import tls from "node:tls";
import { EventEmitter } from "node:events";
import { setImmediate as nextTurn } from "node:timers/promises";
import * as canonical from "../flock.mjs";
import * as legacy from "../bridge.mjs";

const implementations = [canonical, legacy];
const cfg = { protocol: "broker-free-v34", endpoint: "https://fixture.service.signalr.net",
  host: "fixture.service.signalr.net", hub: "fixture_forbidden", clientToken: "fixture-private-token",
  credentialExpiresAt: Number.MAX_SAFE_INTEGER };

const credentialCanaries = ["eyJhbGciOiJIUzI1NiJ9.c2lnbmFsci1zZWNyZXQ.c2lnbmF0dXJl",
  "LOCAL_WS_OPAQUE_CANARY", "SIG_OPAQUE_CANARY", "SIGNATURE_OPAQUE_CANARY", "FRAGMENT_CANARY", "PASSWORD_CANARY"];
const credentialUrl = `wss://user:${credentialCanaries[5]}@fixture.service.signalr.net/client/?access_token=${credentialCanaries[0]}&token=${credentialCanaries[1]}&sig=${credentialCanaries[2]}&signature=${credentialCanaries[3]}#${credentialCanaries[4]}`;

test("both raw WebSocket entrypoints omit credential query, fragment and userinfo from all connection failures", async (t) => {
  for (const mode of ["timeout", "socket-error", "upgrade"]) {
    mockTlsSocket(t, (socket) => {
      if (mode === "socket-error") {
        socket.destroy(Object.assign(new Error(`connect failed at ${credentialUrl}`), { code: "ECONNRESET" }));
      } else if (mode === "upgrade") {
        socket.emit("data", Buffer.from(`HTTP/1.1 403 ${credentialUrl}\r\n\r\n${credentialUrl}`));
      }
    }, { timeout: mode === "timeout" });
    for (const implementation of implementations) {
      await assert.rejects(new implementation.RawWebSocketClient(credentialUrl, { timeoutMs: 5 }).connect(), (error) => {
        assert.match(error.message, /wss:\/\/fixture\.service\.signalr\.net\/client\//);
        assert.doesNotMatch(error.message, /[?#]/);
        const detail = `${error.message}\n${error.stack}\n${JSON.stringify(error)}`;
        for (const canary of credentialCanaries) assert.equal(detail.includes(canary), false);
        if (mode === "upgrade") assert.equal(error.statusCode, 403);
        if (mode === "timeout") assert.equal(error.code, "ETIMEDOUT");
        if (mode === "socket-error") assert.equal(error.code, "ECONNRESET");
        return true;
      });
    }
  }
});

test("central diagnostic formatting scrubs credential URL query values on every error formatting path", () => {
  const query = `wss://fixture.invalid/client/?access_token=${credentialCanaries[0]}&TOKEN=${credentialCanaries[1]}&sig=${credentialCanaries[2]}&signature=${credentialCanaries[3]}`;
  for (const implementation of implementations) {
    for (const value of [
      query, new Error(query), { code: query }, { stack: query }, { detail: query },
    ]) {
      const output = implementation.formatErrorDetail(value);
      for (const canary of credentialCanaries.slice(0, 4)) assert.equal(output.includes(canary), false);
      assert.match(output, /redacted/i);
    }
  }
});

function mockTlsSocket(t, respond, { timeout = false } = {}) {
  const sockets = [];
  t.mock.method(tls, "connect", () => {
    const socket = new EventEmitter();
    socket.destroyed = false;
    socket.setTimeout = (milliseconds) => {
      clearTimeout(socket.timer);
      if (timeout && milliseconds) socket.timer = setTimeout(() => socket.emit("timeout"), 5);
    };
    socket.write = (bytes) => respond(socket, bytes);
    socket.destroy = (error) => {
      if (socket.destroyed) return;
      socket.destroyed = true;
      clearTimeout(socket.timer);
      if (error) socket.emit("error", error);
      socket.emit("close");
    };
    socket.end = () => socket.destroy();
    sockets.push(socket);
    setImmediate(() => socket.emit("secureConnect"));
    return socket;
  });
  t.after(() => sockets.forEach((socket) => socket.destroy()));
  return sockets;
}

test("both raw WebSocket entrypoints send one masked close frame before marking closed and bound unresponsive-peer cleanup", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const implementation of implementations) {
    const ws = new implementation.RawWebSocketClient("ws://127.0.0.1/fixture");
    const frames = [];
    let ended = 0;
    let destroyed = 0;
    ws.socket = {
      write(frame) { assert.equal(ws.closed, false); frames.push(frame); },
      end() { ended++; },
      destroy() { destroyed++; },
    };
    ws.close();
    ws.close();
    assert.equal(ws.closed, true);
    assert.equal(frames.length, 1);
    assert.equal(frames[0][0], 0x88);
    assert.equal(frames[0][1], 0x80);
    assert.equal(frames[0].length, 6);
    t.mock.timers.tick(99);
    assert.equal(ended, 0);
    t.mock.timers.tick(1);
    assert.equal(ended, 1);
    t.mock.timers.tick(249);
    assert.equal(destroyed, 0);
    t.mock.timers.tick(1);
    assert.equal(destroyed, 1);
    ws.close();
    assert.equal(frames.length, 1);
  }
});

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
        onClose: () => { closes++; } }), (error) => {
        assert.equal(error.message, `Scoped SignalR WebSocket failed (HTTP ${status}); credential-bearing details withheld`);
        assert.equal(error.statusCode, status);
        return true;
      });
      await closed.at(-1);
      assert.equal(closes, 1);
    }
  }
  await nextTurn();
});

test("both SignalR entrypoints preserve typed rejection status when data and close fire synchronously before the upgrade catch resumes", async (t) => {
  let status = 401;
  const sockets = mockTlsSocket(t, (socket) => {
    socket.emit("data", Buffer.from(`HTTP/1.1 ${status} Fixture denial mentioning 101\r\n\r\nfixture-private-response-body`));
    socket.destroy();
    socket.emit("data", Buffer.from("HTTP/1.1 101 Switching Protocols\r\n\r\n"));
  });
  for (const implementation of implementations) {
    for (status of [401, 403, 400]) {
      let closes = 0;
      await assert.rejects(implementation.connectSignalRClient(cfg, { userId: "fixture-peer",
        onClose: () => { closes++; } }), (error) => {
        assert.equal(error.message, `Scoped SignalR WebSocket failed (HTTP ${status}); credential-bearing details withheld`);
        assert.equal(error.statusCode, status);
        return true;
      });
      assert.equal(closes, 1);
      assert.equal(sockets.at(-1).destroyed, true);
    }
    await nextTurn();
  }
});

test("both SignalR entrypoints reject pre-upgrade EOF, connect timeout and successful-upgrade immediate close without hanging or inventing authorization status", async (t) => {
  for (const mode of ["eof", "timeout", "upgraded-close"]) {
    const sockets = mockTlsSocket(t, (socket) => {
      if (mode === "timeout") return;
      if (mode === "upgraded-close") socket.emit("data", Buffer.from("HTTP/1.1 101 Switching Protocols\r\n\r\n"));
      socket.destroy();
    }, { timeout: mode === "timeout" });
    for (const implementation of implementations) {
      let closes = 0;
      await assert.rejects(implementation.connectSignalRClient(cfg, { userId: "fixture-peer",
        onClose: () => { closes++; } }), (error) => {
        assert.ok(error.statusCode == null);
        assert.match(error.message, /Scoped SignalR WebSocket failed|SignalR connection closed before handshake completed/);
        assert.doesNotMatch(error.message, /401|403|fixture-private-token/);
        return true;
      });
      assert.equal(closes, 1);
      assert.equal(sockets.at(-1).destroyed, true);
    }
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
    assert.equal(ws.onTextMessage, null);
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
    assert.equal(ws.onTextMessage, null);
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
