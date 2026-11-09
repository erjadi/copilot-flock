import https from "node:https";
import { constants, randomUUID } from "node:crypto";
import WebSocket, { WebSocketServer } from "ws";
import { LIMITS, SESSION, boundedText, endpoint, fingerprint, privateAddress, validCertificate } from "./store.mjs";

const actions = new Set(["status", "sessions", "transcript", "message"]);
function validRequest(r) {
  if (!r || Object.keys(r).sort().join() !== "action,expires,id,payload,session" ||
      !SESSION.test(r.id) || !actions.has(r.action) || !Number.isSafeInteger(r.expires) ||
      r.expires <= Date.now() || r.expires > Date.now() + LIMITS.ttl ||
      !boundedText(r.payload) || typeof r.session !== "string") return false;
  return r.action === "status" || r.action === "sessions"
    ? r.session === "" && r.payload === ""
    : SESSION.test(r.session) && (r.action === "message" ? r.payload.length > 0 : r.payload === "");
}
export class PeerServer {
  constructor({ store, identity, host, port, adapter, allowLoopback = false }) {
    if (!privateAddress(host, allowLoopback) || !Number.isInteger(port) || port < 0 || port > 65535 ||
        (port === 0 && !allowLoopback)) throw new Error("Explicit private IPv4 address and port required");
    validCertificate(identity.cert);
    this.store = store;
    this.pin = fingerprint(identity.cert);
    this.adapter = adapter;
    this.busy = new Set();
    this.pending = new Set();
    this.sockets = new Map();
    this.host = host; this.port = port;
    this.server = https.createServer({
      key: identity.key, cert: identity.cert, requestCert: true,
      rejectUnauthorized: true, ca: store.peers().map((p) => p.cert),
      minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
      secureOptions: constants.SSL_OP_NO_TICKET, numTickets: 0,
    }, (_req, res) => { res.writeHead(404); res.end(); });
    this.server.headersTimeout = 5000;
    this.server.requestTimeout = 5000;
    this.server.maxConnections = LIMITS.connections;
    this.wss = new WebSocketServer({ noServer: true, maxPayload: LIMITS.frame, perMessageDeflate: false });
    this.server.on("tlsClientError", () => {}); // Authentication failure has no application response.
    this.server.on("upgrade", (req, socket, head) => {
      try {
        const pin = fingerprint(socket.getPeerCertificate().raw);
        const peer = store.peer(pin);
        if (!socket.authorized || !peer || req.url !== "/" ||
            this.sockets.size >= LIMITS.connections) return socket.destroy();
        validCertificate(peer.cert);
        this.wss.handleUpgrade(req, socket, head, (ws) => {
          this.sockets.set(ws, { pin, revision: peer.revision });
          ws.on("error", () => {});
          ws.on("close", () => {
            this.sockets.delete(ws);
            for (const work of this.pending) if (work.ws === ws) work.controller.abort();
          });
          ws.on("message", (bytes, binary) => {
            if (binary || this.pending.size >= LIMITS.requests) return ws.close(1008);
            this.handle(ws, pin, bytes).catch(() => ws.close(1011));
          });
        });
      } catch { socket.destroy(); }
    });
  }
  async start() {
    await new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(this.port, this.host, () => { this.server.removeListener("error", reject); resolve(); });
    });
    this.monitor = setInterval(() => {
      try {
        for (const [ws, { pin, revision }] of this.sockets) {
          const peer = this.store.peer(pin);
          if (peer?.revision !== revision) ws.terminate();
          else validCertificate(peer.cert);
        }
        for (const work of this.pending) if (!work.authorize()) work.controller.abort();
      } catch {
        for (const work of this.pending) work.controller.abort();
        for (const ws of this.sockets.keys()) ws.terminate();
      }
    }, 25);
    return `wss://${this.host}:${this.server.address().port}/`;
  }
  async stop() {
    clearInterval(this.monitor);
    for (const work of this.pending) work.controller.abort();
    for (const ws of this.sockets.keys()) ws.terminate();
    await new Promise((resolve) => this.wss.close(resolve));
    await new Promise((resolve) => this.server.close(resolve));
  }
  async handle(ws, pin, bytes) {
    let r;
    try { r = JSON.parse(bytes.toString()); } catch { return ws.close(1008); }
    const reply = (result) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ id: r.id, ...result }));
    };
    if (!validRequest(r)) return ws.close(1008);
    let stamp, claim;
    try {
      stamp = this.store.authorization(pin, r);
      if (!stamp) return reply({ status: "DENIED" });
      claim = this.store.claim(pin, r);
    } catch { return reply({ status: "DENIED", reason: "Authorization/dedup storage unavailable" }); }
    if (claim !== "NEW") return reply({ status: claim });
    const controller = new AbortController();
    const authorize = () => !controller.signal.aborted && Date.now() < r.expires &&
      this.store.authorization(pin, r) === stamp;
    const work = { ws, controller, authorize };
    this.pending.add(work);
    let acquired = false, deliveryPossible = false;
    try {
      if (!authorize()) return reply({ status: "DENIED" });
      let result;
      if (r.action === "status") result = { status: "DELIVERED", peer: this.pin };
      else if (r.action === "sessions") result = {
        status: "DELIVERED", sessions: this.store.shares(pin).map(({ session, title, message, transcript }) =>
          ({ session, title, message: !!message, transcript: !!transcript })),
      };
      else if (r.action === "transcript") result = {
        status: "DELIVERED", snapshot: this.store.grant(pin, r.session).snapshot, source: "locally-approved-snapshot",
      };
      else {
        if (this.busy.has(r.session)) return reply({ status: "BUSY" });
        this.busy.add(r.session); acquired = true;
        deliveryPossible = true;
        result = await this.adapter.send(r.session, r.payload, { signal: controller.signal, authorize, id: r.id, peer: pin });
        if (!result || !["DELIVERED", "BUSY", "DENIED", "OFFLINE", "UNKNOWN"].includes(result.status)) {
          result = { status: "UNKNOWN", reason: "Unsupported adapter result" };
        }
        // An adapter may only disclose a fixed admission result, never local responses/tokens.
        result = { status: result.status, ...(result.status === "DELIVERED" ? { admission: "confirmed", executed: false } : {}) };
      }
      reply(authorize() ? result : { status: deliveryPossible ? "UNKNOWN" : "DENIED" });
    } catch { reply({ status: "UNKNOWN", reason: "Outcome could not be confirmed; do not redispatch" }); }
    finally {
      this.pending.delete(work);
      if (acquired) this.busy.delete(r.session);
    }
  }
}

export function request({ store, identity, pin, action, session = "", payload = "",
  id = randomUUID(), expires = Date.now() + 30000, timeout = 8000, allowLoopback = false }) {
  const r = { id, action, session, payload, expires };
  if (!validRequest(r) || !Number.isInteger(timeout) || timeout < 1 || timeout > LIMITS.ttl) {
    throw new Error("Invalid bounded request");
  }
  const peer = store.peer(pin);
  if (!peer) return Promise.resolve({ status: "DENIED" });
  validCertificate(peer.cert);
  const url = endpoint(peer.endpoint, allowLoopback);
  return new Promise((resolve) => {
    let sent = false, finished = false;
    const ws = new WebSocket(url, {
      key: identity.key, cert: identity.cert, ca: peer.cert, rejectUnauthorized: true,
      minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
      secureOptions: constants.SSL_OP_NO_TICKET,
      checkServerIdentity: (_host, cert) => {
        if (fingerprint(cert.raw) === pin) return undefined;
        return Object.assign(new Error("Peer identity mismatch"), { code: "ERR_LAN_IDENTITY" });
      },
      maxPayload: LIMITS.frame, perMessageDeflate: false, handshakeTimeout: timeout,
    });
    const finish = (result) => {
      if (finished) return;
      finished = true; clearTimeout(timer); clearInterval(monitor); ws.terminate(); resolve(result);
    };
    const timer = setTimeout(() => finish({ status: sent ? "UNKNOWN" : "OFFLINE" }), timeout);
    const monitor = setInterval(() => {
      try {
        if (store.peer(pin)?.revision !== peer.revision) finish({ status: sent ? "UNKNOWN" : "DENIED" });
        else validCertificate(peer.cert);
      }
      catch { finish({ status: sent ? "UNKNOWN" : "DENIED" }); }
    }, 25);
    ws.on("open", () => {
      try {
        if (store.peer(pin)?.revision !== peer.revision) return finish({ status: sent ? "UNKNOWN" : "DENIED" });
        validCertificate(peer.cert);
        sent = true;
        ws.send(JSON.stringify(r), (error) => { if (error) finish({ status: "UNKNOWN" }); });
      } catch { finish({ status: sent ? "UNKNOWN" : "DENIED" }); }
    });
    ws.on("message", (bytes, binary) => {
      try {
        const value = JSON.parse(bytes.toString());
        if (binary || value.id !== id || !["DELIVERED", "BUSY", "DENIED", "OFFLINE", "UNKNOWN"].includes(value.status)) {
          return finish({ status: "UNKNOWN" });
        }
        if (store.peer(pin)?.revision !== peer.revision) return finish({ status: sent ? "UNKNOWN" : "DENIED" });
        validCertificate(peer.cert);
        finish(value);
      } catch { finish({ status: "UNKNOWN" }); }
    });
    ws.on("error", (error) => {
      const authentication = /CERT|SELF_SIGNED|UNKNOWN_CA|BAD_CERTIFICATE|ERR_LAN_IDENTITY/.test(error.code || "");
      finish({ status: sent ? "UNKNOWN" : authentication ? "DENIED" : "OFFLINE",
        ...(authentication ? { reason: "Peer TLS authentication failed" } : {}) });
    });
    ws.on("close", () => finish({ status: sent ? "UNKNOWN" : "OFFLINE" }));
  });
}
