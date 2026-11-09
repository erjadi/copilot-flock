import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import WebSocket from "ws";
import { SESSION, LIMITS } from "./store.mjs";

// No CLI fallback, session creation, model/mode selection, or permission changes.
export class DesktopAdapter {
  constructor(copilotDir, { timeout = 8000 } = {}) {
    this.dir = copilotDir;
    this.timeout = timeout;
  }
  events(session) {
    if (!SESSION.test(session)) throw new Error("Invalid existing session ID");
    const root = fs.realpathSync(path.join(this.dir, "session-state"));
    const file = fs.realpathSync(path.join(root, session, "events.jsonl"));
    if (file !== path.join(root, session, "events.jsonl")) throw new Error("Session symlinks are unsupported");
    return file;
  }
  async send(session, text, { signal, authorize, id, peer }) {
    if (typeof id !== "string" || !SESSION.test(id) ||
        typeof peer !== "string" || !/^[0-9a-f]{64}$/.test(peer)) return { status: "DENIED" };
    const nonce = randomUUID();
    const prompt = `[Untrusted LAN peer ${peer} request ${id} admission ${nonce}; keep this session's existing permissions]\n${text}`;
    const displayPrompt = `[LAN peer ${peer}] ${text}`;
    let file, port, token, offset;
    try {
      file = this.events(session);
      port = fs.readFileSync(path.join(this.dir, "run", "ws.port"), "utf8").split(/\r?\n/, 1)[0].trim();
      token = fs.readFileSync(path.join(this.dir, "run", "ws.token"), "utf8").split(/\r?\n/, 1)[0].trim();
      offset = fs.statSync(file).size;
    } catch (error) {
      if (error.code === "ENOENT") return { status: "DENIED", reason: "Existing Desktop session/control plane unavailable" };
      throw error;
    }
    if (!/^\d{1,5}$/.test(port) || +port < 1 || +port > 65535 ||
        !token || token.length > 4096) return { status: "DENIED", reason: "Invalid local Desktop control plane" };
    if (signal.aborted || !authorize()) return { status: "DENIED" };
    return new Promise((resolve) => {
      let sent = false, finished = false, remainder = "";
      const decoder = new StringDecoder("utf8");
      const ws = new WebSocket(`ws://127.0.0.1:${port}/?token=${encodeURIComponent(token)}`, {
        maxPayload: 16 * 1024 * 1024, handshakeTimeout: this.timeout, perMessageDeflate: false,
      });
      const finish = (result) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer); clearInterval(poll);
        signal.removeEventListener("abort", abort);
        ws.terminate();
        resolve(result);
      };
      const abort = () => finish({ status: sent ? "UNKNOWN" : "DENIED", reason: "Authorization revoked" });
      const disconnect = () => {
        ws.terminate();
        if (!sent) finish({ status: "OFFLINE" });
      };
      const pollOnce = () => {
        if (!sent || finished) return;
        try {
          if (!authorize()) return abort();
          const size = fs.statSync(file).size;
          if (size < offset || size - offset > 1024 * 1024) {
            return finish({ status: "UNKNOWN", reason: "Admission event stream rotated or exceeded bound" });
          }
          const data = Buffer.alloc(size - offset);
          const fd = fs.openSync(file, "r");
          try { fs.readSync(fd, data, 0, data.length, offset); }
          finally { fs.closeSync(fd); }
          offset = size;
          remainder += decoder.write(data);
          if (Buffer.byteLength(remainder) > 1024 * 1024) return finish({ status: "UNKNOWN" });
          const lines = remainder.split("\n");
          remainder = lines.pop();
          for (const rawLine of lines) {
            const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
            let event;
            try { event = JSON.parse(line); } catch { continue; }
            const transformed = event.data?.transformedContent;
            const unwrapped = typeof transformed === "string"
              ? transformed.replace(/^(?:<current_datetime>[^<\r\n]+<\/current_datetime>\r?\n\r?\n)?/, "")
              : null;
            const matchingEnvelope = unwrapped !== null && unwrapped.startsWith(prompt) &&
              (unwrapped === prompt || /^(?:\r?\n){1,2}<[a-z_][a-z0-9_]*(?:[ \t][^<>]*)?>/i.test(unwrapped.slice(prompt.length)));
            if (event.type === "user.message" && event.data?.content === displayPrompt && matchingEnvelope) {
              return finish(authorize() ? { status: "DELIVERED", admission: "confirmed", executed: false } : { status: "UNKNOWN" });
            }
          }
        } catch { finish({ status: "UNKNOWN", reason: "Cannot confirm local admission" }); }
      };
      const timer = setTimeout(() => {
        pollOnce();
        if (!finished) finish({ status: "UNKNOWN", reason: "Admission not confirmed; do not retry automatically" });
      }, this.timeout);
      const poll = setInterval(pollOnce, 25);
      signal.addEventListener("abort", abort, { once: true });
      ws.on("open", () => {
        try {
          if (signal.aborted || !authorize()) return abort();
          sent = true;
          ws.send(JSON.stringify({
            type: "send_message", session_id: session, request_id: id,
            prompt, display_prompt: displayPrompt, attachments: [], canvas_context: [], delivery_mode: "immediate",
          }), (error) => { if (error) disconnect(); });
        } catch { if (sent) disconnect(); else finish({ status: "DENIED" }); }
      });
      ws.on("message", (bytes) => {
        if (bytes.length > LIMITS.frame) return;
        let response;
        try { response = JSON.parse(bytes.toString()); } catch { return; }
        if (response.type === "error" && (response.request_id === id || response.requestId === id)) {
          finish({ status: sent ? "UNKNOWN" : "DENIED", reason: "Desktop reported an error; admission not confirmed" });
        }
      });
      // The app-wide loopback bus can disconnect after admission but before its disk flush.
      ws.on("error", disconnect);
      ws.on("close", disconnect);
    });
  }
}
