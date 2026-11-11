import { open } from "node:fs/promises";
import { validateTodoSnapshot } from "./todo-snapshot.mjs";

export async function handleTodoRequest(req, res, { snapshotPath = process.env.VIEWER_TODOS_PATH, log = console.error } = {}) {
  if (new URL(req.url || "/", "http://localhost").pathname !== "/api/todos") return false;
  const reply = (status, data, headers = {}) => {
    res.writeHead(status, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Cross-Origin-Resource-Policy": "same-origin",
      ...headers,
    });
    res.end(JSON.stringify(data));
    return true;
  };
  // This route deliberately does not inherit the legacy API's wildcard CORS.
  if (req.headers["sec-fetch-site"] === "cross-site") return reply(403, { error: "Same-origin access required" });
  if (req.headers.origin) {
    let origin;
    try { origin = new URL(req.headers.origin); } catch { return reply(403, { error: "Same-origin access required" }); }
    if (origin.host !== req.headers.host) return reply(403, { error: "Same-origin access required" });
  }
  if (req.method !== "GET") return reply(405, { error: "TODO snapshots are read-only" }, { Allow: "GET" });
  if (!snapshotPath) return reply(503, { error: "TODO snapshot is not configured for this viewer" });
  if (!["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket?.remoteAddress)) {
    return reply(403, { error: "Private TODO data requires a loopback connection or authenticated SSH tunnel" });
  }
  let file;
  try {
    file = await open(snapshotPath, "r");
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error("Invalid snapshot file");
    const snapshot = validateTodoSnapshot(JSON.parse(await file.readFile("utf8")));
    return reply(200, snapshot);
  } catch (error) {
    const missing = error?.code === "ENOENT";
    log(`[viewer] TODO snapshot ${missing ? "missing" : "unreadable or invalid"}`);
    return reply(503, { error: missing ? "TODO snapshot is missing" : "TODO snapshot is unreadable or invalid" });
  } finally {
    if (file) await file.close();
  }
}
