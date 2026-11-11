import { open } from "node:fs/promises";
import { isIPv4 } from "node:net";
import { validateTodoSnapshot } from "./todo-snapshot.mjs";

function permittedSocket(address, lanCidr) {
  let network, mask;
  const integer = (ip) => ip.split(".").reduce((value, octet) => value * 256 + Number(octet), 0);
  if (lanCidr) {
    const parts = lanCidr.split("/");
    if (parts.length !== 2 || !isIPv4(parts[0]) || !/^(?:[1-9]|[12]\d|3[0-2])$/.test(parts[1])) {
      throw new Error("Invalid TODO LAN subnet");
    }
    mask = (0xffffffff << (32 - Number(parts[1]))) >>> 0;
    network = integer(parts[0]);
    if (((network & mask) >>> 0) !== network) throw new Error("TODO LAN subnet must use its network address");
  }
  if (["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(address)) return true;
  const ipv4 = typeof address === "string" ? address.replace(/^::ffff:/i, "") : "";
  return network !== undefined && isIPv4(ipv4) && ((integer(ipv4) & mask) >>> 0) === network;
}

export async function handleTodoRequest(req, res, {
  snapshotPath = process.env.VIEWER_TODOS_PATH,
  lanCidr = process.env.VIEWER_TODOS_LAN_CIDR || "",
  log = console.error,
} = {}) {
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
  let permitted;
  try { permitted = permittedSocket(req.socket?.remoteAddress, lanCidr); }
  catch {
    log("[viewer] Invalid TODO LAN subnet configuration");
    return reply(503, { error: "TODO access configuration is invalid" });
  }
  if (!permitted) {
    return reply(403, { error: "TODO access is restricted to loopback, authenticated SSH, or the explicitly configured LAN subnet" });
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
