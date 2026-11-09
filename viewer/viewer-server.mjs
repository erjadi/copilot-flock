#!/usr/bin/env node
/**
 * Copilot Flock Internal Viewer & Mission Control Server (`viewer-server.mjs`)
 *
 * Hosts the Lovable-designed Copilot Flock Console UI and exposes live
 * REST + Server-Sent Events (`/api/*`) backed by Azure SignalR (`your-signalr.service.signalr.net`).
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  BRIDGE_VERSION,
  getBridgeHome,
  loadConfig,
  normalizeScope,
  normalizeGitHubUser,
  connectSignalRClient,
  discoverMachines,
  fetchBootstrapMembers,
  invokeRemoteRpc,
  invokeRemoteRpcBatch,
  filterBroadcastTargets,
  buildCrossSessionEnvelope,
  voteReleaseAcrossFlock,
  callBootstrapV3Endpoint,
  listSharedThreadsForMachine,
  shareThreadWithFlock,
  unshareThreadFromFlock,
  ensureMachineIdentityKeypair,
} from "../flock.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || process.env.VIEWER_PORT) || 8099;
const HOST = process.env.VIEWER_HOST || "127.0.0.1";
const DIST_DIR = path.join(__dirname, "dist");
const SEED_TRAFFIC_PATH = path.join(__dirname, "seed-traffic.json");

const cfg = loadConfig({ autoFetchAz: true, refreshSpecs: false });
const VIEWER_HOST_LABEL = `${cfg.machineId} (${getLocalIpv4() || os.hostname()}:${PORT})`;

function getLocalIpv4() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal && net.address.startsWith("10.0.0.")) {
        return net.address;
      }
    }
  }
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) {
        return net.address;
      }
    }
  }
  return "127.0.0.1";
}

// ---------------------------------------------------------------------------
// Live State, Wire Event Buffer, Topology Corridors & SSE Broadcaster
// ---------------------------------------------------------------------------

const sseClients = new Set();
const wireEvents = [];
const MAX_WIRE_EVENTS = 400;

let hubConnected = false;
let lastRefreshAt = 0;
let lastHttpActivityAt = Date.now();
let refreshInFlight = null;

const fleetCache = {
  members: [],
  sessions: [],
  lastUpdatedAt: new Date().toISOString(),
};

// Edge key: sorted "MachineA|MachineB"
const edgeKey = (a, b) => [a, b].sort().join("|");
const corridorMap = new Map();

function ensureCorridor(m1, m2) {
  const [a, b] = [String(m1).trim(), String(m2).trim()].sort();
  const key = `${a}|${b}`;
  if (!corridorMap.has(key)) {
    corridorMap.set(key, {
      a,
      b,
      ab: 0,
      ba: 0,
      rpc: 0,
      avgLatencyMs: 85,
      peakAt: new Date().toISOString().slice(11, 16),
      threadPairs: [],
      messages: [],
      lastActiveAt: new Date().toISOString(),
    });
  }
  return corridorMap.get(key);
}

function recordCorridorMessage({
  id,
  fromMachine,
  toMachine,
  fromThread = "Copilot Flock Coordinator",
  toThread = "Copilot Flock Coordinator",
  text = "",
  timestamp = new Date().toISOString(),
}) {
  if (!fromMachine || !toMachine || fromMachine === toMachine || toMachine === "*") return;
  const c = ensureCorridor(fromMachine, toMachine);
  if (fromMachine === c.a) c.ab += 1;
  else c.ba += 1;
  c.lastActiveAt = timestamp;
  if (timestamp.length >= 16) {
    c.peakAt = timestamp.slice(11, 16);
  }
  if (fromThread && toThread) {
    const pairA = fromMachine === c.a ? fromThread : toThread;
    const pairB = fromMachine === c.a ? toThread : fromThread;
    const exists = c.threadPairs.some(([x, y]) => x === pairA && y === pairB);
    if (!exists && c.threadPairs.length < 6) {
      c.threadPairs.push([pairA, pairB]);
    }
  }
  if (text) {
    c.messages.unshift({
      id: id || `lm-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
      from: fromMachine,
      to: toMachine,
      fromThread,
      toThread,
      text: String(text).slice(0, 4500),
      timestamp,
    });
    if (c.messages.length > 25) c.messages.length = 25;
  }
}

function recordCorridorRpc(fromMachine, toMachine, latencyMs = null) {
  if (!fromMachine || !toMachine || fromMachine === toMachine || toMachine === "*") return;
  const c = ensureCorridor(fromMachine, toMachine);
  c.rpc += 1;
  if (latencyMs && Number.isFinite(latencyMs) && latencyMs > 0) {
    c.avgLatencyMs = c.avgLatencyMs
      ? Math.round(c.avgLatencyMs * 0.75 + latencyMs * 0.25)
      : Math.round(latencyMs);
  }
  c.lastActiveAt = new Date().toISOString();
}

function loadInitialCorridors() {
  // 1. Seed baseline corridors across all known fleet pairs so the mesh graph is rich immediately
  const baselineCorridors = [
    ["MAIN-WORKSTATION", "3D-STUDIO-PC", 14, 11, 42, 78, [["Robotics stage coordination", "Copilot Flock Coordinator"], ["Rendering pipeline", "Lumen shader consultation"]]],
    ["MAIN-WORKSTATION", "MINI-SERVER-PC", 9, 8, 28, 94, [["Robotics stage coordination", "Copilot Flock Coordinator"]]],
    ["MAIN-WORKSTATION", "ARM64-LAPTOP", 8, 6, 24, 132, [["Stage event routing", "Copilot Flock Coordinator"]]],
    ["MAIN-WORKSTATION", "CLOUD-DEV-VM", 6, 5, 19, 165, [["Stage event routing", "Copilot Flock Coordinator"]]],
    ["MAIN-WORKSTATION", "LINUX-GPU-HOST", 8, 6, 31, 45, [["Robotics stage coordination", "Robotics simulation"]]],
    ["3D-STUDIO-PC", "LINUX-GPU-HOST", 7, 5, 26, 48, [["Robotics simulation status", "Robotics simulation"]]],
    ["ARM64-LAPTOP", "CLOUD-DEV-VM", 7, 6, 18, 118, [["Cross-channel messaging gateway", "Service API and Azure analysis"]]],
    ["3D-STUDIO-PC", "MINI-SERVER-PC", 4, 4, 14, 96, [["Copilot Flock Coordinator", "Copilot Flock Coordinator"]]],
    ["3D-STUDIO-PC", "ARM64-LAPTOP", 4, 3, 12, 142, [["Signalr bridge transcript tail fix", "Copilot Flock Coordinator"]]],
    ["MAIN-WORKSTATION", "LINUX-CONSOLE", 5, 4, 16, 38, [["SignalR bridge internal viewer", "Copilot Flock Console"]]],
    ["3D-STUDIO-PC", "LINUX-CONSOLE", 3, 2, 11, 42, [["Copilot Flock Coordinator", "Copilot Flock Console"]]],
    ["LINUX-GPU-HOST", "LINUX-CONSOLE", 3, 3, 12, 34, [["Robotics simulation", "Copilot Flock Console"]]],
  ];

  for (const [m1, m2, c12, c21, rpc, lat, pairs] of baselineCorridors) {
    const c = ensureCorridor(m1, m2);
    const isSorted = c.a === m1;
    c.ab = isSorted ? c12 : c21;
    c.ba = isSorted ? c21 : c12;
    c.rpc = rpc;
    c.avgLatencyMs = lat;
    c.threadPairs = pairs.map(([t1, t2]) => (isSorted ? [t1, t2] : [t2, t1]));
  }

  // 2. Overlay synthetic demo traffic and local runtime events.
  if (fs.existsSync(SEED_TRAFFIC_PATH)) {
    try {
      const records = JSON.parse(fs.readFileSync(SEED_TRAFFIC_PATH, "utf8"));
      if (Array.isArray(records)) {
        for (const r of records) {
          recordCorridorMessage({
            id: r.id,
            fromMachine: r.fromMachine,
            toMachine: r.toMachine,
            fromThread: r.fromThread,
            toThread: r.toThread,
            text: r.text,
            timestamp: r.timestamp,
          });
          pushWireEvent({
            id: `hist-${r.id}`,
            timestamp: r.timestamp || new Date().toISOString(),
            type: r.direction === "inbound" ? "inbox" : "outbox",
            target: r.toMachine,
            fromMachine: r.fromMachine,
            toMachine: r.toMachine,
            action: "send_message",
            summary: `${r.fromThread} → ${r.toThread}: ${String(r.text || "").slice(0, 72)}`,
            payload: r,
          }, false);
        }
      }
    } catch {}
  }

  const stateDirs = [
    getBridgeHome(),
    path.join(os.homedir(), ".copilot", "flock"),
    path.join(os.homedir(), ".copilot", "signalr-bridge"),
  ];
  const seenLogDirs = new Set();
  for (const dir of stateDirs) {
    if (!dir || seenLogDirs.has(dir) || !fs.existsSync(dir)) continue;
    seenLogDirs.add(dir);
    for (const [fname, direction] of [["inbox.jsonl", "inbound"], ["outbox.jsonl", "outbound"]]) {
      const fpath = path.join(dir, fname);
      if (!fs.existsSync(fpath)) continue;
      try {
        const lines = fs.readFileSync(fpath, "utf8").trim().split(/\r?\n/).slice(-30);
        for (const line of lines) {
          if (!line) continue;
          const item = JSON.parse(line);
          const text = String(item.message || item.text || item.reply || "").trim();
          if (!text) continue;
          const fromMachine = item.fromMachine || cfg.machineId;
          const toMachine = item.toMachine || (Array.isArray(item.targetMachines) ? item.targetMachines[0] : cfg.machineId);
          if (!fromMachine || !toMachine || fromMachine === toMachine) continue;
          recordCorridorMessage({
            id: item.requestId || undefined,
            fromMachine,
            toMachine,
            fromThread: item.fromSessionName || item.fromSession || "Copilot Flock Coordinator",
            toThread: item.matchedTitle || item.sessionTitle || item.toSession || "Copilot Flock Coordinator",
            text,
            timestamp: item.timestamp || item.receivedAt || item.sentAt || new Date().toISOString(),
          });
        }
      } catch {}
    }
  }
}

function pushWireEvent(ev, broadcastSse = true) {
  const eventObj = {
    id: ev.id || `evt-${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
    timestamp: ev.timestamp || new Date().toISOString(),
    type: ev.type || "bridgePresence",
    target: ev.target || "*",
    fromMachine: ev.fromMachine || cfg.machineId,
    toMachine: ev.toMachine || "*",
    action: ev.action || "presence",
    requestId: ev.requestId || undefined,
    summary: ev.summary || `${ev.action || "event"} · ${ev.fromMachine || ""} → ${ev.toMachine || ""}`,
    payload: ev.payload ?? {},
  };

  wireEvents.unshift(eventObj);
  if (wireEvents.length > MAX_WIRE_EVENTS) {
    wireEvents.length = MAX_WIRE_EVENTS;
  }

  if (broadcastSse && sseClients.size > 0) {
    const frame = `event: wire_event\ndata: ${JSON.stringify(eventObj)}\n\n`;
    for (const res of sseClients) {
      try {
        res.write(frame);
      } catch {
        sseClients.delete(res);
      }
    }
  }
  return eventObj;
}

function buildTopologySnapshot(members) {
  const memberIds = new Set(members.map((m) => m.machineId));
  const edges = [];
  for (const c of corridorMap.values()) {
    if (memberIds.has(c.a) && memberIds.has(c.b)) {
      edges.push({
        ...c,
        messages: c.messages.slice(0, 12),
      });
    }
  }
  const nodes = members.map((m) => {
    const sent = edges.reduce((acc, e) => acc + (e.a === m.machineId ? e.ab : e.b === m.machineId ? e.ba : 0), 0);
    const received = edges.reduce((acc, e) => acc + (e.a === m.machineId ? e.ba : e.b === m.machineId ? e.ab : 0), 0);
    const broadcasts = wireEvents.filter((ev) => ev.fromMachine === m.machineId && String(ev.toMachine || "").includes(",")).length;
    return {
      id: m.machineId,
      scope: m.scope,
      sent,
      received,
      broadcasts,
      activeSessionCount: m.activeSessionCount || 0,
      activity: sent + received + (m.activeSessionCount || 0),
      online: Boolean(m.online),
    };
  });
  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Live Fleet Discovery & Session Aggregation over SignalR
// ---------------------------------------------------------------------------

function normalizeSpecs(rawSpecs) {
  return {
    model: rawSpecs?.model || "Compute Node",
    os: rawSpecs?.os || "Unknown OS",
    publicKey: rawSpecs?.publicKey || null,
    keyFingerprint: rawSpecs?.keyFingerprint || null,
    cpu: {
      model: rawSpecs?.cpu?.model || "CPU",
      logicalCores: Number(rawSpecs?.cpu?.logicalCores) || 8,
      physicalCores: Number(rawSpecs?.cpu?.physicalCores) || Number(rawSpecs?.cpu?.logicalCores) || 4,
      arch: rawSpecs?.cpu?.arch || "x64",
    },
    memory: {
      totalGb: Number(rawSpecs?.memory?.totalGb) || 32,
      freeGb: Number(rawSpecs?.memory?.freeGb) || 16,
    },
    gpus: Array.isArray(rawSpecs?.gpus)
      ? rawSpecs.gpus.map((g) => ({
          name: g?.name || "GPU",
          vramGb: g?.vramGb !== undefined && g?.vramGb !== null ? Number(g.vramGb) : null,
          vramFreeGb: g?.vramFreeGb !== undefined && g?.vramFreeGb !== null ? Number(g.vramFreeGb) : null,
          utilizationPct: g?.utilizationPct !== undefined && g?.utilizationPct !== null ? Number(g.utilizationPct) : null,
        }))
      : [],
    disks: Array.isArray(rawSpecs?.disks)
      ? rawSpecs.disks.map((d) => ({
          mount: d?.mount || "/",
          label: d?.label || "",
          type: d?.type === "network" ? "network" : "fixed",
          totalGb: Number(d?.totalGb) || 100,
          freeGb: Number(d?.freeGb) || 50,
        }))
      : [],
  };
}

async function refreshFleetState() {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    const t0 = Date.now();
    try {
      // Single coalesced broadcast `ping` with `includeSessions: true` (eliminates dual ping + list_sessions polling storm)
      const [pingReplies, bootstrapMembers] = await Promise.all([
        invokeRemoteRpc(cfg, {
          toMachine: "*",
          action: "ping",
          params: { includeSessions: true, sessionLimit: 25 },
          timeoutMs: 2600,
          collectAll: true,
        }).catch(() => []),
        Promise.resolve().then(() => fetchBootstrapMembers({
          bootstrapUrl: cfg.bootstrapUrl, bootstrapOriginPin: cfg.bootstrapOriginPin,
        })).catch(() => []),
      ]);

      const onlineMachines = [];
      const seenOnlineIds = new Set();
      for (const r of pingReplies || []) {
        if (r?.result?.machineId) {
          const key = String(r.result.machineId).toLowerCase();
          if (!seenOnlineIds.has(key)) {
            seenOnlineIds.add(key);
            onlineMachines.push(r.result);
          }
        }
      }

      // Only query list_sessions on machines that are still on an older daemon without `ping.sessions`
      const legacyMachinesNeedingSessions = onlineMachines.filter(
        (m) => !Array.isArray(m.sessions)
      );
      const legacySessionReplies =
        legacyMachinesNeedingSessions.length > 0
          ? await invokeRemoteRpcBatch(
              cfg,
              legacyMachinesNeedingSessions.map((m) => ({
                target: m,
                toMachine: m.machineId,
                action: "list_sessions",
                params: { limit: 25 },
              })),
              2600
            ).catch(() => [])
          : [];
      const sessionReplies = [
        ...onlineMachines
          .filter((m) => Array.isArray(m.sessions))
          .map((m) => ({
            fromMachine: m.machineId,
            result: {
              machineId: m.machineId,
              scope: m.scope,
              githubUser: m.githubUser,
              sessions: m.sessions,
            },
          })),
        ...legacySessionReplies
          .filter((o) => o.ok && o.response?.result)
          .map((o) => o.response),
      ];

      const nowIso = new Date().toISOString();
      const onlineById = new Map(
        onlineMachines.map((m) => [String(m.machineId || "").toLowerCase(), m])
      );

      for (const m of onlineMachines) {
        recordCorridorRpc(cfg.machineId, m.machineId, Date.now() - t0);
      }

      const mergedMembers = new Map();

      for (const bm of bootstrapMembers || []) {
        if (!bm || !bm.machineId) continue;
        const key = String(bm.machineId).toLowerCase();
        const live = onlineById.get(key);
        const scope = normalizeScope(live?.scope || bm.scope, "personal");
        mergedMembers.set(key, {
          machineId: live?.machineId || bm.machineId,
          online: Boolean(live),
          githubUser: normalizeGitHubUser(live?.githubUser || bm.githubUser) || "erjadi",
          githubName: bm.githubName || bm.githubUser || "Flock member",
          scope,
          version: live?.version || bm.version || BRIDGE_VERSION,
          copilotDesktopRunning: Boolean(live ? live.copilotDesktopRunning : false),
          wsPort: live?.wsPort || null,
          activeSessionCount: Number(live?.activeSessionCount ?? (live?.recentSessions?.length || 0)),
          offlineReplay: live?.offlineReplay || bm.offlineReplay || { processedCount: 0, pendingAckCount: 0, inFlightCount: 0, ambiguousCount: 0 },
          registeredAt: bm.registeredAt || nowIso,
          lastSeenAt: live?.timestamp || bm.lastSeenAt || nowIso,
          recentSessions: Array.isArray(live?.recentSessions)
            ? live.recentSessions.map((s) => ({ session_id: s.session_id, title: s.title }))
            : [],
          specs: normalizeSpecs(live?.specs || bm.specs),
        });
      }

      for (const live of onlineMachines || []) {
        const key = String(live.machineId || "").toLowerCase();
        if (!mergedMembers.has(key)) {
          mergedMembers.set(key, {
            machineId: live.machineId,
            online: true,
            githubUser: normalizeGitHubUser(live.githubUser) || "erjadi",
            githubName: "Demo Developer",
            scope: normalizeScope(live.scope, "personal"),
            version: live.version || BRIDGE_VERSION,
            copilotDesktopRunning: Boolean(live.copilotDesktopRunning),
            wsPort: live.wsPort || null,
            activeSessionCount: Number(live.activeSessionCount ?? (live.recentSessions?.length || 0)),
            offlineReplay: live.offlineReplay || { processedCount: 0, pendingAckCount: 0, inFlightCount: 0, ambiguousCount: 0 },
            registeredAt: nowIso,
            lastSeenAt: live.timestamp || nowIso,
            recentSessions: Array.isArray(live.recentSessions)
              ? live.recentSessions.map((s) => ({ session_id: s.session_id, title: s.title }))
              : [],
            specs: normalizeSpecs(live.specs),
          });
        }
      }

      const allSessions = [];
      const seenSessionKeys = new Set();

      for (const rep of sessionReplies || []) {
        const res = rep?.result;
        const machineId = res?.machineId || rep?.fromMachine;
        if (!machineId || !Array.isArray(res?.sessions)) continue;
        const memberEntry = mergedMembers.get(String(machineId).toLowerCase());
        const scope = normalizeScope(res.scope || memberEntry?.scope, "personal");
        const githubUser = normalizeGitHubUser(res.githubUser || memberEntry?.githubUser) || "erjadi";

        if (memberEntry) {
          memberEntry.activeSessionCount = res.sessions.length;
          memberEntry.recentSessions = res.sessions.slice(0, 5).map((s) => ({
            session_id: s.session_id,
            title: s.title,
          }));
        }

        for (const s of res.sessions) {
          const skey = `${machineId}:${s.session_id}`;
          if (seenSessionKeys.has(skey)) continue;
          seenSessionKeys.add(skey);
          allSessions.push({
            machineId,
            scope,
            githubUser,
            session_id: s.session_id,
            workspace_id: s.workspace_id || s.session_id,
            title: s.title || "Untitled session",
            session_type: s.session_type || (memberEntry?.copilotDesktopRunning ? "desktop" : "cli"),
            is_running: Boolean(s.is_running),
            mode: s.mode || "interactive",
            model: s.model || "gpt-5",
            repo: s.repo || "copilot/chat",
            branch: s.branch || "main",
            path: s.path || "",
            updated_at: s.updated_at || nowIso,
          });
        }
      }

      // Fallback to recentSessions from ping if list_sessions missed a machine
      for (const m of mergedMembers.values()) {
        for (const rs of m.recentSessions || []) {
          const skey = `${m.machineId}:${rs.session_id}`;
          if (seenSessionKeys.has(skey)) continue;
          seenSessionKeys.add(skey);
          allSessions.push({
            machineId: m.machineId,
            scope: m.scope,
            githubUser: m.githubUser,
            session_id: rs.session_id,
            workspace_id: rs.session_id,
            title: rs.title || "Untitled session",
            session_type: m.copilotDesktopRunning ? "desktop" : "cli",
            is_running: false,
            mode: "interactive",
            model: "gpt-5",
            repo: "copilot/chat",
            branch: "main",
            path: "",
            updated_at: m.lastSeenAt || nowIso,
          });
        }
      }

      const sortedMembers = Array.from(mergedMembers.values()).sort((a, b) => {
        if (a.online !== b.online) return a.online ? -1 : 1;
        return (b.activeSessionCount || 0) - (a.activeSessionCount || 0);
      });

      if (sortedMembers.length > 0) {
        fleetCache.members = sortedMembers;
        fleetCache.sessions = allSessions;
        fleetCache.lastUpdatedAt = nowIso;
        lastRefreshAt = Date.now();
      }
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

// ---------------------------------------------------------------------------
// Persistent SignalR Hub Wire Listener
// ---------------------------------------------------------------------------

async function startSignalRObserverLoop() {
  const observerUserId = `viewer-${cfg.machineId}-${process.pid}`;
  while (true) {
    try {
      let resolveClose;
      const closePromise = new Promise((r) => {
        resolveClose = r;
      });

      const client = await connectSignalRClient(cfg, {
        userId: observerUserId,
        onInvocation: (target, args) => {
          const payload = args?.[0] || {};
          if (target === "bridgePresence") {
            const fromM = payload.machineId || "unknown";
            pushWireEvent({
              type: "bridgePresence",
              target: "all",
              fromMachine: fromM,
              toMachine: "*",
              action: "presence",
              summary: `${fromM} heartbeat · ${payload.activeSessionCount ?? 0} sessions`,
              payload,
            });
          } else if (target === "bridgeRpcRequest") {
            const fromM = payload.fromMachine || "unknown";
            const action = payload.action || "rpc";
            pushWireEvent({
              type: "bridgeRpcRequest",
              target: "*",
              fromMachine: fromM,
              toMachine: "*",
              action,
              requestId: payload.requestId,
              summary: `${action} broadcast from ${fromM}`,
              payload,
            });
          } else if (target === "bridgeRpcResponse") {
            const fromM = payload.fromMachine || "unknown";
            pushWireEvent({
              type: "bridgeRpcResponse",
              target: observerUserId,
              fromMachine: fromM,
              toMachine: cfg.machineId,
              action: "response",
              requestId: payload.requestId,
              summary: `response from ${fromM}`,
              payload,
            });
          }
        },
        onClose: () => resolveClose(),
      });

      hubConnected = true;
      await closePromise;
      hubConnected = false;
      client.close();
    } catch {
      hubConnected = false;
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

// ---------------------------------------------------------------------------
// HTTP Server & API Routes
// ---------------------------------------------------------------------------

function sendJson(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => {
      if (raw.length < 256 * 1024) raw += c;
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    res.end();
    return;
  }

  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    lastHttpActivityAt = Date.now();
  }

  // 1. SSE Real-Time Wire Stream
  if (url.pathname === "/api/stream" && req.method === "GET") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*",
    });
    res.write(`data: ${JSON.stringify({ type: "hello", connected: true, viewerHost: VIEWER_HOST_LABEL })}\n\n`);
    sseClients.add(res);
    req.on("close", () => {
      sseClients.delete(res);
    });
    return;
  }

  // 2. GET /api/overview
  if (url.pathname === "/api/overview" && req.method === "GET") {
    if (fleetCache.members.length === 0 || Date.now() - lastRefreshAt > 6000 || url.searchParams.get("refresh") === "1") {
      await refreshFleetState();
    }
    const topology = buildTopologySnapshot(fleetCache.members);
    sendJson(res, 200, {
      hub: {
        endpoint: cfg.endpoint,
        hub: cfg.hub,
        version: BRIDGE_VERSION,
        viewerHost: VIEWER_HOST_LABEL,
        connected: hubConnected || fleetCache.members.length > 0,
        lastUpdatedAt: fleetCache.lastUpdatedAt,
      },
      members: fleetCache.members,
      sessions: fleetCache.sessions,
      events: wireEvents.slice(0, 160),
      topology,
    });
    return;
  }

  // 3. GET /api/sessions
  if (url.pathname === "/api/sessions" && req.method === "GET") {
    const machine = url.searchParams.get("machine") || "*";
    const scope = url.searchParams.get("scope") || "all";
    const query = (url.searchParams.get("query") || "").toLowerCase();
    const runningOnly = url.searchParams.get("runningOnly") === "true";

    if (Date.now() - lastRefreshAt > 5000) {
      await refreshFleetState();
    }
    const filtered = fleetCache.sessions.filter((s) => {
      if (machine !== "*" && s.machineId !== machine) return false;
      if (scope !== "all" && s.scope !== scope) return false;
      if (runningOnly && !s.is_running) return false;
      if (query && !`${s.title} ${s.repo} ${s.branch} ${s.machineId}`.toLowerCase().includes(query)) return false;
      return true;
    });
    sendJson(res, 200, { count: filtered.length, sessions: filtered });
    return;
  }

  // 4. GET /api/transcript
  if (url.pathname === "/api/transcript" && req.method === "GET") {
    const machine = url.searchParams.get("machine");
    const session = url.searchParams.get("session") || "latest";
    const limit = Number(url.searchParams.get("limit")) || 20;
    if (!machine) {
      sendJson(res, 400, { error: "Missing machine query parameter" });
      return;
    }

    const reqId = `req-${crypto.randomUUID().slice(0, 8)}`;
    const t0 = Date.now();
    pushWireEvent({
      type: "bridgeRpcRequest",
      target: machine,
      fromMachine: cfg.machineId,
      toMachine: machine,
      action: "get_transcript",
      requestId: reqId,
      summary: `get_transcript → ${machine} (${session.slice(0, 12)})`,
      payload: { session, limit },
    });

    try {
      const rpcRes = await invokeRemoteRpc(cfg, {
        toMachine: machine,
        action: "get_transcript",
        params: { session, limit },
        timeoutMs: 10000,
      });
      const lat = Date.now() - t0;
      recordCorridorRpc(cfg.machineId, machine, lat);
      pushWireEvent({
        type: "bridgeRpcResponse",
        target: cfg.machineId,
        fromMachine: machine,
        toMachine: cfg.machineId,
        action: "get_transcript",
        requestId: reqId,
        summary: `get_transcript ok · ${lat}ms (${rpcRes.result?.messages?.length ?? 0} turns)`,
        payload: { requestId: reqId, ok: true, latencyMs: lat },
      });

      const s = rpcRes.result?.session || {};
      sendJson(res, 200, {
        machineId: machine,
        session: {
          session_id: s.session_id || session,
          title: s.title || "Session",
          repo: s.repo || "copilot/chat",
          branch: s.branch || "main",
          session_type: s.session_type || "desktop",
          is_running: Boolean(s.is_running),
        },
        messages: Array.isArray(rpcRes.result?.messages) ? rpcRes.result.messages : [],
      });
    } catch (err) {
      sendJson(res, 502, { error: err.message });
    }
    return;
  }

  // 5. GET /api/projects
  if (url.pathname === "/api/projects" && req.method === "GET") {
    const machine = url.searchParams.get("machine");
    if (!machine) {
      sendJson(res, 400, { error: "Missing machine query parameter" });
      return;
    }
    const reqId = `req-${crypto.randomUUID().slice(0, 8)}`;
    const t0 = Date.now();
    pushWireEvent({
      type: "bridgeRpcRequest",
      target: machine,
      fromMachine: cfg.machineId,
      toMachine: machine,
      action: "list_projects",
      requestId: reqId,
      summary: `list_projects → ${machine}`,
      payload: {},
    });
    try {
      const rpcRes = await invokeRemoteRpc(cfg, {
        toMachine: machine,
        action: "list_projects",
        params: {},
        timeoutMs: 8000,
      });
      const lat = Date.now() - t0;
      recordCorridorRpc(cfg.machineId, machine, lat);
      pushWireEvent({
        type: "bridgeRpcResponse",
        target: cfg.machineId,
        fromMachine: machine,
        toMachine: cfg.machineId,
        action: "list_projects",
        requestId: reqId,
        summary: `list_projects ok · ${lat}ms (${rpcRes.result?.count ?? 0} repos)`,
        payload: { requestId: reqId, ok: true, latencyMs: lat },
      });
      sendJson(res, 200, rpcRes.result || { machineId: machine, scope: "private", count: 0, projects: [] });
    } catch (err) {
      sendJson(res, 502, { error: err.message });
    }
    return;
  }

  // 6. POST /api/send
  if (url.pathname === "/api/send" && req.method === "POST") {
    const body = await readJsonBody(req);
    const toMachine = body.toMachine;
    const toSession = body.toSession || "latest";
    const message = String(body.message || "").trim();
    const mode = body.mode === "enqueue" ? "enqueue" : "immediate";
    const waitForReply = Boolean(body.waitForReply);
    const dryRun = Boolean(body.dryRun);
    const fromMachine = body.fromMachine || cfg.machineId;

    if (!toMachine || !message) {
      sendJson(res, 400, { error: "Missing toMachine or message" });
      return;
    }

    const reqId = `req-${crypto.randomUUID().slice(0, 8)}`;
    const t0 = Date.now();

    // Special case: Node Inspector "Send Test Pulse / Ping Node" sends dryRun=true with "[ping]"
    if (dryRun && message.startsWith("[ping]")) {
      pushWireEvent({
        type: "bridgeRpcRequest",
        target: toMachine,
        fromMachine,
        toMachine,
        action: "ping",
        requestId: reqId,
        summary: `ping pulse → ${toMachine}`,
        payload: { requestId: reqId, toMachine },
      });
      try {
        const pingRes = await invokeRemoteRpc(cfg, {
          toMachine,
          action: "ping",
          params: {},
          timeoutMs: 6000,
        });
        const lat = Math.max(1, Date.now() - t0);
        recordCorridorRpc(fromMachine, toMachine, lat);
        pushWireEvent({
          type: "bridgeRpcResponse",
          target: fromMachine,
          fromMachine: toMachine,
          toMachine: fromMachine,
          action: "ping",
          requestId: reqId,
          summary: `ping ok · ${lat}ms`,
          payload: { requestId: reqId, ok: true, latencyMs: lat, machineId: toMachine },
        });
        sendJson(res, 200, {
          ok: true,
          latencyMs: lat,
          requestId: reqId,
          pong: pingRes.result,
        });
      } catch (err) {
        sendJson(res, 502, { error: err.message });
      }
      return;
    }

    pushWireEvent({
      type: "bridgeRpcRequest",
      target: toMachine,
      fromMachine,
      toMachine,
      action: "send_message",
      requestId: reqId,
      summary: `${dryRun ? "dry_run" : "send_message"} → ${toMachine} (${toSession.slice(0, 12)})`,
      payload: { toMachine, toSession, mode, dryRun, waitForReply },
    });

    try {
      const rpcRes = await invokeRemoteRpc(cfg, {
        toMachine,
        action: "send_message",
        params: {
          targetSession: toSession,
          message,
          fromMachine,
          fromScope: cfg.scope,
          fromGitHubUser: cfg.githubUser || "erjadi",
          fromSessionId: "signalr-fleet-console",
          fromSessionName: "Copilot Flock Console",
          mode,
          waitForReply,
          waitTimeoutMs: 90000,
          dryRun,
        },
        timeoutMs: waitForReply ? 95000 : 15000,
      });
      const lat = Math.max(1, Date.now() - t0);
      recordCorridorRpc(fromMachine, toMachine, lat);

      if (!dryRun) {
        recordCorridorMessage({
          id: reqId,
          fromMachine,
          toMachine,
          fromThread: "Copilot Flock Console",
          toThread: rpcRes.result?.targetSessionTitle || toSession,
          text: message,
        });
      }

      pushWireEvent({
        type: "bridgeRpcResponse",
        target: fromMachine,
        fromMachine: toMachine,
        toMachine: fromMachine,
        action: "send_message",
        requestId: reqId,
        summary: `send_message ${dryRun ? "preview" : "delivered"} · ${lat}ms`,
        payload: { requestId: reqId, latencyMs: lat, result: rpcRes.result },
      });

      sendJson(res, 200, {
        ok: true,
        latencyMs: lat,
        requestId: reqId,
        ...rpcRes.result,
        reply: rpcRes.result?.reply?.content || rpcRes.result?.reply || undefined,
      });
    } catch (err) {
      if (dryRun) {
        sendJson(res, 200, {
          ok: true,
          envelopePreview: buildCrossSessionEnvelope({
            cfg,
            fromMachine,
            fromScope: cfg.scope,
            fromGitHubUser: cfg.githubUser || "erjadi",
            fromSessionId: "signalr-fleet-console",
            fromSessionName: "Copilot Flock Console",
            targetSessionId: toSession,
            message,
          }),
        });
        return;
      }
      sendJson(res, 502, { error: err.message });
    }
    return;
  }

  // 7. POST /api/create-session
  if (url.pathname === "/api/create-session" && req.method === "POST") {
    const body = await readJsonBody(req);
    const toMachine = body.toMachine;
    if (!toMachine) {
      sendJson(res, 400, { error: "Missing toMachine" });
      return;
    }
    const reqId = `req-${crypto.randomUUID().slice(0, 8)}`;
    const t0 = Date.now();
    pushWireEvent({
      type: "bridgeRpcRequest",
      target: toMachine,
      fromMachine: cfg.machineId,
      toMachine,
      action: "create_session",
      requestId: reqId,
      summary: `create_session → ${toMachine} (${body.title || "New session"})`,
      payload: body,
    });
    try {
      const rpcRes = await invokeRemoteRpc(cfg, {
        toMachine,
        action: "create_session",
        params: {
          title: body.title || null,
          repo: body.repo || null,
          workspaceType: body.workspaceType || "branch",
          branch: body.branch || null,
          message: body.message || null,
          fromMachine: cfg.machineId,
          fromScope: cfg.scope,
          fromGitHubUser: cfg.githubUser || "erjadi",
          fromSessionId: "signalr-fleet-console",
          fromSessionName: "Copilot Flock Console",
          mode: "immediate",
          waitForReply: Boolean(body.waitForReply),
          waitTimeoutMs: 90000,
        },
        timeoutMs: body.waitForReply ? 105000 : 25000,
      });
      const lat = Math.max(1, Date.now() - t0);
      recordCorridorRpc(cfg.machineId, toMachine, lat);
      if (body.message) {
        recordCorridorMessage({
          id: reqId,
          fromMachine: cfg.machineId,
          toMachine,
          fromThread: "Copilot Flock Console",
          toThread: body.title || "New session",
          text: body.message,
        });
      }
      pushWireEvent({
        type: "bridgeRpcResponse",
        target: cfg.machineId,
        fromMachine: toMachine,
        toMachine: cfg.machineId,
        action: "create_session",
        requestId: reqId,
        summary: `create_session ok · ${lat}ms`,
        payload: { requestId: reqId, latencyMs: lat, result: rpcRes.result },
      });
      setTimeout(() => refreshFleetState().catch(() => {}), 500);
      sendJson(res, 200, { ok: true, latencyMs: lat, ...rpcRes.result });
    } catch (err) {
      sendJson(res, 502, { error: err.message });
    }
    return;
  }

  // 8. POST /api/broadcast
  if (url.pathname === "/api/broadcast" && req.method === "POST") {
    const body = await readJsonBody(req);
    const dryRun = Boolean(body.dryRun);
    const waitForReply = Boolean(body.waitForReply);
    const newSession = Boolean(body.newSession);
    const toSession = body.toSession || "Copilot Flock Coordinator";
    const message = String(body.message || "").trim();

    if (fleetCache.members.length === 0) {
      await refreshFleetState();
    }

    const onlineMembers = fleetCache.members.filter((m) => m.online);
    const targets = filterBroadcastTargets(onlineMembers, {
      localMachineId: cfg.machineId,
      includeSelf: true,
      machines: body.machines || "*",
      exclude: body.exclude || null,
      scope: body.scope && body.scope !== "all" ? body.scope : null,
      githubUser: body.githubUser || null,
      gpu: body.gpu || null,
      minRamGb: Number(body.minRamGb) || 0,
      minFreeDiskGb: Number(body.minFreeDiskGb) || 0,
      hasRepo: body.hasRepo || null,
    });

    if (dryRun) {
      const envelopePreview = targets
        .map((m) =>
          buildCrossSessionEnvelope({
            cfg,
            fromMachine: cfg.machineId,
            fromScope: cfg.scope,
            fromGitHubUser: cfg.githubUser || "erjadi",
            fromSessionId: "signalr-fleet-console",
            fromSessionName: "Copilot Flock Console",
            targetSessionId: newSession ? "<new_session>" : toSession,
            message: message || "(dry-run preview)",
          })
        )
        .join("\n\n---\n\n");
      sendJson(res, 200, { ok: true, targetCount: targets.length, envelopePreview });
      return;
    }

    const t0 = Date.now();
    const batchItems = targets.map((target) => ({
      target,
      toMachine: target.machineId,
      action: newSession ? "create_session" : "send_message",
      params: newSession
        ? {
            title: body.title || "Broadcast session",
            repo: body.repo || null,
            message,
            fromMachine: cfg.machineId,
            fromScope: cfg.scope,
            fromGitHubUser: cfg.githubUser || "erjadi",
            fromSessionId: "signalr-fleet-console",
            fromSessionName: "Copilot Flock Console",
            mode: "immediate",
            waitForReply,
            waitTimeoutMs: 90000,
          }
        : {
            targetSession: toSession,
            message,
            fromMachine: cfg.machineId,
            fromScope: cfg.scope,
            fromGitHubUser: cfg.githubUser || "erjadi",
            fromSessionId: "signalr-fleet-console",
            fromSessionName: "Copilot Flock Console",
            mode: "immediate",
            waitForReply,
            waitTimeoutMs: 90000,
            dispatchTimeoutMs: waitForReply ? 30000 : 8000,
          },
    }));

    const outcomes = await invokeRemoteRpcBatch(cfg, batchItems, waitForReply ? 95000 : 18000);
    const results = outcomes.map((o) => {
      const lat = Math.max(1, Date.now() - t0);
      const mId = o.item.toMachine;
      recordCorridorRpc(cfg.machineId, mId, lat);
      if (o.ok && message) {
        recordCorridorMessage({
          fromMachine: cfg.machineId,
          toMachine: mId,
          fromThread: "Copilot Flock Console",
          toThread: o.response?.result?.targetSessionTitle || toSession,
          text: message,
        });
      }
      return {
        machineId: mId,
        ok: o.ok,
        latencyMs: lat,
        detail: o.ok
          ? o.response?.result?.targetSessionTitle
            ? `delivered → "${o.response.result.targetSessionTitle}"`
            : "delivered"
          : o.error || "failed",
      };
    });

    pushWireEvent({
      type: "outbox",
      target: "broadcast",
      fromMachine: cfg.machineId,
      toMachine: targets.map((t) => t.machineId).join(","),
      action: "broadcast",
      summary: `broadcast → ${targets.length} machines (${results.filter((r) => r.ok).length} ok)`,
      payload: { results },
    });

    sendJson(res, 200, { ok: true, results });
    return;
  }

  // 8b. POST /api/vote-release — Live pre-merge flock vote (review_release RPC)
  if (url.pathname === "/api/vote-release" && req.method === "POST") {
    const body = await readJsonBody(req);
    const branch = String(body.branch || "main").trim();
    const machines = Array.isArray(body.machines) ? body.machines.join(",") : body.machines || "*";
    try {
      const voteRes = await voteReleaseAcrossFlock(cfg, { branch, machines });
      pushWireEvent({
        type: "outbox",
        target: "governance",
        fromMachine: cfg.machineId,
        toMachine: machines,
        action: "review_release",
        summary: `vote-release (${branch}) → ${voteRes.acceptCount}/${voteRes.onlineVoterCount} ACCEPT`,
        payload: voteRes,
      });
      sendJson(res, 200, {
        ok: true,
        approvedForMerge: voteRes.approvedForMerge,
        accepted: voteRes.acceptCount,
        total: voteRes.onlineVoterCount,
        branch: voteRes.branch,
        votes: voteRes.votes,
      });
    } catch (err) {
      sendJson(res, 502, { error: err.message });
    }
    return;
  }

  // 8c. POST /api/diagnose — Live flock health & coordinator/tracker diagnosis
  if (url.pathname === "/api/diagnose" && req.method === "POST") {
    const body = await readJsonBody(req);
    const fix = Boolean(body.fix);
    const machines = Array.isArray(body.machines) ? body.machines.join(",") : body.machines || "*";
    if (fleetCache.members.length === 0) {
      await refreshFleetState();
    }
    const onlineMembers = fleetCache.members.filter((m) => m.online);
    const targets = filterBroadcastTargets(onlineMembers, {
      localMachineId: cfg.machineId,
      includeSelf: true,
      machines,
    });
    const batchItems = targets.map((t) => ({
      target: t,
      toMachine: t.machineId,
      action: "diagnose",
      params: { fix },
    }));
    const outcomes = batchItems.length > 0 ? await invokeRemoteRpcBatch(cfg, batchItems, 20000) : [];
    const results = outcomes.map((o) => {
      const mId = o.item.toMachine;
      const d = o.ok ? o.response?.result : null;
      const healthy = Boolean(o.ok && d && (!Array.isArray(d.issues) || d.issues.length === 0));
      const detail = o.ok && d
        ? `v${d.version || BRIDGE_VERSION} · PID ${d.daemonPid || "ok"} · ${
            Array.isArray(d.issues) && d.issues.length > 0 ? d.issues.join("; ") : "Single daemon, Ed25519 key, boot persistence, Coordinator + Tracker healthy"
          }`
        : o.error || "unreachable";
      return { machineId: mId, ok: healthy, detail };
    });
    const healthyCount = results.filter((r) => r.ok).length;
    pushWireEvent({
      type: "outbox",
      target: "governance",
      fromMachine: cfg.machineId,
      toMachine: targets.map((t) => t.machineId).join(","),
      action: "diagnose",
      summary: `diagnose → ${healthyCount}/${results.length} healthy`,
      payload: { results },
    });
    sendJson(res, 200, { ok: true, healthy: healthyCount, total: results.length, results });
    return;
  }

  // 8d. GET /api/v3/my-flocks — Multi-Flock Roster & Hierarchy
  if (url.pathname === "/api/v3/my-flocks" && req.method === "GET") {
    try {
      if (fleetCache.members.length === 0) {
        await refreshFleetState();
      }
      const raw = callBootstrapV3Endpoint(cfg, "/my-flocks", { method: "GET" }) || {};
      const byId = new Map();
      for (const f of [...(raw.ownedFlocks || []), ...(raw.joinedFlocks || [])]) {
        if (!f || !f.flockId || byId.has(f.flockId)) continue;
        const kind =
          f.flockType === "owner_root"
            ? "owner_root"
            : f.flockType === "owner_scope"
            ? "owner_scope"
            : f.targetMachineId
            ? "guest"
            : "collaborator";
        const trustTier =
          f.ownerGitHubUser?.toLowerCase() === (cfg.githubUser || "erjadi").toLowerCase() &&
          (kind === "owner_root" || kind === "owner_scope")
            ? "owner"
            : kind === "guest"
            ? "guest"
            : "collaborator";
        byId.set(f.flockId, {
          flockId: f.flockId,
          flockUuid: f.flockUuid,
          hubName: f.hubName,
          rosterEpoch: Number(f.rosterEpoch) || 1,
          kind,
          trustTier,
          sessionVisibility: trustTier === "owner" ? "all" : "explicit_opt_in_only",
          members: Array.isArray(f.members)
            ? f.members.map((m) => ({
                machineId: m.machineId,
                peerId: m.peerId,
                membershipExpiresAt: m.membershipExpiresAt || null,
              }))
            : [],
        });
      }
      const owner = (cfg.githubUser || "erjadi").toLowerCase();
      const toMember = (m, expiresAt = null) => ({
        machineId: m.machineId,
        peerId: `demo-owner:${m.specs?.keyFingerprint || crypto.createHash("sha256").update(m.machineId).digest("hex").slice(0, 32)}`,
        membershipExpiresAt: expiresAt,
      });
      const builtIns = [
        {
          flockId: owner,
          flockUuid: "00000000-0000-4000-8000-000000000001",
          hubName: "v3_flock_00000000000040008000000000000001",
          rosterEpoch: 7,
          kind: "owner_root",
          trustTier: "owner",
          sessionVisibility: "all",
          members: fleetCache.members.map((m) => toMember(m)),
        },
        {
          flockId: `${owner}/personal`,
          flockUuid: "00000000-0000-4000-8000-000000000002",
          hubName: "v3_flock_00000000000040008000000000000002",
          rosterEpoch: 5,
          kind: "owner_scope",
          trustTier: "owner",
          sessionVisibility: "all",
          members: fleetCache.members.filter((m) => m.scope === "personal").map((m) => toMember(m)),
        },
        {
          flockId: `${owner}/work`,
          flockUuid: "00000000-0000-4000-8000-000000000003",
          hubName: "v3_flock_00000000000040008000000000000003",
          rosterEpoch: 3,
          kind: "owner_scope",
          trustTier: "owner",
          sessionVisibility: "all",
          members: fleetCache.members.filter((m) => m.scope === "work").map((m) => toMember(m)),
        },
        {
          flockId: `${owner}/studio-team`,
          flockUuid: "00000000-0000-4000-8000-000000000004",
          hubName: "v3_flock_00000000000040008000000000000004",
          rosterEpoch: 2,
          kind: "collaborator",
          trustTier: "collaborator",
          sessionVisibility: "explicit_opt_in_only",
          members: fleetCache.members.filter((m) => m.scope === "work" || m.machineId === "LINUX-GPU-HOST").map((m) => toMember(m)),
        },
        {
          flockId: `${owner}/work/CLOUD-DEV-VM`,
          flockUuid: "00000000-0000-4000-8000-000000000005",
          hubName: "v3_flock_00000000000040008000000000000005",
          rosterEpoch: 1,
          kind: "guest",
          trustTier: "guest",
          sessionVisibility: "explicit_opt_in_only",
          members: fleetCache.members
            .filter((m) => m.machineId === "CLOUD-DEV-VM")
            .map((m) => toMember(m, new Date(Date.now() + 120 * 60000).toISOString())),
        },
      ];
      for (const bf of builtIns) {
        if (!byId.has(bf.flockId)) {
          byId.set(bf.flockId, bf);
        } else {
          const existing = byId.get(bf.flockId);
          const haveIds = new Set(existing.members.map((m) => m.machineId));
          for (const m of bf.members) {
            if (!haveIds.has(m.machineId)) existing.members.push(m);
          }
        }
      }
      sendJson(res, 200, { ok: true, flocks: Array.from(byId.values()) });
    } catch (err) {
      sendJson(res, 502, { ok: false, error: err.message });
    }
    return;
  }

  // 8e. GET /api/v3/maintainer/overview — Platform Maintainer Overview
  if (url.pathname === "/api/v3/maintainer/overview" && req.method === "GET") {
    try {
      const raw = callBootstrapV3Endpoint(cfg, "/maintainer/overview", { method: "GET" });
      if (raw?.ok) {
        sendJson(res, 200, raw);
        return;
      }
      sendJson(res, 200, {
        ok: true,
        maintainer: cfg.githubUser || "erjadi",
        version: BRIDGE_VERSION,
        viewerHost: VIEWER_HOST_LABEL,
        activeMachines: fleetCache.members.filter((m) => m.online).length,
        totalMachines: fleetCache.members.length,
        builtInFlocks: ["erjadi", "example/personal", "example/work"],
      });
    } catch (err) {
      sendJson(res, 502, { ok: false, error: err.message });
    }
    return;
  }

  // 8f. GET /api/v3/shared-threads — "What Am I Sharing?" Thread Audit
  if (url.pathname === "/api/v3/shared-threads" && req.method === "GET") {
    try {
      const resAudit = listSharedThreadsForMachine(cfg) || {};
      const threads = Array.isArray(resAudit.sharedThreads)
        ? resAudit.sharedThreads.map((t) => ({
            sessionId: t.sessionId,
            title: t.title || t.sessionId,
            machineId: resAudit.machineId || cfg.machineId,
            sharingMode: t.sharingMode || "approved-snapshot",
            boundFlockId: t.flockId || t.boundFlockId,
          }))
        : [];
      sendJson(res, 200, { ok: true, threads });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message, threads: [] });
    }
    return;
  }

  // 8g. POST /api/v3/flocks/invite — Copilot-First Streamlined Invite Generator
  if (url.pathname === "/api/v3/flocks/invite" && req.method === "POST") {
    const body = await readJsonBody(req);
    try {
      const targetAddress = String(body.targetPath || body.targetAddress || body.flockId || "").trim();
      const invitedUser = String(body.githubHandle || body.invitedUser || "").replace(/^@/, "").trim();
      const durationMinutes = body.durationMinutes ? Number(body.durationMinutes) : null;
      const maxDevices = Number(body.maxDevices) || 3;
      const out = callBootstrapV3Endpoint(cfg, "/flocks/invite", {
        method: "POST",
        body: { targetAddress, invitedUser, durationMinutes, maxDevices },
      });
      if (out?.ok) {
        sendJson(res, 200, {
          ok: true,
          copilotPrompt: out.pasteablePrompt || out.copilotPrompt,
          enrollment: out.enrollmentJson || out.enrollment,
        });
        return;
      }
      const idKey = ensureMachineIdentityKeypair();
      const nowMs = Date.now();
      const voucherExpiresAt = new Date(nowMs + 24 * 3600000).toISOString();
      const membershipExpiresAt = durationMinutes ? new Date(nowMs + durationMinutes * 60000).toISOString() : null;
      const flockUuid = crypto.randomUUID();
      const payloadToSign = `v3|invite|${targetAddress}|${invitedUser.toLowerCase()}|${voucherExpiresAt}|${membershipExpiresAt || "permanent"}|${maxDevices}`;
      const voucherSignature = crypto.sign(null, Buffer.from(payloadToSign, "utf8"), idKey.privateKey).toString("base64");
      const enrollment = {
        v: 3,
        invitedUser,
        invitedBy: cfg.githubUser || "erjadi",
        bootstrapUrl: cfg.bootstrapUrl || "https://your-flock-bootstrap.azurewebsites.net/api/bootstrap",
        voucherExpiresAt,
        membershipExpiresAt,
        maxDevices,
        flocks: [
          {
            flockId: targetAddress,
            flockUuid,
            recommendedScope: "work",
            voucherSignature,
            signerFingerprint: idKey.fingerprint,
          },
        ],
      };
      const copilotPrompt = [
        `Accept my pending GitHub repo invite to \`erjadi/copilot-flock\` (if any), clone \`https://github.com/erjadi/copilot-flock\`, install and set up the SignalR bridge on this machine, and enroll me in \`${targetAddress}\` using this signed v3 enrollment JSON:`,
        "```json",
        JSON.stringify(enrollment, null, 2),
        "```",
      ].join("\n");
      sendJson(res, 200, { ok: true, copilotPrompt, enrollment });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }

  // 8h. POST /api/v3/flocks/kick — Instant Member Revocation & Live Eviction
  if (url.pathname === "/api/v3/flocks/kick" && req.method === "POST") {
    const body = await readJsonBody(req);
    try {
      const out = callBootstrapV3Endpoint(cfg, "/flocks/kick", {
        method: "POST",
        body: {
          flockId: body.flockId,
          targetPeerId: body.peerId || null,
          targetMachineId: body.machineId || null,
          targetUser: body.githubUser || null,
        },
      });
      sendJson(res, 200, out || { ok: true });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }

  // 8i. POST /api/v3/unshare-thread — 1-Click Unshare Thread
  if (url.pathname === "/api/v3/unshare-thread" && req.method === "POST") {
    const body = await readJsonBody(req);
    try {
      const out = unshareThreadFromFlock(cfg, {
        flockId: body.boundFlockId || body.flockId,
        sessionId: body.sessionId,
      });
      sendJson(res, 200, { ok: true, ...out });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }

  // 9. Serve Static Frontend Assets from dist/
  let filePath = path.join(DIST_DIR, url.pathname === "/" ? "index.html" : url.pathname);
  if (!filePath.startsWith(DIST_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(DIST_DIR, "index.html");
  }
  if (!fs.existsSync(filePath)) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Frontend build not found in dist/. Run 'npm run build' first.");
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || "application/octet-stream";
  res.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600",
  });
  fs.createReadStream(filePath).pipe(res);
});

loadInitialCorridors();
startSignalRObserverLoop().catch(() => {});
refreshFleetState().catch(() => {});
setInterval(() => {
  // Pause active SignalR broadcast polling when no browser SSE client or recent HTTP client is active
  if (sseClients.size === 0 && Date.now() - lastHttpActivityAt > 45000) {
    return;
  }
  refreshFleetState().catch(() => {});
}, 25000).unref?.();

server.listen(PORT, HOST, () => {
  console.log(`Copilot Flock Console listening on http://${HOST}:${PORT} (${VIEWER_HOST_LABEL})`);
});
