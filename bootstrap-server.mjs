#!/usr/bin/env node
/**
 * GitHub-Verified Bootstrap Server for copilot-signalr-bridge
 *
 * Allows deployment maintainers, repository owners, write collaborators and explicitly allowlisted users
 * of `erjadi/copilot-flock` to bootstrap with ONLY
 * their GitHub repo credentials (`gh auth token` or `git credential fill`),
 * without requiring Azure CLI (`az login`) or manual connection strings,
 * and without storing any secrets in the git repository.
 */

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import { matchesMember, verifyLeave } from "./flock-membership.mjs";

const PORT = Number(process.env.PORT) || 8080;
const ALLOWED_REPO = (
  process.env.ALLOWED_GITHUB_REPO ||
  process.env.ALLOWED_REPO ||
  "erjadi/copilot-flock"
).toLowerCase();
const ALLOWED_REPOS_SET = new Set([
  ALLOWED_REPO,
  "erjadi/copilot-flock",
  "erjadi/copilot-signalr-bridge",
]);
const PLATFORM_MAINTAINER_USER = (process.env.PLATFORM_MAINTAINER_USER || "erjadi").toLowerCase();
const DEFAULT_HUB =
  process.env.COPILOT_FLOCK_HUB ||
  process.env.COPILOT_BRIDGE_HUB ||
  process.env.SIGNALR_HUB ||
  "copilotbridge";
const SERVICEBUS_NAMESPACE = process.env.SERVICEBUS_NAMESPACE || "";
const SERVICEBUS_TOPIC = process.env.SERVICEBUS_TOPIC || "copilot-bridge-offline";
const DATA_DIR = fs.existsSync("/home/site")
  ? "/home/site/data"
  : path.join(process.cwd(), ".data");
const MEMBERS_PATH = path.join(DATA_DIR, "members.json");
const OFFLINE_QUEUE_PATH = path.join(DATA_DIR, "offline-queue.json");
const V3_FLOCKS_PATH = path.join(DATA_DIR, "v3-flocks.json");
const V3_PREVIEW_FLOCKS_PATH = path.join(DATA_DIR, "v3-preview-flocks.json");
const V3_PREVIEW_QUEUE_PATH = path.join(DATA_DIR, "v3-preview-queue.json");

let cachedSbToken = null;
let cachedSbTokenExpiresAt = 0;

function sanitizeSbEntityName(name) {
  return String(name || "unknown")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

async function acquireServiceBusToken() {
  const now = Date.now();
  if (cachedSbToken && now < cachedSbTokenExpiresAt - 60000) {
    return cachedSbToken;
  }
  const endpoint = process.env.IDENTITY_ENDPOINT || process.env.MSI_ENDPOINT;
  const header = process.env.IDENTITY_HEADER || process.env.MSI_SECRET;
  if (!endpoint || !header) return null;

  return new Promise((resolve) => {
    try {
      const u = new URL(endpoint);
      u.searchParams.set("api-version", process.env.IDENTITY_ENDPOINT ? "2019-08-01" : "2017-09-01");
      u.searchParams.set("resource", "https://servicebus.windows.net/");
      const mod = u.protocol === "https:" ? https : http;
      const headers = process.env.IDENTITY_ENDPOINT
        ? { "X-IDENTITY-HEADER": header, Metadata: "true" }
        : { secret: header, Metadata: "true" };
      const req = mod.request(
        u,
        { method: "GET", headers, timeout: 5000 },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c));
          res.on("end", () => {
            try {
              const j = JSON.parse(data);
              if (j?.access_token) {
                cachedSbToken = j.access_token;
                const expSec = Number(j.expires_on);
                cachedSbTokenExpiresAt = expSec > 1e9 ? expSec * 1000 : Date.now() + 1800000;
                return resolve(cachedSbToken);
              }
            } catch {}
            resolve(null);
          });
        }
      );
      req.on("error", () => resolve(null));
      req.on("timeout", () => {
        req.destroy();
        resolve(null);
      });
      req.end();
    } catch {
      resolve(null);
    }
  });
}

async function ensureServiceBusSubscription(sbToken, machineId) {
  if (!sbToken || !SERVICEBUS_NAMESPACE || !SERVICEBUS_TOPIC || !machineId) return false;
  const subName = `sub-${sanitizeSbEntityName(machineId)}`;
  const bodyXml = `<entry xmlns="http://www.w3.org/2005/Atom"><content type="application/xml"><SubscriptionDescription xmlns="http://schemas.microsoft.com/netservices/2010/10/servicebus/connect" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><LockDuration>PT1M</LockDuration><RequiresSession>false</RequiresSession><DefaultMessageTimeToLive>P1D</DefaultMessageTimeToLive><DeadLetteringOnMessageExpiration>false</DeadLetteringOnMessageExpiration><MaxDeliveryCount>10</MaxDeliveryCount></SubscriptionDescription></content></entry>`;

  const putXml = (apiPath, xml) =>
    new Promise((resolve) => {
      const payload = Buffer.from(xml, "utf8");
      const req = https.request(
        {
          hostname: SERVICEBUS_NAMESPACE,
          port: 443,
          path: apiPath,
          method: "PUT",
          headers: {
            Authorization: `Bearer ${sbToken}`,
            "Content-Type": "application/atom+xml;type=entry;charset=utf-8",
            "Content-Length": payload.length,
          },
          timeout: 6000,
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode || 500));
        }
      );
      req.on("error", () => resolve(500));
      req.on("timeout", () => {
        req.destroy();
        resolve(504);
      });
      req.write(payload);
      req.end();
    });

  const status = await putXml(
    `/${encodeURIComponent(SERVICEBUS_TOPIC)}/subscriptions/${encodeURIComponent(subName)}?api-version=2017-04`,
    bodyXml
  );
  return status >= 200 && status < 300;
}

async function publishToServiceBusRest(item, ttlSeconds = 86400) {
  const sbToken = await acquireServiceBusToken();
  if (!sbToken || !SERVICEBUS_NAMESPACE || !SERVICEBUS_TOPIC) {
    return { published: false, reason: "no_msi_token" };
  }
  await ensureServiceBusSubscription(sbToken, item.toMachine);
  const body = Buffer.from(JSON.stringify(item), "utf8");
  const brokerProps = JSON.stringify({
    MessageId: item.requestId,
    TimeToLive: Math.max(60, Number(ttlSeconds) || 86400),
    Label: String(item.toMachine || "").toLowerCase(),
  });

  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: SERVICEBUS_NAMESPACE,
        port: 443,
        path: `/${encodeURIComponent(SERVICEBUS_TOPIC)}/messages?api-version=2017-04`,
        method: "POST",
        headers: {
          Authorization: `Bearer ${sbToken}`,
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": body.length,
          BrokerProperties: brokerProps,
          toMachine: JSON.stringify(String(item.toMachine || "").toLowerCase()),
        },
        timeout: 6000,
      },
      (res) => {
        res.resume();
        res.on("end", () => {
          resolve({
            published: (res.statusCode || 500) >= 200 && (res.statusCode || 500) < 300,
            statusCode: res.statusCode,
          });
        });
      }
    );
    req.on("error", (err) => resolve({ published: false, error: err.message }));
    req.on("timeout", () => {
      req.destroy();
      resolve({ published: false, error: "timeout" });
    });
    req.write(body);
    req.end();
  });
}

let queueStoreMutex = Promise.resolve();

export function withQueueStoreLock(fn) {
  const next = queueStoreMutex.then(fn, fn);
  queueStoreMutex = next.catch(() => {});
  return next;
}

export function loadOfflineQueueStore(customPath = OFFLINE_QUEUE_PATH) {
  try {
    if (fs.existsSync(customPath)) {
      const parsed = JSON.parse(fs.readFileSync(customPath, "utf8"));
      if (parsed && Array.isArray(parsed.items)) {
        const now = Date.now();
        parsed.items = parsed.items.filter((x) => x && (!x.expiresAtMs || x.expiresAtMs > now));
        return parsed;
      }
    }
  } catch {}
  return { items: [] };
}

export function saveOfflineQueueStore(store, customPath = OFFLINE_QUEUE_PATH) {
  const now = Date.now();
  const valid = (store.items || [])
    .filter((x) => x && (!x.expiresAtMs || x.expiresAtMs > now))
    .slice(-500);
  const tmpPath = `${customPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    fs.mkdirSync(path.dirname(customPath), { recursive: true });
    fs.writeFileSync(tmpPath, JSON.stringify({ items: valid }, null, 2), "utf8");
    fs.renameSync(tmpPath, customPath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {}
    const storageErr = new Error(`Offline queue storage failure: ${err.message}`);
    storageErr.code = "QUEUE_STORAGE_ERROR";
    storageErr.statusCode = 500;
    throw storageErr;
  }
}

export async function enqueueOfflineStoreItem({
  toMachine,
  rpcPayload,
  githubUser = null,
  machineId = null,
  ttlSeconds = 86400,
  queuePath = OFFLINE_QUEUE_PATH,
  publishFn = publishToServiceBusRest,
}) {
  const cleanMachine = String(toMachine || "").trim();
  const safeTtl = Math.max(60, Math.min(7 * 86400, Number(ttlSeconds) || 86400));
  if (!cleanMachine || !rpcPayload || !rpcPayload.requestId) {
    const inputErr = new Error("Missing toMachine or rpcPayload.requestId");
    inputErr.code = "INVALID_QUEUE_INPUT";
    inputErr.statusCode = 400;
    throw inputErr;
  }

  const nowMs = Date.now();
  const entry = {
    requestId: rpcPayload.requestId,
    fromMachine: rpcPayload.fromMachine || machineId || "unknown",
    fromGitHubUser: githubUser,
    toMachine: cleanMachine,
    ttlSeconds: safeTtl,
    enqueuedAt: new Date(nowMs).toISOString(),
    expiresAtMs: nowMs + safeTtl * 1000,
    rpcPayload,
  };

  // Perform async Service Bus publish outside the file lock, then serialize file read-modify-write inside the mutex
  const sbRes = publishFn ? await publishFn(entry, safeTtl) : { published: false };
  entry.serviceBusPublished = Boolean(sbRes?.published);
  entry.serviceBusNamespace = SERVICEBUS_NAMESPACE;
  entry.serviceBusTopic = SERVICEBUS_TOPIC;

  return await withQueueStoreLock(async () => {
    const store = loadOfflineQueueStore(queuePath);
    const existingIdx = store.items.findIndex((x) => x.requestId === rpcPayload.requestId);
    if (existingIdx !== -1) {
      return {
        ok: true,
        deduplicated: true,
        queuedItem: store.items[existingIdx],
      };
    }
    store.items.push(entry);
    saveOfflineQueueStore(store, queuePath);
    return {
      ok: true,
      status: "queued",
      requestId: entry.requestId,
      toMachine: entry.toMachine,
      fromMachine: entry.fromMachine,
      fromGitHubUser: entry.fromGitHubUser,
      enqueuedAt: entry.enqueuedAt,
      expiresAt: new Date(entry.expiresAtMs).toISOString(),
      serviceBusNamespace: SERVICEBUS_NAMESPACE,
      serviceBusTopic: SERVICEBUS_TOPIC,
      serviceBusPublished: entry.serviceBusPublished,
    };
  });
}

export async function drainOfflineStoreItems({
  targetMachine,
  peekOnly = true,
  queuePath = OFFLINE_QUEUE_PATH,
}) {
  const cleanMachine = String(targetMachine || "").trim();
  if (!cleanMachine) {
    const inputErr = new Error("Missing machineId for drain");
    inputErr.code = "INVALID_QUEUE_INPUT";
    inputErr.statusCode = 400;
    throw inputErr;
  }
  const targetLower = cleanMachine.toLowerCase();

  return await withQueueStoreLock(async () => {
    const store = loadOfflineQueueStore(queuePath);
    const matched = [];
    const remaining = [];
    for (const item of store.items) {
      if (String(item.toMachine || "").toLowerCase() === targetLower) {
        matched.push(item);
        if (peekOnly) remaining.push(item);
      } else {
        remaining.push(item);
      }
    }
    if (!peekOnly && matched.length > 0) {
      saveOfflineQueueStore({ items: remaining }, queuePath);
    }
    return {
      ok: true,
      machineId: cleanMachine,
      peekOnly,
      drainedCount: matched.length,
      messages: matched,
    };
  });
}

export async function ackOfflineStoreItems({
  requestIds = [],
  queuePath = OFFLINE_QUEUE_PATH,
}) {
  const ackSet = new Set(
    (Array.isArray(requestIds) ? requestIds : []).map((id) => String(id || "").trim()).filter(Boolean)
  );
  return await withQueueStoreLock(async () => {
    const store = loadOfflineQueueStore(queuePath);
    const before = store.items.length;
    const remaining = store.items.filter((item) => !ackSet.has(item.requestId));
    if (remaining.length !== before) {
      saveOfflineQueueStore({ items: remaining }, queuePath);
    }
    return {
      ok: true,
      ackedCount: before - remaining.length,
      remainingCount: remaining.length,
    };
  });
}

function loadMembersRegistry() {
  try {
    if (fs.existsSync(MEMBERS_PATH)) {
      return JSON.parse(fs.readFileSync(MEMBERS_PATH, "utf8")) || {};
    }
  } catch {}
  return {};
}

function saveMemberRegistration(entry) {
  if (!entry || !entry.machineId) return loadMembersRegistry();
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const registry = loadMembersRegistry();
    const key = String(entry.machineId).trim();
    const prev = registry[key] || {};
    const now = new Date().toISOString();
    registry[key] = {
      machineId: key,
      githubUser: entry.githubUser || prev.githubUser || null,
      githubName: entry.githubName || prev.githubName || null,
      scope: entry.scope || prev.scope || "work",
      version: entry.version || prev.version || null,
      hostname: entry.hostname || prev.hostname || key,
      platform: entry.platform || prev.platform || null,
      publicKey: entry.publicKey || entry.specs?.publicKey || prev.publicKey || null,
      keyFingerprint:
        entry.keyFingerprint || entry.specs?.keyFingerprint || prev.keyFingerprint || null,
      specs: entry.specs || prev.specs || null,
      registeredAt: prev.registeredAt || now,
      lastSeenAt: now,
    };
    fs.writeFileSync(MEMBERS_PATH, JSON.stringify(registry, null, 2), "utf8");
    return registry;
  } catch {
    return loadMembersRegistry();
  }
}

function githubApiGet(apiPath, githubToken, redirectsLeft = 3) {
  return new Promise((resolve) => {
    const isFullUrl = /^https?:\/\//i.test(apiPath);
    const u = isFullUrl ? new URL(apiPath) : null;
    const req = https.request(
      {
        hostname: u ? u.hostname : "api.github.com",
        port: 443,
        path: u ? `${u.pathname}${u.search}` : apiPath,
        method: "GET",
        headers: {
          Authorization: `Bearer ${githubToken}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "copilot-signalr-bridge-bootstrap/3.0",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout: 8000,
      },
      (res) => {
        if (
          redirectsLeft > 0 &&
          [301, 302, 307, 308].includes(res.statusCode) &&
          res.headers.location
        ) {
          res.resume();
          resolve(githubApiGet(res.headers.location, githubToken, redirectsLeft - 1));
          return;
        }
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let parsed = null;
          try {
            parsed = JSON.parse(data);
          } catch {}
          resolve({ statusCode: res.statusCode || 500, body: parsed });
        });
      }
    );
    req.on("error", (err) => resolve({ statusCode: 502, error: err.message }));
    req.on("timeout", () => {
      req.destroy();
      resolve({ statusCode: 504, error: "GitHub API request timed out" });
    });
    req.end();
  });
}

function verifiedGitHubIdentity(userRes) {
  const login = userRes.statusCode === 200 && typeof userRes.body?.login === "string"
    ? userRes.body.login.trim()
    : "";
  if (!login) {
    return { ok: false, statusCode: 403, reason: "Authenticated GitHub identity required" };
  }
  return {
    ok: true,
    githubUser: login,
    githubUserId: userRes.body?.id ? Number(userRes.body.id) : null,
    githubName: userRes.body?.name || null,
  };
}

export async function verifyGitHubRepoAccess(githubToken, apiGet = githubApiGet) {
  const [repoRes, userRes] = await Promise.all([
    apiGet(`/repos/${ALLOWED_REPO}`, githubToken),
    apiGet(`/user`, githubToken),
  ]);

  const identity = verifiedGitHubIdentity(userRes);
  if (!identity.ok) return identity;
  const login = identity.githubUser.toLowerCase();
  const platformMaintainerUser = String(process.env.PLATFORM_MAINTAINER_USER || "erjadi").trim().toLowerCase();
  const allowedUsers = new Set(
    String(process.env.ALLOWED_GITHUB_USERS || "")
      .split(",")
      .map((user) => user.trim().toLowerCase())
      .filter(Boolean)
  );
  const owner = String(repoRes.body?.owner?.login || "").toLowerCase();
  const permissions = repoRes.body?.permissions || {};
  const matchesRepo =
    repoRes.statusCode === 200 &&
    repoRes.body &&
    ALLOWED_REPOS_SET.has(String(repoRes.body.full_name || "").toLowerCase());
  if (
    login === platformMaintainerUser ||
    allowedUsers.has(login) ||
    (matchesRepo && (
      login === owner ||
      permissions.push === true ||
      permissions.admin === true ||
      permissions.maintain === true
    ))
  ) {
    return {
      ...identity,
      repo: matchesRepo ? repoRes.body.full_name : ALLOWED_REPO,
    };
  }

  return {
    ok: false,
    statusCode: repoRes.statusCode === 200 ? 403 : repoRes.statusCode || 403,
    reason: repoRes.statusCode === 200
      ? "Repository collaborator/write access required"
      : repoRes.error || `GitHub API returned HTTP ${repoRes.statusCode} for ${ALLOWED_REPO}`,
  };
}

function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

// ---------------------------------------------------------------------------
// v3.0 Multi-Flock P2P Platform Broker Engine
// ---------------------------------------------------------------------------

export function normalizeV3Scope(rawScope, fallback = "work") {
  const s = String(rawScope || "").trim().toLowerCase();
  if (s === "personal" || s === "private") return "personal";
  if (s === "work") return "work";
  const fb = String(fallback || "work").trim().toLowerCase();
  return fb === "personal" || fb === "private" ? "personal" : "work";
}

export function parseFlockAddress(targetStr, defaultOwner = null) {
  const raw = String(targetStr || "").trim().replace(/^\/+|\/+$/g, "");
  if (!raw || raw.includes("..")) {
    throw new Error(`Invalid flock address: "${targetStr}"`);
  }
  const parts = raw.split("/").map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0 || parts.length > 3) {
    throw new Error(
      `Invalid flock address "${targetStr}". Expected <owner>/<flock>[/<machineId>]`
    );
  }
  for (const seg of parts) {
    if (!/^[A-Za-z0-9._-]+$/.test(seg)) {
      throw new Error(`Invalid segment "${seg}" in flock address "${targetStr}"`);
    }
  }
  if (parts.length === 1) {
    const owner = parts[0].toLowerCase();
    return {
      owner,
      flockName: null,
      flockId: owner,
      machineId: null,
      isOwnerRoot: true,
      isBuiltInScope: true,
      canonicalPath: owner,
    };
  }
  const owner = (parts[0] || defaultOwner || "").toLowerCase();
  const flockName = parts[1].toLowerCase() === "private" ? "personal" : parts[1].toLowerCase();
  const machineId = parts.length === 3 ? parts[2] : null;
  const flockId = `${owner}/${flockName}`;
  const isBuiltInScope = flockName === "personal" || flockName === "work";
  return {
    owner,
    flockName,
    flockId,
    machineId,
    isOwnerRoot: false,
    isBuiltInScope,
    canonicalPath: machineId ? `${flockId}/${machineId}` : flockId,
  };
}

function parseSignalRConnectionString(connStr = process.env.SIGNALR_CONNECTION_STRING || "") {
  const map = {};
  for (const part of String(connStr || "").split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0) {
      map[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
    }
  }
  const endpoint = (map.Endpoint || "").replace(/\/+$/, "");
  const accessKey = map.AccessKey || "";
  return { endpoint, accessKey };
}

function base64UrlEncode(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function mintSignalRHubToken({
  connectionString = process.env.SIGNALR_CONNECTION_STRING || "",
  hub,
  userId,
  expiresAtMs = Date.now() + 3600 * 1000,
  role = "peer",
}) {
  const { endpoint, accessKey } = parseSignalRConnectionString(connectionString);
  if (!endpoint || !accessKey || !hub || !userId) {
    return null;
  }
  const aud = `${endpoint}/client/?hub=${encodeURIComponent(hub)}`;
  const exp = Math.floor(expiresAtMs / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64UrlEncode(
    JSON.stringify({
      aud,
      sub: userId,
      nameid: userId,
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": userId,
      role,
      iat: Math.floor(Date.now() / 1000),
      exp,
    })
  );
  const sig = base64UrlEncode(
    crypto.createHmac("sha256", Buffer.from(accessKey, "utf8")).update(`${header}.${payload}`).digest()
  );
  return {
    endpoint,
    hub,
    userId,
    hubToken: `${header}.${payload}.${sig}`,
    expiresAt: new Date(expiresAtMs).toISOString(),
    expiresAtMs,
  };
}

export async function evictSignalRHubUserImmediate({
  connectionString = process.env.SIGNALR_CONNECTION_STRING || "",
  hub,
  userId,
}) {
  const { endpoint, accessKey } = parseSignalRConnectionString(connectionString);
  if (!endpoint || !accessKey || !hub || !userId) {
    return { evicted: false, reason: "missing_signalr_config" };
  }
  try {
    const u = new URL(
      `${endpoint}/api/v1/hubs/${encodeURIComponent(hub)}/users/${encodeURIComponent(userId)}`
    );
    const aud = `${u.origin}${u.pathname}`;
    const exp = Math.floor(Date.now() / 1000) + 300;
    const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = base64UrlEncode(JSON.stringify({ aud, exp }));
    const sig = base64UrlEncode(
      crypto
        .createHmac("sha256", Buffer.from(accessKey, "utf8"))
        .update(`${header}.${payload}`)
        .digest()
    );
    const jwt = `${header}.${payload}.${sig}`;
    return await new Promise((resolve) => {
      const req = https.request(
        u,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${jwt}` },
          timeout: 4000,
        },
        (res) => {
          res.resume();
          res.on("end", () =>
            resolve({
              evicted: (res.statusCode || 500) >= 200 && (res.statusCode || 500) < 300,
              statusCode: res.statusCode,
            })
          );
        }
      );
      req.on("error", (err) => resolve({ evicted: false, error: err.message }));
      req.on("timeout", () => {
        req.destroy();
        resolve({ evicted: false, error: "timeout" });
      });
      req.end();
    });
  } catch (err) {
    return { evicted: false, error: err.message };
  }
}

let flockStoreMutex = Promise.resolve();

export function withFlockStoreLock(fn) {
  const next = flockStoreMutex.then(fn, fn);
  flockStoreMutex = next.catch(() => {});
  return next;
}

export function loadV3FlockStore(customPath = V3_FLOCKS_PATH) {
  try {
    if (fs.existsSync(customPath)) {
      const parsed = JSON.parse(fs.readFileSync(customPath, "utf8"));
      if (parsed && typeof parsed.flocks === "object") {
        return {
          flocks: parsed.flocks || {},
          nonces: parsed.nonces || {},
        };
      }
    }
  } catch {}
  return { flocks: {}, nonces: {} };
}

export function saveV3FlockStore(store, customPath = V3_FLOCKS_PATH) {
  const now = Date.now();
  const nonces = {};
  for (const [k, v] of Object.entries(store.nonces || {})) {
    if (v && now - (v.issuedAtMs || 0) < 3600 * 1000) {
      nonces[k] = v;
    }
  }
  const tmpPath = `${customPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.mkdirSync(path.dirname(customPath), { recursive: true });
  fs.writeFileSync(
    tmpPath,
    JSON.stringify({ flocks: store.flocks || {}, nonces, updatedAt: new Date(now).toISOString() }, null, 2),
    "utf8"
  );
  fs.renameSync(tmpPath, customPath);
}

function buildFlockHubName(flockUuid, { sandbox = false, isGuestPass = false } = {}) {
  const cleanUuid = String(flockUuid || "").replace(/[^a-zA-Z0-9]/g, "");
  const prefix = sandbox ? "v3_preview" : "v3";
  return isGuestPass ? `${prefix}_guest_${cleanUuid}` : `${prefix}_flock_${cleanUuid}`;
}

function ensureFlockRecord(
  store,
  {
    flockId,
    ownerGitHubUser,
    ownerGitHubUserId = null,
    flockType = "shared",
    allowedScopes = ["personal", "work"],
    targetMachineId = null,
    expiresAtMs = null,
    sandbox = false,
  }
) {
  const key = String(flockId).toLowerCase();
  if (!store.flocks[key]) {
    const flockUuid = crypto.randomUUID();
    store.flocks[key] = {
      flockId: key,
      flockUuid,
      hubName: buildFlockHubName(flockUuid, {
        sandbox,
        isGuestPass: flockType === "guest_pass" || Boolean(targetMachineId),
      }),
      ownerGitHubUser: String(ownerGitHubUser).toLowerCase(),
      ownerGitHubUserId: ownerGitHubUserId ? Number(ownerGitHubUserId) : null,
      flockType,
      allowedScopes,
      targetMachineId: targetMachineId || null,
      rosterEpoch: 1,
      createdAt: new Date().toISOString(),
      expiresAtMs: expiresAtMs || null,
      members: {},
      revokedPrincipals: {},
      vouchers: {},
    };
  }
  return store.flocks[key];
}

function issueRefreshNonceForPeer(store, { deviceId, githubUserId, flockUuid }) {
  const nonce = crypto.randomUUID();
  store.nonces[nonce] = {
    nonce,
    deviceId,
    githubUserId: Number(githubUserId) || null,
    flockUuid,
    issuedAtMs: Date.now(),
    consumedAtMs: null,
  };
  return nonce;
}

export async function enrollV3Device(
  {
    githubUser,
    githubUserId,
    deviceId,
    machineId,
    scope,
    publicKey,
    keyFingerprint,
    specs = null,
    enrollmentJson = null,
    maintainerVisibilityAck = true,
    signature = null,
    timestamp = null,
    replaceExistingMachineKey = true,
  },
  {
    storePath = V3_FLOCKS_PATH,
    sandbox = false,
    connectionString = process.env.SIGNALR_CONNECTION_STRING || "",
  } = {}
) {
  const cleanUser = String(githubUser || "").trim().toLowerCase();
  const numUserId = Number(githubUserId) || 0;
  const cleanDevice = String(deviceId || keyFingerprint || "").trim().toLowerCase();
  const cleanMachine = String(machineId || "").trim();
  const normScope = normalizeV3Scope(scope, "work");

  if (!cleanUser || !cleanDevice || !cleanMachine || !publicKey) {
    const err = new Error("Missing required v3 enrollment fields (githubUser, deviceId, machineId, publicKey)");
    err.statusCode = 400;
    throw err;
  }

  if (signature && timestamp) {
    const tsMs = Date.parse(timestamp);
    if (!Number.isFinite(tsMs) || Math.abs(Date.now() - tsMs) > 300000) {
      const err = new Error("Enrollment signature timestamp out of bounds");
      err.statusCode = 401;
      throw err;
    }
    const enrollmentDigest = crypto
      .createHash("sha256")
      .update(enrollmentJson ? JSON.stringify(enrollmentJson) : "", "utf8")
      .digest("hex");
    const canonical = `enroll|v3|${numUserId}|${cleanDevice}|${cleanMachine}|${normScope}|${
      keyFingerprint || cleanDevice
    }|${enrollmentDigest}|${Boolean(maintainerVisibilityAck)}|${timestamp}`;
    const validSig = crypto.verify(
      null,
      Buffer.from(canonical, "utf8"),
      publicKey,
      Buffer.from(String(signature), "base64")
    );
    if (!validSig) {
      const err = new Error("Invalid Ed25519 enrollment signature");
      err.statusCode = 401;
      throw err;
    }
  }

  return await withFlockStoreLock(async () => {
    const store = loadV3FlockStore(storePath);
    const now = Date.now();
    const peerId = `${numUserId || cleanUser}:${cleanDevice}`;
    const displayAddress = `${cleanUser}/${normScope}/${cleanMachine}`;

    // 1. Ensure built-in owner root flock (`<owner>`) and scope flock (`<owner>/personal` or `<owner>/work`)
    const rootFlock = ensureFlockRecord(store, {
      flockId: cleanUser,
      ownerGitHubUser: cleanUser,
      ownerGitHubUserId: numUserId,
      flockType: "owner_root",
      allowedScopes: ["personal", "work"],
      sandbox,
    });
    const scopeFlock = ensureFlockRecord(store, {
      flockId: `${cleanUser}/${normScope}`,
      ownerGitHubUser: cleanUser,
      ownerGitHubUserId: numUserId,
      flockType: "owner_scope",
      allowedScopes: [normScope],
      sandbox,
    });

    for (const [flock, flockType] of [[rootFlock, "owner_root"], [scopeFlock, "owner_scope"]]) {
      if (
        flock.ownerGitHubUser !== cleanUser ||
        (flock.ownerGitHubUserId && Number(flock.ownerGitHubUserId) !== numUserId)
      ) {
        const err = new Error(`Built-in flock "${flock.flockId}" belongs to a different GitHub principal`);
        err.statusCode = 403;
        throw err;
      }
      flock.flockType = flockType;
      flock.ownerGitHubUserId = numUserId || null;
    }
    const targetFlocksToJoin = new Map([
      [rootFlock.flockId, { flock: rootFlock, trustTier: "owner", membershipExpiresAtMs: null }],
      [scopeFlock.flockId, { flock: scopeFlock, trustTier: "owner", membershipExpiresAtMs: null }],
    ]);

    // 2. Redeem any Enrollment JSON vouchers atomically
    if (enrollmentJson && Array.isArray(enrollmentJson.flocks)) {
      if (!maintainerVisibilityAck) {
        const err = new Error("Joining a shared flock requires maintainerVisibilityAck: true");
        err.statusCode = 400;
        throw err;
      }
      for (const fInvite of enrollmentJson.flocks) {
        const parsedAddr = parseFlockAddress(fInvite.flockId);
        const targetFlock = store.flocks[parsedAddr.flockId];
        if (!targetFlock) {
          const err = new Error(`Target flock "${parsedAddr.flockId}" does not exist`);
          err.statusCode = 404;
          throw err;
        }
        const voucher = targetFlock.vouchers?.[fInvite.voucherId];
        if (!voucher) {
          const err = new Error(`Invalid or unknown voucherId for flock "${parsedAddr.flockId}"`);
          err.statusCode = 403;
          throw err;
        }
        if (voucher.voucherExpiresAtMs && voucher.voucherExpiresAtMs <= now) {
          const err = new Error(`Invite voucher for "${parsedAddr.flockId}" has expired`);
          err.statusCode = 403;
          throw err;
        }
        if (voucher.membershipExpiresAtMs && voucher.membershipExpiresAtMs <= now) {
          const err = new Error(`Invite membership for "${parsedAddr.flockId}" has expired`);
          err.statusCode = 403;
          throw err;
        }
        if (
          targetFlock.revokedPrincipals?.[String(numUserId)] ||
          targetFlock.revokedPrincipals?.[cleanUser] ||
          targetFlock.revokedPrincipals?.[peerId]
        ) {
          const err = new Error(`Principal is revoked from flock "${parsedAddr.flockId}"`);
          err.statusCode = 403;
          throw err;
        }
        const invitedMatch =
          (voucher.invitedGitHubUserId &&
            Number(voucher.invitedGitHubUserId) === Number(numUserId)) ||
          (!voucher.invitedGitHubUserId &&
            String(voucher.invitedUser || "").toLowerCase() === cleanUser);
        if (!invitedMatch) {
          const err = new Error(
            `Voucher for "${parsedAddr.flockId}" is bound to a different GitHub principal`
          );
          err.statusCode = 403;
          throw err;
        }
        if (
          Array.isArray(targetFlock.allowedScopes) &&
          targetFlock.allowedScopes.length > 0 &&
          !targetFlock.allowedScopes.includes(normScope)
        ) {
          const err = new Error(
            `Machine scope "${normScope}" is not permitted in flock "${parsedAddr.flockId}" (allowed: ${targetFlock.allowedScopes.join(", ")})`
          );
          err.statusCode = 403;
          throw err;
        }
        voucher.redeemedDeviceIds = Array.isArray(voucher.redeemedDeviceIds)
          ? voucher.redeemedDeviceIds
          : [];
        const maxDevices = Math.max(1, Number(voucher.maxDevices) || 3);
        if (!voucher.redeemedDeviceIds.includes(cleanDevice)) {
          if (voucher.redeemedDeviceIds.length >= maxDevices) {
            const err = new Error(
              `Invite voucher for "${parsedAddr.flockId}" has reached maxDevices (${maxDevices})`
            );
            err.statusCode = 403;
            throw err;
          }
          voucher.redeemedDeviceIds.push(cleanDevice);
        }
        const durationMs =
          Number(voucher.durationMinutes) > 0 ? Number(voucher.durationMinutes) * 60000 : null;
        const membershipExpiresAtMs = durationMs
          ? voucher.membershipExpiresAtMs || now + durationMs
          : voucher.membershipExpiresAtMs || null;
        voucher.membershipExpiresAtMs = membershipExpiresAtMs;

        const trustTier = voucher.trustTier ||
          (targetFlock.flockType === "guest_pass" || targetFlock.targetMachineId ? "guest" : "collaborator");
        if (trustTier !== "collaborator" && trustTier !== "guest") {
          const err = new Error("Invite vouchers cannot grant owner trust");
          err.statusCode = 403;
          throw err;
        }
        const previous = targetFlocksToJoin.get(targetFlock.flockId);
        // Only the authenticated principal's built-ins above confer owner authority.
        if (previous?.trustTier !== "owner") {
          const expirations = [previous?.membershipExpiresAtMs, membershipExpiresAtMs]
            .filter((expiry) => expiry != null);
          targetFlocksToJoin.set(targetFlock.flockId, {
            flock: targetFlock,
            trustTier: previous?.trustTier === "guest" || trustTier === "guest" ? "guest" : "collaborator",
            membershipExpiresAtMs: expirations.length ? Math.min(...expirations) : null,
          });
        }
      }
    }

    const enrolledFlocks = [];
    for (const item of targetFlocksToJoin.values()) {
      const f = item.flock;
      if (replaceExistingMachineKey) {
        for (const [mKey, mVal] of Object.entries(f.members || {})) {
          if (
            mKey !== peerId &&
            String(mVal.githubUser || "").toLowerCase() === cleanUser &&
            String(mVal.machineId || "").toLowerCase() === cleanMachine.toLowerCase()
          ) {
            delete f.members[mKey];
          }
        }
      }
      const prevMember = f.members[peerId];
      f.members[peerId] = {
        peerId,
        githubUser: cleanUser,
        githubUserId: numUserId,
        deviceId: cleanDevice,
        machineId: cleanMachine,
        displayAddress,
        scope: normScope,
        publicKey,
        keyFingerprint: keyFingerprint || cleanDevice,
        specs: specs || prevMember?.specs || null,
        trustTier: item.trustTier,
        joinedAt: prevMember?.joinedAt || new Date(now).toISOString(),
        lastSeenAt: new Date(now).toISOString(),
        membershipExpiresAtMs: item.membershipExpiresAtMs || null,
        membershipExpiresAt: item.membershipExpiresAtMs
          ? new Date(item.membershipExpiresAtMs).toISOString()
          : null,
      };
      if (!prevMember || prevMember.publicKey !== publicKey) {
        f.rosterEpoch = (Number(f.rosterEpoch) || 1) + 1;
      }

      const tokenExpMs = item.membershipExpiresAtMs
        ? Math.min(now + 3600 * 1000, item.membershipExpiresAtMs)
        : now + 3600 * 1000;
      const hubCred = mintSignalRHubToken({
        connectionString,
        hub: f.hubName,
        userId: peerId,
        expiresAtMs: tokenExpMs,
        role: item.trustTier,
      });
      const serverNonce = issueRefreshNonceForPeer(store, {
        deviceId: cleanDevice,
        githubUserId: numUserId,
        flockUuid: f.flockUuid,
      });

      enrolledFlocks.push({
        flockId: f.flockId,
        flockUuid: f.flockUuid,
        hubName: f.hubName,
        flockType: f.flockType,
        ownerGitHubUser: f.ownerGitHubUser,
        ownerGitHubUserId: f.ownerGitHubUserId,
        trustTier: item.trustTier,
        allowedScopes: f.allowedScopes,
        targetMachineId: f.targetMachineId || null,
        rosterEpoch: f.rosterEpoch,
        membershipExpiresAt: item.membershipExpiresAtMs
          ? new Date(item.membershipExpiresAtMs).toISOString()
          : null,
        membershipExpiresAtMs: item.membershipExpiresAtMs || null,
        hubToken: hubCred?.hubToken || null,
        endpoint: hubCred?.endpoint || null,
        tokenExpiresAt: hubCred?.expiresAt || null,
        serverNonce,
        members: Object.values(f.members),
      });
    }

    saveV3FlockStore(store, storePath);
    return {
      ok: true,
      v: 3,
      peerId,
      githubUser: cleanUser,
      githubUserId: numUserId,
      deviceId: cleanDevice,
      machineId: cleanMachine,
      scope: normScope,
      enrolledFlocks,
    };
  });
}

export async function refreshV3FlockToken(
  {
    flockId,
    flockUuid,
    githubUserId,
    deviceId,
    rosterEpoch,
    serverNonce,
    timestamp,
    signature,
  },
  {
    storePath = V3_FLOCKS_PATH,
    connectionString = process.env.SIGNALR_CONNECTION_STRING || "",
  } = {}
) {
  return await withFlockStoreLock(async () => {
    const store = loadV3FlockStore(storePath);
    const now = Date.now();
    const f =
      (flockId && store.flocks[String(flockId).toLowerCase()]) ||
      Object.values(store.flocks).find((x) => x.flockUuid === flockUuid);
    if (!f) {
      const err = new Error(`Flock not found for refresh: ${flockId || flockUuid}`);
      err.statusCode = 404;
      throw err;
    }
    const cleanDevice = String(deviceId || "").trim().toLowerCase();
    const member = Object.values(f.members || {}).find(
      (m) => m.deviceId === cleanDevice && (!githubUserId || m.githubUserId === Number(githubUserId))
    );
    if (!member) {
      const err = new Error(`Device "${cleanDevice}" is not an active member of flock "${f.flockId}"`);
      err.statusCode = 403;
      throw err;
    }
    if (
      f.revokedPrincipals?.[String(member.githubUserId)] ||
      f.revokedPrincipals?.[member.githubUser] ||
      f.revokedPrincipals?.[member.peerId]
    ) {
      const err = new Error(`Member "${member.peerId}" has been revoked from "${f.flockId}"`);
      err.statusCode = 403;
      throw err;
    }
    if (
      (member.membershipExpiresAtMs && member.membershipExpiresAtMs <= now) ||
      (f.expiresAtMs && f.expiresAtMs <= now)
    ) {
      delete f.members[member.peerId];
      f.rosterEpoch = (Number(f.rosterEpoch) || 1) + 1;
      saveV3FlockStore(store, storePath);
      await evictSignalRHubUserImmediate({
        connectionString,
        hub: f.hubName,
        userId: member.peerId,
      });
      const err = new Error(`Time-bound membership in flock "${f.flockId}" has expired`);
      err.code = "MEMBERSHIP_EXPIRED";
      err.statusCode = 403;
      throw err;
    }

    const nonceEntry = store.nonces?.[serverNonce];
    const withinGraceWindow =
      nonceEntry &&
      nonceEntry.deviceId === cleanDevice &&
      nonceEntry.flockUuid === f.flockUuid &&
      (!nonceEntry.consumedAtMs || now - nonceEntry.consumedAtMs <= 30000);
    if (!withinGraceWindow) {
      const err = new Error("Invalid, expired, or already-consumed refresh serverNonce");
      err.code = "INVALID_REFRESH_NONCE";
      err.statusCode = 401;
      throw err;
    }

    const tsMs = Date.parse(timestamp);
    if (!Number.isFinite(tsMs) || Math.abs(now - tsMs) > 300000) {
      const err = new Error("Refresh timestamp out of bounds");
      err.statusCode = 401;
      throw err;
    }

    const canonical = `refresh|v3|${f.flockUuid}|${member.githubUserId}|${cleanDevice}|${rosterEpoch}|${serverNonce}|${timestamp}`;
    const validSig = crypto.verify(
      null,
      Buffer.from(canonical, "utf8"),
      member.publicKey,
      Buffer.from(String(signature || ""), "base64")
    );
    if (!validSig) {
      const err = new Error("Invalid Ed25519 refresh signature");
      err.statusCode = 401;
      throw err;
    }

    if (!nonceEntry.consumedAtMs) {
      nonceEntry.consumedAtMs = now;
    }
    const nextNonce = nonceEntry.nextNonce || issueRefreshNonceForPeer(store, {
      deviceId: cleanDevice,
      githubUserId: member.githubUserId,
      flockUuid: f.flockUuid,
    });
    nonceEntry.nextNonce = nextNonce;

    const tokenExpMs = member.membershipExpiresAtMs
      ? Math.min(now + 3600 * 1000, member.membershipExpiresAtMs)
      : now + 3600 * 1000;
    const hubCred = mintSignalRHubToken({
      connectionString,
      hub: f.hubName,
      userId: member.peerId,
      expiresAtMs: tokenExpMs,
      role: member.trustTier,
    });
    member.lastSeenAt = new Date(now).toISOString();
    saveV3FlockStore(store, storePath);

    return {
      ok: true,
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      hubName: f.hubName,
      rosterEpoch: f.rosterEpoch,
      hubToken: hubCred?.hubToken || null,
      endpoint: hubCred?.endpoint || null,
      tokenExpiresAt: hubCred?.expiresAt || null,
      membershipExpiresAt: member.membershipExpiresAt || null,
      serverNonce: nextNonce,
      members: Object.values(f.members),
    };
  });
}

export async function createV3FlockInvite(
  {
    callerGitHubUser,
    callerGitHubUserId,
    targetAddress,
    invitedUser,
    invitedGitHubUserId = null,
    durationMinutes = null,
    voucherTtlSeconds = 86400,
    maxDevices = 3,
    allowedScopes = ["work"],
    trustTier = null,
    voucherSignature = null,
    bootstrapUrl = process.env.PUBLIC_BOOTSTRAP_URL ||
      (process.env.WEBSITE_HOSTNAME
        ? `https://${process.env.WEBSITE_HOSTNAME}`
        : "https://bootstrap.example.invalid"),
  },
  { storePath = V3_FLOCKS_PATH, sandbox = false } = {}
) {
  const parsed = parseFlockAddress(targetAddress, callerGitHubUser);
  const cleanCaller = String(callerGitHubUser || "").trim().toLowerCase();
  const cleanInvited = String(invitedUser || "").replace(/^@/, "").trim().toLowerCase();
  if (!cleanCaller || !cleanInvited) {
    const err = new Error("Missing callerGitHubUser or invitedUser for invite");
    err.statusCode = 400;
    throw err;
  }
  if (trustTier && trustTier !== "collaborator" && trustTier !== "guest") {
    const err = new Error("Invite vouchers can grant only collaborator or guest trust");
    err.statusCode = 400;
    throw err;
  }

  return await withFlockStoreLock(async () => {
    const store = loadV3FlockStore(storePath);
    const now = Date.now();
    let flockIdToUse = parsed.flockId;
    let flockType = parsed.isOwnerRoot ? "owner_root" : parsed.isBuiltInScope ? "owner_scope" : "shared";

    // If inviting a guest to a single PC (`erjadi/work/CLOUD-DEV-VM`) or built-in personal/work flock for a bounded duration,
    // create an isolated guest-pass flock so the guest never sees sibling PCs' broadcast metadata
    if (parsed.machineId) {
      const shortId = crypto.randomBytes(3).toString("hex");
      flockIdToUse = `${parsed.owner}/guest-${cleanInvited}-${shortId}`;
      flockType = "guest_pass";
    }

    const existing = store.flocks[flockIdToUse];
    if (existing) {
      const isOwner =
        existing.ownerGitHubUser === cleanCaller ||
        (existing.ownerGitHubUserId &&
          callerGitHubUserId &&
          Number(existing.ownerGitHubUserId) === Number(callerGitHubUserId));
      const isActivePeer = Object.values(existing.members || {}).some(
        (m) => m.githubUser === cleanCaller && m.trustTier !== "guest"
      );
      if (!isOwner && !isActivePeer && cleanCaller !== PLATFORM_MAINTAINER_USER) {
        const err = new Error(
          `User "@${cleanCaller}" is not authorized to invite peers to flock "${flockIdToUse}"`
        );
        err.statusCode = 403;
        throw err;
      }
    } else if (parsed.owner !== cleanCaller && cleanCaller !== PLATFORM_MAINTAINER_USER) {
      const err = new Error(
        `Only "@${parsed.owner}" can create flock "${flockIdToUse}"`
      );
      err.statusCode = 403;
      throw err;
    }

    const durMins = Number(durationMinutes) > 0 ? Number(durationMinutes) : null;
    const voucherExpiresAtMs = now + Math.max(60, Number(voucherTtlSeconds) || 86400) * 1000;
    const f = ensureFlockRecord(store, {
      flockId: flockIdToUse,
      ownerGitHubUser: parsed.owner,
      ownerGitHubUserId: callerGitHubUserId,
      flockType,
      allowedScopes: Array.isArray(allowedScopes) && allowedScopes.length > 0 ? allowedScopes : ["work"],
      targetMachineId: parsed.machineId || null,
      expiresAtMs: durMins ? voucherExpiresAtMs : null,
      sandbox,
    });

    // If this is a single-PC guest pass, also copy the host machine (`parsed.machineId`) from the owner's root/scope flock into the guest hub
    if (parsed.machineId) {
      const ownerRoot = store.flocks[parsed.owner] || store.flocks[parsed.flockId];
      if (ownerRoot?.members) {
        for (const [mKey, mVal] of Object.entries(ownerRoot.members)) {
          if (
            String(mVal.machineId || "").toLowerCase() === parsed.machineId.toLowerCase() &&
            String(mVal.githubUser || "").toLowerCase() === parsed.owner
          ) {
            f.members[mKey] = { ...mVal, trustTier: "owner" };
          }
        }
      }
    }

    const voucherId = crypto.randomUUID();
    const effectiveTrust =
      trustTier || (parsed.machineId || durMins ? "guest" : "collaborator");
    f.vouchers[voucherId] = {
      voucherId,
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      targetAddress: parsed.canonicalPath,
      targetMachineId: parsed.machineId || null,
      invitedUser: cleanInvited,
      invitedGitHubUserId: invitedGitHubUserId ? Number(invitedGitHubUserId) : null,
      invitedBy: cleanCaller,
      trustTier: effectiveTrust,
      durationMinutes: durMins,
      maxDevices: Math.max(1, Number(maxDevices) || 3),
      redeemedDeviceIds: [],
      createdAt: new Date(now).toISOString(),
      voucherExpiresAt: new Date(voucherExpiresAtMs).toISOString(),
      voucherExpiresAtMs,
      voucherSignature: voucherSignature || null,
    };

    saveV3FlockStore(store, storePath);

    const enrollmentJson = {
      v: 3,
      invitedUser: cleanInvited,
      invitedGitHubUserId: invitedGitHubUserId ? Number(invitedGitHubUserId) : null,
      invitedBy: cleanCaller,
      bootstrapUrl,
      voucherExpiresAt: new Date(voucherExpiresAtMs).toISOString(),
      maxDevices: Math.max(1, Number(maxDevices) || 3),
      flocks: [
        {
          voucherId,
          flockId: f.flockId,
          flockUuid: f.flockUuid,
          targetAddress: parsed.canonicalPath,
          targetMachineId: parsed.machineId || null,
          recommendedScope: f.allowedScopes?.[0] || "work",
          trustTier: effectiveTrust,
          durationMinutes: durMins,
          voucherSignature: voucherSignature || null,
        },
      ],
    };

    const pasteablePrompt =
      `Accept my pending GitHub repo invite to \`erjadi/copilot-flock\` (if any), clone \`https://github.com/erjadi/copilot-flock\`, install and set up Copilot Flock on this machine, and enroll me using this enrollment JSON:\n` +
      `\`\`\`json\n${JSON.stringify(enrollmentJson, null, 2)}\n\`\`\``;

    return {
      ok: true,
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      targetAddress: parsed.canonicalPath,
      voucherId,
      enrollmentJson,
      pasteablePrompt,
    };
  });
}

export async function kickV3FlockMember(
  {
    callerGitHubUser,
    callerGitHubUserId,
    flockId,
    targetUser = null,
    targetGitHubUserId = null,
    targetDeviceId = null,
    targetMachineId = null,
  },
  {
    storePath = V3_FLOCKS_PATH,
    connectionString = process.env.SIGNALR_CONNECTION_STRING || "",
  } = {}
) {
  const parsed = parseFlockAddress(flockId, callerGitHubUser);
  const cleanCaller = String(callerGitHubUser || "").trim().toLowerCase();
  const cleanTargetUser = targetUser ? String(targetUser).replace(/^@/, "").trim().toLowerCase() : null;
  const cleanTargetMachine = targetMachineId || parsed.machineId || null;

  return await withFlockStoreLock(async () => {
    const store = loadV3FlockStore(storePath);
    const f = store.flocks[parsed.flockId];
    if (!f) {
      const err = new Error(`Flock "${parsed.flockId}" not found`);
      err.statusCode = 404;
      throw err;
    }
    const isOwnerOrMaintainer =
      f.ownerGitHubUser === cleanCaller ||
      cleanCaller === PLATFORM_MAINTAINER_USER ||
      (f.ownerGitHubUserId &&
        callerGitHubUserId &&
        Number(f.ownerGitHubUserId) === Number(callerGitHubUserId));
    const isSelfLeave = Boolean(cleanTargetUser && cleanTargetUser === cleanCaller);
    if (!isOwnerOrMaintainer && !isSelfLeave) {
      const err = new Error(`User "@${cleanCaller}" is not authorized to kick members from "${f.flockId}"`);
      err.statusCode = 403;
      throw err;
    }

    const kickedPeers = [];
    for (const [peerKey, m] of Object.entries(f.members || {})) {
      if (matchesMember(m, { targetUser: cleanTargetUser, targetGitHubUserId,
        targetDeviceId, targetMachineId: cleanTargetMachine })) {
        kickedPeers.push(m);
        delete f.members[peerKey];
        if (!isSelfLeave) {
          if (cleanTargetUser && !cleanTargetMachine && !targetDeviceId) {
            f.revokedPrincipals[m.githubUser] = new Date().toISOString();
            if (m.githubUserId) f.revokedPrincipals[String(m.githubUserId)] = new Date().toISOString();
          }
          f.revokedPrincipals[peerKey] = new Date().toISOString();
        }
      }
    }

    // Invalidate any unredeemed vouchers for the kicked user
    if (!targetDeviceId && !cleanTargetMachine && (cleanTargetUser || targetGitHubUserId)) {
      for (const [vId, v] of Object.entries(f.vouchers || {})) {
        if (
          (cleanTargetUser && v.invitedUser === cleanTargetUser) ||
          (targetGitHubUserId && Number(v.invitedGitHubUserId) === Number(targetGitHubUserId))
        ) {
          delete f.vouchers[vId];
        }
      }
    }

    f.rosterEpoch = (Number(f.rosterEpoch) || 1) + 1;
    saveV3FlockStore(store, storePath);

    const evictionResults = [];
    for (const kp of kickedPeers) {
      const ev = await evictSignalRHubUserImmediate({
        connectionString,
        hub: f.hubName,
        userId: kp.peerId,
      });
      evictionResults.push({ peerId: kp.peerId, machineId: kp.machineId, ...ev });
    }

    return {
      ok: true,
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      rosterEpoch: f.rosterEpoch,
      kickedCount: kickedPeers.length,
      kickedPeers: kickedPeers.map((p) => ({
        peerId: p.peerId,
        githubUser: p.githubUser,
        machineId: p.machineId,
      })),
      evictionResults,
    };
  });
}

async function deleteLegacyPeerSubscription(member) {
  const token = await acquireServiceBusToken();
  if (!token || !SERVICEBUS_NAMESPACE) {
    return { confirmed: false, reason: "Service Bus management authorization unavailable" };
  }
  const sub = `sub-${sanitizeSbEntityName(member.machineId)}`;
  const response = await fetch(`https://${SERVICEBUS_NAMESPACE}/${encodeURIComponent(SERVICEBUS_TOPIC)}/subscriptions/${encodeURIComponent(sub)}?api-version=2017-04`, {
    method: "DELETE", redirect: "error", signal: AbortSignal.timeout(6000),
    headers: { Authorization: `Bearer ${token}` },
  });
  return { confirmed: response.ok || response.status === 404, status: response.status };
}

export function planV3DeviceLeave(request, { storePath = V3_FLOCKS_PATH } = {}) {
  if (request.flockId !== "*") throw new Error("Leave inventory requires an explicit all-flocks signature");
  const store = loadV3FlockStore(storePath);
  const matching = Object.values(store.flocks).flatMap((flock) =>
    [...Object.values(flock.members || {}), ...Object.values(flock.leaveReceipts || {}).map((receipt) => receipt.member)]
      .filter((member) => matchesMember(member, { targetDeviceId: request.deviceId, targetMachineId: request.machineId })));
  if (!matching.length) throw new Error("Cannot authenticate device inventory; no retained device proof");
  for (const member of matching) verifyLeave(request, member.publicKey);
  return { ok: true, flockIds: Object.entries(store.flocks).filter(([, flock]) =>
    Object.values(flock.members || {}).some((member) =>
      matchesMember(member, { targetDeviceId: request.deviceId, targetMachineId: request.machineId })) ||
    Object.values(flock.leaveReceipts || {}).some((receipt) => !receipt.confirmed &&
      matchesMember(receipt.member, { targetDeviceId: request.deviceId, targetMachineId: request.machineId })))
    .map(([id]) => id) };
}

export async function leaveV3Device(request, {
  storePath = V3_FLOCKS_PATH,
  membersPath = null,
  deleteSubscription = deleteLegacyPeerSubscription,
  evict = (member, flock) => evictSignalRHubUserImmediate({
    connectionString: process.env.SIGNALR_CONNECTION_STRING || "",
    hub: flock.hubName, userId: member.peerId,
  }),
} = {}) {
  return withFlockStoreLock(async () => {
    const store = loadV3FlockStore(storePath);
    const flock = store.flocks[request.flockId];
    if (!flock) throw new Error("Cannot acknowledge leave from an unknown flock");
    const old = flock.leaveReceipts?.[request.requestId];
    const entries = Object.entries(flock.members || {}).filter(([, member]) =>
      matchesMember(member, { targetDeviceId: request.deviceId, targetMachineId: request.machineId }));
    if (entries.length > 1) throw new Error("Ambiguous device leave; refusing to remove multiple peers");
    const member = old?.member || entries[0]?.[1];
    if (!member) throw new Error("Device not enrolled and no authenticated leave receipt exists");
    if (!matchesMember(member, { targetDeviceId: request.deviceId, targetMachineId: request.machineId })) {
      throw new Error("Leave receipt selectors do not match the signed device");
    }
    verifyLeave(request, member.publicKey);
    if (old?.confirmed) return { ok: true, confirmed: true, flockId: request.flockId, peerId: member.peerId };
    if (old && entries.length) throw new Error("Device re-enrolled after leave; stale leave cannot remove it");
    flock.leaveReceipts ||= {};
    if (!old) {
      delete flock.members[entries[0][0]];
      flock.rosterEpoch = (Number(flock.rosterEpoch) || 1) + 1;
      flock.leaveReceipts[request.requestId] = { member, confirmed: false };
      saveV3FlockStore(store, storePath);
    }
    const sameMachineOtherDevice = Object.values(store.flocks).some((other) =>
      Object.values(other.members || {}).some((peer) =>
        String(peer.machineId).toLowerCase() === String(member.machineId).toLowerCase() &&
        peer.deviceId !== member.deviceId));
    if (sameMachineOtherDevice) {
      return { ok: false, confirmed: false, flockId: request.flockId,
        pending: "Legacy machine-named subscription is shared by another device; refusing deletion" };
    }
    let subscription;
    let eviction;
    try {
      subscription = await deleteSubscription(member);
      eviction = await evict(member, flock);
    } catch (error) {
      return { ok: false, confirmed: false, flockId: request.flockId, pending: error.message };
    }
    const confirmed = subscription?.confirmed === true && eviction?.evicted === true;
    if (confirmed && membersPath && fs.existsSync(membersPath) &&
        !Object.values(store.flocks).some((other) => Object.values(other.members || {}).some((peer) =>
          peer.deviceId === member.deviceId))) {
      const registry = JSON.parse(fs.readFileSync(membersPath, "utf8"));
      for (const [id, registered] of Object.entries(registry)) {
        if (String(registered.machineId).toLowerCase() === String(member.machineId).toLowerCase() &&
            registered.publicKey?.trim() === member.publicKey?.trim()) delete registry[id];
      }
      const temporary = `${membersPath}.${crypto.randomUUID()}.tmp`;
      fs.writeFileSync(temporary, JSON.stringify(registry, null, 2), { mode: 0o600, flag: "wx" });
      fs.renameSync(temporary, membersPath);
    }
    flock.leaveReceipts[request.requestId].confirmed = confirmed;
    saveV3FlockStore(store, storePath);
    return { ok: confirmed, confirmed, flockId: request.flockId, peerId: member.peerId,
      rosterEpoch: flock.rosterEpoch, subscription, eviction };
  });
}

export async function listV3UserFlocks(
  { githubUser, githubUserId = null, deviceId = null },
  { storePath = V3_FLOCKS_PATH } = {}
) {
  const cleanUser = String(githubUser || "").trim().toLowerCase();
  const cleanDevice = deviceId ? String(deviceId).trim().toLowerCase() : null;
  const store = loadV3FlockStore(storePath);
  const now = Date.now();
  const ownedFlocks = [];
  const joinedFlocks = [];

  for (const f of Object.values(store.flocks || {})) {
    if (f.expiresAtMs && f.expiresAtMs <= now) continue;
    const activeMembers = Object.values(f.members || {}).filter(
      (m) => !m.membershipExpiresAtMs || m.membershipExpiresAtMs > now
    );
    const summary = {
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      hubName: f.hubName,
      flockType: f.flockType,
      ownerGitHubUser: f.ownerGitHubUser,
      allowedScopes: f.allowedScopes,
      targetMachineId: f.targetMachineId || null,
      rosterEpoch: f.rosterEpoch,
      memberCount: activeMembers.length,
      members: activeMembers.map((m) => ({
        peerId: m.peerId,
        githubUser: m.githubUser,
        machineId: m.machineId,
        scope: m.scope,
        trustTier: m.trustTier,
        publicKey: m.publicKey,
        keyFingerprint: m.keyFingerprint,
        membershipExpiresAt: m.membershipExpiresAt || null,
      })),
    };
    if (
      f.ownerGitHubUser === cleanUser ||
      (githubUserId && f.ownerGitHubUserId && Number(f.ownerGitHubUserId) === Number(githubUserId))
    ) {
      ownedFlocks.push(summary);
    }
    if (
      activeMembers.some(
        (m) =>
          m.githubUser === cleanUser && (!cleanDevice || m.deviceId === cleanDevice)
      )
    ) {
      joinedFlocks.push(summary);
    }
  }

  return {
    ok: true,
    githubUser: cleanUser,
    ownedFlocks,
    joinedFlocks,
  };
}

function readRequestBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => {
      if (body.length < 65536) body += chunk;
    });
    req.on("end", () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

export function createBootstrapServer({
  apiGet = githubApiGet,
  v3StorePath = V3_FLOCKS_PATH,
  v3PreviewStorePath = V3_PREVIEW_FLOCKS_PATH,
} = {}) {
  return http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/" || url.pathname === "/healthz" || url.pathname === "/health") {
    const registry = loadMembersRegistry();
    const qStore = loadOfflineQueueStore();
    const v3Store = loadV3FlockStore();
    sendJson(res, 200, {
      ok: true,
      service: "copilot-flock-bootstrap",
      version: "3.3.1",
      allowedRepo: ALLOWED_REPO,
      hub: DEFAULT_HUB,
      serviceBusNamespace: SERVICEBUS_NAMESPACE,
      serviceBusTopic: SERVICEBUS_TOPIC,
      msiConfigured: Boolean(process.env.IDENTITY_ENDPOINT || process.env.MSI_ENDPOINT),
      configured: Boolean(process.env.SIGNALR_CONNECTION_STRING),
      registeredMemberCount: Object.keys(registry).length,
      queuedOfflineMessageCount: qStore.items.length,
      v3FlockCount: Object.keys(v3Store.flocks || {}).length,
    });
    return;
  }

  if (url.pathname.startsWith("/api/v3/")) {
    const isPreview =
      url.pathname.startsWith("/api/v3/preview/") ||
      url.searchParams.get("sandbox") === "v3";
    const subPath = url.pathname.replace(/^\/api\/v3(?:\/preview)?/, "");
    const storePath = isPreview ? v3PreviewStorePath : v3StorePath;
    const bodyData = req.method === "POST" ? await readRequestBody(req) : {};

    // Token refresh does not require a GitHub token (uses challenge-bound Ed25519 signature)
    if (subPath === "/token/refresh" && req.method === "POST") {
      try {
        const out = await refreshV3FlockToken(bodyData, { storePath });
        sendJson(res, 200, out);
      } catch (err) {
        sendJson(res, err.statusCode || 500, {
          ok: false,
          code: err.code || "REFRESH_ERROR",
          error: err.message,
        });
      }
      return;
    }

    if ((subPath === "/flocks/leave" || subPath === "/flocks/leave-plan") && req.method === "POST") {
      try {
        const out = subPath === "/flocks/leave-plan" ? planV3DeviceLeave(bodyData, { storePath })
          : await leaveV3Device(bodyData, { storePath, membersPath: MEMBERS_PATH });
        sendJson(res, out.ok ? 200 : 409, out);
      } catch (error) {
        sendJson(res, 403, { ok: false, confirmed: false, error: error.message });
      }
      return;
    }

    if (subPath === "/teardown" && req.method === "POST" && isPreview) {
      try {
        if (fs.existsSync(V3_PREVIEW_FLOCKS_PATH)) fs.unlinkSync(V3_PREVIEW_FLOCKS_PATH);
        if (fs.existsSync(V3_PREVIEW_QUEUE_PATH)) fs.unlinkSync(V3_PREVIEW_QUEUE_PATH);
        sendJson(res, 200, { ok: true, tornDown: true, sandbox: "v3" });
      } catch (err) {
        sendJson(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    const authHeader = String(req.headers.authorization || "");
    const bearerMatch = authHeader.match(/^(?:Bearer|token)\s+(.+)$/i);
    const githubToken = (bearerMatch ? bearerMatch[1] : String(req.headers["x-github-token"] || "")).trim();

    if (!githubToken) {
      sendJson(res, 401, {
        ok: false,
        error: `Missing GitHub token for ${url.pathname}`,
      });
      return;
    }

    const privilegedVerification = await verifyGitHubRepoAccess(githubToken, apiGet);
    const isEnrollment = subPath === "/enroll" && req.method === "POST";
    const isMyFlocks = subPath === "/my-flocks" && req.method === "GET";
    const verification = !privilegedVerification.ok && (isEnrollment || isMyFlocks)
      ? verifiedGitHubIdentity(await apiGet("/user", githubToken))
      : privilegedVerification;
    if (!verification.ok) {
      sendJson(res, 403, {
        ok: false,
        error: `Access denied: deployment maintainer, repository collaborator/write access or explicit allowlisting required for ${ALLOWED_REPO} (${verification.reason}).`,
      });
      return;
    }

    const callerGitHubUser = verification.githubUser.toLowerCase();
    const callerGitHubUserId = verification.githubUserId;

    try {
      if (isEnrollment) {
        if (!privilegedVerification.ok) {
          if (!Array.isArray(bodyData.enrollmentJson?.flocks) || !bodyData.enrollmentJson.flocks.length) {
            sendJson(res, 403, { ok: false, error: "Invited enrollment requires a recipient-bound broker voucher" });
            return;
          }
          if (typeof bodyData.signature !== "string" || !bodyData.signature || typeof bodyData.timestamp !== "string" || !bodyData.timestamp) {
            sendJson(res, 401, { ok: false, error: "Invited enrollment requires a signed device enrollment" });
            return;
          }
          if (bodyData.sandboxPrincipalOverride) {
            sendJson(res, 403, { ok: false, error: "Invited enrollment cannot override the authenticated GitHub identity" });
            return;
          }
        }
        // In sandbox mode, allow simulated test-principal overrides (`sandboxPrincipalOverride`) for testing cross-user collaborator walls on @erjadi test PCs
        const effectiveUser =
          isPreview && bodyData.sandboxPrincipalOverride?.githubUser
            ? String(bodyData.sandboxPrincipalOverride.githubUser).toLowerCase()
            : callerGitHubUser;
        const effectiveUserId =
          isPreview && bodyData.sandboxPrincipalOverride?.githubUserId
            ? Number(bodyData.sandboxPrincipalOverride.githubUserId)
            : callerGitHubUserId;

        const out = await enrollV3Device(
          {
            ...bodyData,
            githubUser: effectiveUser,
            githubUserId: effectiveUserId,
          },
          { storePath, sandbox: isPreview }
        );
        sendJson(res, 200, out);
        return;
      }

      if (isMyFlocks) {
        const requestedUser = (url.searchParams.get("githubUser") || callerGitHubUser).trim().toLowerCase();
        if (!privilegedVerification.ok && requestedUser !== callerGitHubUser) {
          sendJson(res, 403, { ok: false, error: "Flock lookup cannot override the authenticated GitHub identity" });
          return;
        }
        const out = await listV3UserFlocks(
          {
            githubUser: requestedUser,
            githubUserId: callerGitHubUserId,
            deviceId: url.searchParams.get("deviceId") || null,
          },
          { storePath }
        );
        sendJson(res, 200, out);
        return;
      }

      if ((subPath === "/flocks/create" || subPath === "/flocks/invite") && req.method === "POST") {
        const out = await createV3FlockInvite(
          {
            ...bodyData,
            callerGitHubUser,
            callerGitHubUserId,
            invitedUser: bodyData.invitedUser || callerGitHubUser,
          },
          { storePath, sandbox: isPreview }
        );
        sendJson(res, 200, out);
        return;
      }

      if (subPath === "/flocks/kick" && req.method === "POST") {
        const out = await kickV3FlockMember(
          {
            ...bodyData,
            callerGitHubUser,
            callerGitHubUserId,
          },
          { storePath }
        );
        sendJson(res, 200, out);
        return;
      }

      if (subPath === "/maintainer/overview" && req.method === "GET") {
        if (callerGitHubUser !== PLATFORM_MAINTAINER_USER) {
          sendJson(res, 403, { ok: false, error: "Maintainer overview is restricted to @erjadi" });
          return;
        }
        const store = loadV3FlockStore(storePath);
        sendJson(res, 200, {
          ok: true,
          maintainer: callerGitHubUser,
          sandbox: isPreview,
          flocks: Object.values(store.flocks || {}),
        });
        return;
      }
    } catch (err) {
      sendJson(res, err.statusCode || 500, {
        ok: false,
        code: err.code || "V3_ERROR",
        error: err.message,
      });
      return;
    }

    sendJson(res, 404, { ok: false, error: `Unknown v3 endpoint: ${url.pathname}` });
    return;
  }

  if (
    url.pathname === "/api/bootstrap" ||
    url.pathname === "/api/register" ||
    url.pathname === "/api/members" ||
    url.pathname === "/api/queue/enqueue" ||
    url.pathname === "/api/queue/drain" ||
    url.pathname === "/api/queue/ack" ||
    url.pathname === "/api/queue/status"
  ) {
    const authHeader = String(req.headers.authorization || "");
    const bearerMatch = authHeader.match(/^(?:Bearer|token)\s+(.+)$/i);
    const githubToken = (bearerMatch ? bearerMatch[1] : String(req.headers["x-github-token"] || "")).trim();

    if (!githubToken) {
      sendJson(res, 401, {
        ok: false,
        error: `Missing GitHub token. Pass 'Authorization: Bearer <github_token>' from a user with access to ${ALLOWED_REPO}.`,
      });
      return;
    }

    const verification = await verifyGitHubRepoAccess(githubToken, apiGet);
    if (!verification.ok) {
      sendJson(res, 403, {
        ok: false,
        error: `Access denied: deployment maintainer, repository collaborator/write access or explicit allowlisting required for ${ALLOWED_REPO} (${verification.reason}).`,
      });
      return;
    }

    const bodyData = req.method === "POST" ? await readRequestBody(req) : {};
    const machineId =
      bodyData.machineId ||
      url.searchParams.get("machineId") ||
      req.headers["x-machine-id"] ||
      null;
    const scope =
      bodyData.scope ||
      url.searchParams.get("scope") ||
      req.headers["x-machine-scope"] ||
      null;
    const version =
      bodyData.version ||
      url.searchParams.get("version") ||
      req.headers["x-bridge-version"] ||
      null;
    const hostname =
      bodyData.hostname ||
      url.searchParams.get("hostname") ||
      machineId;
    const platform =
      bodyData.platform ||
      url.searchParams.get("platform") ||
      null;
    const githubUser =
      verification.githubUser ||
      bodyData.githubUser ||
      url.searchParams.get("githubUser") ||
      null;

    let registry = loadMembersRegistry();
    if (machineId && (url.pathname === "/api/bootstrap" || url.pathname === "/api/register")) {
      registry = saveMemberRegistration({
        machineId,
        githubUser,
        githubName: verification.githubName || bodyData.githubName || null,
        scope,
        version,
        hostname,
        platform,
        specs: bodyData.specs || null,
      });
    }

    if (url.pathname === "/api/members") {
      sendJson(res, 200, {
        ok: true,
        repo: verification.repo,
        callerGitHubUser: githubUser,
        members: Object.values(registry),
      });
      return;
    }

    if (url.pathname === "/api/queue/status") {
      const store = loadOfflineQueueStore();
      const targetFilter = (url.searchParams.get("machineId") || "").trim().toLowerCase();
      const items = targetFilter
        ? store.items.filter((x) => String(x.toMachine || "").toLowerCase() === targetFilter)
        : store.items;
      sendJson(res, 200, {
        ok: true,
        serviceBusNamespace: SERVICEBUS_NAMESPACE,
        serviceBusTopic: SERVICEBUS_TOPIC,
        msiConfigured: Boolean(process.env.IDENTITY_ENDPOINT || process.env.MSI_ENDPOINT),
        queuedCount: items.length,
        items: items.map((x) => ({
          requestId: x.requestId,
          fromMachine: x.fromMachine,
          fromGitHubUser: x.fromGitHubUser,
          toMachine: x.toMachine,
          enqueuedAt: x.enqueuedAt,
          expiresAt: new Date(x.expiresAtMs).toISOString(),
          serviceBusPublished: Boolean(x.serviceBusPublished),
        })),
      });
      return;
    }

    if (url.pathname === "/api/queue/enqueue") {
      try {
        const result = await enqueueOfflineStoreItem({
          toMachine: bodyData.toMachine,
          rpcPayload: bodyData.rpcPayload,
          githubUser,
          machineId,
          ttlSeconds: bodyData.ttlSeconds,
        });
        sendJson(res, 200, result);
      } catch (err) {
        sendJson(res, err.statusCode || 500, {
          ok: false,
          code: err.code || "QUEUE_ERROR",
          error: err.message,
        });
      }
      return;
    }

    if (url.pathname === "/api/queue/drain") {
      try {
        const result = await drainOfflineStoreItems({
          targetMachine: bodyData.machineId || machineId,
          peekOnly: Boolean(bodyData.peekOnly),
        });
        sendJson(res, 200, result);
      } catch (err) {
        sendJson(res, err.statusCode || 500, {
          ok: false,
          code: err.code || "QUEUE_ERROR",
          error: err.message,
        });
      }
      return;
    }

    if (url.pathname === "/api/queue/ack") {
      try {
        const result = await ackOfflineStoreItems({
          requestIds: bodyData.requestIds,
        });
        sendJson(res, 200, result);
      } catch (err) {
        sendJson(res, err.statusCode || 500, {
          ok: false,
          code: err.code || "QUEUE_ERROR",
          error: err.message,
        });
      }
      return;
    }

    if (url.pathname === "/api/register") {
      sendJson(res, 200, {
        ok: true,
        repo: verification.repo,
        githubUser,
        registered: machineId ? registry[machineId] : null,
        members: Object.values(registry),
      });
      return;
    }

    const connStr = process.env.SIGNALR_CONNECTION_STRING || "";
    if (!connStr) {
      sendJson(res, 500, {
        ok: false,
        error: "Server is missing SIGNALR_CONNECTION_STRING environment configuration.",
      });
      return;
    }

    sendJson(res, 200, {
      ok: true,
      repo: verification.repo,
      hub: DEFAULT_HUB,
      githubUser,
      githubName: verification.githubName || null,
      connectionString: connStr,
      registered: machineId ? registry[machineId] : null,
    });
    return;
  }

  sendJson(res, 404, { ok: false, error: "Not found" });
  });
}

const server = createBootstrapServer();

const isBootstrapEntrypoint = (() => {
  if (!process.argv[1]) return false;
  try {
    return (
      fs.realpathSync(process.argv[1]).toLowerCase() ===
      fs.realpathSync(new URL(import.meta.url)).toLowerCase()
    );
  } catch {
    return String(process.argv[1]).endsWith("bootstrap-server.mjs");
  }
})();

if (isBootstrapEntrypoint) {
  server.listen(PORT, () => {
    console.log(`copilot-signalr-bridge bootstrap listening on port ${PORT} (repo: ${ALLOWED_REPO})`);
  });
}
