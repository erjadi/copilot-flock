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
import { matchesMember, verifyLeave, isPrincipalRevokedInFlock } from "./flock-membership.mjs";
import { SupportMailbox } from "./flock-support.mjs";

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

export const DEFAULT_SERVICEBUS_RESOURCE = "https://servicebus.azure.net";
const serviceBusTokens = new Map();
const serviceBusResources = new Set([DEFAULT_SERVICEBUS_RESOURCE,
  "https://servicebus.usgovcloudapi.net", "https://servicebus.chinacloudapi.cn"]);

function serviceBusResource() {
  const value = process.env.SERVICEBUS_ENTRA_RESOURCE || DEFAULT_SERVICEBUS_RESOURCE;
  return serviceBusResources.has(value.replace(/\/$/, "")) ? value.replace(/\/$/, "") : null;
}

function serviceBusFailure(category, stage, reason, statusCode = null) {
  return { ok: false, category, stage, reason, statusCode };
}

function sanitizeSbEntityName(name) {
  return String(name || "unknown")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

export async function acquireServiceBusTokenDetailed({ tokenProvider } = {}) {
  const now = Date.now();
  const resource = serviceBusResource();
  if (!resource) return serviceBusFailure("msi_unconfigured", "msi_token", "invalid_servicebus_resource");
  if (tokenProvider) {
    try {
      const provided = await tokenProvider(resource);
      if (typeof provided === "string" && provided) return { ok: true, token: provided, resource };
      return serviceBusFailure("msi_token_rejected", "msi_token", "invalid_test_token_response");
    } catch (error) {
      const aadsts = String(error?.message || "").match(/\bAADSTS\d{5,9}\b/)?.[0];
      return serviceBusFailure(aadsts ? "msi_token_rejected" : "msi_transient_error", "msi_token",
        aadsts || "test_token_provider_unavailable");
    }
  }
  const endpoint = process.env.IDENTITY_ENDPOINT || process.env.MSI_ENDPOINT;
  const header = process.env.IDENTITY_HEADER || process.env.MSI_SECRET;
  if (!endpoint || !header) return serviceBusFailure("msi_unconfigured", "msi_token", "identity_endpoint_unconfigured");
  const cached = serviceBusTokens.get(resource);
  if (cached && now < cached.expiresAt - 60000) return { ok: true, ...cached, resource };

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => { if (!settled) { settled = true; resolve(result); } };
    try {
      const u = new URL(endpoint);
      if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) {
        return finish(serviceBusFailure("msi_unconfigured", "msi_token", "invalid_identity_endpoint"));
      }
      u.searchParams.set("api-version", process.env.IDENTITY_ENDPOINT ? "2019-08-01" : "2017-09-01");
      u.searchParams.set("resource", resource);
      const mod = u.protocol === "https:" ? https : http;
      const headers = process.env.IDENTITY_ENDPOINT
        ? { "X-IDENTITY-HEADER": header, Metadata: "true" }
        : { secret: header, Metadata: "true" };
      const req = mod.request(
        u,
        { method: "GET", headers, timeout: 5000 },
        (res) => {
          let data = "";
          res.on("data", (c) => {
            if (data.length + c.length > 65536) {
              finish(serviceBusFailure("msi_token_rejected", "msi_token", "oversized_token_response", res.statusCode));
              req.destroy();
            } else data += c;
          });
          res.on("error", () => finish(serviceBusFailure("msi_transient_error", "msi_token", "token_response_failed")));
          res.on("end", () => {
            if (settled) return;
            const status = res.statusCode || 500;
            const rejection = (status < 200 || status >= 300) ? data.match(/\bAADSTS\d{5,9}\b/)?.[0] : null;
            if (rejection) return finish(serviceBusFailure("msi_token_rejected", "msi_token", rejection, status));
            if (status === 429 || status >= 500) {
              return finish(serviceBusFailure("msi_transient_error", "msi_token", "identity_endpoint_unavailable", status));
            }
            if (status < 200 || status >= 300) {
              return finish(serviceBusFailure("msi_token_rejected", "msi_token",
                data.match(/\bAADSTS\d{5,9}\b/)?.[0] || "token_request_rejected", status));
            }
            try {
              const j = JSON.parse(data);
              const expiresAt = Number(j.expires_on) > 1e9 ? Number(j.expires_on) * 1000 : Date.parse(j.expires_on);
              if (typeof j?.access_token === "string" && j.access_token && Number.isFinite(expiresAt) && expiresAt > now) {
                const credential = { token: j.access_token, expiresAt };
                serviceBusTokens.set(resource, credential);
                return finish({ ok: true, ...credential, resource });
              }
            } catch {}
            finish(serviceBusFailure("msi_token_rejected", "msi_token", "invalid_token_response", status));
          });
        }
      );
      req.on("error", () => finish(serviceBusFailure("msi_transient_error", "msi_token", "token_request_failed")));
      req.on("timeout", () => {
        finish(serviceBusFailure("msi_transient_error", "msi_token", "token_request_timeout"));
        req.destroy();
      });
      req.end();
    } catch {
      finish(serviceBusFailure("msi_unconfigured", "msi_token", "invalid_identity_endpoint"));
    }
  });
}

function requestServiceBus({ token, method, apiPath, stage, body, ttlSeconds, messageId, machineId }) {
  return new Promise((resolve) => {
    try {
      const req = https.request({
        hostname: SERVICEBUS_NAMESPACE, port: 443, path: apiPath, method, timeout: 6000,
        headers: { Authorization: `Bearer ${token}`,
          ...(body ? { "Content-Type": stage === "subscription_put" ? "application/atom+xml;type=entry;charset=utf-8" : "application/json; charset=utf-8",
            "Content-Length": Buffer.byteLength(body) } : {}),
          ...(stage === "topic_post" ? { BrokerProperties: JSON.stringify({ MessageId: messageId,
            TimeToLive: Math.max(60, Number(ttlSeconds) || 86400), Label: String(machineId || "").toLowerCase() }),
          toMachine: JSON.stringify(String(machineId || "").toLowerCase()) } : {}) },
      }, (res) => {
        let description = "";
        let descriptionOversized = false;
        const inspectDescription = stage === "subscription_get" || stage === "subscription_verify";
        if (inspectDescription) res.on("data", (chunk) => {
          if (Buffer.byteLength(description) + chunk.length > 65536) descriptionOversized = true;
          else description += chunk.toString("utf8");
        });
        res.on("error", () => resolve(serviceBusFailure("servicebus_transient_error", stage, "response_failed")));
        res.on("end", () => {
          const statusCode = res.statusCode || 500;
          if (inspectDescription && statusCode === 200 && (descriptionOversized ||
              !/<(?:[\w.-]+:)?SubscriptionDescription\b/i.test(description) ||
              /<(?:[\w.-]+:)?Status\b[^>]*>\s*(?:Disabled|ReceiveDisabled)\s*</i.test(description))) {
            return resolve(serviceBusFailure("servicebus_client_error", stage, "invalid_subscription_description", statusCode));
          }
          if ((statusCode >= 200 && statusCode < 300) || (method === "DELETE" && statusCode === 404)) {
            return resolve({ ok: true, category: "servicebus_ok", stage, reason: null, statusCode });
          }
          resolve(serviceBusFailure([401, 403].includes(statusCode) ? "servicebus_authz_denied"
            : statusCode === 429 || statusCode >= 500 ? "servicebus_transient_error" : "servicebus_client_error",
          stage, "servicebus_request_rejected", statusCode));
        });
        res.resume();
      });
      req.on("error", () => resolve(serviceBusFailure("servicebus_transient_error", stage, "request_failed")));
      req.on("timeout", () => { resolve(serviceBusFailure("servicebus_transient_error", stage, "request_timeout")); req.destroy(); });
      req.end(body);
    } catch {
      resolve(serviceBusFailure("servicebus_client_error", stage, "invalid_servicebus_request"));
    }
  });
}

const subscriptionEnsureFlights = new Map();
async function ensureServiceBusSubscription(sbToken, machineId) {
  if (!sbToken || !SERVICEBUS_NAMESPACE || !SERVICEBUS_TOPIC || !machineId) {
    return serviceBusFailure("msi_unconfigured", "subscription_put", "servicebus_namespace_unconfigured");
  }
  const subName = `sub-${sanitizeSbEntityName(machineId)}`;
  const flightKey = `${SERVICEBUS_NAMESPACE}/${SERVICEBUS_TOPIC}/${subName}`;
  if (subscriptionEnsureFlights.has(flightKey)) return subscriptionEnsureFlights.get(flightKey);
  const flight = (async () => {
  const bodyXml = `<entry xmlns="http://www.w3.org/2005/Atom"><content type="application/xml"><SubscriptionDescription xmlns="http://schemas.microsoft.com/netservices/2010/10/servicebus/connect" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><LockDuration>PT1M</LockDuration><RequiresSession>false</RequiresSession><DefaultMessageTimeToLive>P1D</DefaultMessageTimeToLive><DeadLetteringOnMessageExpiration>false</DeadLetteringOnMessageExpiration><MaxDeliveryCount>10</MaxDeliveryCount></SubscriptionDescription></content></entry>`;
  const apiPath = `/${encodeURIComponent(SERVICEBUS_TOPIC)}/subscriptions/${encodeURIComponent(subName)}?api-version=2017-04`;
  const inspect = async (stage = "subscription_get") => {
    const result = await requestServiceBus({ token: sbToken, method: "GET", stage, apiPath });
    return result.ok && result.statusCode !== 200
      ? serviceBusFailure("servicebus_client_error", stage, "unexpected_subscription_status", result.statusCode)
      : result;
  };
  const existing = await inspect();
  if (existing.ok || existing.statusCode !== 404) return existing;
  const created = await requestServiceBus({ token: sbToken, method: "PUT", stage: "subscription_put", apiPath,
    body: bodyXml });
  if (created.statusCode !== 409) return created;
  const verified = await inspect("subscription_verify");
  return verified.ok || ["servicebus_authz_denied", "servicebus_transient_error"].includes(verified.category)
    ? verified : serviceBusFailure("servicebus_client_error", "subscription_put", "subscription_conflict_unverified", 409);
  })().finally(() => subscriptionEnsureFlights.delete(flightKey));
  subscriptionEnsureFlights.set(flightKey, flight);
  return flight;
}

export async function publishToServiceBusRest(item, ttlSeconds = 86400, { tokenProvider } = {}) {
  const authorization = await acquireServiceBusTokenDetailed({ tokenProvider });
  if (!authorization.ok) return { published: false, ...authorization };
  const subscription = await ensureServiceBusSubscription(authorization.token, item.toMachine);
  if (!subscription.ok) return { published: false, ...subscription,
    reason: subscription.reason === "subscription_conflict_unverified" ? subscription.reason : "subscription_ensure_failed" };
  const body = Buffer.from(JSON.stringify(item), "utf8");
  const result = await requestServiceBus({ token: authorization.token, method: "POST", stage: "topic_post",
    apiPath: `/${encodeURIComponent(SERVICEBUS_TOPIC)}/messages?api-version=2017-04`,
    body, ttlSeconds, messageId: item.requestId, machineId: item.toMachine });
  return { published: result.ok, ...result };
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
  entry.serviceBusCategory = ["msi_unconfigured", "msi_token_rejected", "msi_transient_error",
    "servicebus_authz_denied", "servicebus_client_error", "servicebus_transient_error", "servicebus_ok"].includes(sbRes?.category)
    ? sbRes.category : "servicebus_transient_error";
  entry.serviceBusStage = ["msi_token", "subscription_get", "subscription_verify", "subscription_put", "topic_post"].includes(sbRes?.stage) ? sbRes.stage : null;
  entry.serviceBusReason = ["invalid_servicebus_resource", "invalid_test_token_response", "test_token_provider_unavailable",
    "identity_endpoint_unconfigured", "invalid_identity_endpoint", "identity_endpoint_unavailable", "token_request_rejected",
    "invalid_token_response", "token_response_failed", "token_request_failed", "token_request_timeout", "oversized_token_response",
    "request_timeout", "request_failed", "response_failed", "servicebus_request_rejected", "servicebus_namespace_unconfigured",
    "subscription_ensure_failed", "subscription_conflict_unverified", "invalid_servicebus_request"].includes(sbRes?.reason) ? sbRes.reason
      : /^AADSTS\d{5,9}$/.test(sbRes?.reason || "") ? sbRes.reason : null;
  entry.serviceBusStatusCode = Number.isInteger(sbRes?.statusCode) && sbRes.statusCode >= 100 && sbRes.statusCode <= 599 ? sbRes.statusCode : null;
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
      serviceBusReason: entry.serviceBusReason,
      serviceBusCategory: entry.serviceBusCategory,
      serviceBusStage: entry.serviceBusStage,
      serviceBusStatusCode: entry.serviceBusStatusCode,
    };
  });
}

export async function drainOfflineStoreItems({
  targetMachine,
  peekOnly = true,
  queuePath = OFFLINE_QUEUE_PATH,
  normalizeStoredTarget = (value) => value,
  allMachines = false,
}) {
  const cleanMachine = String(targetMachine || "").trim();
  if (!cleanMachine && !allMachines) {
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
    let healed = false;
    for (const item of store.items) {
      const bareTarget = normalizeStoredTarget(item.toMachine);
      if (bareTarget && (allMachines || String(bareTarget).toLowerCase() === targetLower)) {
        const normalized = bareTarget !== item.toMachine ? { ...item, toMachine: bareTarget } : item;
        healed ||= normalized !== item;
        matched.push(normalized);
        if (peekOnly) remaining.push(normalized);
      } else {
        remaining.push(item);
      }
    }
    if (healed || (!peekOnly && matched.length > 0)) {
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
  onlyForMachine = null,
  queuePath = OFFLINE_QUEUE_PATH,
  normalizeStoredTarget = (value) => value,
}) {
  const ackSet = new Set(
    (Array.isArray(requestIds) ? requestIds : []).map((id) => String(id || "").trim()).filter(Boolean)
  );
  const scopedMachine = onlyForMachine ? String(onlyForMachine).trim().toLowerCase() : null;
  return await withQueueStoreLock(async () => {
    const store = loadOfflineQueueStore(queuePath);
    const before = store.items.length;
    let scopedRemaining = 0;
    let healed = false;
    const remaining = store.items.flatMap((item) => {
      const target = normalizeStoredTarget(item.toMachine);
      const inScope = target && (scopedMachine === null || String(target).toLowerCase() === scopedMachine);
      if (inScope && ackSet.has(item.requestId)) return [];
      if (inScope) scopedRemaining++;
      if (inScope && target !== item.toMachine) {
        healed = true;
        return [{ ...item, toMachine: target }];
      }
      return [item];
    });
    if (healed || remaining.length !== before) {
      saveOfflineQueueStore({ items: remaining }, queuePath);
    }
    return {
      ok: true,
      ackedCount: before - remaining.length,
      remainingCount: scopedMachine ? scopedRemaining : remaining.length,
    };
  });
}

function queueTargetNormalizer(store, { deviceAuth, verification, isGitHubMaintainer }) {
  const now = Date.now();
  const rosters = Object.values(store.flocks || {}).filter((flock) =>
    !flock.revoked && (!flock.expiresAtMs || Number(flock.expiresAtMs) > now)).map((flock) => ({
    flock,
    members: Object.values(flock.members || {}).filter((member) => member && !member.removed &&
      (!member.membershipExpiresAtMs || Number(member.membershipExpiresAtMs) > now) &&
      (!Array.isArray(flock.allowedScopes) || flock.allowedScopes.length === 0 || flock.allowedScopes.includes(member.scope)) &&
      !isPrincipalRevokedInFlock(flock, member)),
  }));
  const matchesCaller = (member) => deviceAuth
    ? member.deviceId === deviceAuth.deviceId && Number(member.githubUserId) === Number(deviceAuth.githubUserId)
    : Number(member.githubUserId) === Number(verification.githubUserId) &&
      String(member.githubUser).toLowerCase() === String(verification.githubUser).toLowerCase();
  return (raw, { enqueue = false } = {}) => {
    const deny = () => { throw Object.assign(new Error("Queue target is invalid or outside the caller's authorized enrolled owner/flock scope"),
      { code: "QUEUE_TARGET_UNAUTHORIZED", statusCode: 403 }); };
    const malformed = () => { throw Object.assign(new Error("Malformed queue target; use a bare machineId or owner/flock/machineId"),
      { code: "INVALID_QUEUE_TARGET", statusCode: 400 }); };
    if (typeof raw !== "string" || raw !== raw.trim() || !raw || raw.length > 300) return malformed();
    const parts = raw.split("/");
    if (![1, 3].includes(parts.length) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(parts.at(-1)) ||
        (parts.length === 3 && (!parts.slice(0, 2).every((part) => /^[a-z0-9][a-z0-9-]{0,62}$/i.test(part)) ||
          parts[1].toLowerCase() === "private"))) return malformed();
    const machine = parts.at(-1).toLowerCase();
    const flockId = parts.length === 3 ? parts.slice(0, 2).join("/").toLowerCase() : null;
    const matches = [];
    for (const { flock, members } of rosters) {
      if (flockId && flock.flockId.toLowerCase() !== flockId) continue;
      const caller = members.find(matchesCaller);
      for (const member of members) {
        if (String(member.machineId || "").toLowerCase() !== machine) continue;
        const permitted = isGitHubMaintainer || (enqueue
          ? caller && ["owner", "collaborator"].includes(caller.trustTier)
          : matchesCaller(member));
        if (permitted) matches.push(member);
      }
    }
    if (!matches.length) return deny();
    const principal = `${matches[0].githubUserId}:${String(matches[0].githubUser).toLowerCase()}`;
    if (rosters.some(({ members }) => members.some((member) =>
      String(member.machineId || "").toLowerCase() === machine &&
      `${member.githubUserId}:${String(member.githubUser).toLowerCase()}` !== principal))) return deny();
    return matches[0].machineId;
  };
}

function loadMembersRegistry(customPath = MEMBERS_PATH) {
  try {
    if (fs.existsSync(customPath)) {
      return JSON.parse(fs.readFileSync(customPath, "utf8")) || {};
    }
  } catch {}
  return {};
}

export function saveMemberRegistration(entry, customPath = MEMBERS_PATH) {
  if (!entry || !entry.machineId) return loadMembersRegistry(customPath);
  try {
    fs.mkdirSync(path.dirname(customPath), { recursive: true });
    const registry = loadMembersRegistry(customPath);
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
    fs.writeFileSync(customPath, JSON.stringify(registry, null, 2), "utf8");
    return registry;
  } catch {
    return loadMembersRegistry(customPath);
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
          ...(githubToken ? { Authorization: `Bearer ${githubToken}` } : {}),
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

export function projectV3EnrollmentResponse(result, protocolVersion) {
  if (Number(protocolVersion) >= 36) return result;
  const compatible = (entry) => entry?.trustTier !== "owner" ||
    /^[^/]+(?:\/(?:personal|work))?$/.test(String(entry?.flockId || ""));
  const output = { ...result, completeMembershipSnapshot: false, authoritativeSnapshot: false };
  for (const field of ["enrolledFlocks", "ownedFlocks", "joinedFlocks", "revokedFlockSummaries", "expiredFlockSummaries"]) {
    if (Array.isArray(output[field])) output[field] = output[field].filter(compatible);
  }
  if (Array.isArray(output.controlHints)) {
    const retained = new Set((output.enrolledFlocks || []).map((entry) => entry.flockId));
    output.controlHints = output.controlHints.filter((entry) => retained.has(entry.flockId));
  }
  return output;
}

// ---------------------------------------------------------------------------
// v3.0 Multi-Flock P2P Platform Broker Engine
// ---------------------------------------------------------------------------

export function normalizeV3Scope(rawScope, fallback = "work") {
  const s = String(rawScope || "").trim().toLowerCase();
  if (s === "personal" || s === "work") return s;
  if (s === "private") {
    const err = new Error(`Obsolete machine scope "private" is not supported; use "personal" explicitly`);
    err.code = "OBSOLETE_SCOPE";
    err.statusCode = 400;
    throw err;
  }
  if (s) {
    const err = new Error(`Invalid machine scope "${rawScope}"; expected "personal" or "work"`);
    err.code = "INVALID_SCOPE";
    err.statusCode = 400;
    throw err;
  }
  const fb = String(fallback || "work").trim().toLowerCase();
  if (fb === "personal" || fb === "work") return fb;
  throw new Error(`Invalid fallback machine scope "${fallback}"`);
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
  const flockName = parts[1].toLowerCase();
  if (flockName === "private") {
    const err = new Error(`Obsolete flock scope "private" is not supported; use "${owner}/personal" explicitly`);
    err.code = "OBSOLETE_SCOPE";
    err.statusCode = 400;
    throw err;
  }
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
  hub = DEFAULT_HUB,
  userId,
  targetUserIds = [],
  expiresAtMs = Date.now() + 3600 * 1000,
  role = "peer",
}) {
  const { endpoint, accessKey } = parseSignalRConnectionString(connectionString);
  if (!endpoint || !accessKey || !hub || !userId) {
    return null;
  }
  const exp = Math.floor(expiresAtMs / 1000);
  const mint = (aud, claims = {}) => {
    const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = base64UrlEncode(JSON.stringify({
      aud,
      iat: Math.floor(Date.now() / 1000),
      exp,
      ...claims,
    }));
    const sig = base64UrlEncode(
      crypto
        .createHmac("sha256", Buffer.from(accessKey, "utf8"))
        .update(`${header}.${payload}`)
        .digest()
    );
    return `${header}.${payload}.${sig}`;
  };
  const clientAudience = `${endpoint}/client/?hub=${encodeURIComponent(hub)}`;
  const clientClaims = {
    sub: userId,
    nameid: userId,
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": userId,
    role,
  };
  const broadcastAudience = `${endpoint}/api/v1/hubs/${encodeURIComponent(hub)}`;
  const users = {};
  for (const rawTarget of targetUserIds) {
    const target = String(rawTarget || "").trim();
    if (!target || users[target]) continue;
    const audience = `${broadcastAudience}/users/${encodeURIComponent(target)}`;
    users[target] = {
      audience,
      token: mint(audience),
    };
  }
  const clientToken = mint(clientAudience, clientClaims);
  return {
    endpoint,
    hub,
    userId,
    clientAudience,
    clientToken,
    hubToken: clientToken,
    restTokens: {
      broadcast: {
        audience: broadcastAudience,
        token: mint(broadcastAudience),
      },
      users,
    },
    expiresAt: new Date(expiresAtMs).toISOString(),
    expiresAtMs,
  };
}

function activeSignalRTargetUserIds(flock, now = Date.now()) {
  return Object.values(flock?.members || {})
    .filter(
      (member) =>
        member &&
        member.machineId &&
        (!member.membershipExpiresAtMs || Number(member.membershipExpiresAtMs) > now)
    )
    .map((member) => String(member.machineId));
}

function addOwnerMachinesToSharedFlock(store, flock, ownerGitHubUser, now = Date.now()) {
  const cleanOwner = String(ownerGitHubUser || "").trim().toLowerCase();
  if (!cleanOwner || !flock || ["owner_root", "owner_scope"].includes(flock.flockType)) return false;
  let changed = false;
  for (const source of Object.values(store.flocks || {})) {
    if (
      !source ||
      source === flock ||
      String(source.ownerGitHubUser || "").toLowerCase() !== cleanOwner ||
      !["owner_root", "owner_scope"].includes(source.flockType)
    ) {
      continue;
    }
    for (const [memberKey, member] of Object.entries(source.members || {})) {
      if (
        !member ||
        String(member.githubUser || "").toLowerCase() !== cleanOwner ||
        (member.membershipExpiresAtMs && Number(member.membershipExpiresAtMs) <= now) ||
        (Array.isArray(flock.allowedScopes) &&
          flock.allowedScopes.length > 0 &&
          !flock.allowedScopes.includes(member.scope))
      ) {
        continue;
      }
      const previous = flock.members?.[memberKey];
      flock.members ||= {};
      flock.members[memberKey] = {
        ...member,
        trustTier: "owner",
        membershipExpiresAt: null,
        membershipExpiresAtMs: null,
      };
      if (!previous || previous.publicKey !== member.publicKey || previous.trustTier !== "owner") {
        flock.rosterEpoch = (Number(flock.rosterEpoch) || 1) + 1;
        changed = true;
      }
    }
  }
  return changed;
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
      `${endpoint}/api/hubs/${encodeURIComponent(hub)}/users/${encodeURIComponent(userId)}/:closeConnections?api-version=2022-06-01`
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
          method: "POST",
          headers: { Authorization: `Bearer ${jwt}`, "Content-Length": "0" },
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

export function leaveV3EvictionTarget(member) {
  return { hub: DEFAULT_HUB, userId: member.machineId };
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
    for (const ownedFlock of Object.values(store.flocks || {})) {
      if (
        ownedFlock &&
        !["owner_root", "owner_scope"].includes(ownedFlock.flockType) &&
        !ownedFlock.targetMachineId &&
        String(ownedFlock.ownerGitHubUser || "").toLowerCase() === cleanUser &&
        (!ownedFlock.ownerGitHubUserId || Number(ownedFlock.ownerGitHubUserId) === numUserId) &&
        (!Array.isArray(ownedFlock.allowedScopes) ||
          ownedFlock.allowedScopes.length === 0 ||
          ownedFlock.allowedScopes.includes(normScope))
      ) {
        targetFlocksToJoin.set(ownedFlock.flockId, {
          flock: ownedFlock,
          trustTier: "owner",
          membershipExpiresAtMs: null,
        });
      }
    }

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
        if (voucher.invalidatedAtMs) {
          const err = new Error(
            voucher.invalidationReason === "superseded"
              ? `Invite voucher for "${parsedAddr.flockId}" was superseded by a newer invitation`
              : `Invite voucher for "${parsedAddr.flockId}" is no longer valid`
          );
          err.code =
            voucher.invalidationReason === "superseded"
              ? "VOUCHER_SUPERSEDED"
              : "VOUCHER_INVALIDATED";
          err.statusCode = 403;
          throw err;
        }
        if (voucher.voucherExpiresAtMs && voucher.voucherExpiresAtMs <= now) {
          const err = new Error(`Invite voucher for "${parsedAddr.flockId}" has expired`);
          err.code = "VOUCHER_EXPIRED";
          err.statusCode = 403;
          throw err;
        }
        if (!voucher.voucherSecret || !fInvite.voucherSecret) {
          const err = new Error(`Invite voucher for "${parsedAddr.flockId}" requires voucherSecret`);
          err.code = "VOUCHER_SECRET_REQUIRED";
          err.statusCode = 403;
          throw err;
        }
        const expectedSecret = Buffer.from(String(voucher.voucherSecret), "utf8");
        const suppliedSecret = Buffer.from(String(fInvite.voucherSecret), "utf8");
        if (
          expectedSecret.length !== suppliedSecret.length ||
          !crypto.timingSafeEqual(expectedSecret, suppliedSecret)
        ) {
          const err = new Error(`Invite voucher secret for "${parsedAddr.flockId}" is invalid`);
          err.code = "VOUCHER_SECRET_INVALID";
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
        voucher.redeemedAtByDevice =
          voucher.redeemedAtByDevice && typeof voucher.redeemedAtByDevice === "object"
            ? voucher.redeemedAtByDevice
            : {};
        voucher.membershipExpiresAtByDevice =
          voucher.membershipExpiresAtByDevice &&
          typeof voucher.membershipExpiresAtByDevice === "object"
            ? voucher.membershipExpiresAtByDevice
            : {};
        const maxDevices = Math.max(1, Number(voucher.maxDevices) || 3);
        if (voucher.redeemedDeviceIds.includes(cleanDevice)) {
          const existingMember = targetFlock.members?.[peerId];
          if (!existingMember || existingMember.publicKey !== publicKey) {
            const err = new Error(
              `Invite voucher replay rejected for device "${cleanDevice}" in flock "${parsedAddr.flockId}"`
            );
            err.code = "VOUCHER_REPLAY";
            err.statusCode = 403;
            throw err;
          }
        } else {
          if (voucher.redeemedDeviceIds.length >= maxDevices) {
            const err = new Error(
              `Invite voucher for "${parsedAddr.flockId}" has reached maxDevices (${maxDevices})`
            );
            err.statusCode = 403;
            throw err;
          }
          voucher.redeemedDeviceIds.push(cleanDevice);
          voucher.redeemedAtByDevice[cleanDevice] = now;
        }
        const durationMs =
          Number(voucher.membershipDurationMinutes ?? voucher.durationMinutes) > 0
            ? Number(voucher.membershipDurationMinutes ?? voucher.durationMinutes) * 60000
            : null;
        const membershipExpiresAtMs = durationMs
          ? voucher.membershipExpiresAtByDevice[cleanDevice] || now + durationMs
          : null;
        if (membershipExpiresAtMs) {
          voucher.membershipExpiresAtByDevice[cleanDevice] = membershipExpiresAtMs;
        }
        if (targetFlock.flockType === "guest_pass" && membershipExpiresAtMs) {
          targetFlock.expiresAtMs = Math.max(
            Number(targetFlock.expiresAtMs) || 0,
            membershipExpiresAtMs
          );
        }

        const trustTier = voucher.trustTier ||
          (targetFlock.flockType === "guest_pass" || targetFlock.targetMachineId ? "guest" : "collaborator");
        if (trustTier !== "collaborator" && trustTier !== "guest") {
          const err = new Error("Invite vouchers cannot grant owner trust");
          err.statusCode = 403;
          throw err;
        }
        const isAuthenticatedBuiltInOwner =
          numUserId > 0 &&
          !targetFlock.targetMachineId &&
          (targetFlock.flockType === "owner_root" || targetFlock.flockType === "owner_scope") &&
          targetFlock.ownerGitHubUser === cleanUser &&
          (!targetFlock.ownerGitHubUserId || Number(targetFlock.ownerGitHubUserId) === numUserId);
        const existingOwnerMember =
          isAuthenticatedBuiltInOwner &&
          targetFlock.members?.[peerId]?.trustTier === "owner" &&
          Number(targetFlock.members?.[peerId]?.githubUserId) === numUserId;
        const previous = targetFlocksToJoin.get(targetFlock.flockId);
        // Only the authenticated principal's built-ins confer owner authority; never downgrade them via lower-role vouchers.
        if (previous?.trustTier === "owner" || isAuthenticatedBuiltInOwner || existingOwnerMember) {
          targetFlocksToJoin.set(targetFlock.flockId, {
            flock: targetFlock,
            trustTier: "owner",
            membershipExpiresAtMs: null,
          });
        } else {
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
      let restoredAuthority = false;
      f.revokedPrincipals ||= {};
      const restoredKeys = [peerId, cleanDevice];
      if (["owner_root", "owner_scope"].includes(f.flockType) && f.ownerGitHubUser === cleanUser &&
          (!f.ownerGitHubUserId || Number(f.ownerGitHubUserId) === numUserId)) {
        restoredKeys.push(cleanUser, String(numUserId));
      }
      for (const key of restoredKeys) {
        if (f.revokedPrincipals[key]) { delete f.revokedPrincipals[key]; restoredAuthority = true; }
      }
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
      if (f.removedMachines) {
        delete f.removedMachines[`${cleanUser}:${cleanMachine.toLowerCase()}`];
      }
      if (
        restoredAuthority || !prevMember ||
        prevMember.publicKey !== publicKey ||
        prevMember.trustTier !== item.trustTier
      ) {
        f.rosterEpoch = (Number(f.rosterEpoch) || 1) + 1;
      }

      const tokenExpMs = item.membershipExpiresAtMs
        ? Math.min(now + 3600 * 1000, item.membershipExpiresAtMs)
        : now + 3600 * 1000;
      const hubCred = mintSignalRHubToken({
        connectionString,
        hub: DEFAULT_HUB,
        userId: cleanMachine,
        targetUserIds: activeSignalRTargetUserIds(f, now),
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
        clientToken: hubCred?.clientToken || null,
        clientAudience: hubCred?.clientAudience || null,
        restTokens: hubCred?.restTokens || null,
        transportHub: hubCred?.hub || DEFAULT_HUB,
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
      completeMembershipSnapshot: false,
      authoritativeSnapshot: false,
      enrolledFlocks,
      controlHints: enrolledFlocks.map((flock) => ({
        type: "roster_epoch_changed",
        flockId: flock.flockId,
        rosterEpoch: flock.rosterEpoch,
      })),
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
        hub: DEFAULT_HUB,
        userId: member.machineId,
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
      hub: DEFAULT_HUB,
      userId: member.machineId,
      targetUserIds: activeSignalRTargetUserIds(f, now),
      expiresAtMs: tokenExpMs,
      role: member.trustTier,
    });
    member.lastSeenAt = new Date(now).toISOString();
    saveV3FlockStore(store, storePath);

    return {
      ok: true,
      flockId: f.flockId,
      completeMembershipSnapshot: false,
      authoritativeSnapshot: false,
      flockUuid: f.flockUuid,
      hubName: f.hubName,
      rosterEpoch: f.rosterEpoch,
      hubToken: hubCred?.hubToken || null,
      clientToken: hubCred?.clientToken || null,
      clientAudience: hubCred?.clientAudience || null,
      restTokens: hubCred?.restTokens || null,
      transportHub: hubCred?.hub || DEFAULT_HUB,
      endpoint: hubCred?.endpoint || null,
      tokenExpiresAt: hubCred?.expiresAt || null,
      membershipExpiresAt: member.membershipExpiresAt || null,
      serverNonce: nextNonce,
      peerId: member.peerId,
      githubUser: member.githubUser,
      githubUserId: member.githubUserId,
      deviceId: member.deviceId,
      machineId: member.machineId,
      flockType: f.flockType,
      ownerGitHubUser: f.ownerGitHubUser,
      ownerGitHubUserId: f.ownerGitHubUserId,
      trustTier: member.trustTier,
      allowedScopes: f.allowedScopes,
      targetMachineId: f.targetMachineId || null,
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
    voucherTtlSeconds = null,
    maxDevices = 3,
    allowedScopes = ["work"],
    trustTier = null,
    reissue = false,
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
    const effectiveTrust =
      trustTier || (parsed.machineId || durMins ? "guest" : "collaborator");
    const defaultVoucherTtlSeconds = effectiveTrust === "guest" ? 86400 : 259200;
    const effectiveVoucherTtlSeconds = Math.max(
      60,
      Number(voucherTtlSeconds) || defaultVoucherTtlSeconds
    );
    const voucherExpiresAtMs = now + effectiveVoucherTtlSeconds * 1000;
    const f = ensureFlockRecord(store, {
      flockId: flockIdToUse,
      ownerGitHubUser: parsed.owner,
      ownerGitHubUserId: callerGitHubUserId,
      flockType,
      allowedScopes: Array.isArray(allowedScopes) && allowedScopes.length > 0 ? allowedScopes : ["work"],
      targetMachineId: parsed.machineId || null,
      expiresAtMs: null,
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
    addOwnerMachinesToSharedFlock(store, f, parsed.owner, now);

    const voucherId = crypto.randomUUID();
    const voucherSecret = crypto.randomBytes(24).toString("base64url");
    const resolvedInvitedId = invitedGitHubUserId ? Number(invitedGitHubUserId) : null;
    const supersededVoucherIds = [];
    if (reissue) {
      for (const candidateFlock of Object.values(store.flocks || {})) {
        if (
          !candidateFlock ||
          String(candidateFlock.ownerGitHubUser || "").toLowerCase() !== parsed.owner
        ) {
          continue;
        }
        for (const existingVoucher of Object.values(candidateFlock.vouchers || {})) {
          if (
            existingVoucher &&
            !existingVoucher.invalidatedAtMs &&
            String(existingVoucher.invitedUser || "").toLowerCase() === cleanInvited &&
            String(existingVoucher.targetAddress || "") === parsed.canonicalPath
          ) {
            existingVoucher.invalidatedAtMs = now;
            existingVoucher.invalidatedAt = new Date(now).toISOString();
            existingVoucher.invalidationReason = "superseded";
            existingVoucher.supersededByVoucherId = voucherId;
            supersededVoucherIds.push(existingVoucher.voucherId);
          }
        }
      }
    }
    f.vouchers[voucherId] = {
      voucherId,
      voucherSecret,
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      targetAddress: parsed.canonicalPath,
      targetMachineId: parsed.machineId || null,
      invitedUser: cleanInvited,
      invitedGitHubUserId: resolvedInvitedId,
      invitedBy: cleanCaller,
      trustTier: effectiveTrust,
      durationMinutes: durMins,
      membershipDurationMinutes: durMins,
      maxDevices: Math.max(1, Number(maxDevices) || 3),
      redeemedDeviceIds: [],
      redeemedAtByDevice: {},
      createdAt: new Date(now).toISOString(),
      voucherExpiresAt: new Date(voucherExpiresAtMs).toISOString(),
      voucherExpiresAtMs,
      remainingRedemptionLifetimeSeconds: effectiveVoucherTtlSeconds,
      voucherSignature: voucherSignature || null,
    };

    saveV3FlockStore(store, storePath);

    const enrollmentJson = {
      v: 3,
      tokenLocalVoucherAuth: true,
      invitedUser: cleanInvited,
      invitedGitHubUserId: resolvedInvitedId,
      invitedBy: cleanCaller,
      bootstrapUrl,
      voucherExpiresAt: new Date(voucherExpiresAtMs).toISOString(),
      remainingRedemptionLifetimeSeconds: effectiveVoucherTtlSeconds,
      membershipDurationMinutes: durMins,
      maxDevices: Math.max(1, Number(maxDevices) || 3),
      flocks: [
        {
          voucherId,
          voucherSecret,
          flockId: f.flockId,
          flockUuid: f.flockUuid,
          targetAddress: parsed.canonicalPath,
          targetMachineId: parsed.machineId || null,
          recommendedScope: f.allowedScopes?.[0] || "work",
          trustTier: effectiveTrust,
          durationMinutes: durMins,
          membershipDurationMinutes: durMins,
          voucherSignature: voucherSignature || null,
        },
      ],
    };

    const pasteablePrompt =
      `Accept my pending GitHub repo invite to \`erjadi/copilot-flock\` (if any), clone \`https://github.com/erjadi/copilot-flock\`, install and set up Copilot Flock on this machine, and enroll me using this token-local enrollment JSON (no GitHub token is sent to the bootstrap server):\n` +
      `\`\`\`json\n${JSON.stringify(enrollmentJson, null, 2)}\n\`\`\``;

    return {
      ok: true,
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      targetAddress: parsed.canonicalPath,
      voucherId,
      supersededVoucherIds,
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
    const changedFlocks = new Map();
    for (const [peerKey, m] of Object.entries(f.members || {})) {
      if (matchesMember(m, { targetUser: cleanTargetUser, targetGitHubUserId,
        targetDeviceId, targetMachineId: cleanTargetMachine })) {
        kickedPeers.push(m);
        delete f.members[peerKey];
        f.removedMachines ||= {};
        if (m.machineId) {
          f.removedMachines[`${String(m.githubUser || "").toLowerCase()}:${String(m.machineId).toLowerCase()}`] = {
            githubUser: m.githubUser,
            machineId: m.machineId,
            peerId: m.peerId,
            deviceId: m.deviceId || null,
            keyFingerprint: m.keyFingerprint || m.deviceId || null,
            removedAtEpoch: (Number(f.rosterEpoch) || 1) + 1,
            removedAt: new Date().toISOString(),
          };
        }
        if (!isSelfLeave) {
          const isBuiltInOwner = ["owner_root", "owner_scope"].includes(f.flockType) &&
            String(m.githubUser).toLowerCase() === String(f.ownerGitHubUser).toLowerCase();
          if (cleanTargetUser && !cleanTargetMachine && !targetDeviceId && !isBuiltInOwner) {
            f.revokedPrincipals[m.githubUser] = new Date().toISOString();
            if (m.githubUserId) f.revokedPrincipals[String(m.githubUserId)] = new Date().toISOString();
          }
          f.revokedPrincipals[peerKey] = new Date().toISOString();
        }
      }
    }
    if (kickedPeers.length > 0) {
      changedFlocks.set(f.flockId, f);
    }

    const kickedOwnerDevices = kickedPeers.filter(
      (member) =>
        String(member.githubUser || "").toLowerCase() === f.ownerGitHubUser &&
        member.trustTier === "owner"
    );
    if (
      kickedOwnerDevices.length > 0 &&
      ["owner_root", "owner_scope"].includes(f.flockType)
    ) {
      for (const related of Object.values(store.flocks || {})) {
        if (
          related === f ||
          ["owner_root", "owner_scope"].includes(related.flockType) ||
          String(related.ownerGitHubUser || "").toLowerCase() !== f.ownerGitHubUser
        ) {
          continue;
        }
        let changed = false;
        for (const [peerKey, member] of Object.entries(related.members || {})) {
          if (
            !kickedOwnerDevices.some(
              (kicked) =>
                kicked.peerId === member.peerId ||
                (kicked.deviceId && kicked.deviceId === member.deviceId) ||
                (kicked.machineId &&
                  String(kicked.machineId).toLowerCase() ===
                    String(member.machineId || "").toLowerCase())
            )
          ) {
            continue;
          }
          delete related.members[peerKey];
          related.removedMachines ||= {};
          related.removedMachines[
            `${String(member.githubUser || "").toLowerCase()}:${String(member.machineId || "").toLowerCase()}`
          ] = {
            githubUser: member.githubUser,
            machineId: member.machineId,
            peerId: member.peerId,
            deviceId: member.deviceId || null,
            keyFingerprint: member.keyFingerprint || member.deviceId || null,
            removedAtEpoch: (Number(related.rosterEpoch) || 1) + 1,
            removedAt: new Date().toISOString(),
          };
          related.revokedPrincipals[peerKey] = new Date().toISOString();
          kickedPeers.push(member);
          changed = true;
        }
        if (changed) {
          related.rosterEpoch = (Number(related.rosterEpoch) || 1) + 1;
          changedFlocks.set(related.flockId, related);
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
    changedFlocks.set(f.flockId, f);
    saveV3FlockStore(store, storePath);

    const evictionResults = [];
    for (const kp of kickedPeers) {
      const ev = await evictSignalRHubUserImmediate({
        connectionString,
        hub: DEFAULT_HUB,
        userId: kp.machineId,
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
      controlHints: Array.from(changedFlocks.values()).map((changed) => ({
        type: "roster_epoch_changed",
        flockId: changed.flockId,
        rosterEpoch: changed.rosterEpoch,
      })),
    };
  });
}

export async function deleteLegacyPeerSubscription(member, { tokenProvider } = {}) {
  const authorization = await acquireServiceBusTokenDetailed({ tokenProvider });
  if (!authorization.ok) return { confirmed: false, ...authorization };
  if (!SERVICEBUS_NAMESPACE) return { confirmed: false,
    ...serviceBusFailure("msi_unconfigured", "subscription_delete", "servicebus_namespace_unconfigured") };
  const sub = `sub-${sanitizeSbEntityName(member.machineId)}`;
  const result = await requestServiceBus({ token: authorization.token, method: "DELETE", stage: "subscription_delete",
    apiPath: `/${encodeURIComponent(SERVICEBUS_TOPIC)}/subscriptions/${encodeURIComponent(sub)}?api-version=2017-04` });
  return { confirmed: result.ok, ...result };
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
  evict = (member) => evictSignalRHubUserImmediate({
    connectionString: process.env.SIGNALR_CONNECTION_STRING || "",
    ...leaveV3EvictionTarget(member),
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
      flock.removedMachines ||= {};
      if (member.machineId) {
        flock.removedMachines[`${String(member.githubUser || "").toLowerCase()}:${String(member.machineId).toLowerCase()}`] = {
          githubUser: member.githubUser,
          machineId: member.machineId,
          peerId: member.peerId,
          deviceId: member.deviceId || null,
          keyFingerprint: member.keyFingerprint || member.deviceId || null,
          removedAtEpoch: flock.rosterEpoch,
          removedAt: new Date().toISOString(),
        };
      }
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
    return {
      ok: confirmed,
      confirmed,
      flockId: request.flockId,
      peerId: member.peerId,
      rosterEpoch: flock.rosterEpoch,
      subscription,
      eviction,
      controlHints: [{
        type: "roster_epoch_changed",
        flockId: request.flockId,
        rosterEpoch: flock.rosterEpoch,
      }],
    };
  });
}

export async function syncV3DeviceMemberships(
  {
    githubUser,
    githubUserId,
    deviceId,
    machineId = null,
    signature = null,
    timestamp = null,
    requireSignature = false,
  },
  {
    storePath = V3_FLOCKS_PATH,
    connectionString = process.env.SIGNALR_CONNECTION_STRING || "",
  } = {}
) {
  const cleanUser = String(githubUser || "").trim().toLowerCase();
  const numUserId = Number(githubUserId);
  const cleanDevice = String(deviceId || "").trim().toLowerCase();
  const cleanMachine = machineId ? String(machineId).trim() : "";

  if (!cleanUser || !Number.isSafeInteger(numUserId) || numUserId <= 0 || !cleanDevice) {
    const err = new Error("Authenticated githubUser, numeric githubUserId, and deviceId are required for membership sync");
    err.statusCode = 400;
    throw err;
  }

  return await withFlockStoreLock(async () => {
    const store = loadV3FlockStore(storePath);
    const now = Date.now();
    const peerId = `${numUserId}:${cleanDevice}`;

    if (requireSignature || signature || timestamp) {
      if (typeof signature !== "string" || !signature || typeof timestamp !== "string" || !timestamp) {
        const err = new Error("Signed device membership sync proof is required");
        err.statusCode = 401;
        throw err;
      }
      const tsMs = Date.parse(timestamp);
      if (!Number.isFinite(tsMs) || Math.abs(now - tsMs) > 300000) {
        const err = new Error("Membership sync signature timestamp out of bounds");
        err.statusCode = 401;
        throw err;
      }
      const pinnedKeys = new Set();
      for (const f of Object.values(store.flocks || {})) {
        for (const m of Object.values(f.members || {})) {
          if (
            m.deviceId === cleanDevice &&
            Number(m.githubUserId) === numUserId &&
            m.publicKey
          ) {
            pinnedKeys.add(m.publicKey);
          }
        }
      }
      if (pinnedKeys.size === 0) {
        const err = new Error(`No enrolled device key pinned for "${peerId}"`);
        err.statusCode = 403;
        throw err;
      }
      const canonical = `sync|v3|${cleanDevice}|${cleanMachine}|${timestamp}`;
      const sigBuf = Buffer.from(String(signature), "base64");
      for (const pubKey of pinnedKeys) {
        const ok = crypto.verify(null, Buffer.from(canonical, "utf8"), pubKey, sigBuf);
        if (!ok) {
          const err = new Error("Invalid Ed25519 membership sync signature");
          err.statusCode = 401;
          throw err;
        }
      }
    }

    const enrolledFlocks = [];
    const revokedFlockIds = [];
    const expiredFlockIds = [];
    const revokedFlockSummaries = [];
    const expiredFlockSummaries = [];
    let mutated = false;

    for (const f of Object.values(store.flocks || {})) {
      const priorMember = Object.values(f.members || {}).find((m) => m &&
        m.deviceId === cleanDevice && Number(m.githubUserId) === numUserId &&
        String(m.githubUser || "").toLowerCase() === cleanUser);
      const isAuthenticatedBuiltInOwner = Boolean(priorMember && !f.targetMachineId &&
        ["owner_root", "owner_scope"].includes(f.flockType) && f.ownerGitHubUser === cleanUser &&
        (!f.ownerGitHubUserId || Number(f.ownerGitHubUserId) === numUserId) &&
        (!Array.isArray(f.allowedScopes) || f.allowedScopes.length === 0 || f.allowedScopes.includes(priorMember.scope)));
      if (isAuthenticatedBuiltInOwner) {
        for (const key of [cleanUser, String(numUserId)]) {
          if (f.revokedPrincipals?.[key]) {
            delete f.revokedPrincipals[key];
            f.rosterEpoch = (Number(f.rosterEpoch) || 1) + 1;
            mutated = true;
          }
        }
      }
      if (
        isPrincipalRevokedInFlock(f, {
          githubUser: cleanUser,
          githubUserId: numUserId,
          peerId,
          deviceId: cleanDevice,
        })
      ) {
        revokedFlockIds.push(f.flockId);
        revokedFlockSummaries.push({
          flockId: f.flockId,
          flockUuid: f.flockUuid,
          flockType: f.flockType,
          ownerGitHubUser: f.ownerGitHubUser,
          ownerGitHubUserId: f.ownerGitHubUserId,
          rosterEpoch: f.rosterEpoch,
          members: [],
        });
        continue;
      }

      if (
        !["owner_root", "owner_scope"].includes(f.flockType) &&
        !f.targetMachineId &&
        String(f.ownerGitHubUser || "").toLowerCase() === cleanUser &&
        (!f.ownerGitHubUserId || Number(f.ownerGitHubUserId) === numUserId)
      ) {
        mutated = addOwnerMachinesToSharedFlock(store, f, cleanUser, now) || mutated;
      }

      const refreshedEntry = Object.entries(f.members || {}).find(([, m]) => m &&
        m.deviceId === cleanDevice && Number(m.githubUserId) === numUserId &&
        String(m.githubUser || "").toLowerCase() === cleanUser);
      if (!refreshedEntry) continue;
      const [memberKey, member] = refreshedEntry;
      if (Array.isArray(f.allowedScopes) && f.allowedScopes.length && !f.allowedScopes.includes(member.scope)) continue;

      if (
        (member.membershipExpiresAtMs && Number(member.membershipExpiresAtMs) <= now) ||
        (f.expiresAtMs && Number(f.expiresAtMs) <= now)
      ) {
        delete f.members[memberKey];
        f.rosterEpoch = (Number(f.rosterEpoch) || 1) + 1;
        mutated = true;
        expiredFlockIds.push(f.flockId);
        expiredFlockSummaries.push({
          flockId: f.flockId,
          flockUuid: f.flockUuid,
          flockType: f.flockType,
          ownerGitHubUser: f.ownerGitHubUser,
          ownerGitHubUserId: f.ownerGitHubUserId,
          rosterEpoch: f.rosterEpoch,
          members: [],
        });
        await evictSignalRHubUserImmediate({
          connectionString,
          hub: DEFAULT_HUB,
          userId: member.machineId,
        });
        continue;
      }

      if (
        isAuthenticatedBuiltInOwner &&
        (member.trustTier !== "owner" || member.membershipExpiresAtMs != null || member.membershipExpiresAt != null)
      ) {
        member.trustTier = "owner";
        member.membershipExpiresAtMs = null;
        member.membershipExpiresAt = null;
        f.ownerGitHubUserId = numUserId;
        f.rosterEpoch = (Number(f.rosterEpoch) || 1) + 1;
        mutated = true;
      }

      const tokenExpMs = member.membershipExpiresAtMs
        ? Math.min(now + 3600 * 1000, Number(member.membershipExpiresAtMs))
        : now + 3600 * 1000;
      const hubCred = mintSignalRHubToken({
        connectionString,
        hub: DEFAULT_HUB,
        userId: member.machineId,
        targetUserIds: activeSignalRTargetUserIds(f, now),
        expiresAtMs: tokenExpMs,
        role: member.trustTier,
      });
      const serverNonce = issueRefreshNonceForPeer(store, {
        deviceId: cleanDevice,
        githubUserId: numUserId,
        flockUuid: f.flockUuid,
      });
      member.lastSeenAt = new Date(now).toISOString();
      mutated = true;

      enrolledFlocks.push({
        flockId: f.flockId,
        flockUuid: f.flockUuid,
        hubName: f.hubName,
        flockType: f.flockType,
        ownerGitHubUser: f.ownerGitHubUser,
        ownerGitHubUserId: f.ownerGitHubUserId,
        trustTier: member.trustTier,
        allowedScopes: f.allowedScopes,
        targetMachineId: f.targetMachineId || null,
        rosterEpoch: f.rosterEpoch,
        membershipExpiresAt: member.membershipExpiresAt || null,
        membershipExpiresAtMs: member.membershipExpiresAtMs || null,
        hubToken: hubCred?.hubToken || null,
        clientToken: hubCred?.clientToken || null,
        clientAudience: hubCred?.clientAudience || null,
        restTokens: hubCred?.restTokens || null,
        transportHub: hubCred?.hub || DEFAULT_HUB,
        endpoint: hubCred?.endpoint || null,
        tokenExpiresAt: hubCred?.expiresAt || null,
        serverNonce,
        members: Object.values(f.members),
      });
    }

    if (mutated) {
      saveV3FlockStore(store, storePath);
    }

    return {
      ok: true,
      v: 3,
      peerId,
      githubUser: cleanUser,
      githubUserId: numUserId,
      deviceId: cleanDevice,
      machineId: cleanMachine || null,
      enrolledFlocks,
      revokedFlockIds,
      expiredFlockIds,
      revokedFlockSummaries,
      expiredFlockSummaries,
      authoritativeSnapshot: true,
      completeMembershipSnapshot: true,
    };
  });
}

export async function listV3UserFlocks(
  { githubUser, githubUserId = null, deviceId = null },
  { storePath = V3_FLOCKS_PATH } = {}
) {
  const cleanUser = String(githubUser || "").trim().toLowerCase();
  const numUserId = githubUserId && Number.isSafeInteger(Number(githubUserId)) && Number(githubUserId) > 0
    ? Number(githubUserId)
    : null;
  const cleanDevice = deviceId ? String(deviceId).trim().toLowerCase() : null;
  const store = loadV3FlockStore(storePath);
  const now = Date.now();
  const ownedFlocks = [];
  const joinedFlocks = [];

  for (const f of Object.values(store.flocks || {})) {
    if (f.expiresAtMs && f.expiresAtMs <= now) continue;
    const activeMembers = Object.values(f.members || {}).filter(
      (m) =>
        (!m.membershipExpiresAtMs || m.membershipExpiresAtMs > now) &&
        !f.revokedPrincipals?.[m.peerId] &&
        !f.revokedPrincipals?.[m.githubUser] &&
        !(m.githubUserId && f.revokedPrincipals?.[String(m.githubUserId)])
    );
    const isOwner =
      f.ownerGitHubUser === cleanUser ||
      Boolean(githubUserId && f.ownerGitHubUserId && Number(f.ownerGitHubUserId) === Number(githubUserId));
    const summary = {
      flockId: f.flockId,
      flockUuid: f.flockUuid,
      hubName: f.hubName,
      flockType: f.flockType,
      ownerGitHubUser: f.ownerGitHubUser,
      ownerGitHubUserId: f.ownerGitHubUserId || null,
      allowedScopes: f.allowedScopes,
      targetMachineId: f.targetMachineId || null,
      rosterEpoch: f.rosterEpoch,
      memberCount: activeMembers.length,
      removedMachines: Object.values(f.removedMachines || {}),
      members: activeMembers.map((m) => ({
        peerId: m.peerId,
        githubUser: m.githubUser,
        githubUserId: m.githubUserId || null,
        deviceId: m.deviceId || null,
        machineId: m.machineId,
        scope: m.scope,
        trustTier: m.trustTier,
        publicKey: m.publicKey,
        keyFingerprint: m.keyFingerprint,
        joinedAt: m.joinedAt || null,
        lastSeenAt: m.lastSeenAt || null,
        membershipExpiresAt: m.membershipExpiresAt || null,
        membershipExpiresAtMs: m.membershipExpiresAtMs || null,
      })),
    };
    if (
      isOwner ||
      f.ownerGitHubUser === cleanUser ||
      (numUserId && f.ownerGitHubUserId && Number(f.ownerGitHubUserId) === numUserId)
    ) {
      ownedFlocks.push(summary);
    }
    if (
      !isPrincipalRevokedInFlock(f, {
        githubUser: cleanUser,
        githubUserId: numUserId,
        peerId: numUserId && cleanDevice ? `${numUserId}:${cleanDevice}` : null,
        deviceId: cleanDevice,
      }) &&
      activeMembers.some(
        (m) =>
          (m.githubUser === cleanUser ||
            (githubUserId && m.githubUserId && Number(m.githubUserId) === Number(githubUserId))) &&
          (!cleanDevice || m.deviceId === cleanDevice)
      )
    ) {
      joinedFlocks.push(summary);
    }
  }

  return {
    ok: true,
    fetchedAt: new Date(now).toISOString(),
    githubUser: cleanUser,
    githubUserId: numUserId,
    deviceId: cleanDevice,
    peerId: numUserId && cleanDevice ? `${numUserId}:${cleanDevice}` : null,
    ownedFlocks,
    joinedFlocks,
    completeMembershipSnapshot: false,
    authoritativeSnapshot: false,
  };
}

function readRequestBodyWithRaw(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => {
      if (body.length < 65536) body += chunk;
    });
    req.on("end", () => {
      if (!body) return resolve({ raw: "", parsed: {} });
      try {
        resolve({ raw: body, parsed: JSON.parse(body) });
      } catch {
        resolve({ raw: body, parsed: {} });
      }
    });
    req.on("error", () => resolve({ raw: "", parsed: {} }));
  });
}

export function verifyTokenLocalDeviceHttpAuth(
  req,
  url,
  rawBody = "",
  { storePath = V3_FLOCKS_PATH } = {}
) {
  const cleanDevice = String(req.headers["x-flock-device-id"] || "").trim().toLowerCase();
  const timestamp = String(req.headers["x-flock-timestamp"] || "").trim();
  const signature = String(req.headers["x-flock-signature"] || "").trim();
  if (!cleanDevice && !timestamp && !signature) return null;
  if (!cleanDevice || !timestamp || !signature) {
    return {
      ok: false,
      statusCode: 401,
      error: "Incomplete token-local device authentication headers",
    };
  }
  const now = Date.now();
  const tsMs = Date.parse(timestamp);
  if (!Number.isFinite(tsMs) || Math.abs(now - tsMs) > 300000) {
    return {
      ok: false,
      statusCode: 401,
      error: "Token-local device signature timestamp out of bounds",
    };
  }

  const store = loadV3FlockStore(storePath);
  const pinnedKeys = new Set();
  const allowedPeerMachines = new Set();
  const allowedEnqueueMachines = new Set();
  let githubUser = null;
  let githubUserId = null;
  let machineId = null;
  let hasCollaboratorOrOwner = false;

  for (const f of Object.values(store.flocks || {})) {
    if (f.expiresAtMs && Number(f.expiresAtMs) <= now) continue;
    const activeMembers = Object.values(f.members || {}).filter(
      (m) =>
        m &&
        (!m.membershipExpiresAtMs || Number(m.membershipExpiresAtMs) > now) &&
        !isPrincipalRevokedInFlock(f, {
          githubUser: m.githubUser,
          githubUserId: m.githubUserId,
          peerId: m.peerId,
          deviceId: m.deviceId,
        })
    );
    const matching = activeMembers.find((m) => m.deviceId === cleanDevice && m.publicKey);
    if (!matching) continue;

    const mUser = String(matching.githubUser || "").trim().toLowerCase();
    const mUserId = Number(matching.githubUserId) || null;
    if (!mUser || !mUserId) continue;
    if (githubUser && githubUser !== mUser) {
      return {
        ok: false,
        statusCode: 403,
        error: "Conflicting principals for device fingerprint",
      };
    }
    githubUser = mUser;
    githubUserId = mUserId;
    if (matching.machineId) machineId = matching.machineId;
    pinnedKeys.add(matching.publicKey);
    if (matching.trustTier === "owner" || matching.trustTier === "collaborator") {
      hasCollaboratorOrOwner = true;
    }
    for (const peer of activeMembers) {
      if (peer.machineId) allowedPeerMachines.add(String(peer.machineId).toLowerCase());
      if (peer.machineId && ["owner", "collaborator"].includes(matching.trustTier)) {
        allowedEnqueueMachines.add(String(peer.machineId).toLowerCase());
      }
    }
  }

  if (pinnedKeys.size === 0 || !githubUser || !githubUserId) {
    return {
      ok: false,
      statusCode: 403,
      error: `Device "${cleanDevice}" has no active enrolled flock membership`,
    };
  }

  const bodyDigest = crypto
    .createHash("sha256")
    .update(String(rawBody || ""), "utf8")
    .digest("hex");
  const canonical = `http|v3|${String(req.method || "GET").toUpperCase()}|${url.pathname}${url.search}|${bodyDigest}|${cleanDevice}|${timestamp}`;
  const sigBuf = Buffer.from(signature, "base64");
  for (const pubKey of pinnedKeys) {
    const valid = crypto.verify(null, Buffer.from(canonical, "utf8"), pubKey, sigBuf);
    if (!valid) {
      return {
        ok: false,
        statusCode: 401,
        error: "Invalid Ed25519 token-local device HTTP signature",
      };
    }
  }

  return {
    ok: true,
    tokenLocalDevice: true,
    deviceId: cleanDevice,
    machineId,
    githubUser,
    githubUserId,
    hasCollaboratorOrOwner,
    allowedPeerMachines,
    allowedEnqueueMachines,
  };
}

export function createBootstrapServer({
  apiGet = githubApiGet,
  v3StorePath = V3_FLOCKS_PATH,
  v3PreviewStorePath = V3_PREVIEW_FLOCKS_PATH,
  membersPath = MEMBERS_PATH,
  queuePath = OFFLINE_QUEUE_PATH,
  supportRoot = path.join(path.dirname(v3StorePath), "support-quarantine", "mailbox"),
  supportOptions = {},
  serviceBusTokenProvider,
} = {}) {
  const supportMailbox = new SupportMailbox(supportRoot, supportOptions);
  return http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname.startsWith("/api/v3/support/")) {
    try {
      // Support never enters ordinary enrollment, transport, queue or GitHub authentication paths.
      if (req.headers.authorization) throw Object.assign(new Error("Support routes do not accept GitHub or bearer credentials"), { statusCode: 401 });
      supportMailbox.consumeRequest({ ip: req.socket.remoteAddress });
      const rawBody = await new Promise((resolve, reject) => {
        const chunks = [];
        let bytes = 0;
        req.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes <= 16384) chunks.push(chunk);
        });
        req.on("end", () => bytes > 16384
          ? reject(Object.assign(new Error("Support payload exceeds 16384 bytes"), { statusCode: 413 }))
          : resolve(Buffer.concat(chunks).toString("utf8")));
        req.on("error", reject);
      });
      let body;
      try { body = rawBody ? JSON.parse(rawBody) : {}; }
      catch { throw new Error("Invalid support JSON"); }
      if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Support body must be an object");
      const route = url.pathname.slice("/api/v3/support/".length);
      const fields = {
        "tickets/issue": ["flock", "ticket", "supportPublicKey"],
        "tickets/revoke": ["flock", "ticketId"],
        reports: ["ticket", "supportPublicKey", "report", "signature"],
        attempts: ["flock", "cursor", "limit", "includeClosed"],
        "attempts/read": ["flock", "attemptId"],
        "attempts/reply": ["flock", "attemptId", "text"],
        "attempts/close": ["flock", "attemptId"],
      }[route];
      if (req.method !== "POST" || !fields) throw Object.assign(new Error("Unsupported support route"), { statusCode: 404 });
      if (Object.keys(body).some((key) => !fields.includes(key))) throw new Error("Unsupported support field");
      if (route === "reports") {
        supportMailbox.consumeRequest({ ip: req.socket.remoteAddress, ticketId: body.ticket?.body?.ticketId || "missing" });
        sendJson(res, 200, supportMailbox.submit(body));
        return;
      }
      const auth = verifyTokenLocalDeviceHttpAuth(req, url, rawBody, { storePath: v3StorePath });
      if (!auth?.ok) throw Object.assign(new Error("Verified owner device authentication required"), { statusCode: 403 });
      const store = loadV3FlockStore(v3StorePath);
      const owned = Object.values(store.flocks || {}).filter((flock) =>
        (!body.flock || flock.flockId === body.flock) &&
        (!flock.expiresAtMs || Number(flock.expiresAtMs) > Date.now()) &&
        String(flock.ownerGitHubUser).toLowerCase() === auth.githubUser &&
        Number(flock.ownerGitHubUserId) === auth.githubUserId &&
        Object.values(flock.members || {}).some((member) => member.deviceId === auth.deviceId &&
          member.trustTier === "owner" && member.publicKey &&
          (!member.membershipExpiresAtMs || Number(member.membershipExpiresAtMs) > Date.now()) &&
          !isPrincipalRevokedInFlock(flock, member)));
      if (owned.length !== 1) throw Object.assign(new Error("Select exactly one flock owned by this verified maintainer"), { statusCode: 403 });
      const flock = owned[0];
      const owner = Object.values(flock.members).find((member) => member.deviceId === auth.deviceId && member.trustTier === "owner");
      supportMailbox.consumeRequest({ ip: req.socket.remoteAddress, requestSignature: req.headers["x-flock-signature"] });
      const maintainerDeviceId = auth.deviceId;
      const entry = body.ticketId ? supportMailbox.read().tickets[body.ticketId]
        : body.attemptId ? supportMailbox.read().attempts[body.attemptId] : null;
      if ((body.ticketId || body.attemptId) && (!entry || entry.flockId !== flock.flockId)) {
        throw Object.assign(new Error("Support record is outside the selected flock"), { statusCode: 403 });
      }
      let result;
      if (route === "tickets/issue") result = supportMailbox.issue({
        maintainerIdentity: { publicKey: owner.publicKey, deviceId: auth.deviceId },
        flockId: flock.flockId, supportPublicKey: body.supportPublicKey, signedTicket: body.ticket,
      });
      if (route === "tickets/revoke") result = supportMailbox.revoke({ ticketId: body.ticketId, maintainerDeviceId });
      if (route === "attempts") result = supportMailbox.list({ ...body, maintainerDeviceId, flockId: flock.flockId });
      if (route === "attempts/read") result = supportMailbox.get({ attemptId: body.attemptId, maintainerDeviceId });
      if (route === "attempts/reply") result = supportMailbox.reply({ attemptId: body.attemptId, text: body.text, maintainerDeviceId });
      if (route === "attempts/close") result = supportMailbox.close({ attemptId: body.attemptId, maintainerDeviceId });
      sendJson(res, 200, result);
    } catch (error) {
      sendJson(res, error.statusCode || 400, {
        ok: false, code: error.statusCode === 429 ? "SUPPORT_RATE_LIMITED" : "SUPPORT_REQUEST_REJECTED",
        error: "Support request rejected; verify schema, device signature, ticket state, expiry and quotas.",
      });
    }
    return;
  }

  if (url.pathname === "/" || url.pathname === "/healthz" || url.pathname === "/health") {
    const registry = loadMembersRegistry(membersPath);
    const qStore = loadOfflineQueueStore(queuePath);
    const v3Store = loadV3FlockStore(v3StorePath);
    sendJson(res, 200, {
      ok: true,
      service: "copilot-flock-bootstrap",
      version: "3.6.0",
      allowedRepo: ALLOWED_REPO,
      hub: DEFAULT_HUB,
      serviceBusNamespace: SERVICEBUS_NAMESPACE,
      serviceBusTopic: SERVICEBUS_TOPIC,
      msiConfigured: Boolean(process.env.IDENTITY_ENDPOINT || process.env.MSI_ENDPOINT),
      serviceBusResource: serviceBusResource(),
      configured: Boolean(process.env.SIGNALR_CONNECTION_STRING),
      registeredMemberCount: Object.keys(registry).length,
      queuedOfflineMessageCount: qStore.items.length,
      v3FlockCount: Object.keys(v3Store.flocks || {}).length,
      capabilities: {
        rosterSync: true,
        tokenLocalDeviceAuth: true,
        deviceSignedOperations: true,
        scopedSignalRTransportTokens: true,
        voucherReissue: true,
        enrollmentReadiness: true,
      },
    });
    return;
  }

  if (url.pathname.startsWith("/api/v3/")) {
    const isPreview =
      url.pathname.startsWith("/api/v3/preview/") ||
      url.searchParams.get("sandbox") === "v3";
    const subPath = url.pathname.replace(/^\/api\/v3(?:\/preview)?/, "");
    const storePath = isPreview ? v3PreviewStorePath : v3StorePath;
    const { raw: rawBody, parsed: bodyData } =
      req.method === "POST" ? await readRequestBodyWithRaw(req) : { raw: "", parsed: {} };
    const correlationId =
      String(req.headers["x-flock-correlation-id"] || bodyData.correlationId || "").trim() ||
      crypto.randomUUID();

    if (subPath === "/capabilities" && req.method === "GET") {
      sendJson(res, 200, {
        ok: true,
        version: "3.6.0",
        correlationId,
        capabilities: {
          rosterSync: true,
          tokenLocalDeviceAuth: true,
          deviceSignedOperations: true,
          scopedSignalRTransportTokens: true,
          voucherReissue: true,
          enrollmentReadiness: true,
          offlineQueueDeviceAuth: true,
        },
      });
      return;
    }

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
          : await leaveV3Device(bodyData, { storePath, membersPath,
            ...(serviceBusTokenProvider ? { deleteSubscription: (member) =>
              deleteLegacyPeerSubscription(member, { tokenProvider: serviceBusTokenProvider }) } : {}) });
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
    const isEnrollment = subPath === "/enroll" && req.method === "POST";
    const isMyFlocks = subPath === "/my-flocks" && req.method === "GET";
    const isFlocksSync = subPath === "/flocks/sync" && req.method === "POST";

    if (!githubToken && isEnrollment && Array.isArray(bodyData.enrollmentJson?.flocks) && bodyData.enrollmentJson.flocks.length > 0) {
      try {
        if (typeof bodyData.signature !== "string" || !bodyData.signature || typeof bodyData.timestamp !== "string" || !bodyData.timestamp) {
          sendJson(res, 401, { ok: false, error: "Token-local invited enrollment requires a signed device enrollment" });
          return;
        }
        if (bodyData.sandboxPrincipalOverride) {
          sendJson(res, 403, { ok: false, error: "Token-local invited enrollment cannot override the invited GitHub identity" });
          return;
        }
        const store = loadV3FlockStore(storePath);
        let matchedUser = null;
        let matchedUserId = null;
        for (const fInvite of bodyData.enrollmentJson.flocks) {
          const parsedAddr = parseFlockAddress(fInvite?.flockId);
          const targetFlock = store.flocks[parsedAddr.flockId];
          const voucher = targetFlock?.vouchers?.[fInvite?.voucherId];
          if (!voucher) {
            sendJson(res, 403, { ok: false, error: `Invalid or unknown voucherId for flock "${parsedAddr.flockId}"` });
            return;
          }
          if (!voucher.voucherSecret || !fInvite.voucherSecret) {
            sendJson(res, 403, { ok: false, code: "VOUCHER_SECRET_REQUIRED", error: "Invalid or missing voucherSecret for token-local enrollment" });
            return;
          }
          const suppliedSecret = String(fInvite.voucherSecret);
          const expectedBuf = Buffer.from(String(voucher.voucherSecret), "utf8");
          const suppliedBuf = Buffer.from(suppliedSecret, "utf8");
          if (expectedBuf.length !== suppliedBuf.length || !crypto.timingSafeEqual(expectedBuf, suppliedBuf)) {
            sendJson(res, 403, { ok: false, code: "VOUCHER_SECRET_INVALID", error: "Invalid or missing voucherSecret for token-local enrollment" });
            return;
          }
          const vUser = String(voucher.invitedUser || "").trim().toLowerCase();
          if (!vUser) {
            sendJson(res, 403, { ok: false, error: "Voucher is missing invitedUser binding" });
            return;
          }
          if (matchedUser && matchedUser !== vUser) {
            sendJson(res, 403, { ok: false, error: "All vouchers in a single enrollment must bind to the same invitedUser" });
            return;
          }
          matchedUser = vUser;
          if (voucher.invitedGitHubUserId && Number.isSafeInteger(Number(voucher.invitedGitHubUserId)) && Number(voucher.invitedGitHubUserId) > 0) {
            matchedUserId = Number(voucher.invitedGitHubUserId);
          }
        }
        if (!matchedUserId && matchedUser) {
          const publicUserRes = await apiGet(`/users/${encodeURIComponent(matchedUser)}`, "");
          if (publicUserRes.statusCode === 200 && Number.isSafeInteger(Number(publicUserRes.body?.id)) && Number(publicUserRes.body.id) > 0) {
            matchedUserId = Number(publicUserRes.body.id);
          }
        }
        if (!matchedUser || !matchedUserId) {
          sendJson(res, 403, { ok: false, error: "Could not resolve numeric GitHub principal ID for token-local voucher" });
          return;
        }
        const out = await enrollV3Device(
          {
            ...bodyData,
            githubUser: matchedUser,
            githubUserId: matchedUserId,
          },
          { storePath, sandbox: isPreview }
        );
        if (bodyData.machineId) {
          saveMemberRegistration({
            machineId: bodyData.machineId,
            githubUser: matchedUser,
            githubName: null,
            scope: bodyData.scope || "work",
            version: bodyData.version || "3.6.0",
            hostname: bodyData.hostname || bodyData.machineId,
            platform: bodyData.platform || null,
            specs: bodyData.specs || null,
          }, membersPath);
        }
        sendJson(res, 200, {
          ...projectV3EnrollmentResponse(out, req.headers["x-flock-protocol-version"]),
          hub: DEFAULT_HUB,
        });
        return;
      } catch (err) {
        sendJson(res, err.statusCode || 500, {
          ok: false,
          code: err.code || "V3_ERROR",
          error: err.message,
        });
        return;
      }
    }

    if (!githubToken && isFlocksSync && bodyData.deviceId && bodyData.signature && bodyData.timestamp) {
      try {
        if (bodyData.sandboxPrincipalOverride) {
          sendJson(res, 403, { ok: false, error: "Membership sync cannot override the authenticated GitHub identity" });
          return;
        }
        const cleanDev = String(bodyData.deviceId).trim().toLowerCase();
        const store = loadV3FlockStore(storePath);
        let pinnedUser = null;
        let pinnedUserId = null;
        for (const f of Object.values(store.flocks || {})) {
          for (const m of Object.values(f.members || {})) {
            if (m && m.deviceId === cleanDev && m.githubUser && Number(m.githubUserId) > 0 && m.publicKey) {
              pinnedUser = String(m.githubUser).toLowerCase();
              pinnedUserId = Number(m.githubUserId);
              break;
            }
          }
          if (pinnedUser && pinnedUserId) break;
        }
        if (!pinnedUser || !pinnedUserId) {
          sendJson(res, 403, { ok: false, error: `No enrolled device key pinned for device "${cleanDev}"` });
          return;
        }
        const out = await syncV3DeviceMemberships(
          {
            ...bodyData,
            githubUser: pinnedUser,
            githubUserId: pinnedUserId,
            requireSignature: true,
          },
          { storePath }
        );
        sendJson(res, 200, projectV3EnrollmentResponse(out, req.headers["x-flock-protocol-version"]));
        return;
      } catch (err) {
        sendJson(res, err.statusCode || 500, {
          ok: false,
          code: err.code || "V3_ERROR",
          error: err.message,
        });
        return;
      }
    }

    let privilegedVerification;
    let verification;
    if (!githubToken) {
      const deviceAuth = verifyTokenLocalDeviceHttpAuth(req, url, rawBody, { storePath });
      if (!deviceAuth) {
        sendJson(res, 401, {
          ok: false,
          error: `Missing GitHub token for ${url.pathname}`,
        });
        return;
      }
      if (!deviceAuth.ok) {
        sendJson(res, deviceAuth.statusCode || 401, {
          ok: false,
          error: deviceAuth.error,
        });
        return;
      }
      if (subPath === "/maintainer/overview") {
        sendJson(res, 403, { ok: false, error: "Maintainer overview requires GitHub token authentication" });
        return;
      }
      privilegedVerification = { ok: false, reason: "Token-local device auth" };
      verification = {
        ok: true,
        githubUser: deviceAuth.githubUser,
        githubUserId: deviceAuth.githubUserId,
      };
    } else {
      privilegedVerification = await verifyGitHubRepoAccess(githubToken, apiGet);
      verification = !privilegedVerification.ok && (isEnrollment || isMyFlocks || isFlocksSync)
        ? verifiedGitHubIdentity(await apiGet("/user", githubToken))
        : privilegedVerification;
      if (!verification.ok) {
        sendJson(res, 403, {
          ok: false,
          error: `Access denied: deployment maintainer, repository collaborator/write access or explicit allowlisting required for ${ALLOWED_REPO} (${verification.reason}).`,
        });
        return;
      }
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
        sendJson(res, 200, projectV3EnrollmentResponse(out, req.headers["x-flock-protocol-version"]));
        return;
      }

      if (isFlocksSync) {
        if (bodyData.sandboxPrincipalOverride && !privilegedVerification.ok) {
          sendJson(res, 403, { ok: false, error: "Membership sync cannot override the authenticated GitHub identity" });
          return;
        }
        const effectiveUser =
          isPreview && bodyData.sandboxPrincipalOverride?.githubUser
            ? String(bodyData.sandboxPrincipalOverride.githubUser).toLowerCase()
            : callerGitHubUser;
        const effectiveUserId =
          isPreview && bodyData.sandboxPrincipalOverride?.githubUserId
            ? Number(bodyData.sandboxPrincipalOverride.githubUserId)
            : callerGitHubUserId;
        const out = await syncV3DeviceMemberships(
          {
            ...bodyData,
            githubUser: effectiveUser,
            githubUserId: effectiveUserId,
            requireSignature: true,
          },
          { storePath }
        );
        sendJson(res, 200, projectV3EnrollmentResponse(out, req.headers["x-flock-protocol-version"]));
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
            githubUserId: requestedUser === callerGitHubUser ? callerGitHubUserId : null,
            deviceId: url.searchParams.get("deviceId") || null,
          },
          { storePath }
        );
        sendJson(res, 200, out);
        return;
      }

      if ((subPath === "/flocks/create" || subPath === "/flocks/invite") && req.method === "POST") {
        let resolvedInvitedUserId = bodyData.invitedGitHubUserId || null;
        const rawInvitedUser = String(bodyData.invitedUser || callerGitHubUser).replace(/^@/, "").trim().toLowerCase();
        if (!resolvedInvitedUserId && rawInvitedUser) {
          if (rawInvitedUser === callerGitHubUser && callerGitHubUserId) {
            resolvedInvitedUserId = callerGitHubUserId;
          } else {
            try {
              const invitedRes = await apiGet(`/users/${encodeURIComponent(rawInvitedUser)}`, githubToken);
              if (invitedRes.statusCode === 200 && Number.isSafeInteger(Number(invitedRes.body?.id)) && Number(invitedRes.body.id) > 0) {
                resolvedInvitedUserId = Number(invitedRes.body.id);
              }
            } catch {}
          }
        }
        const out = await createV3FlockInvite(
          {
            ...bodyData,
            callerGitHubUser,
            callerGitHubUserId,
            invitedUser: bodyData.invitedUser || callerGitHubUser,
            invitedGitHubUserId: resolvedInvitedUserId,
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

    sendJson(res, 404, {
      ok: false,
      code: "V3_ENDPOINT_UNSUPPORTED",
      correlationId,
      error: `Unknown v3 endpoint: ${url.pathname}`,
    });
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
    const { raw: rawBody, parsed: bodyData } =
      req.method === "POST" ? await readRequestBodyWithRaw(req) : { raw: "", parsed: {} };

    let verification = null;
    let deviceAuth = null;
    if (!githubToken) {
      deviceAuth = verifyTokenLocalDeviceHttpAuth(req, url, rawBody, { storePath: v3StorePath });
      if (!deviceAuth) {
        sendJson(res, 401, {
          ok: false,
          error: `Missing GitHub token. Pass 'Authorization: Bearer <github_token>' from a user with access to ${ALLOWED_REPO}.`,
        });
        return;
      }
      if (!deviceAuth.ok) {
        sendJson(res, deviceAuth.statusCode || 401, {
          ok: false,
          error: deviceAuth.error,
        });
        return;
      }
      if (url.pathname === "/api/bootstrap") {
        sendJson(res, 403, {
          ok: false,
          error: "Token-local devices cannot access /api/bootstrap; use /api/v3/enroll.",
        });
        return;
      }
      verification = {
        ok: true,
        repo: ALLOWED_REPO,
        githubUser: deviceAuth.githubUser,
        githubName: null,
      };
    } else {
      verification = await verifyGitHubRepoAccess(githubToken, apiGet);
      if (!verification.ok) {
        sendJson(res, 403, {
          ok: false,
          error: `Access denied: deployment maintainer, repository collaborator/write access or explicit allowlisting required for ${ALLOWED_REPO} (${verification.reason}).`,
        });
        return;
      }
    }

    let machineId =
      bodyData.machineId ||
      url.searchParams.get("machineId") ||
      req.headers["x-machine-id"] ||
      deviceAuth?.machineId ||
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
    const githubUser = deviceAuth
      ? deviceAuth.githubUser
      : verification.githubUser ||
        bodyData.githubUser ||
        url.searchParams.get("githubUser") ||
        null;
    const isMaintainer = String(githubUser || "").toLowerCase() ===
      String(process.env.PLATFORM_MAINTAINER_USER || PLATFORM_MAINTAINER_USER).toLowerCase();
    const isGitHubMaintainer = !deviceAuth && isMaintainer;
    if (url.pathname === "/api/bootstrap" && !isMaintainer) {
      sendJson(res, 403, { ok: false, code: "MAINTAINER_REQUIRED", error: "Master transport bootstrap is restricted to the platform maintainer. Use scoped device enrollment." });
      return;
    }
    const ownedMachines = new Set();
    const sharedPeerPrincipals = new Set();
    const sharedQueueMachines = new Set();
    if (!deviceAuth && !isMaintainer) {
      const store = loadV3FlockStore(v3StorePath);
      const now = Date.now();
      const allActive = Object.values(store.flocks || {}).filter((flock) =>
        !flock.expiresAtMs || Number(flock.expiresAtMs) > now).flatMap((flock) =>
        Object.values(flock.members || {}).filter((member) => member && !member.removed &&
          (!member.membershipExpiresAtMs || Number(member.membershipExpiresAtMs) > now) &&
          !isPrincipalRevokedInFlock(flock, member)));
      const matchesCaller = (member) => Number(verification.githubUserId) > 0 &&
        Number(member.githubUserId) === Number(verification.githubUserId) &&
        String(member.githubUser).toLowerCase() === String(githubUser).toLowerCase();
      for (const member of allActive.filter(matchesCaller)) {
        const machine = String(member.machineId || "").toLowerCase();
        if (machine && !allActive.some((other) => String(other.machineId || "").toLowerCase() === machine && !matchesCaller(other))) {
          ownedMachines.add(machine);
        }
      }
      for (const flock of Object.values(store.flocks || {})) {
        if (flock.expiresAtMs && Number(flock.expiresAtMs) <= now) continue;
        const active = Object.values(flock.members || {}).filter((member) => member && !member.removed &&
          (!member.membershipExpiresAtMs || Number(member.membershipExpiresAtMs) > now) &&
          !isPrincipalRevokedInFlock(flock, member));
        if (!active.some(matchesCaller)) continue;
        for (const member of active) sharedPeerPrincipals.add(`${String(member.githubUser).toLowerCase()}:${String(member.machineId).toLowerCase()}`);
        if (active.some((member) => matchesCaller(member) && ["owner", "collaborator"].includes(member.trustTier))) {
          for (const member of active) {
            const machine = String(member.machineId || "").toLowerCase();
            if (machine && !allActive.some((other) => String(other.machineId || "").toLowerCase() === machine &&
                Number(other.githubUserId) !== Number(member.githubUserId))) sharedQueueMachines.add(machine);
          }
        }
      }
    }
    const visibleRegistryMembers = (registry) => deviceAuth
      ? Object.values(registry).filter((member) => member?.machineId && deviceAuth.allowedPeerMachines.has(String(member.machineId).toLowerCase()))
      : isMaintainer ? Object.values(registry)
      : Object.values(registry).filter((member) => sharedPeerPrincipals.has(`${String(member.githubUser).toLowerCase()}:${String(member.machineId).toLowerCase()}`));
    let normalizeQueueTarget = null;
    let normalizeStoredTarget = (value) => value;
    if (url.pathname.startsWith("/api/queue/")) {
      normalizeQueueTarget = queueTargetNormalizer(loadV3FlockStore(v3StorePath), {
        deviceAuth, verification, isGitHubMaintainer,
      });
      normalizeStoredTarget = (value) => {
        if (typeof value !== "string" || !value.includes("/")) return value;
        try { return normalizeQueueTarget(value); }
        catch (error) {
          if (!["QUEUE_TARGET_UNAUTHORIZED", "INVALID_QUEUE_TARGET"].includes(error.code)) throw error;
          return null;
        }
      };
      try {
        const selectors = [
          ...(Object.hasOwn(bodyData, "machineId") ? [bodyData.machineId] : []),
          ...url.searchParams.getAll("machineId"),
          ...(req.headers["x-machine-id"] !== undefined ? [req.headers["x-machine-id"]] : []),
        ];
        const normalizedSelectors = selectors.map((value) => normalizeQueueTarget(value));
        if (deviceAuth) {
          const ownMachine = normalizeQueueTarget(deviceAuth.machineId);
          if (normalizedSelectors.some((value) => value.toLowerCase() !== ownMachine.toLowerCase())) {
            throw Object.assign(new Error("Token-local queue selectors must identify the device's own enrolled machineId"),
              { statusCode: 403, code: "QUEUE_TARGET_UNAUTHORIZED" });
          }
          machineId = ownMachine;
          if (Object.hasOwn(bodyData, "machineId")) bodyData.machineId = ownMachine;
        } else if (machineId) {
          machineId = normalizeQueueTarget(machineId);
          if (normalizedSelectors.some((value) => value.toLowerCase() !== machineId.toLowerCase())) {
            throw Object.assign(new Error("Queue machine selectors disagree"), { statusCode: 403, code: "QUEUE_TARGET_UNAUTHORIZED" });
          }
          if (Object.hasOwn(bodyData, "machineId")) bodyData.machineId = machineId;
        }
        if (url.pathname === "/api/queue/enqueue") bodyData.toMachine = normalizeQueueTarget(bodyData.toMachine, { enqueue: true });
      } catch (error) {
        sendJson(res, error.statusCode || 403, { ok: false, code: error.code || "QUEUE_TARGET_UNAUTHORIZED", error: error.message });
        return;
      }
    }
    const ownsQueue = (target) => deviceAuth
      ? Boolean(deviceAuth.machineId) && String(target || "").trim().toLowerCase() === String(deviceAuth.machineId).trim().toLowerCase()
      : isGitHubMaintainer || ownedMachines.has(String(target || "").trim().toLowerCase());
    if (deviceAuth && url.pathname === "/api/register") {
      if (
        !deviceAuth.machineId ||
        String(machineId || "").trim().toLowerCase() !== String(deviceAuth.machineId).trim().toLowerCase()
      ) {
        sendJson(res, 403, {
          ok: false,
          error: "Token-local device can only register its own enrolled machineId.",
        });
        return;
      }
    }

    let registry = loadMembersRegistry(membersPath);
    if (!deviceAuth && !isMaintainer && url.pathname === "/api/register" &&
        !ownedMachines.has(String(machineId || "").toLowerCase())) {
      sendJson(res, 403, { ok: false, error: "Registration requires an authoritative owned machine" });
      return;
    }
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
      }, membersPath);
    }

    if (url.pathname === "/api/members") {
      const visibleMembers = visibleRegistryMembers(registry);
      sendJson(res, 200, {
        ok: true,
        repo: verification.repo,
        callerGitHubUser: githubUser,
        members: visibleMembers,
      });
      return;
    }

    if (url.pathname === "/api/queue/status") {
      const rawFilter = String(machineId || "").toLowerCase();
      if (!deviceAuth && !isGitHubMaintainer && !ownsQueue(rawFilter)) {
        sendJson(res, 403, { ok: false, error: "Queue status requires an authoritative owned target machine" });
        return;
      }
      if (deviceAuth) {
        const ownMachineLower = String(deviceAuth.machineId || "").trim().toLowerCase();
        if (!ownMachineLower || (rawFilter && rawFilter !== ownMachineLower)) {
          sendJson(res, 403, {
            ok: false,
            error: "Token-local device can only inspect offline queue status for its own machineId.",
          });
          return;
        }
      }
      const targetFilter = deviceAuth
        ? String(deviceAuth.machineId || "").trim().toLowerCase()
        : rawFilter;
      let status;
      try {
        status = await drainOfflineStoreItems({ queuePath, targetMachine: targetFilter, peekOnly: true,
          allMachines: isGitHubMaintainer && !targetFilter, normalizeStoredTarget });
      } catch (error) {
        sendJson(res, error.statusCode || 500, { ok: false, code: error.code || "QUEUE_ERROR",
          error: "Offline queue status/healing could not be persisted; inspect broker storage before retrying." });
        return;
      }
      const items = status.messages;
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
          serviceBusReason: x.serviceBusReason || null,
          serviceBusCategory: x.serviceBusCategory || null,
          serviceBusStage: x.serviceBusStage || null,
          serviceBusStatusCode: x.serviceBusStatusCode ?? null,
        })),
      });
      return;
    }

    if (url.pathname === "/api/queue/enqueue") {
      if (!deviceAuth && !isGitHubMaintainer && !sharedQueueMachines.has(String(bodyData.toMachine || "").trim().toLowerCase())) {
        sendJson(res, 403, { ok: false, error: "Offline enqueue requires an authorized peer in an active shared flock" });
        return;
      }
      if (deviceAuth) {
        const targetLower = String(bodyData.toMachine || "").trim().toLowerCase();
        if (!targetLower || !deviceAuth.allowedEnqueueMachines.has(targetLower)) {
          sendJson(res, 403, {
            ok: false,
            error: "Token-local device can only enqueue offline messages to peers in an active shared flock.",
          });
          return;
        }
      }
      try {
        const result = await enqueueOfflineStoreItem({
          queuePath,
          toMachine: bodyData.toMachine,
          rpcPayload: bodyData.rpcPayload,
          githubUser,
          machineId: deviceAuth ? deviceAuth.machineId : machineId,
          ttlSeconds: bodyData.ttlSeconds,
          publishFn: (entry, ttl) => publishToServiceBusRest(entry, ttl, { tokenProvider: serviceBusTokenProvider }),
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
      const requestedDrainTarget = bodyData.machineId || machineId;
      if (!ownsQueue(requestedDrainTarget)) {
        sendJson(res, 403, { ok: false, error: "Queue drain requires ownership of the target machine" });
        return;
      }
      if (deviceAuth) {
        const ownMachineLower = String(deviceAuth.machineId || "").trim().toLowerCase();
        if (!ownMachineLower || String(requestedDrainTarget || "").trim().toLowerCase() !== ownMachineLower) {
          sendJson(res, 403, {
            ok: false,
            error: "Token-local device can only drain offline queue items addressed to its own machineId.",
          });
          return;
        }
      }
      try {
        const result = await drainOfflineStoreItems({
          queuePath,
          targetMachine: requestedDrainTarget,
          peekOnly: Boolean(bodyData.peekOnly),
          normalizeStoredTarget,
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
      const ackTarget = deviceAuth?.machineId || machineId;
      if (!ownsQueue(ackTarget)) {
        sendJson(res, 403, { ok: false, error: "Queue acknowledgement requires ownership of the target machine" });
        return;
      }
      if (deviceAuth && !deviceAuth.machineId) {
        sendJson(res, 403, {
          ok: false,
          error: "Token-local device must have an enrolled machineId to acknowledge offline queue items.",
        });
        return;
      }
      try {
        const result = await ackOfflineStoreItems({
          queuePath,
          requestIds: bodyData.requestIds,
          onlyForMachine: deviceAuth ? deviceAuth.machineId : isGitHubMaintainer && !machineId ? null : ackTarget,
          normalizeStoredTarget,
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
      const visibleMembers = visibleRegistryMembers(registry);
      sendJson(res, 200, {
        ok: true,
        repo: verification.repo,
        githubUser,
        registered: machineId ? registry[machineId] : null,
        members: visibleMembers,
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
