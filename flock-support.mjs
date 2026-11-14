import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { atomicJson, assertNoLinks } from "./flock-lifecycle.mjs";

const TYPE = "copilot-flock-support-mailbox-v1";
const TICKET_TYPE = "SupportCapabilityV1";
const MAX_TEXT_BYTES = 4096;
const MAX_REPORT_BYTES = 16 * 1024;
const DEFAULT_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;
const ALLOWED_DIAGNOSTICS = new Set([
  "artifact", "protocol", "platform", "stage", "error", "correlation",
  "clock", "fingerprint", "rosterEpoch",
]);
const SECRET_PATTERN =
  /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|SharedAccessSignature|SharedAccessKey|(?:AccessKey|api[_-]?key|password|token)\s*[:=]|github_pat_|gh[pousr]_|Bearer\s+[A-Za-z0-9._~+/-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i;
const ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'(])(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\|\/(?:home|Users|var|etc|root|tmp|mnt|opt|srv|run|data)\/)/i;

const canonical = (value) => JSON.stringify(value);
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fingerprint = (publicKey) => digest(String(publicKey)).slice(0, 32);
const iso = (ms) => new Date(ms).toISOString();
const DENIED_AUTHORITIES = [
  "flock", "signalr", "service_bus", "roster", "presence", "session", "thread",
  "file", "repository", "config", "mutation", "command", "queue", "autopilot",
  "enrollment", "key_rotation",
];
function assertTicketShape(ticket) {
  const keys = ["deniedAuthorities", "expiresAt", "flockId", "issuedAt", "issuerDeviceId",
    "issuerFingerprint", "nonce", "permissions", "supportKeyFingerprint", "ticketId", "type"].sort();
  if (canonical(Object.keys(ticket || {}).sort()) !== canonical(["body", "issuerPublicKey", "signature"]) ||
      canonical(Object.keys(ticket?.body || {}).sort()) !== canonical(keys)) {
    throw new Error("Support ticket contains unsupported fields");
  }
}

export function createSupportTicket({ maintainerIdentity, flockId, supportPublicKey, ttlSeconds = 900, now = Date.now() }) {
  if (crypto.createPublicKey(supportPublicKey).asymmetricKeyType !== "ed25519") throw new Error("Support-only key must use Ed25519");
  const body = {
    type: TICKET_TYPE, ticketId: crypto.randomUUID(),
    flockId: boundedText(flockId, "flockId", 256),
    issuerDeviceId: maintainerIdentity.deviceId,
    issuerFingerprint: fingerprint(maintainerIdentity.publicKey),
    supportKeyFingerprint: fingerprint(supportPublicKey),
    nonce: crypto.randomBytes(24).toString("base64url"),
    issuedAt: iso(now), expiresAt: iso(now + Math.min(3600, Math.max(60, Number(ttlSeconds) || 900)) * 1000),
    permissions: ["submit_text_report"], deniedAuthorities: DENIED_AUTHORITIES,
  };
  return {
    body, issuerPublicKey: maintainerIdentity.publicKey,
    signature: crypto.sign(null, Buffer.from(canonical(body)), maintainerIdentity.privateKey).toString("base64"),
  };
}

export function ensureSupportDeviceKey(root) {
  const resolvedRoot = assertNoLinks(path.resolve(root));
  const filename = path.join(resolvedRoot, "support-device.json");
  fs.mkdirSync(resolvedRoot, { recursive: true });
  if (fs.existsSync(filename)) {
    const stored = JSON.parse(fs.readFileSync(assertNoLinks(filename), "utf8"));
    if (stored?.type !== "copilot-flock-support-device-v1" || !stored.publicKey || !stored.privateKey) {
      throw new Error("Invalid support-only device key");
    }
    return stored;
  }
  const pair = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const stored = {
    type: "copilot-flock-support-device-v1",
    deviceId: crypto.randomUUID(),
    fingerprint: fingerprint(pair.publicKey),
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    createdAt: iso(Date.now()),
  };
  atomicJson(filename, stored);
  return stored;
}

function boundedText(value, field, maxBytes = MAX_TEXT_BYTES) {
  if (typeof value !== "string") throw new Error(`${field} must be a string`);
  const text = value.trim();
  if (!text) throw new Error(`${field} is required`);
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error(`${field} exceeds ${maxBytes} bytes`);
  if (SECRET_PATTERN.test(text)) throw new Error(`${field} contains credential-like content`);
  if (ABSOLUTE_PATH_PATTERN.test(text)) throw new Error(`${field} contains an absolute or network path`);
  return text;
}

function validateDiagnostics(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("diagnostics must be an object");
  }
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (!ALLOWED_DIAGNOSTICS.has(key)) throw new Error(`Unsupported diagnostic field "${key}"`);
    if (key === "rosterEpoch") {
      if (!Number.isSafeInteger(value) || value < 0) throw new Error("rosterEpoch must be a non-negative integer");
      output[key] = value;
      continue;
    }
    output[key] = boundedText(value, `diagnostics.${key}`, 1024);
  }
  return output;
}

export function validateSupportReport(report, now = Date.now()) {
  if (!report || typeof report !== "object" || Array.isArray(report) ||
      Object.keys(report).some((key) => !["diagnostics", "submittedAt", "text"].includes(key))) {
    throw new Error("Support report contains unsupported fields");
  }
  const normalized = {
    text: boundedText(report.text, "report.text"),
    diagnostics: validateDiagnostics(report.diagnostics || {}),
    submittedAt: report.submittedAt || iso(now),
  };
  if (typeof normalized.submittedAt !== "string" || !Number.isFinite(Date.parse(normalized.submittedAt)) ||
      Math.abs(Date.parse(normalized.submittedAt) - now) > 300_000) {
    throw new Error("Support report timestamp is outside the allowed clock window");
  }
  if (Buffer.byteLength(canonical(normalized), "utf8") > MAX_REPORT_BYTES) throw new Error("Support report exceeds payload limit");
  return normalized;
}

export function validateSupportText(text) {
  return boundedText(text, "reply.text");
}

function verifySignature(publicKey, payload, signature) {
  if (!crypto.verify(null, Buffer.from(canonical(payload)), publicKey, Buffer.from(String(signature), "base64"))) {
    throw new Error("Invalid support signature");
  }
}

function safeAttempt(attempt) {
  return { untrustedData: {
    attemptId: attempt.attemptId,
    ticketId: attempt.ticketId,
    identity: "ticket_holder",
    state: attempt.state,
    createdAt: attempt.createdAt,
    updatedAt: attempt.updatedAt,
    expiresAt: attempt.expiresAt,
    report: attempt.report,
    replies: attempt.replies,
  } };
}

export class SupportMailbox {
  constructor(root, { clock = Date.now, retentionMs = DEFAULT_RETENTION_MS } = {}) {
    this.root = assertNoLinks(path.resolve(root));
    this.filename = path.join(this.root, "support-mailbox.json");
    this.clock = clock;
    this.retentionMs = Math.max(60_000, Number(retentionMs) || DEFAULT_RETENTION_MS);
  }

  read() {
    if (!fs.existsSync(this.filename)) {
      return { type: TYPE, tickets: {}, attempts: {}, audit: [] };
    }
    const data = JSON.parse(fs.readFileSync(assertNoLinks(this.filename), "utf8"));
    if (data?.type !== TYPE || !data.tickets || !data.attempts || !Array.isArray(data.audit)) {
      throw new Error("Invalid support mailbox state");
    }
    for (let index = 0; index < data.audit.length; index++) {
      const { hash: entryHash, ...entry } = data.audit[index];
      if (digest(canonical(entry)) !== entryHash ||
          (index > 0 && entry.previousHash !== data.audit[index - 1].hash)) {
        throw new Error("Support audit chain integrity check failed");
      }
    }
    return data;
  }

  save(data) {
    fs.mkdirSync(this.root, { recursive: true });
    data.updatedAt = iso(this.clock());
    atomicJson(this.filename, data);
  }

  audit(data, event, details = {}) {
    const previousHash = data.audit.at(-1)?.hash || "0".repeat(64);
    const entry = {
      eventId: crypto.randomUUID(),
      event,
      at: iso(this.clock()),
      previousHash,
      ...details,
    };
    entry.hash = digest(canonical(entry));
    data.audit.push(entry);
    data.audit = data.audit.slice(-500);
  }

  cleanup(data = this.read()) {
    const cutoff = this.clock() - this.retentionMs;
    for (const [attemptId, attempt] of Object.entries(data.attempts)) {
      if (!["closed", "revoked", "expired"].includes(attempt.state) && Date.parse(attempt.expiresAt) <= this.clock()) {
        attempt.state = "expired";
        attempt.updatedAt = attempt.expiresAt;
        this.audit(data, "attempt_expired", { attemptId });
      }
      if (["closed", "revoked", "expired"].includes(attempt.state) &&
          Date.parse(attempt.updatedAt || attempt.createdAt) < cutoff) {
        delete data.attempts[attemptId];
      }
    }
    for (const [ticketId, ticket] of Object.entries(data.tickets)) {
      if (ticket.status === "issued" && Date.parse(ticket.expiresAt) <= this.clock()) {
        ticket.status = "expired";
        ticket.updatedAt = ticket.expiresAt;
      }
      if (ticket.status !== "issued" && Date.parse(ticket.updatedAt || ticket.createdAt) < cutoff) {
        delete data.tickets[ticketId];
      }
    }
    let prefix = 0;
    while (prefix < data.audit.length && Date.parse(data.audit[prefix].at) < cutoff) prefix++;
    data.audit = data.audit.slice(prefix);
    return data;
  }

  consumeRequest({ ip, ticketId = null, requestSignature = null }) {
    const data = this.cleanup();
    const now = this.clock();
    data.requestLimits = (data.requestLimits || []).filter((entry) => entry.at > now - 600_000);
    const ipHash = digest(String(ip));
    const ticketHash = ticketId ? digest(String(ticketId)) : null;
    const signatureHash = requestSignature ? digest(requestSignature) : null;
    if (signatureHash && data.requestLimits.some((entry) => entry.signatureHash === signatureHash)) {
      throw Object.assign(new Error("Support request replay rejected"), { statusCode: 409 });
    }
    if (data.requestLimits.filter((entry) => entry.ipHash === ipHash && entry.at > now - 60_000).length >= 30 ||
        (ticketHash && data.requestLimits.filter((entry) => entry.ticketHash === ticketHash).length >= 5)) {
      throw Object.assign(new Error("Support request rate limit exceeded"), { statusCode: 429 });
    }
    if (data.requestLimits.length >= 5000) throw Object.assign(new Error("Support mailbox request capacity exceeded"), { statusCode: 429 });
    data.requestLimits.push({ ipHash, ticketHash, signatureHash, at: now });
    this.save(data);
  }

  issue({ maintainerIdentity, flockId, supportPublicKey, ttlSeconds = 900, signedTicket = null }) {
    if ((!maintainerIdentity?.privateKey && !signedTicket) || !maintainerIdentity?.publicKey || !maintainerIdentity?.deviceId) {
      throw new Error("Maintainer device identity is required");
    }
    const now = this.clock();
    const ticket = signedTicket || createSupportTicket({ maintainerIdentity, flockId, supportPublicKey, ttlSeconds, now });
    assertTicketShape(ticket);
    const body = ticket.body;
    verifySignature(maintainerIdentity.publicKey, body, ticket.signature);
    if (ticket.issuerPublicKey !== maintainerIdentity.publicKey ||
        body?.issuerDeviceId !== maintainerIdentity.deviceId ||
        body?.issuerFingerprint !== fingerprint(maintainerIdentity.publicKey) ||
        body?.supportKeyFingerprint !== fingerprint(supportPublicKey) || body?.flockId !== flockId ||
        body?.type !== TICKET_TYPE || !/^[a-f0-9-]{36}$/.test(body?.ticketId || "") ||
        !/^[A-Za-z0-9_-]{32}$/.test(body?.nonce || "") ||
        !Number.isFinite(Date.parse(body.issuedAt)) || Math.abs(Date.parse(body.issuedAt) - now) > 300_000 ||
        !Number.isFinite(Date.parse(body.expiresAt)) || Date.parse(body.expiresAt) <= now ||
        Date.parse(body.expiresAt) - Date.parse(body.issuedAt) > 3600_000 ||
        canonical(body.permissions) !== canonical(["submit_text_report"]) ||
        canonical(body.deniedAuthorities) !== canonical(DENIED_AUTHORITIES)) {
      throw new Error("Support ticket does not match verified owner authority");
    }
    const data = this.cleanup();
    if (data.tickets[body.ticketId]) throw new Error("Support ticket already issued; replay rejected");
    const recentIssues = data.audit.filter(
      (entry) =>
        entry.event === "ticket_issued" &&
        entry.issuerDeviceId === body.issuerDeviceId &&
        Date.parse(entry.at) > now - 60_000
    );
    if (recentIssues.length >= 10) throw new Error("Support ticket issue rate limit exceeded");
    data.tickets[body.ticketId] = {
      flockId: body.flockId,
      ticketDigest: digest(canonical(ticket)),
      issuerDeviceId: body.issuerDeviceId,
      supportKeyFingerprint: body.supportKeyFingerprint,
      status: "issued",
      createdAt: body.issuedAt,
      updatedAt: body.issuedAt,
      expiresAt: body.expiresAt,
    };
    this.audit(data, "ticket_issued", { ticketId: body.ticketId, issuerDeviceId: body.issuerDeviceId });
    this.save(data);
    return ticket;
  }

  revoke({ ticketId, maintainerDeviceId }) {
    const data = this.cleanup();
    const ticket = data.tickets[ticketId];
    if (!ticket) throw new Error("Unknown support ticket");
    if (ticket.issuerDeviceId !== maintainerDeviceId) throw new Error("Support ticket maintainer mismatch");
    ticket.status = "revoked";
    ticket.updatedAt = iso(this.clock());
    for (const attempt of Object.values(data.attempts)) {
      if (attempt.ticketId === ticketId) {
        attempt.state = "revoked";
        attempt.updatedAt = ticket.updatedAt;
      }
    }
    this.audit(data, "ticket_revoked", { ticketId, issuerDeviceId: maintainerDeviceId });
    this.save(data);
    return { ticketId, state: "revoked" };
  }

  submit({ ticket, supportPublicKey, report, signature }) {
    if (ticket?.body?.type !== TICKET_TYPE) throw new Error("Invalid support ticket");
    assertTicketShape(ticket);
    verifySignature(ticket.issuerPublicKey, ticket.body, ticket.signature);
    if (fingerprint(ticket.issuerPublicKey) !== ticket.body.issuerFingerprint) {
      throw new Error("Support ticket issuer fingerprint mismatch");
    }
    if (fingerprint(supportPublicKey) !== ticket.body.supportKeyFingerprint) {
      throw new Error("Support ticket is bound to another support device key");
    }
    if (Date.parse(ticket.body.expiresAt) <= this.clock()) throw new Error("Support ticket expired");
    const normalizedReport = validateSupportReport(report, this.clock());
    verifySignature(supportPublicKey, {
      ticketId: ticket.body.ticketId,
      nonce: ticket.body.nonce,
      report: normalizedReport,
    }, signature);
    const data = this.cleanup();
    const stored = data.tickets[ticket.body.ticketId];
    if (!stored || stored.ticketDigest !== digest(canonical(ticket))) throw new Error("Support ticket is not trusted by this mailbox");
    if (stored.status !== "issued") throw new Error(`Support ticket is ${stored.status}; replay rejected`);
    const attemptId = crypto.randomUUID();
    const now = iso(this.clock());
    stored.status = "redeemed";
    stored.updatedAt = now;
    data.attempts[attemptId] = {
      flockId: ticket.body.flockId,
      attemptId,
      ticketId: ticket.body.ticketId,
      issuerDeviceId: ticket.body.issuerDeviceId,
      supportKeyFingerprint: ticket.body.supportKeyFingerprint,
      state: "report_submitted",
      createdAt: now,
      updatedAt: now,
      expiresAt: iso(this.clock() + this.retentionMs),
      report: normalizedReport,
      replies: [],
    };
    this.audit(data, "report_submitted", { attemptId, ticketId: ticket.body.ticketId });
    this.save(data);
    return safeAttempt(data.attempts[attemptId]);
  }

  assertMaintainer(attempt, maintainerDeviceId) {
    if (!attempt || attempt.issuerDeviceId !== maintainerDeviceId) {
      throw new Error("Support attempt maintainer mismatch");
    }
  }

  list({ maintainerDeviceId, flockId = null, cursor = 0, limit = 25, includeClosed = false }) {
    const data = this.cleanup();
    this.save(data);
    const offset = Math.max(0, Number(cursor) || 0);
    const size = Math.min(50, Math.max(1, Number(limit) || 25));
    const all = Object.values(data.attempts)
      .filter((attempt) => attempt.issuerDeviceId === maintainerDeviceId)
      .filter((attempt) => !flockId || attempt.flockId === flockId)
      .filter((attempt) => includeClosed || !["closed", "revoked", "expired"].includes(attempt.state))
      .sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
    const items = all.slice(offset, offset + size).map(safeAttempt);
    return { items, nextCursor: offset + items.length < all.length ? offset + items.length : null, total: all.length };
  }

  get({ attemptId, maintainerDeviceId }) {
    const data = this.cleanup();
    this.save(data);
    const attempt = data.attempts[attemptId];
    this.assertMaintainer(attempt, maintainerDeviceId);
    return safeAttempt(attempt);
  }

  reply({ attemptId, maintainerDeviceId, text }) {
    const data = this.cleanup();
    const attempt = data.attempts[attemptId];
    this.assertMaintainer(attempt, maintainerDeviceId);
    if (["closed", "revoked", "expired"].includes(attempt.state)) throw new Error(`Support attempt is ${attempt.state}`);
    if (attempt.replies.length >= 10) throw new Error("Support reply quota exceeded");
    attempt.replies.push({
      replyId: crypto.randomUUID(),
      from: "maintainer",
      text: boundedText(text, "reply.text"),
      createdAt: iso(this.clock()),
    });
    attempt.state = "maintainer_replied";
    attempt.updatedAt = iso(this.clock());
    this.audit(data, "maintainer_replied", { attemptId });
    this.save(data);
    return safeAttempt(attempt);
  }

  close({ attemptId, maintainerDeviceId }) {
    const data = this.cleanup();
    const attempt = data.attempts[attemptId];
    this.assertMaintainer(attempt, maintainerDeviceId);
    attempt.state = "closed";
    attempt.updatedAt = iso(this.clock());
    this.audit(data, "attempt_closed", { attemptId });
    this.save(data);
    return safeAttempt(attempt);
  }
}

